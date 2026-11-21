"""overrides.db access. Human-owned: the pipeline opens it read-only, structurally."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import quote

MAX_LINK_DEPTH = 32
OVERRIDES_BUSY_TIMEOUT_S = 5.0  # how long a read waits for a writer of overrides.db
# Review statuses that quiet an incident; a pinned mirror of vigie_api.incident_decisions.
QUIET_STATUSES = frozenset({"acknowledged", "expected"})
# The one overrides schema this build understands. A LITERAL on purpose: derived from the
# migration list it would follow every new migration silently, and a new table or column that names
# a device would be pruned from under. Bump only after reviewing PROTECTED_READS (and the
# classification test in tests/pipeline/test_prune_protected_set.py) against the new schema.
SUPPORTED_USER_VERSION = 10
# Tables the protected-device query reads; all must exist before anything is pruned on its word.
PROTECTED_TABLES = (
    "candidate_decisions",
    "device_overrides",
    "essential_devices",
    "identity_links",
    "identity_merges",
    "identity_rules",
    "incident_decisions",
    "suggestion_decisions",
)
# Every column below names a device a human decision refers to. Unfiltered on purpose: expired or
# revoked rules, cleared marks, undone merges and revoked links still protect (over-protecting
# fails safe). Incident decisions, cleared ones (status NULL) included, protect while their row
# exists; the API deletes the row together with its incident (vigie_api.incident_decisions), and
# the protection ends with it. Kept in this module with the other identity_links SQL.
DURABLE_READS = (
    "SELECT device_id FROM device_overrides",
    "SELECT device_id FROM essential_devices",
    "SELECT device_id FROM identity_rules",
    "SELECT from_device, into_device FROM identity_merges",
    "SELECT device_a, device_b FROM candidate_decisions",
    "SELECT from_device, into_device FROM identity_links",
)
# Incident decisions are the one source that expires on its own, so it is kept out of
# DURABLE_READS: it protects, but its disappearance is not a lost decision.
INCIDENT_READS = ("SELECT device_id FROM incident_decisions",)
PROTECTED_READS = DURABLE_READS + INCIDENT_READS
# The owner's decision on a suggestion (accepted or rejected) is keyed by suggestion id, not by
# device: the devices it concerns are in the inventory's `suggestions` row (prune_exclusions).
SUGGESTION_READS = ("SELECT suggestion_id FROM suggestion_decisions",)
logger = logging.getLogger("vigie_pipeline")


class OverridesNotUsable(Exception):
    """overrides.db cannot vouch for which devices a human decision refers to."""


def overrides_uri(path: Path) -> str:
    """Layer 1 of 2: SQLite refuses every write on a mode=ro connection."""
    return f"file:{quote(str(path.resolve()))}?mode=ro"


def open_overrides_ro(path: Path) -> sqlite3.Connection | None:
    """Open overrides.db with mode=ro (URI) plus query_only.

    Returns None when there is nothing usable: the file does not exist yet, or it cannot be read
    (corrupt, unreadable, or a read-only mount whose writer holds no connection). None means "no
    identity links, no rules": the pipeline then trusts nothing from overrides.db (it never
    reads None as permission), and an unreadable file is logged at ERROR so it is noticed.
    The file is never created, written, or migrated from here."""
    if not path.exists():
        return None
    try:
        conn = sqlite3.connect(overrides_uri(path), uri=True, timeout=OVERRIDES_BUSY_TIMEOUT_S)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()  # really readable?
    except sqlite3.Error as exc:
        logger.error(
            "overrides_unreadable path=%s error=%s: continuing with no identity links", path, exc
        )
        return None
    return conn


def link_revocations_supported(conn: sqlite3.Connection) -> bool:
    """Only live links canonicalize; pre-revocation API schemas contain live links only."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(identity_links)")}
    return "revoked_at" in columns


def read_decisions(conn: sqlite3.Connection) -> list[tuple[str, str, float | None]]:
    """(incident_id, status, snooze_until) for every owner decision. Sole reader of the
    API-owned incident_decisions table; sqlite3.Error propagates to the caller."""
    rows = conn.execute("SELECT incident_id,status,snooze_until FROM incident_decisions")
    return [(r[0], r[1], r[2]) for r in rows.fetchall()]


def decided_incident_ids(
    conn: sqlite3.Connection, incident_ids: list[str], statuses: Iterable[str]
) -> list[str]:
    """Ids among incident_ids whose decision status is in statuses (sqlite3.Error propagates)."""
    statuses = tuple(statuses)
    status_marks = ",".join("?" * len(statuses))
    id_marks = ",".join("?" * len(incident_ids))
    rows = conn.execute(
        f"SELECT incident_id FROM incident_decisions WHERE status IN ({status_marks})"  # noqa: S608
        f" AND incident_id IN ({id_marks})",
        (*statuses, *incident_ids),
    )
    return [r[0] for r in rows]


def _live_filter(conn: sqlite3.Connection) -> str:
    return " AND revoked_at IS NULL" if link_revocations_supported(conn) else ""


def links_select_sql(conn: sqlite3.Connection) -> str:
    """SQL listing every live (from_device, into_device) link."""
    where = " WHERE revoked_at IS NULL" if link_revocations_supported(conn) else ""
    return f"SELECT from_device, into_device FROM identity_links{where}"  # noqa: S608


def link_target(conn: sqlite3.Connection, device_id: str) -> str | None:
    """The device a live link merges device_id into, or None."""
    row = conn.execute(
        f"SELECT into_device FROM identity_links WHERE from_device=?{_live_filter(conn)}",  # noqa: S608
        (device_id,),
    ).fetchone()
    return None if row is None else row[0]


def link_sources(conn: sqlite3.Connection, device_id: str, limit: int = 257) -> list[str]:
    """Devices a live link merges into device_id (at most limit)."""
    return [
        row[0]
        for row in conn.execute(
            f"SELECT from_device FROM identity_links WHERE into_device=?{_live_filter(conn)}"  # noqa: S608
            " LIMIT ?",
            (device_id, limit),
        )
    ]


def canonical_device(conn: sqlite3.Connection | None, device_id: str) -> str:
    """Follow identity_links (from_device -> into_device) to the canonical device.
    Links are flattened on merge, but a bounded walk also tolerates chains and cycles."""
    if conn is None:
        return device_id
    seen = {device_id}
    current = device_id
    for _ in range(MAX_LINK_DEPTH):
        try:
            target = link_target(conn, current)
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):  # api has not created the schema yet
                return device_id
            if "no such column" in str(exc):  # malformed: no links, never an aborted run
                logger.error("overrides_unreadable error=%s: ignoring identity links", exc)
                return device_id
            raise
        if target is None or target in seen:
            return current
        current = target
        seen.add(current)
    return current


def overrides_data_version(conn: sqlite3.Connection | None) -> int:
    """SQLite's `PRAGMA data_version` of overrides.db: it changes when ANOTHER connection commits
    anything (on this mode=ro connection it really moves, unlike with immutable=1). Not
    identity_version, whose triggers miss names, essential marks, merges and incident decisions.
    sqlite3.Error propagates; None raises OverridesNotUsable."""
    if conn is None:
        raise OverridesNotUsable("overrides.db is missing or could not be opened")
    return int(conn.execute("PRAGMA data_version").fetchone()[0])


def _read_text_ids(conn: sqlite3.Connection | None, statements: Iterable[str]) -> set[str]:
    """The non-empty text values of `statements`. FAILS CLOSED: raises OverridesNotUsable unless
    the file is open, at exactly the supported schema version, and holds every table the prune
    reads; an empty set must mean "nothing is protected", never "could not tell"."""
    if conn is None:
        raise OverridesNotUsable("overrides.db is missing or could not be opened")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != SUPPORTED_USER_VERSION:
        raise OverridesNotUsable(
            f"overrides.db schema v{version}, this build supports v{SUPPORTED_USER_VERSION}"
        )
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing = [t for t in PROTECTED_TABLES if t not in tables]
    if missing:
        raise OverridesNotUsable(f"overrides.db lacks table(s): {', '.join(missing)}")
    values = [value for sql in statements for row in conn.execute(sql) for value in row]
    if not all(isinstance(value, str) and value for value in values):
        # str(b"..") or str(7) would name an id that never matches a row: a protection that
        # silently protects nothing. Say what kind of value, never its content.
        raise OverridesNotUsable("overrides.db holds an id that is not non-empty text")
    return set(values)


def protected_device_ids(conn: sqlite3.Connection | None) -> set[str]:
    """Devices a human decision refers to: names/groups, essential marks, identity-rule targets,
    incident and candidate decisions, and both ends of every identity merge and link, undone
    or revoked ones included. Fails closed (`_read_text_ids`)."""
    return _read_text_ids(conn, PROTECTED_READS)


def durable_decisions_found(conn: sqlite3.Connection | None) -> bool:
    """True when a decision that does not expire with an incident is on file (`DURABLE_READS`).
    Fails closed (`_read_text_ids`)."""
    return bool(_read_text_ids(conn, DURABLE_READS))


def decided_suggestion_ids(conn: sqlite3.Connection | None) -> set[str]:
    """Ids of the suggestions the owner accepted or rejected. Fails closed (`_read_text_ids`)."""
    return _read_text_ids(conn, SUGGESTION_READS)


def overrides_identity(path: Path) -> tuple[int, int]:
    """(st_dev, st_ino) of the file at `path`: a removed or replaced overrides.db (a restored
    backup, a recreated file) is a different file than the one a connection reads."""
    try:
        info = path.stat()
    except OSError as exc:
        reason = type(exc).__name__
        raise OverridesNotUsable(f"overrides.db cannot be inspected ({reason})") from exc
    return (info.st_dev, info.st_ino)
