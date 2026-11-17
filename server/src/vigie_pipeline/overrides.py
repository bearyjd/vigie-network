"""overrides.db access. Human-owned: the pipeline opens it read-only, structurally."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from urllib.parse import quote

MAX_LINK_DEPTH = 32
logger = logging.getLogger("vigie_pipeline")


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
        conn = sqlite3.connect(overrides_uri(path), uri=True, timeout=5.0)
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
