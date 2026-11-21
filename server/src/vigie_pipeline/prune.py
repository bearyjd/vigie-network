"""Pruning the MAC rows of devices the server retired 90 days ago (PRP section 8).

Everything here fails closed: an unusable overrides.db, an unread batch, a clock that cannot be
checked or a decision that cannot be ruled out all mean nothing is deleted this pass."""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.config import (
    PRUNE_BATCH_ROWS,
    PRUNE_CLOCK_WARN_S,
    RETIRED_MAC_RETENTION_S,
)
from vigie_pipeline.logs import log
from vigie_pipeline.overrides import (
    OverridesNotUsable,
    decided_suggestion_ids,
    durable_decisions_found,
    open_overrides_ro,
    overrides_data_version,
    overrides_identity,
    protected_device_ids,
)
from vigie_pipeline.prune_exclusions import (
    LIVE_SUGGESTION_PARAMS,
    PRUNE_EXCLUSIONS_SQL,
    suggestion_devices,
)
from vigie_pipeline.stitch_db import state_get, state_set

logger = logging.getLogger("vigie_pipeline")

PRUNED_COUNTER_KEY = "retired_mac_rows_pruned"


class _PruneDeferred(Exception):
    """The pass cannot prove it is safe to prune; roll back and try next pass."""

    reason = "unknown"


class _OverridesMoved(_PruneDeferred):
    """overrides.db committed (or could not be asked) since the protected set was read."""

    reason = "overrides_changed"


@dataclass(frozen=True)
class _OverridesRead:
    """A dedicated read-only connection to overrides.db and what it must still show at the end:
    the file's identity from before the open and `PRAGMA data_version` from before the read."""

    conn: sqlite3.Connection
    path: Path
    identity: tuple[int, int]
    version: int

    def moved(self) -> bool:
        """True when overrides.db changed or was replaced since, or cannot say (fail closed)."""
        try:
            return (
                overrides_identity(self.path) != self.identity
                or overrides_data_version(self.conn) != self.version
            )
        except (sqlite3.Error, OverridesNotUsable):
            return True


def _open_overrides_read(path: Path) -> _OverridesRead:
    """The identity is taken BEFORE the open: a file swapped in between is seen as moved. This
    connection is opened here for the prune alone, so no cursor an earlier stage left open on the
    pipeline's own connection can hold its `data_version` still."""
    identity = overrides_identity(path)
    conn = open_overrides_ro(path)
    if conn is None:
        raise OverridesNotUsable("overrides.db could not be opened")
    try:
        return _OverridesRead(conn, path, identity, overrides_data_version(conn))
    except BaseException:
        conn.close()
        raise


def prune_retired_macs(
    inv: sqlite3.Connection,
    overrides_path: Path,
    now: float,
) -> int:
    """Drop self-linked MAC rows of retired devices 90 days after the server retired them
    (transient_state.since; PRP section 8), on the older of the server clock and the oldest live
    collector's `last_sent_ts` (`_trusted_now`), so a stepped server clock prunes nothing. One
    bounded batch per pass; the running total is the aggregate kept in `pipeline_meta` and each
    pass logs only a count.
    Devices are never deleted; a pruned MAC that returns starts over as a new transient. Devices
    that overrides.db refers to (merge, rule, name, group, essential mark, decisions, and the
    devices of every suggestion the owner decided) are never pruned: human decisions live there,
    not in `link_source`. Fails closed: with no
    overrides.db (a DEBUG line: normal before the API ran) nothing is pruned, and with one that
    is unreadable, locked, of another schema version, missing a table or holding an id that is
    not text, an ERROR line; a busy inventory skips the pass. The protected set is read on a
    connection of its own and re-validated just before COMMIT (the file is the same one and
    `PRAGMA data_version` is unchanged): a human decision committed meanwhile defers the whole
    pass, which rolls back. The two databases cannot share a transaction, so a commit landing
    after that last check and before COMMIT (microseconds) is not seen, same as stitch_apply's
    attach. A file that once held a decision and now holds none, or whose audit counter fell below
    its stored high-water mark (an older backup restored, a file recreated), skips the pass. A
    returning MAC whose rows were pruned gets a new device id (accepted). Either skip is latched."""
    if not overrides_path.exists():
        # normal before the API ran; an ERROR once this install has seen a decision (a lost file)
        seen = _marks_set(inv)
        log(
            logger,
            logging.ERROR if seen else logging.DEBUG,
            "prune_skipped",
            reason="overrides_missing",
        )
        return 0
    read = None
    try:
        read = _open_overrides_read(overrides_path)
        protected = protected_device_ids(read.conn)
        decided = decided_suggestion_ids(read.conn)
        found = durable_decisions_found(read.conn) or bool(decided)
        if not _decisions_not_lost(inv, found, _audit_high_water(read.conn)):
            return 0
        protected = protected | suggestion_devices(inv, decided)  # a new set: nothing mutated
        pruned = _delete_retired_rows(inv, read, protected, now)
    except _PruneDeferred as exc:
        log(logger, logging.INFO, "prune_deferred", reason=exc.reason)
        return 0
    except (sqlite3.Error, OverridesNotUsable) as exc:  # busy, locked, unusable: skip the pass
        log(logger, logging.ERROR, "prune_skipped", error=str(exc))
        return 0
    finally:
        if read is not None:
            read.conn.close()
    if pruned:
        log(logger, logging.INFO, "retired_macs_pruned", count=pruned)  # a count, never a MAC
    return pruned


OVERRIDES_SEEN_KEY = "prune_overrides_seen"
OVERRIDES_AUDIT_KEY = "prune_overrides_audit_mark"
OVERRIDES_LATCH_KEY = "prune_overrides_latched"


def _marks_set(inv: sqlite3.Connection) -> bool:
    return any(state_get(inv, key) is not None for key in (OVERRIDES_SEEN_KEY, OVERRIDES_AUDIT_KEY))


def _audit_high_water(conn: sqlite3.Connection) -> int:
    """`audit_log.seq` is AUTOINCREMENT and the API writes a row with every decision, so the
    largest one only grows for as long as this is the same file's history. sqlite3.Error
    propagates (the pass is skipped)."""
    return int(conn.execute("SELECT COALESCE(MAX(seq), 0) FROM audit_log").fetchone()[0])


def _decisions_not_lost(inv: sqlite3.Connection, found: bool, audit_mark: int) -> bool:
    """False when overrides.db looks like a different, poorer file than the one this install has
    read before, and an empty or shrunken protected set would then protect nothing. Two markers,
    both `stitch_state` rows, set by the first read that finds a decision / an audit row:
    `found` (this read saw a lasting decision) against the presence marker, and `audit_mark` (the
    file's audit counter) against its high-water mark, which catches an older backup restored over
    the file and a file recreated and given one new decision. Either finding LATCHES the prune off
    (`OVERRIDES_LATCH_KEY`): the counter catching up later (unrelated audit rows) does not show the
    decisions came back, so only the operator's deletion of the marker rows resumes it. An install
    that never had either (nothing to lose) prunes as usual."""
    latched = state_get(inv, OVERRIDES_LATCH_KEY)
    if latched is not None:
        log(logger, logging.ERROR, "prune_skipped", reason="overrides_latched", latched=latched)
        return False
    stored = state_get(inv, OVERRIDES_AUDIT_KEY)
    try:
        high_water = 0 if stored is None else int(stored)
    except ValueError:
        high_water = audit_mark + 1  # unreadable mark: cannot show the file is the same history
    seen = state_get(inv, OVERRIDES_SEEN_KEY) is not None
    reason = (
        "overrides_rolled_back"
        if audit_mark < high_water
        else "overrides_lost_decisions"
        if seen and not found
        else None
    )
    writes = {}
    if reason is not None:
        writes[OVERRIDES_LATCH_KEY] = reason
    else:
        if found and not seen:
            writes[OVERRIDES_SEEN_KEY] = "1"
        if audit_mark > high_water:
            writes[OVERRIDES_AUDIT_KEY] = str(audit_mark)
    if writes:  # a pass that changes no marker takes no write lock
        with immediate(inv):
            for key, value in writes.items():
                state_set(inv, key, value)
    if reason is not None:
        log(logger, logging.ERROR, "prune_skipped", reason=reason)
    return reason is None


def _delete_retired_rows(
    inv: sqlite3.Connection,
    read: _OverridesRead,
    protected: set[str],
    now: float,
) -> int:
    trusted = _trusted_now(inv, now)
    if trusted is None:
        return 0  # no collector has ever sent: the server clock cannot be checked, prune nothing
    args = _prune_args(trusted)
    candidates = _prune_candidates(inv, protected, args)  # selected before the write lock
    with immediate(inv):
        pruned = _delete_candidates(inv, candidates, args)
        if pruned:
            inv.execute(
                "INSERT INTO pipeline_meta (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+?",
                (PRUNED_COUNTER_KEY, str(pruned), pruned),
            )
        if read.moved():
            raise _OverridesMoved  # immediate() rolls the DELETEs back
    return pruned


def _trusted_now(inv: sqlite3.Connection, now: float) -> float | None:
    """The instant the server can vouch for: the older of its own time and the oldest
    `collectors.last_sent_ts` among live collectors that ever sent. Ingest keeps that column as a
    never-purged running maximum of accepted send times and accepts a send time only within its
    skew window of the server clock, so a stepped server clock cannot drag it along for a collector
    that kept true time, and purging batch rows cannot erase it. A silent collector holds the clock
    back until it is revoked: fail safe, and named in a WARNING once it has been silent for
    PRUNE_CLOCK_WARN_S. None (no collector with an accepted send) prunes nothing; a live collector
    whose `last_sent_ts` is not a number raises sqlite3.DataError (the pass is skipped)."""
    if inv.execute(
        "SELECT 1 FROM collectors WHERE revoked=0 AND typeof(last_sent_ts) NOT IN ('integer','real')"
    ).fetchone():  # text sorts after every number and would silently leave the minimum
        raise sqlite3.DataError("collectors.last_sent_ts holds a value that is not a number")
    row = inv.execute(
        "SELECT id, last_sent_ts FROM collectors WHERE revoked=0 AND last_sent_ts>0"
        " ORDER BY last_sent_ts LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    if row[1] < now - PRUNE_CLOCK_WARN_S:
        log(logger, logging.WARNING, "prune_clock_held_back", collector=row[0], last_sent_ts=row[1])
    return min(now, float(row[1]))


def _prune_args(trusted: float) -> tuple[str, ...]:
    """Binds of the prunable predicate, in order: stamp cutoff, last_seen cutoff, then the instant
    a suggestion must still be live at, once per direction."""
    cutoff = iso_utc(trusted - RETIRED_MAC_RETENTION_S)
    return (cutoff, cutoff, *(iso_utc(trusted),) * LIVE_SUGGESTION_PARAMS)


# The whole prunable predicate, selected before the lock and repeated by the DELETE inside it.
# Aliases: o observations, d devices, t transient_state (the server-clock retirement stamp; a
# retired device without one is not prunable). Placeholders: see `_prune_args`.
_PRUNABLE_SQL = (
    "FROM observations o JOIN devices d ON d.id=o.device_id"  # noqa: S608
    " JOIN transient_state t ON t.device_id=d.id"
    " WHERE d.status='retired' AND o.link_source='self' AND t.since<? AND o.last_seen<?"
    f" AND d.id NOT IN (SELECT id FROM prune_protected){PRUNE_EXCLUSIONS_SQL}"
)


def _prune_candidates(
    inv: sqlite3.Connection, protected: set[str], args: tuple[str, ...]
) -> list[str]:
    """Up to PRUNE_BATCH_ROWS MACs, oldest retirement first, with every protection already
    applied in SQL so a protected oldest batch cannot starve the LIMIT. The scan runs here, with
    no write lock held; the temp table lives in the temp database, not the main one."""
    inv.execute("CREATE TEMP TABLE IF NOT EXISTS prune_protected (id TEXT PRIMARY KEY)")
    inv.execute("DELETE FROM prune_protected")
    inv.executemany(
        "INSERT OR IGNORE INTO prune_protected (id) VALUES (?)", [(i,) for i in protected]
    )
    return [
        r[0]
        for r in inv.execute(
            f"SELECT o.mac {_PRUNABLE_SQL} ORDER BY t.since, o.mac LIMIT ?",  # noqa: S608
            (*args, PRUNE_BATCH_ROWS),
        )
    ]


def _delete_candidates(inv: sqlite3.Connection, macs: list[str], args: tuple[str, ...]) -> int:
    """Inside the lock: one DELETE per candidate that repeats the whole predicate as point
    lookups (a candidate revived, protected or stamped anew since the select is skipped). A
    pruned MAC's last-known IP goes with it: the MAC returning with traffic that carries no
    address (DNS only) would otherwise show the old IP on its new device."""
    pruned = 0
    for mac in macs:
        deleted = inv.execute(
            "DELETE FROM observations WHERE mac=? AND mac IN"  # noqa: S608
            f" (SELECT o.mac {_PRUNABLE_SQL} AND o.mac=?)",
            (mac, *args, mac),
        ).rowcount
        if deleted:
            inv.execute("DELETE FROM mac_last_ip WHERE mac=?", (mac,))
        pruned += deleted
    return pruned
