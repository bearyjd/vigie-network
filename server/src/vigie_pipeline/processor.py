"""Core pass: recorded batches -> observations/devices/events, then transient GC."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.activity import purge_activity, record_activity
from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.characterization_store import (
    read_services,
    refresh_characterization,
    save_services,
)
from vigie_pipeline.config import (
    PRUNE_BATCH_ROWS,
    PRUNE_CLOCK_WARN_S,
    RETIRED_BACKFILL_INTERVAL_S,
    RETIRED_MAC_RETENTION_S,
    PipelineConfig,
)
from vigie_pipeline.delivery_wiring import run_delivery_stage
from vigie_pipeline.last_ip import save_last_ips
from vigie_pipeline.logs import log
from vigie_pipeline.measurements import apply_measurements, read_measurements
from vigie_pipeline.monitoring_engine import analyze_monitoring, prune_monitoring
from vigie_pipeline.new_device_notice import sweep_new_devices
from vigie_pipeline.overrides import (
    OverridesNotUsable,
    canonical_device,
    decided_suggestion_ids,
    open_overrides_ro,
    overrides_data_version,
    overrides_identity,
    protected_device_ids,
)
from vigie_pipeline.probes import fold_probes, retire_status
from vigie_pipeline.prune_exclusions import (
    LIVE_SUGGESTION_PARAMS,
    PRUNE_EXCLUSIONS_SQL,
    suggestion_devices,
)
from vigie_pipeline.retirement import retirement_stamp
from vigie_pipeline.schema import open_pipeline_inventory
from vigie_pipeline.snapshot import EMPTY, OverridesUnreadable, Snapshot, load_snapshot
from vigie_pipeline.sources import MacActivity, ShardReadError, is_randomized, read_batch
from vigie_pipeline.stitch import StitchStats, stitch
from vigie_pipeline.stitch_db import emit_once, state_get, state_set
from vigie_pipeline.stitch_types import fold

logger = logging.getLogger("vigie_pipeline")

PROMOTE_MIN_HOURS = 2  # distinct server-received hours


@dataclass(frozen=True)
class RunStats:
    batches: int = 0
    macs: int = 0
    new_devices: int = 0
    skipped_macs: int = 0
    promoted: int = 0
    retired: int = 0
    suggestions: int = 0
    attached: int = 0


def run_once(
    config: PipelineConfig,
    now: float | None = None,
    should_stop: Callable[[], bool] = lambda: False,
) -> RunStats:
    """Process every recorded, not-yet-processed batch, then promote/retire transients.
    `should_stop` only reaches the delivery stage (no new claim once set); earlier stages run on."""
    clock = time.time() if now is None else now
    live = time.time if now is None else None  # injected `now` pins every clock read (tests)
    inv = open_pipeline_inventory(config.inventory_path, config.migrate)
    overrides = open_overrides_ro(config.overrides_path)
    failures: list[ShardReadError] = []
    try:
        # a malformed overrides.db gets the unreadable-file policy BEFORE any batch is touched:
        # no identity links for the batches, no stitching, cursor progress is kept
        usable = _overrides_readable(inv, overrides, config, clock)
        totals = _process_batches(inv, overrides if usable else None, config, failures)
        stitched = (
            _stitch(inv, overrides, config, live or (lambda: clock)) if usable else StitchStats()
        )
        promoted, retired = sweep_transients(
            inv, clock, config, retired_at=(live or (lambda: clock))()
        )
        if usable and not failures:  # an unread batch may carry a returning MAC: prune next pass
            prune_retired_macs(inv, config.overrides_path, clock)  # fails closed on its own
        if config.new_device_notice and usable:  # F5, default off: nothing else touches it
            sweep_new_devices(inv, overrides, config, clock)
        purge_activity(inv, clock, config.activity_retention_s)
        _monitor_deliver_probe(inv, overrides, config, usable, clock, live, should_stop)
    finally:
        inv.close()
        if overrides is not None:
            overrides.close()
    stats = RunStats(
        **totals,
        promoted=promoted,
        retired=retired,
        suggestions=stitched.suggestions,
        attached=stitched.attached,
    )
    log(logger, logging.INFO, "run_complete", failed_collectors=len(failures), **stats.__dict__)
    if failures:
        raise failures[0]
    return stats


def _monitor_deliver_probe(
    inv: sqlite3.Connection,
    overrides: sqlite3.Connection | None,
    config: PipelineConfig,
    usable: bool,
    clock: float,
    live: Callable[[], float] | None,
    should_stop: Callable[[], bool],
) -> None:
    """The stages after the prune; they need a readable overrides.db except the probes."""
    if usable:
        analyze_monitoring(inv, overrides, monitoring_policy(config), clock)
        run_delivery_stage(inv, overrides, config, live or (lambda: clock), should_stop=should_stop)
        refresh_characterization(inv, overrides, clock)
    prune_monitoring(inv, clock)
    if config.probes.enabled:  # needs no overrides; contains its own errors
        fold_probes(inv, config.probes, live or (lambda: clock))
    else:  # a status stored while it was on must not keep saying ok (a read when none exists)
        retire_status(inv, live or (lambda: clock))


def monitoring_policy(config: PipelineConfig) -> BaselineConfig | TodConfig:
    "The baseline family is an explicit opt-in; the default stays pooled-median-v1."
    family = TodConfig if config.monitoring_baseline == "tod" else BaselineConfig
    return family(large_upload_bytes=config.monitoring_large_upload_bytes)


def _overrides_readable(
    inv: sqlite3.Connection, overrides: sqlite3.Connection | None, config: PipelineConfig,
    now: float,
) -> bool:  # fmt: skip
    """overrides.db missing entirely => readable (no rules, basis versions 0). Present but
    unreadable or malformed => fail closed: log `stitching_skipped` and report False."""
    try:
        if overrides is not None:
            load_snapshot(overrides, now)
        elif config.overrides_path.exists():
            raise OverridesUnreadable("overrides.db exists but could not be opened")
    except OverridesUnreadable as exc:
        log(
            logger,
            logging.ERROR,
            "stitching_skipped",
            reason="overrides_unreadable",
            error=str(exc),
        )
        with immediate(inv):  # one event per UTC day, so the API can surface it
            emit_once(inv, None, "stitching_skipped", "warn",
                      "stitching skipped: overrides.db unreadable or malformed "
                      f"({type(exc.__cause__ or exc).__name__})",
                      iso_utc(now)[:10], now)  # fmt: skip
        return False
    return True


def _stitch(
    inv: sqlite3.Connection,
    overrides: sqlite3.Connection | None,
    config: PipelineConfig,
    clock: Callable[[], float],
) -> StitchStats:
    """Run identity stitching on a snapshot read NOW (after the batches, so rule expiry is judged
    against the current time, not the start of the run). A snapshot that turns unreadable between
    the early check and now also skips stitching."""
    now = clock()
    snap: Snapshot = EMPTY
    try:
        if overrides is not None:
            snap = load_snapshot(overrides, now)
    except OverridesUnreadable as exc:
        log(logger, logging.ERROR, "stitching_skipped", reason="overrides_unreadable",
            error=str(exc))  # fmt: skip
        return StitchStats()
    return stitch(inv, snap, config, now, clock, overrides)


def _process_batches(
    inv: sqlite3.Connection,
    overrides: sqlite3.Connection | None,
    config: PipelineConfig,
    failures: list[ShardReadError],
) -> dict[str, int]:
    totals = {"batches": 0, "macs": 0, "new_devices": 0, "skipped_macs": 0}
    collectors = [r[0] for r in inv.execute("SELECT DISTINCT collector_id FROM batches")]
    for collector in sorted(collectors):
        for rowid, batch_id, received in _pending(inv, collector):
            try:
                acts, skipped = read_batch(config.data_dir, collector, batch_id, _epoch(received))
                measured = read_measurements(inv, config.data_dir, collector, batch_id)
                services = read_services(config.data_dir, measured)
            except ShardReadError as exc:
                # never advance past an unreadable batch: it and its successors stay pending
                failures.append(exc)
                break
            with immediate(inv):
                created = _apply_batch(inv, overrides, acts, received)
                save_last_ips(inv, acts)
                record_activity(
                    inv, acts, config.activity_gap_s, _epoch(received), config.activity_retention_s
                )
                apply_measurements(inv, measured)
                save_services(inv, services, _epoch(received))
                _advance_cursor(inv, collector, rowid, batch_id)
            totals["batches"] += 1
            totals["macs"] += len(acts)
            totals["new_devices"] += created
            totals["skipped_macs"] += skipped
            log(logger, logging.DEBUG, "batch_processed", collector=collector, batch_id=batch_id,
                macs=len(acts), new_devices=created)  # fmt: skip
    return totals


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _pending(inv: sqlite3.Connection, collector: str) -> list[tuple[int, str, str]]:
    """Recorded batches (batches.rowid order == commit order) past this collector's cursor."""
    row = inv.execute(
        "SELECT last_batch_rowid, last_batch_id FROM pipeline_cursor WHERE collector_id=?",
        (collector,),
    ).fetchone()
    cursor = row[0] if row else 0
    if row:
        at = inv.execute(
            "SELECT batch_id FROM batches WHERE collector_id=? AND rowid=?", (collector, cursor)
        ).fetchone()
        if at is None or at[0] != row[1]:
            # batches was purged and its rowids reused; reprocessing is idempotent
            log(logger, logging.WARNING, "cursor_reset", collector=collector, cursor=cursor)
            cursor = 0
    return [
        (r[0], r[1], r[2])
        for r in inv.execute(
            "SELECT rowid, batch_id, received_at FROM batches"
            " WHERE collector_id=? AND rowid>? ORDER BY rowid",
            (collector, cursor),
        )
    ]


def _advance_cursor(inv: sqlite3.Connection, collector: str, rowid: int, batch_id: str) -> None:
    inv.execute(
        "INSERT INTO pipeline_cursor (collector_id, last_batch_rowid, last_batch_id, updated_at)"
        " VALUES (?,?,?,?) ON CONFLICT(collector_id) DO UPDATE SET"
        " last_batch_rowid=excluded.last_batch_rowid, last_batch_id=excluded.last_batch_id,"
        " updated_at=excluded.updated_at",
        (collector, rowid, batch_id, iso_utc(time.time())),
    )


def _apply_batch(
    inv: sqlite3.Connection,
    overrides: sqlite3.Connection | None,
    acts: dict[str, MacActivity],
    received: str,
) -> int:
    created = 0
    for mac, act in sorted(acts.items()):
        existing = inv.execute("SELECT * FROM observations WHERE mac=?", (mac,)).fetchone()
        if existing is None:
            device_id = _create_device(inv, mac, act, received)
            created += 1
        else:
            device_id = existing["device_id"]
            _update_observation(inv, existing, act)
            _revive_if_retired(inv, device_id, mac, act, received)
        _touch_devices(inv, overrides, device_id, act)
        _record_hours(inv, device_id, received)
    return created


def _create_device(inv: sqlite3.Connection, mac: str, act: MacActivity, received: str) -> str:
    device_id = str(uuid.uuid4())
    first, last = iso_utc(act.first_ts), iso_utc(act.last_ts)
    randomized = is_randomized(mac)
    inv.execute(
        "INSERT INTO devices (id, first_seen, last_seen, status) VALUES (?,?,?,?)",
        (device_id, first, last, "transient" if randomized else "active"),
    )
    if randomized:
        inv.execute(
            "INSERT INTO transient_state (device_id, since) VALUES (?,?)", (device_id, received)
        )
    inv.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, dhcp_fingerprint, vendor_class,"
        " hostname, mdns_name, link_source, first_seen, last_seen, hostname_fold, mdns_fold)"
        " VALUES (?,?,?,?,?,?,?,'self',?,?,?,?)",
        (mac, device_id, int(randomized), act.opt55, act.opt60, act.hostname, act.mdns_name,
         first, last, _fold(act.hostname), _fold(act.mdns_name)),
    )  # fmt: skip
    inv.execute(
        "INSERT OR IGNORE INTO events (id, device_id, ts, kind, severity, summary)"
        " VALUES (?,?,?,'new_device','info',?)",
        (str(uuid.uuid4()), device_id, first, f"new device {mac}"),
    )
    return device_id


def _revive_if_retired(
    inv: sqlite3.Connection, device_id: str, mac: str, act: MacActivity, received: str
) -> None:
    """A retired device seen again goes back to transient with a fresh window; it must earn
    promotion again. One device_reappeared event per revival."""
    revived = inv.execute(
        "UPDATE devices SET status='transient' WHERE id=? AND status='retired'", (device_id,)
    ).rowcount
    if not revived:
        return
    inv.execute(
        "INSERT OR REPLACE INTO transient_state (device_id, since) VALUES (?,?)",
        (device_id, received),
    )
    inv.execute("DELETE FROM transient_hours WHERE device_id=?", (device_id,))
    inv.execute(
        "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
        " VALUES (?,?,?,'device_reappeared','info',?)",
        (str(uuid.uuid4()), device_id, iso_utc(act.last_ts), f"retired device {mac} reappeared"),
    )


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _flag_conflict(
    inv: sqlite3.Connection, row: sqlite3.Row, field: str, new: str, ts: str
) -> None:
    """Fingerprint/vendor class are the identity signature: a differing value for the same MAC
    is kept out of the record and flagged. One event per (device, field) per day; values appear
    only as short hashes."""
    device_id = row["device_id"]
    inv.execute("UPDATE devices SET identity_state='conflict' WHERE id=?", (device_id,))
    seen = inv.execute(
        "SELECT 1 FROM events WHERE device_id=? AND kind='identity_conflict'"
        " AND substr(ts,1,10)=? AND summary LIKE ?",
        (device_id, ts[:10], f"{field} changed%"),
    ).fetchone()
    if seen:
        return
    summary = f"{field} changed on {row['mac']}: {_short_hash(row[field])} -> {_short_hash(new)}"
    inv.execute(
        "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
        " VALUES (?,?,?,'identity_conflict','warn',?)",
        (str(uuid.uuid4()), device_id, ts, summary),
    )


def _update_observation(inv: sqlite3.Connection, row: sqlite3.Row, act: MacActivity) -> None:
    """Widen first/last seen. Hostname/mDNS name follow the newest batch (they legitimately
    change). Fingerprint and vendor class are first-wins; a differing value is a conflict."""
    first, last = iso_utc(act.first_ts), iso_utc(act.last_ts)
    newer = last >= row["last_seen"]

    def pick(old: str | None, new: str | None) -> str | None:
        if new is None:
            return old
        return new if newer or old is None else old

    def first_wins(field: str, new: str | None) -> str | None:
        old = row[field]
        if old is None or new is None or new == old:
            return old if old is not None else new
        _flag_conflict(inv, row, field, new, last)
        return old

    host, mdns = pick(row["hostname"], act.hostname), pick(row["mdns_name"], act.mdns_name)
    inv.execute(
        "UPDATE observations SET first_seen=MIN(first_seen,?), last_seen=MAX(last_seen,?),"
        " hostname=?, dhcp_fingerprint=?, vendor_class=?, mdns_name=?, hostname_fold=?,"
        " mdns_fold=? WHERE mac=?",
        (first, last, host, first_wins("dhcp_fingerprint", act.opt55),
         first_wins("vendor_class", act.opt60), mdns, _fold(host), _fold(mdns), row["mac"]),
    )  # fmt: skip


def _fold(name: str | None) -> str | None:
    return fold(name) if name else None


def _touch_devices(
    inv: sqlite3.Connection, overrides: sqlite3.Connection | None, device_id: str, act: MacActivity
) -> None:
    """Extend first/last seen on the observation's device and on its canonical device."""
    first, last = iso_utc(act.first_ts), iso_utc(act.last_ts)
    for target in {device_id, canonical_device(overrides, device_id)}:
        inv.execute(
            "UPDATE devices SET first_seen=MIN(first_seen,?), last_seen=MAX(last_seen,?)"
            " WHERE id=?",
            (first, last, target),
        )


def _record_hours(inv: sqlite3.Connection, device_id: str, received: str) -> None:
    """Persistence is counted in server-received hours; record timestamps are collector-supplied
    and never count toward promotion."""
    status = inv.execute("SELECT status FROM devices WHERE id=?", (device_id,)).fetchone()[0]
    if status == "transient":
        inv.execute(
            "INSERT OR IGNORE INTO transient_hours (device_id, hour) VALUES (?,?)",
            (device_id, received[:13]),
        )


def sweep_transients(
    inv: sqlite3.Connection, now: float, config: PipelineConfig, retired_at: float | None = None
) -> tuple[int, int]:
    """Promote transients seen in >=2 server-received hours with >= min dwell between first and
    last seen, at most `promotion_cap_per_hour` per server hour; retire the rest once the window
    has elapsed since they became transient. Devices are retired, never deleted. A hostname is
    attacker-controlled and is never a promotion signal. `retired_at` is the server moment the
    retirement is stamped with (default `now`), never earlier than the newest batch receipt
    (`retirement_stamp`): a fresh clock read, not the pass start."""
    hour = iso_utc(now)[:13]
    stamp = retirement_stamp(inv, now if retired_at is None else retired_at)
    with immediate(inv):
        promoted = _promote(inv, hour, iso_utc(now), config)
        retired = _retire_due(inv, now, stamp, config)
        inv.execute(
            "DELETE FROM transient_hours WHERE device_id IN"
            " (SELECT id FROM devices WHERE status<>'transient')"
        )
        # a retired device keeps its stamp: it is the prune's clock
        inv.execute(
            "DELETE FROM transient_state WHERE device_id IN"
            " (SELECT id FROM devices WHERE status='active')"
        )
        _backfill_stamps(inv, stamp)
    return promoted, retired


BACKFILL_KEY = "retired_stamp_backfilled"


def _backfill_stamps(inv: sqlite3.Connection, stamp: str) -> None:
    """Retired devices without a stamp start their clock now, at most once per
    RETIRED_BACKFILL_INTERVAL_S: every retirement of this build stamps itself (`_retire_due`,
    stitch_apply), but one retired before the stamp existed, or by a build rolled back to, has
    none and is not prunable until stamped. The scan of devices therefore repeats daily, not each
    pass. The marker holds the stamp of the last scan; one from the future (the clock was set
    back) counts as due. It is a `stitch_state` row, not `pipeline_meta`: that table's contents
    are pinned byte for byte by the freeze tests."""
    last = state_get(inv, BACKFILL_KEY)
    if last is not None and last <= stamp < iso_utc(_epoch(last) + RETIRED_BACKFILL_INTERVAL_S):
        return
    inv.execute(
        "INSERT OR IGNORE INTO transient_state (device_id, since)"
        " SELECT id, ? FROM devices WHERE status='retired'",
        (stamp,),
    )
    state_set(inv, BACKFILL_KEY, stamp)


def _retire_due(inv: sqlite3.Connection, now: float, stamp: str, config: PipelineConfig) -> int:
    """Retire the transients whose window elapsed and stamp them with the server moment of
    retirement: transient_state.since means "since the current status began" (the prune ages a
    retired device from it; a revival rewrites it)."""
    due = [
        (r[0],)
        for r in inv.execute(
            "SELECT s.device_id FROM transient_state s JOIN devices d ON d.id=s.device_id"
            " WHERE d.status='transient' AND s.since<=?",
            (iso_utc(now - config.transient_window_s),),
        )
    ]
    inv.executemany("UPDATE devices SET status='retired' WHERE id=?", due)
    inv.executemany(
        "UPDATE transient_state SET since=? WHERE device_id=?",
        [(stamp, device_id) for (device_id,) in due],
    )
    return len(due)


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
    that overrides.db refers to (merge, rule, name, group, essential mark, decisions) are never
    pruned: human decisions live there, not in `link_source`. Fails closed: with no
    overrides.db (a DEBUG line: normal before the API ran) nothing is pruned, and with one that
    is unreadable, locked, of another schema version, missing a table or holding an id that is
    not text, an ERROR line; a busy inventory skips the pass. The protected set is read on a
    connection of its own and re-validated just before COMMIT (the file is the same one and
    `PRAGMA data_version` is unchanged): a human decision committed meanwhile defers the whole
    pass, which rolls back. The two databases cannot share a transaction, so a commit landing
    after that last check and before COMMIT (microseconds) is not seen, same as stitch_apply's
    attach. A returning MAC whose rows were pruned gets a new device id (accepted)."""
    if not overrides_path.exists():
        log(logger, logging.DEBUG, "prune_skipped", reason="overrides_missing")
        return 0
    read = None
    try:
        read = _open_overrides_read(overrides_path)
        protected = protected_device_ids(read.conn)
        decided = decided_suggestion_ids(read.conn)
        if not _decisions_not_lost(inv, bool(protected or decided)):
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


def _decisions_not_lost(inv: sqlite3.Connection, found: bool) -> bool:
    """`found`: this read saw a decision in some protected source. False when overrides.db once
    held a decision and now holds none: the file was probably lost
    or recreated empty, and an empty protected set would then protect nothing. The marker is a
    `stitch_state` row set by the first read that finds a decision; an install that never had one
    (nothing to lose) prunes as usual."""
    seen = state_get(inv, OVERRIDES_SEEN_KEY) is not None
    if found and not seen:
        with immediate(inv):
            state_set(inv, OVERRIDES_SEEN_KEY, "1")
    elif seen and not found:
        log(logger, logging.ERROR, "prune_skipped", reason="overrides_lost_decisions")
        return False
    return True


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
    PRUNE_CLOCK_WARN_S. None (no collector with an accepted send) prunes nothing."""
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


def _promote(inv: sqlite3.Connection, hour: str, now_iso: str, config: PipelineConfig) -> int:
    candidates = [
        r[0]
        for r in inv.execute(
            "SELECT d.id FROM devices d WHERE d.status='transient'"
            " AND (SELECT COUNT(*) FROM transient_hours h WHERE h.device_id=d.id) >= ?"
            " AND CAST(strftime('%s', d.last_seen) AS INTEGER)"
            "   - CAST(strftime('%s', d.first_seen) AS INTEGER) >= ?"
            " ORDER BY d.first_seen, d.id",
            (PROMOTE_MIN_HOURS, config.transient_min_dwell_s),
        )
    ]
    inv.execute("INSERT OR IGNORE INTO promotion_log (hour) VALUES (?)", (hour,))
    used, emitted = inv.execute(
        "SELECT promoted, limited_emitted FROM promotion_log WHERE hour=?", (hour,)
    ).fetchone()
    allowed = candidates[: max(0, config.promotion_cap_per_hour - used)]
    for device_id in allowed:
        inv.execute("UPDATE devices SET status='active' WHERE id=?", (device_id,))
    held = len(candidates) - len(allowed)
    if held and not emitted:
        inv.execute(
            "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
            " VALUES (?,NULL,?,'promotion_rate_limited','warn',?)",
            (str(uuid.uuid4()), now_iso,
             f"promotion cap {config.promotion_cap_per_hour}/hour reached; {held} held transient"),
        )  # fmt: skip
        inv.execute("UPDATE promotion_log SET limited_emitted=1 WHERE hour=?", (hour,))
        log(logger, logging.WARNING, "promotion_rate_limited", held=held, hour=hour)
    inv.execute("UPDATE promotion_log SET promoted=promoted+? WHERE hour=?", (len(allowed), hour))
    return len(allowed)
