"""Core pass: recorded batches -> observations/devices/events, then transient GC."""

from __future__ import annotations

import logging
import sqlite3
import time
import uuid
from dataclasses import dataclass

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.logs import log
from vigie_pipeline.overrides import canonical_device, open_overrides_ro
from vigie_pipeline.schema import open_pipeline_inventory
from vigie_pipeline.sources import MacActivity, ShardReadError, is_randomized, read_batch

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


def run_once(config: PipelineConfig, now: float | None = None) -> RunStats:
    """Process every recorded, not-yet-processed batch, then promote/retire transients."""
    clock = time.time() if now is None else now
    inv = open_pipeline_inventory(config.inventory_path)
    overrides = open_overrides_ro(config.overrides_path)
    failures: list[ShardReadError] = []
    try:
        totals = _process_batches(inv, overrides, config, failures)
        promoted, retired = sweep_transients(inv, clock, config)
    finally:
        inv.close()
        if overrides is not None:
            overrides.close()
    stats = RunStats(**totals, promoted=promoted, retired=retired)
    log(logger, logging.INFO, "run_complete", failed_collectors=len(failures), **stats.__dict__)
    if failures:
        raise failures[0]
    return stats


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
                acts, skipped = read_batch(config.data_dir, collector, batch_id)
            except ShardReadError as exc:
                # never advance past an unreadable batch: it and its successors stay pending
                failures.append(exc)
                break
            with immediate(inv):
                created = _apply_batch(inv, overrides, acts, received)
                _advance_cursor(inv, collector, rowid, batch_id)
            totals["batches"] += 1
            totals["macs"] += len(acts)
            totals["new_devices"] += created
            totals["skipped_macs"] += skipped
            log(logger, logging.DEBUG, "batch_processed", collector=collector, batch_id=batch_id,
                macs=len(acts), new_devices=created)  # fmt: skip
    return totals


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
        " hostname, mdns_name, link_source, first_seen, last_seen)"
        " VALUES (?,?,?,?,?,?,?,'self',?,?)",
        (mac, device_id, int(randomized), act.opt55, act.opt60, act.hostname, act.mdns_name,
         first, last),
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


def _update_observation(inv: sqlite3.Connection, row: sqlite3.Row, act: MacActivity) -> None:
    """Widen first/last seen; a value from an older batch never replaces a newer one,
    and a missing value never erases a known one."""
    first, last = iso_utc(act.first_ts), iso_utc(act.last_ts)
    newer = last >= row["last_seen"]

    def pick(old: str | None, new: str | None) -> str | None:
        if new is None:
            return old
        return new if newer or old is None else old

    inv.execute(
        "UPDATE observations SET first_seen=MIN(first_seen,?), last_seen=MAX(last_seen,?),"
        " hostname=?, dhcp_fingerprint=?, vendor_class=?, mdns_name=? WHERE mac=?",
        (first, last, pick(row["hostname"], act.hostname),
         pick(row["dhcp_fingerprint"], act.opt55), pick(row["vendor_class"], act.opt60),
         pick(row["mdns_name"], act.mdns_name), row["mac"]),
    )  # fmt: skip


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
    inv: sqlite3.Connection, now: float, config: PipelineConfig
) -> tuple[int, int]:
    """Promote transients seen in >=2 server-received hours with >= min dwell between first and
    last seen, at most `promotion_cap_per_hour` per server hour; retire the rest once the window
    has elapsed since they became transient. Devices are retired, never deleted. A hostname is
    attacker-controlled and is never a promotion signal."""
    hour = iso_utc(now)[:13]
    with immediate(inv):
        promoted = _promote(inv, hour, iso_utc(now), config)
        retired = inv.execute(
            "UPDATE devices SET status='retired' WHERE status='transient' AND id IN"
            " (SELECT device_id FROM transient_state WHERE since<=?)",
            (iso_utc(now - config.transient_window_s),),
        ).rowcount
        for table in ("transient_hours", "transient_state"):
            inv.execute(
                f"DELETE FROM {table} WHERE device_id IN"  # noqa: S608
                " (SELECT id FROM devices WHERE status<>'transient')"
            )
    return promoted, retired


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
