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
from vigie_pipeline.sources import MacActivity, is_randomized, read_batch

logger = logging.getLogger("vigie_pipeline")

PROMOTE_MIN_HOURS = 2


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
    try:
        totals = _process_batches(inv, overrides, config)
        promoted, retired = sweep_transients(inv, clock, config.transient_window_s)
    finally:
        inv.close()
        if overrides is not None:
            overrides.close()
    stats = RunStats(**totals, promoted=promoted, retired=retired)
    log(logger, logging.INFO, "run_complete", **stats.__dict__)
    return stats


def _process_batches(
    inv: sqlite3.Connection, overrides: sqlite3.Connection | None, config: PipelineConfig
) -> dict[str, int]:
    totals = {"batches": 0, "macs": 0, "new_devices": 0, "skipped_macs": 0}
    collectors = [r[0] for r in inv.execute("SELECT DISTINCT collector_id FROM batches")]
    for collector in sorted(collectors):
        for rowid, batch_id in _pending(inv, collector):
            acts, skipped = read_batch(config.data_dir, collector, batch_id)
            with immediate(inv):
                created = _apply_batch(inv, overrides, acts)
                _advance_cursor(inv, collector, rowid, batch_id)
            totals["batches"] += 1
            totals["macs"] += len(acts)
            totals["new_devices"] += created
            totals["skipped_macs"] += skipped
            log(logger, logging.DEBUG, "batch_processed", collector=collector, batch_id=batch_id,
                macs=len(acts), new_devices=created)  # fmt: skip
    return totals


def _pending(inv: sqlite3.Connection, collector: str) -> list[tuple[int, str]]:
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
        (r[0], r[1])
        for r in inv.execute(
            "SELECT rowid, batch_id FROM batches WHERE collector_id=? AND rowid>? ORDER BY rowid",
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
    inv: sqlite3.Connection, overrides: sqlite3.Connection | None, acts: dict[str, MacActivity]
) -> int:
    created = 0
    for mac, act in sorted(acts.items()):
        existing = inv.execute("SELECT * FROM observations WHERE mac=?", (mac,)).fetchone()
        if existing is None:
            device_id = _create_device(inv, mac, act)
            created += 1
        else:
            device_id = existing["device_id"]
            _update_observation(inv, existing, act)
        _touch_devices(inv, overrides, device_id, act)
        _record_hours(inv, device_id, act)
    return created


def _create_device(inv: sqlite3.Connection, mac: str, act: MacActivity) -> str:
    device_id = str(uuid.uuid4())
    first, last = iso_utc(act.first_ts), iso_utc(act.last_ts)
    randomized = is_randomized(mac)
    inv.execute(
        "INSERT INTO devices (id, first_seen, last_seen, status) VALUES (?,?,?,?)",
        (device_id, first, last, "transient" if randomized else "active"),
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


def _record_hours(inv: sqlite3.Connection, device_id: str, act: MacActivity) -> None:
    status = inv.execute("SELECT status FROM devices WHERE id=?", (device_id,)).fetchone()[0]
    if status != "transient":
        return
    inv.executemany(
        "INSERT OR IGNORE INTO transient_hours (device_id, hour) VALUES (?,?)",
        [(device_id, iso_utc(h * 3600)[:13]) for h in act.hours],
    )


def sweep_transients(inv: sqlite3.Connection, now: float, window_s: int) -> tuple[int, int]:
    """Promote transients seen on >=2 distinct hours or with a hostname; retire the rest once
    the window has elapsed since first_seen. Devices are retired, never deleted."""
    cutoff = iso_utc(now - window_s)
    with immediate(inv):
        promoted = inv.execute(
            "UPDATE devices SET status='active' WHERE status='transient' AND ("
            " EXISTS (SELECT 1 FROM observations o WHERE o.device_id=devices.id"
            "         AND o.hostname IS NOT NULL AND o.hostname<>'')"
            " OR (SELECT COUNT(*) FROM transient_hours h WHERE h.device_id=devices.id) >= ?)",
            (PROMOTE_MIN_HOURS,),
        ).rowcount
        retired = inv.execute(
            "UPDATE devices SET status='retired' WHERE status='transient' AND first_seen<=?",
            (cutoff,),
        ).rowcount
        inv.execute(
            "DELETE FROM transient_hours WHERE device_id IN"
            " (SELECT id FROM devices WHERE status<>'transient')"
        )
    return promoted, retired
