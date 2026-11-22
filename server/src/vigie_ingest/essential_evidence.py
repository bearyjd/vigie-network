"""Essential-device observation evidence, written inside the accepted batch transaction."""

from __future__ import annotations

import sqlite3

from vigie_ingest.models import Batch

HOUR_S = 3600
MASK_BYTES = HOUR_S // 8
INFORMATIONAL_KEYS = ("ct_unmapped_bytes", "ct_unmapped_flows", "mcast_unmapped", "mcast_dropped")


def recording_since(conn: sqlite3.Connection) -> int | None:
    # Ingest may start before the pipeline installs its optional schema.
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='essential_recording'"
    ).fetchone():
        return None
    row = conn.execute("SELECT since_hour FROM essential_recording WHERE enabled=1").fetchone()
    return row[0] if row else None


def _valid_mac(mac: str) -> bool:
    # Batch validation already checked canonical MAC syntax.
    return mac != "00:00:00:00:00:00" and not int(mac[:2], 16) & 1


def _clean(batch: Batch) -> bool:
    return (
        {"truncated", "dropped_batches", "dns", "conntrack"} <= batch.model_fields_set
        and batch.observation_kind == "observation"
        and batch.health is not None
        and "dns_log_quiet" in batch.health.model_fields_set
        and not batch.health.dns_log_quiet
        and batch.dropped_batches == 0
        and not any(
            (value & ~8 if key == "source_flags" else value)
            for key, value in batch.truncated.items()
            if key not in INFORMATIONAL_KEYS
        )
        and all(_valid_mac(r.mac) for r in batch.dns)
        and all(_valid_mac(r.mac) for r in batch.conntrack)
    )


def record_accepted(conn: sqlite3.Connection, batch: Batch, since: int) -> None:
    """Certify the same accepted receipt that advanced the fallback fence in this transaction."""
    conn.execute("UPDATE essential_recording SET since_hour=? WHERE singleton=1", (since,))
    if batch.observation_kind == "probe":
        return
    start, end = batch.window_start, batch.window_end
    # Flow deltas belong somewhere in [start,end); use their latest possible hour. DNS has
    # an event timestamp and ingest clamps it to the inclusive batch endpoints.
    last_flow_hour = (max(start, end - 1) // HOUR_S) * HOUR_S
    latest = {r.mac: last_flow_hour for r in batch.conntrack if _valid_mac(r.mac)}
    for row in batch.dns:
        if _valid_mac(row.mac):
            hour = min(end, max(start, row.ts)) // HOUR_S * HOUR_S
            latest[row.mac] = max(latest.get(row.mac, hour), hour)
    conn.executemany(
        "INSERT INTO essential_activity VALUES (?,?,?) ON CONFLICT(collector_id,mac)"
        " DO UPDATE SET hour=MAX(hour,excluded.hour) WHERE hour<excluded.hour",
        ((batch.collector_id, mac, hour) for mac, hour in latest.items() if hour >= since),
    )
    clean = _clean(batch) and start < end
    # A lost DNS event could have been stamped at the inclusive endpoint.
    stop = end if clean else end + 1
    for hour in range(max(since, start // HOUR_S * HOUR_S), stop, HOUR_S):
        key = (batch.collector_id, hour)
        prior = conn.execute(
            "SELECT observed FROM essential_observation_hours WHERE collector_id=? AND hour=?", key
        ).fetchone()
        if prior is not None and prior[0] is None:
            continue  # any dirty overlap vetoes this hour permanently
        mask = None
        seconds = 0
        if clean:
            lo, hi = max(start, hour) - hour, min(end, hour + HOUR_S) - hour
            bits = ((1 << (hi - lo)) - 1) << lo
            if prior is not None:
                bits |= int.from_bytes(prior[0], "little")
            mask = bits.to_bytes(MASK_BYTES, "little")
            seconds = bits.bit_count()
        conn.execute(
            "INSERT OR REPLACE INTO essential_observation_hours VALUES (?,?,?,?)",
            (*key, mask, seconds),
        )
