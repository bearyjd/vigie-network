"""Bounded window measurements. Raw reads precede the inventory writer transaction."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from vigie_ingest.db import shard_name, utc_day
from vigie_ingest.models import FUTURE_WINDOW_SLACK
from vigie_pipeline.sources import ShardReadError, normalize_mac

MAX_VALUE = (2**63 - 1) // 64  # at most64 canonical MACs can be summed safely


@dataclass(frozen=True)
class Measurements:
    collector: str
    batch_id: str
    start: int | None
    end: int | None
    received: str
    reasons: tuple[str, ...]
    counters: dict[str, tuple[int, int, int, int]]


def read_measurements(
    inv: sqlite3.Connection, root: Path, collector: str, batch_id: str
) -> Measurements:
    row = inv.execute(
        "SELECT * FROM batches WHERE collector_id=? AND batch_id=?", (collector, batch_id)
    ).fetchone()
    start, end = row["window_start"], row["window_end"]
    reasons = []
    counters: dict[str, list[int]] = {}
    if row["observation_kind"] == "probe":
        reasons.append("probe")
    elif start is None or end is None:
        reasons.append("legacy_window")
    else:
        if row["observation_kind"] != "observation":
            reasons.append("legacy_kind")
        if start >= end:
            reasons.append("empty_window")
        elif start // 3600 != (end - 1) // 3600:
            reasons.append("cross_hour")
        if row["health"] is None:
            reasons.append("health_missing")
        truncated = json.loads(row["truncated"] or "{}")
        if (
            truncated.get("source_flags", 0) & ~8
            or row["dropped_batches"]
            or any(
                value
                for key, value in truncated.items()
                if key != "source_flags" and (key.startswith("ct_") or key.startswith("conntrack"))
            )
        ):
            reasons.append("flow_degraded")
        end_path = root / shard_name(utc_day(end))
        if not end_path.exists():
            reasons.append("raw_missing")
        low = max(0, start - FUTURE_WINDOW_SLACK) // 86400 * 86400
        high = (end + FUTURE_WINDOW_SLACK) // 86400 * 86400
        paths = {root / shard_name(utc_day(day)) for day in range(low, high + 1, 86400)}
        if len(paths) > 3:
            raise ShardReadError("measurement shard bound exceeded")
        flows, dns = [], []
        for path in sorted(paths):
            if not path.exists():
                continue
            db = None
            try:
                db = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=2)
                flows.extend(
                    db.execute(
                        "SELECT device_mac,bytes_up,bytes_down,flows FROM raw_flow "
                        "WHERE collector_id=? AND batch_id=? LIMIT 5001",
                        (collector, batch_id),
                    ).fetchall()
                )
                dns.extend(
                    db.execute(
                        "SELECT device_mac FROM raw_dns WHERE collector_id=? AND "
                        "batch_id=? LIMIT 5001",
                        (collector, batch_id),
                    ).fetchall()
                )
                if len(flows) > 5000 or len(dns) > 5000:
                    raise ShardReadError("measurement row bound exceeded")
            except sqlite3.Error as exc:
                raise ShardReadError("measurement shard unavailable") from exc
            finally:
                if db is not None:
                    db.close()
        if row["dns_queries"] is not None and len(dns) != row["dns_queries"]:
            reasons.append("raw_missing")
        for mac, up, down, count in flows:
            mac = normalize_mac(mac)
            if mac is None:
                reasons.append("invalid_mac")
                continue
            values = counters.setdefault(mac, [0, 0, 0, 0])
            for i, value in enumerate((up, down, count)):
                if not isinstance(value, int) or value < 0:
                    raise ShardReadError("invalid measurement counter")
                if values[i] + value > MAX_VALUE:
                    reasons.append("counter_overflow")
                values[i] = min(MAX_VALUE, values[i] + value)
        for (mac,) in dns:
            mac = normalize_mac(mac)
            if mac is not None:
                counters.setdefault(mac, [0, 0, 0, 0])[3] += 1
    return Measurements(
        collector,
        batch_id,
        start,
        end,
        row["received_at"],
        tuple(sorted(set(reasons))),
        {mac: tuple(v) for mac, v in counters.items()},
    )


def apply_measurements(inv: sqlite3.Connection, measured: Measurements) -> None:
    m = measured
    if inv.execute(
        "SELECT 1 FROM measurement_batches WHERE collector_id=? AND batch_id=?",
        (m.collector, m.batch_id),
    ).fetchone():
        return
    reasons = list(m.reasons)
    hour = (
        (m.end - 1) // 3600 * 3600
        if m.start is not None and m.end is not None and m.end > m.start
        else None
    )
    if hour is not None and "cross_hour" not in reasons:
        overlap = inv.execute(
            "SELECT 1 FROM measurement_batches WHERE collector_id=? AND hour=? "
            "AND window_start<? AND window_end>? AND quality NOT LIKE ? LIMIT 1",
            (m.collector, hour, m.end, m.start, "%probe%"),
        ).fetchone()
        if overlap:
            reasons.append("overlapping_window")
    if "overlapping_window" in reasons:
        prior = inv.execute(
            "SELECT reasons FROM coverage_hourly WHERE collector_id=? AND hour=?",
            (m.collector, hour),
        ).fetchone()
        if prior is not None:
            degraded = sorted(set(json.loads(prior[0])) | {"overlapping_window"})
            inv.execute(
                "UPDATE coverage_hourly SET qualified_seconds=0,reasons=? "
                "WHERE collector_id=? AND hour=?",
                (json.dumps(degraded), m.collector, hour),
            )
            inv.execute(
                "INSERT OR IGNORE INTO monitoring_quality_work VALUES (?,?,'')", (m.collector, hour)
            )
    inv.execute(
        "INSERT INTO measurement_batches VALUES (?,?,?,?,?,?,?)",
        (m.collector, m.batch_id, m.start, m.end, m.received, hour, json.dumps(reasons)),
    )
    if hour is None or any(
        reason in reasons
        for reason in ("probe", "cross_hour", "empty_window", "legacy_window", "overlapping_window")
    ):
        return
    bounded = {}
    for mac, values in m.counters.items():
        prior = inv.execute(
            "SELECT bytes_up,bytes_down,flows,dns_queries FROM measurements_hourly "
            "WHERE collector_id=? AND mac=? AND hour=?",
            (m.collector, mac, hour),
        ).fetchone()
        old_values = tuple(prior) if prior else (0, 0, 0, 0)
        if any(old + value > MAX_VALUE for old, value in zip(old_values, values, strict=True)):
            reasons.append("counter_overflow")
        bounded[mac] = tuple(min(MAX_VALUE, value) for value in values)
    duration = m.end - m.start
    qualified = duration if not reasons else 0
    old = inv.execute(
        "SELECT reasons FROM coverage_hourly WHERE collector_id=? AND hour=?", (m.collector, hour)
    ).fetchone()
    combined = sorted(set(reasons) | set(json.loads(old[0]) if old else []))
    inv.execute(
        "INSERT INTO coverage_hourly VALUES (?,?,?,?,?) ON CONFLICT(collector_id,hour) "
        "DO UPDATE SET observed_seconds=observed_seconds+excluded.observed_seconds, "
        "qualified_seconds=qualified_seconds+excluded.qualified_seconds,reasons=excluded.reasons",
        (m.collector, hour, duration, qualified, json.dumps(combined)),
    )
    for mac, values in bounded.items():
        inv.execute(
            "INSERT INTO monitoring_dirty VALUES (?,?,?) ON CONFLICT(collector_id,mac) "
            "DO UPDATE SET queued_at=MIN(queued_at,excluded.queued_at)",
            (m.collector, mac, m.end),
        )
        inv.execute(
            "INSERT INTO measurements_hourly VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(collector_id,mac,hour) DO UPDATE SET "
            "bytes_up=MIN(?,bytes_up+excluded.bytes_up),bytes_down=MIN(?,bytes_down+excluded.bytes_down),"
            "flows=MIN(?,flows+excluded.flows),dns_queries=MIN(?,dns_queries+excluded.dns_queries)",
            (m.collector, mac, hour, *values, MAX_VALUE, MAX_VALUE, MAX_VALUE, MAX_VALUE),
        )
