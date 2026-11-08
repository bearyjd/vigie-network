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

# Unattributed traffic seen on every batch of a normal LAN; reported, never a coverage defect.
# Every other ct_*/conntrack* key (and any future one) stays degrading: fail closed.
INFORMATIONAL_TRUNCATED_KEYS = frozenset({"ct_unmapped_bytes", "ct_unmapped_flows"})
# Independent whole-second truncation of the collector's wall and monotonic clocks can overlap
# consecutive 60 s windows by 1 s. Replays are already rejected by batch_id.
OVERLAP_TOLERANCE_S = 2
# The tolerance only covers the EDGE overlap of two normal windows. The collector's nominal window
# is 60 s; windows under 30 s get no tolerance. That bounds the counters that may be summed twice
# for the shared sliver to 2 s of a >= 30 s window (about 6.7%) per boundary, and a short window
# can never hide inside, or duplicate, another one (a 4 s window every 2 s used to double them).
MIN_TOLERANT_WINDOW_S = 30
# Second bound, independent of the constants above: the shared seconds are at most 1/10 of the
# shorter window. Redundant today (2 s <= 30 s / 10) but it keeps the bound if either is changed.
MAX_SHARED_FRACTION_INV = 10
# A tolerated window has at most one neighbour on each edge; more intersecting rows disqualify.
MAX_TOLERATED_NEIGHBOURS = 2
HOUR_S = 3600
# The collector folds the smallest counters (ct_unmapped_flows first) into `truncated_other` once
# more than 16 distinct counters are non-zero. Any non-zero value therefore means severe
# degradation, and may hide ct_errors/ct_dropped_keys/conntrack_lost, so it always degrades even
# though the informational pair is folded into it first.
ALWAYS_DEGRADING_TRUNCATED_KEYS = frozenset({"truncated_other"})
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
                if key in ALWAYS_DEGRADING_TRUNCATED_KEYS
                or (
                    key != "source_flags"
                    and key not in INFORMATIONAL_TRUNCATED_KEYS
                    and (key.startswith("ct_") or key.startswith("conntrack"))
                )
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
        {mac: (v[0], v[1], v[2], v[3]) for mac, v in counters.items()},
    )


def _tolerated_overlap(start: int, end: int, neighbours: list) -> int | None:
    """Seconds of the new window already credited to its neighbours, or None to disqualify.

    Tolerated only when every neighbour is an edge overlap (neither window contains the other)
    of at most OVERLAP_TOLERANCE_S, at most 1/MAX_SHARED_FRACTION_INV of the shorter window,
    between two windows of at least MIN_TOLERANT_WINDOW_S. Counters of that sliver may still be
    summed twice: at most 2 s of deltas (about 6.7% of a window) per window boundary.
    Neighbours are (start, end, credited) rows; rows never credited (already flagged
    overlapping_window) still count as overlaps but are not subtracted from the credit.
    """
    if not neighbours:
        return 0
    if len(neighbours) > MAX_TOLERATED_NEIGHBOURS or end - start < MIN_TOLERANT_WINDOW_S:
        return None
    covered = 0
    for n_start, n_end, credited in neighbours:
        shared = min(end, n_end) - max(start, n_start)
        # Containment is redundant with the minimum-window rule (a nested overlap of at most
        # OVERLAP_TOLERANCE_S needs a window shorter than MIN_TOLERANT_WINDOW_S); kept as defence
        # in depth.
        nested = (n_start <= start and n_end >= end) or (start <= n_start and end >= n_end)
        if (
            shared > OVERLAP_TOLERANCE_S
            or nested
            or n_end - n_start < MIN_TOLERANT_WINDOW_S
            or shared * MAX_SHARED_FRACTION_INV > min(end - start, n_end - n_start)
        ):
            return None
        if credited:
            covered += shared
    return covered


def apply_measurements(inv: sqlite3.Connection, measured: Measurements) -> None:
    m = measured
    if inv.execute(
        "SELECT 1 FROM measurement_batches WHERE collector_id=? AND batch_id=?",
        (m.collector, m.batch_id),
    ).fetchone():
        return
    reasons = list(m.reasons)
    start, end = m.start, m.end
    hour = (
        (end - 1) // 3600 * 3600 if start is not None and end is not None and end > start else None
    )
    already_covered = 0
    if (
        start is not None
        and end is not None
        and hour is not None
        and "cross_hour" not in reasons
        and "probe" not in reasons
    ):
        neighbours = inv.execute(
            "SELECT window_start,window_end,quality FROM measurement_batches "
            "WHERE collector_id=? AND hour=? AND window_start<? AND window_end>? "
            "AND quality NOT LIKE ? AND quality NOT LIKE ? LIMIT ?",
            (
                m.collector,
                hour,
                end,
                start,
                "%probe%",
                "%cross_hour%",
                MAX_TOLERATED_NEIGHBOURS + 1,
            ),
        ).fetchall()
        shared = _tolerated_overlap(
            start, end, [(n[0], n[1], "overlapping_window" not in n[2]) for n in neighbours]
        )
        if shared is None:
            reasons.append("overlapping_window")
        else:
            already_covered = shared
    if "overlapping_window" in reasons and "probe" not in reasons:
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
    if (
        hour is None
        or start is None
        or end is None
        or any(
            reason in reasons
            for reason in (
                "probe",
                "cross_hour",
                "empty_window",
                "legacy_window",
                "overlapping_window",
            )
        )
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
    # Credit only seconds not already covered by a prior batch, so a chain's total is its union.
    duration = max(0, end - start - already_covered)
    qualified = duration if not reasons else 0
    old = inv.execute(
        "SELECT reasons FROM coverage_hourly WHERE collector_id=? AND hour=?", (m.collector, hour)
    ).fetchone()
    combined = sorted(set(reasons) | set(json.loads(old[0]) if old else []))
    inv.execute(
        "INSERT INTO coverage_hourly VALUES (?,?,?,?,?) ON CONFLICT(collector_id,hour) "
        "DO UPDATE SET observed_seconds=MIN(?,observed_seconds+excluded.observed_seconds), "
        "qualified_seconds=MIN(?,qualified_seconds+excluded.qualified_seconds),"
        "reasons=excluded.reasons",
        (m.collector, hour, duration, qualified, json.dumps(combined), HOUR_S, HOUR_S),
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
