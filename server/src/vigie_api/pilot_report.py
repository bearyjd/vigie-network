"""Read-only pilot gate report: counts from inventory.db and overrides.db, never a write.

Run it as the user that owns the databases (the service user). Both files are opened `mode=ro` with
`query_only`, but a read-only WAL open can still create `-wal`/`-shm` files owned by the runner, so
it refuses to run as anyone else.

A missing file, a missing table or a window with no evidence for a section yields status "unknown"
with a reason, never a zero that reads as healthy. Every query has a time window and a LIMIT (the
sections that could truncate say so); the delivery outbox has no time index and is bounded by its
own retention instead.
"""

from __future__ import annotations

import os
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from vigie_ingest.db import iso_utc
from vigie_pipeline.baselines import BaselineConfig

SCHEMA = "vigie-pilot-report/1"
QUALIFIED_SECONDS = 3420  # same floor as vigie_pipeline.monitoring_engine.samples_for
ROW_LIMIT = 10_000
CHUNK = 500
TARGET_UNWANTED_PER_NETWORK_DAY = 1
NOT_DERIVABLE = "not_derivable"
DELIVERY_STATES = ("sent", "failed")
_GATE = BaselineConfig()
COVERAGE_NOTE = (
    f"upper bound only: a qualified hour also needs a measurement row, a non-suspicious sample "
    f"below the large-upload size and a time after training_since; a window shorter than "
    f"{_GATE.minimum_days} days can never reach {_GATE.minimum_days} dates"
)

Section = dict[str, Any]


class NotDatabaseOwner(PermissionError):
    """A read-only WAL open as another user would leave -wal/-shm files the service cannot use."""


def open_ro(path: Path) -> sqlite3.Connection | None:
    """Open an existing database read-only; None when the file is not there."""
    if not path.is_file():
        return None
    if os.geteuid() != path.stat().st_uid:
        raise NotDatabaseOwner("pilot report must run as the database owner")
    conn = sqlite3.connect(
        f"file:{quote(str(path.resolve()))}?mode=ro", uri=True, timeout=5.0, isolation_level=None
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _unknown(reason: str) -> Section:
    return {"status": "unknown", "reason": reason}


def _has_table(conn: sqlite3.Connection | None, name: str) -> bool:
    if conn is None:
        return False
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return row.fetchone() is not None


def _day(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d")


def pipeline_ran(inv: sqlite3.Connection | None, lo: int, hi: int) -> bool:
    """Coverage rows in the window prove the pipeline observed it, so zero events are real."""
    if inv is None or not _has_table(inv, "coverage_hourly"):
        return False
    row = inv.execute("SELECT 1 FROM coverage_hourly WHERE hour>=? AND hour<? LIMIT 1", (lo, hi))
    return row.fetchone() is not None


def incidents_section(inv: sqlite3.Connection | None, lo: int, hi: int, ran: bool) -> Section:
    if inv is None or not _has_table(inv, "monitoring_incidents"):
        return _unknown("monitoring_incidents table missing")
    rows = inv.execute(
        "SELECT detector,substr(detected_at,1,10) AS day,COUNT(*) AS n FROM monitoring_incidents "
        "WHERE last_hour>=? AND detected_at>=? AND detected_at<? GROUP BY detector,day "
        "ORDER BY day,detector LIMIT ?",
        # the engine stamps last_hour with the hour just completed: one hour before detection
        (lo // 3600 * 3600 - 3600, iso_utc(lo), iso_utc(hi), ROW_LIMIT + 1),
    ).fetchall()
    if not rows and not ran:
        return _unknown("no incidents and no coverage evidence in the window")
    per_detector: dict[str, int] = defaultdict(int)
    per_day: dict[str, dict[str, int]] = defaultdict(dict)
    for row in rows[:ROW_LIMIT]:
        per_detector[row["detector"]] += row["n"]
        per_day[row["day"]][row["detector"]] = row["n"]
    return {
        "status": "ok",
        "truncated": len(rows) > ROW_LIMIT,
        "total": sum(per_detector.values()),
        "per_detector": dict(sorted(per_detector.items())),
        "per_day": {d: per_day[d] for d in sorted(per_day)},
    }


def decisions_section(ov: sqlite3.Connection | None, lo: int) -> Section:
    if ov is None or not _has_table(ov, "incident_decisions"):
        return _unknown("incident_decisions table missing")
    rows = ov.execute(
        "SELECT status,COUNT(*) AS n FROM incident_decisions WHERE decided_at>=? "
        "AND status IS NOT NULL GROUP BY status LIMIT 10",
        (iso_utc(lo),),
    ).fetchall()
    counts = {row["status"]: row["n"] for row in rows}
    total = sum(counts.values())
    if total == 0:
        return _unknown("no decisions in the window")
    names = ("acknowledged", "expected", "snoozed")
    return {
        "status": "ok",
        "total": total,
        "counts": {name: counts.get(name, 0) for name in names},
        "ratios": {name: round(counts.get(name, 0) / total, 4) for name in names},
    }


def deliveries_section(inv: sqlite3.Connection | None, lo: int, hi: int, ran: bool) -> Section:
    """Per UTC day of completion (updated_at: when it was sent or failed), not of enqueue."""
    if inv is None or not _has_table(inv, "incident_deliveries"):
        return _unknown("incident_deliveries table missing")
    rows = inv.execute(
        "SELECT strftime('%Y-%m-%d',updated_at,'unixepoch') AS day,state,COUNT(*) AS n "
        "FROM incident_deliveries WHERE updated_at>=? AND updated_at<? "
        "GROUP BY day,state ORDER BY day,state LIMIT ?",
        (lo, hi, ROW_LIMIT + 1),
    ).fetchall()
    if not rows and not ran:
        return _unknown("no deliveries and no coverage evidence in the window")
    per_day: dict[str, dict[str, int]] = defaultdict(
        lambda: dict.fromkeys((*DELIVERY_STATES, "other"), 0)
    )
    for row in rows[:ROW_LIMIT]:
        key = row["state"] if row["state"] in DELIVERY_STATES else "other"
        per_day[row["day"]][key] += row["n"]
    return {
        "status": "ok",
        "truncated": len(rows) > ROW_LIMIT,
        "per_day": {d: per_day[d] for d in sorted(per_day)},
    }


def coverage_section(inv: sqlite3.Connection | None, lo: int, hi: int) -> Section:
    if inv is None or not _has_table(inv, "coverage_hourly"):
        return _unknown("coverage_hourly table missing")
    rows = inv.execute(
        "SELECT collector_id,hour FROM coverage_hourly WHERE hour>=? AND hour<? "
        "AND qualified_seconds>=? AND reasons IN ('[]','') ORDER BY hour LIMIT ?",
        (lo // 3600 * 3600, hi, QUALIFIED_SECONDS, ROW_LIMIT + 1),
    ).fetchall()
    if not rows:
        return _unknown("no qualified hours in the window")
    hours: dict[str, list[int]] = defaultdict(list)
    for row in rows[:ROW_LIMIT]:
        hours[row["collector_id"]].append(row["hour"])
    per_collector = {}
    for cid, hs in sorted(hours.items()):
        dates = len({_day(h) for h in hs})
        per_collector[cid] = {
            "qualified_hours": len(hs),
            "distinct_utc_dates": dates,
            "dates_needed": _GATE.minimum_days,
            "collector_dates_met_upper_bound": dates >= _GATE.minimum_days,
        }
    return {
        "status": "ok",
        "truncated": len(rows) > ROW_LIMIT,
        "note": COVERAGE_NOTE,
        "per_collector": per_collector,
    }


def profiles_section(inv: sqlite3.Connection | None, baseline: str) -> Section:
    """Per-state device counts. The pooled 20-hour / 14-date gate is only meaningful for pooled
    baselines and only for devices still learning; every other state or baseline is not derivable
    as "can mature" and reports no gate count."""
    if inv is None or not _has_table(inv, "monitoring_profiles"):
        return _unknown("monitoring_profiles table missing")
    rows = inv.execute(
        "SELECT state,COUNT(*) AS n,"
        "SUM(state='learning' AND sample_hours>=? AND distinct_days>=?) AS gate_met "
        "FROM monitoring_profiles GROUP BY state LIMIT 20",
        (_GATE.minimum_hours, _GATE.minimum_days),
    ).fetchall()
    if not rows:
        return _unknown("no monitoring profiles")

    def gate(row: sqlite3.Row) -> Any:
        if baseline != "pooled":
            return NOT_DERIVABLE
        return row["gate_met"] if row["state"] == "learning" else None

    return {
        "status": "ok",
        "baseline": baseline,
        "pooled_gate": {"hours_needed": _GATE.minimum_hours, "dates_needed": _GATE.minimum_days},
        "per_state": {r["state"]: {"devices": r["n"], "gate_met": gate(r)} for r in rows},
    }


def _lookup(conn: sqlite3.Connection, sql: str, ids: list[str]) -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    for i in range(0, len(ids), CHUNK):
        chunk = ids[i : i + CHUNK]
        marks = ",".join("?" for _ in chunk)
        for row in conn.execute(sql.format(marks), chunk):  # noqa: S608
            out[row[0]] = tuple(row[1:])
    return out


def unwanted_section(
    inv: sqlite3.Connection | None, ov: sqlite3.Connection | None, lo: int, hi: int, ran: bool
) -> Section:
    """Open notifications sent (by completion time) for incidents the owner marked `expected`,
    per network-day; the network is the decision row's collector.

    The verdict (`within_target`) exists only when every sent notification has a decision and
    nothing was truncated. Otherwise the status is "unknown" and the counts say why.
    """
    if not (_has_table(inv, "incident_deliveries") and _has_table(ov, "incident_decisions")):
        return {"status": NOT_DERIVABLE, "reason": "needs incident_deliveries and decisions"}
    assert inv is not None and ov is not None  # noqa: S101 (narrowing for mypy)
    rows = inv.execute(
        "SELECT incident_id,strftime('%Y-%m-%d',updated_at,'unixepoch') AS day "
        "FROM incident_deliveries WHERE updated_at>=? AND updated_at<? AND state='sent' "
        "AND kind='open' ORDER BY updated_at,row_id LIMIT ?",
        (lo, hi, ROW_LIMIT + 1),
    ).fetchall()
    if not rows and not ran:
        return _unknown("no notifications and no coverage evidence in the window")
    truncated = len(rows) > ROW_LIMIT
    sent = rows[:ROW_LIMIT]
    decided = _lookup(
        ov,
        "SELECT incident_id,status,collector_id FROM incident_decisions WHERE incident_id IN ({})",
        sorted({r["incident_id"] for r in sent}),
    )
    undecided = 0
    unwanted: dict[tuple[str, str], int] = defaultdict(int)
    for row in sent:
        status, network = decided.get(row["incident_id"], (None, None))
        if status is None:
            undecided += 1
        elif status == "expected":
            unwanted[(network, row["day"])] += 1
    worst = max(unwanted.values(), default=0)
    complete = undecided == 0 and not truncated
    out: Section = {
        "status": "ok" if complete else "unknown",
        "definition": "sent open notifications for incidents marked expected",
        "target_per_network_day": TARGET_UNWANTED_PER_NETWORK_DAY,
        "truncated": truncated,
        "notifications_sent": len(sent),
        "undecided_total": undecided,
        "unwanted_total": sum(unwanted.values()),
        "worst_network_day": worst,
    }
    if complete:
        out["within_target"] = worst <= TARGET_UNWANTED_PER_NETWORK_DAY
    else:
        out["reason"] = "evidence incomplete: undecided or truncated notifications"
    return out


def build_report(
    inv_path: Path, ov_path: Path, since: float, now: float, baseline: str = "pooled"
) -> dict[str, Any]:
    lo, hi = int(since), int(now)
    done = hi // 3600 * 3600  # complete hours only, like the engine
    inv = ov = None
    try:
        inv, ov = open_ro(inv_path), open_ro(ov_path)
        ran = pipeline_ran(inv, lo // 3600 * 3600, done)
        return {
            "schema": SCHEMA,
            "generated_at": iso_utc(now),
            "since": iso_utc(since),
            "gate": {
                "min_distinct_dates": _GATE.minimum_days,
                "pooled_min_hours": _GATE.minimum_hours,
            },
            "inventory": "present" if inv is not None else "unknown: file missing",
            "incidents": incidents_section(inv, lo, hi, ran),
            "decisions": decisions_section(ov, lo),
            "deliveries": deliveries_section(inv, lo, hi, ran),
            "coverage": coverage_section(inv, lo, done),
            "profiles": profiles_section(inv, baseline),
            "unwanted_notifications": unwanted_section(inv, ov, lo, hi, ran),
        }
    finally:
        for conn in (inv, ov):
            if conn is not None:
                conn.close()
