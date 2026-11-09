"""Read-only pilot gate report: counts from inventory.db and overrides.db, never a write.

Both files are opened `mode=ro` with `query_only`. A missing file, a missing table or a window with
no evidence for a section yields status "unknown" with a reason, never a zero that reads as
healthy. Every query is bounded by a time window, an index where one exists, and a LIMIT.
"""

from __future__ import annotations

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
UNKNOWN_NETWORK = "unattributed"
_GATE = BaselineConfig()

Section = dict[str, Any]


def open_ro(path: Path) -> sqlite3.Connection | None:
    """Open an existing database read-only; None when the file is not there."""
    if not path.is_file():
        return None
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
        "WHERE last_hour>=? AND detected_at>=? AND detected_at<? GROUP BY detector,day LIMIT ?",
        (lo // 3600 * 3600, iso_utc(lo), iso_utc(hi), ROW_LIMIT),
    ).fetchall()
    if not rows and not ran:
        return _unknown("no incidents and no coverage evidence in the window")
    per_detector: dict[str, int] = defaultdict(int)
    per_day: dict[str, dict[str, int]] = defaultdict(dict)
    for row in rows:
        per_detector[row["detector"]] += row["n"]
        per_day[row["day"]][row["detector"]] = row["n"]
    return {
        "status": "ok",
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
    if inv is None or not _has_table(inv, "incident_deliveries"):
        return _unknown("incident_deliveries table missing")
    rows = inv.execute(
        "SELECT strftime('%Y-%m-%d',created_at,'unixepoch') AS day,state,COUNT(*) AS n "
        "FROM incident_deliveries WHERE created_at>=? AND created_at<? "
        "GROUP BY day,state LIMIT ?",
        (lo, hi, ROW_LIMIT),
    ).fetchall()
    if not rows and not ran:
        return _unknown("no deliveries and no coverage evidence in the window")
    per_day: dict[str, dict[str, int]] = defaultdict(lambda: {"sent": 0, "failed": 0})
    for row in rows:
        per_day[row["day"]][row["state"]] = row["n"]
    return {"status": "ok", "per_day": {d: per_day[d] for d in sorted(per_day)}}


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
            "dates_met": dates >= _GATE.minimum_days,
        }
    return {"status": "ok", "truncated": len(rows) > ROW_LIMIT, "per_collector": per_collector}


def profiles_section(inv: sqlite3.Connection | None) -> Section:
    if inv is None or not _has_table(inv, "monitoring_profiles"):
        return _unknown("monitoring_profiles table missing")
    rows = inv.execute(
        "SELECT state,COUNT(*) AS n,"
        "SUM(sample_hours>=? AND distinct_days>=?) AS gate_met FROM monitoring_profiles "
        "GROUP BY state LIMIT 20",
        (_GATE.minimum_hours, _GATE.minimum_days),
    ).fetchall()
    if not rows:
        return _unknown("no monitoring profiles")
    return {
        "status": "ok",
        "pooled_gate": {"hours_needed": _GATE.minimum_hours, "dates_needed": _GATE.minimum_days},
        "per_state": {r["state"]: {"devices": r["n"], "gate_met": r["gate_met"]} for r in rows},
    }


def _lookup(conn: sqlite3.Connection, sql: str, ids: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for i in range(0, len(ids), CHUNK):
        chunk = ids[i : i + CHUNK]
        marks = ",".join("?" for _ in chunk)
        for row in conn.execute(sql.format(marks), chunk):  # noqa: S608
            out[row[0]] = row[1]
    return out


def unwanted_section(
    inv: sqlite3.Connection | None, ov: sqlite3.Connection | None, lo: int, hi: int, ran: bool
) -> Section:
    """Sent open-notifications whose incident the owner marked `expected`, per network-day.

    A network is the incident's collector; an incident already pruned counts as unattributed.
    Not derivable without both the delivery outbox and the decisions overlay.
    """
    if not (_has_table(inv, "incident_deliveries") and _has_table(ov, "incident_decisions")):
        return {"status": "not_derivable", "reason": "needs incident_deliveries and decisions"}
    assert inv is not None and ov is not None  # noqa: S101 (narrowing for mypy)
    sent = inv.execute(
        "SELECT incident_id,strftime('%Y-%m-%d',created_at,'unixepoch') AS day "
        "FROM incident_deliveries WHERE created_at>=? AND created_at<? AND state='sent' "
        "AND kind='open' LIMIT ?",
        (lo, hi, ROW_LIMIT),
    ).fetchall()
    if not sent and not ran:
        return _unknown("no notifications and no coverage evidence in the window")
    ids = sorted({r["incident_id"] for r in sent})
    status = _lookup(
        ov, "SELECT incident_id,status FROM incident_decisions WHERE incident_id IN ({})", ids
    )
    networks = (
        _lookup(inv, "SELECT id,collector_id FROM monitoring_incidents WHERE id IN ({})", ids)
        if _has_table(inv, "monitoring_incidents")
        else {}
    )
    unwanted: dict[tuple[str, str], int] = defaultdict(int)
    for row in sent:
        if status.get(row["incident_id"]) == "expected":
            unwanted[(networks.get(row["incident_id"], UNKNOWN_NETWORK), row["day"])] += 1
    worst = max(unwanted.values(), default=0)
    return {
        "status": "ok",
        "definition": "sent open notifications for incidents marked expected",
        "target_per_network_day": TARGET_UNWANTED_PER_NETWORK_DAY,
        "notifications_sent": len(sent),
        "unwanted_total": sum(unwanted.values()),
        "worst_network_day": worst,
        "within_target": worst <= TARGET_UNWANTED_PER_NETWORK_DAY,
    }


def build_report(inv_path: Path, ov_path: Path, since: float, now: float) -> dict[str, Any]:
    lo, hi = int(since), int(now)
    inv, ov = open_ro(inv_path), open_ro(ov_path)
    try:
        ran = pipeline_ran(inv, lo // 3600 * 3600, hi)
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
            "coverage": coverage_section(inv, lo, hi),
            "profiles": profiles_section(inv),
            "unwanted_notifications": unwanted_section(inv, ov, lo, hi, ran),
        }
    finally:
        for conn in (inv, ov):
            if conn is not None:
                conn.close()
