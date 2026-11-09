"""Read-only pilot gate report: counts from inventory.db and overrides.db, never a write.

Run it as the user that owns the databases (the service user). Both files are opened `mode=ro` with
`query_only`, but a read-only WAL open can still create `-wal`/`-shm` files owned by the runner, so
it refuses to run as anyone else.

A missing file, a missing table or a window with no evidence for a section yields status "unknown"
with a reason, never a zero that reads as healthy. Every query has a time window and a LIMIT; a
section that truncated says so and is "partial". The delivery outbox has no time index and is
bounded by its own retention instead.

Evidence rules: coverage rows prove ingest, a recently stamped monitoring profile proves the engine
ran; windows older than a table's retention are unknown (or partial) because the rows are gone.
Sent delivery rows are inert: only the completion statement writes `updated_at` on a `sent` row, and
its next change is deletion after retention, so `updated_at` is the send time.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from vigie_ingest.db import iso_utc
from vigie_pipeline.baselines import ALGORITHM as POOLED_ALGORITHM
from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.baselines_tod import ALGORITHM as TOD_ALGORITHM
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.delivery_types import DeliveryConfig
from vigie_pipeline.monitoring_engine import AGGREGATE_DAYS

SCHEMA = "vigie-pilot-report/1"
QUALIFIED_SECONDS = 3420  # same floor as vigie_pipeline.monitoring_engine.samples_for
ROW_LIMIT = 10_000
CHUNK = 500
TARGET_UNWANTED_PER_NETWORK_DAY = 1
NOT_DERIVABLE = "not_derivable"
DELIVERY_STATES = ("sent", "failed")
# The pipeline reads VIGIE_DELIVERY_RETENTION_S; this process cannot see that env, so the report
# assumes the default and says so (override with --delivery-retention).
DELIVERY_RETENTION_S = DeliveryConfig().retention_seconds
INCIDENT_RETENTION_S = AGGREGATE_DAYS * 86400
FAMILY_BY_ALGORITHM = {POOLED_ALGORITHM: "pooled", TOD_ALGORITHM: "tod"}
FAMILY_BY_VERSION = {BaselineConfig().version: "pooled", TodConfig().version: "tod"}
_GATE = BaselineConfig()
COVERAGE_NOTE = (
    f"upper bound only: a qualified hour also needs a measurement row, a non-suspicious sample "
    f"below the large-upload size and a time after training_since; a window shorter than "
    f"{_GATE.minimum_days} days can never reach {_GATE.minimum_days} dates"
)
# the engine stamps last_hour with the hour just completed: one hour before detection
_INCIDENT_WINDOW = "last_hour>=? AND detected_at>=? AND detected_at<?"

Section = dict[str, Any]


class BaselineConflict(ValueError):
    """--baseline names a family the stored profiles contradict."""


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


def _status(truncated: bool, *reasons: str) -> Section:
    """ok, or partial (with the reasons) when the counts cannot be the whole story."""
    why = [r for r in reasons if r]
    if truncated:
        why.insert(0, f"truncated at {ROW_LIMIT} rows")
    return {"status": "partial", "reason": "; ".join(why)} if why else {"status": "ok"}


def engine_lo(lo: int) -> int:
    """First `updated_hour` the engine can stamp for a pass at or after `lo` (the last hour)."""
    return lo // 3600 * 3600 - 3600


def beyond_incident_retention(lo: int, hi: int) -> bool:
    """The engine deletes last_hour < floor_h(now) - retention; a window reaching earlier than one
    hour past that edge (queries accept last_hour >= floor_h(lo) - 1h) would silently miss rows."""
    return lo < hi // 3600 * 3600 - INCIDENT_RETENTION_S + 3600


def evidence_gap(inv: sqlite3.Connection | None, lo: int, done: int) -> str | None:
    """Why zero events in the window would not be real: no ingest, or no engine pass."""
    if inv is None or not _has_table(inv, "coverage_hourly"):
        return "no coverage evidence in the window"
    row = inv.execute(
        "SELECT 1 FROM coverage_hourly WHERE hour>=? AND hour<? LIMIT 1", (lo // 3600 * 3600, done)
    )
    if row.fetchone() is None:
        return "no coverage evidence in the window"
    if not _has_table(inv, "monitoring_profiles"):
        return "monitoring engine did not run in window"
    row = inv.execute(
        "SELECT 1 FROM monitoring_profiles WHERE updated_hour>=? LIMIT 1", (engine_lo(lo),)
    )
    return None if row.fetchone() else "monitoring engine did not run in window"


def _incident_args(lo: int, hi: int) -> tuple[int, str, str]:
    return engine_lo(lo), iso_utc(lo), iso_utc(hi)


def incidents_section(inv: sqlite3.Connection | None, lo: int, hi: int, gap: str | None) -> Section:
    if inv is None or not _has_table(inv, "monitoring_incidents"):
        return _unknown("monitoring_incidents table missing")
    if beyond_incident_retention(lo, hi):
        return _unknown("window exceeds incident retention")
    rows = inv.execute(
        "SELECT detector,substr(detected_at,1,10) AS day,COUNT(*) AS n FROM monitoring_incidents "  # noqa: S608
        f"WHERE {_INCIDENT_WINDOW} GROUP BY detector,day ORDER BY day,detector LIMIT ?",
        (*_incident_args(lo, hi), ROW_LIMIT + 1),
    ).fetchall()
    if not rows and gap:
        return _unknown(f"no incidents: {gap}")
    per_detector: dict[str, int] = defaultdict(int)
    per_day: dict[str, dict[str, int]] = defaultdict(dict)
    for row in rows[:ROW_LIMIT]:
        per_detector[row["detector"]] += row["n"]
        per_day[row["day"]][row["detector"]] = row["n"]
    return {
        **_status(len(rows) > ROW_LIMIT),
        "truncated": len(rows) > ROW_LIMIT,
        "total": sum(per_detector.values()),
        "per_detector": dict(sorted(per_detector.items())),
        "per_day": {d: per_day[d] for d in sorted(per_day)},
    }


def incidents_missing_open(inv: sqlite3.Connection | None, lo: int, hi: int) -> int | None:
    """Incidents in the window with no `open` delivery row at all (None: cannot be checked).

    Conservative: an incident older than the delivery watermark legitimately has none and is
    counted too, so a non-zero value makes the notification verdict unknown rather than clean."""
    if inv is None or not (
        _has_table(inv, "monitoring_incidents") and _has_table(inv, "incident_deliveries")
    ):
        return None
    row = inv.execute(
        "SELECT COUNT(*) FROM (SELECT 1 FROM monitoring_incidents i "  # noqa: S608
        f"WHERE {_INCIDENT_WINDOW} AND NOT EXISTS (SELECT 1 FROM incident_deliveries d "
        "WHERE d.incident_id=i.id AND d.kind='open') LIMIT ?)",
        (*_incident_args(lo, hi), ROW_LIMIT),
    )
    return int(row.fetchone()[0])


def decisions_section(ov: sqlite3.Connection | None, lo: int, hi: int) -> Section:
    if ov is None or not _has_table(ov, "incident_decisions"):
        return _unknown("incident_decisions table missing")
    if beyond_incident_retention(lo, hi):
        return _unknown("window exceeds incident retention")
    rows = ov.execute(
        "SELECT status,COUNT(*) AS n FROM incident_decisions WHERE decided_at>=? "
        "AND decided_at<? AND status IS NOT NULL GROUP BY status LIMIT 10",
        (iso_utc(lo), iso_utc(hi)),
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


def deliveries_section(  # noqa: PLR0913
    inv: sqlite3.Connection | None,
    lo: int,
    hi: int,
    gap: str | None,
    retention: int,
    missing_open: int | None,
) -> Section:
    """Per UTC day of completion (updated_at: when it was sent or failed), not of enqueue."""
    if inv is None or not _has_table(inv, "incident_deliveries"):
        return _unknown("incident_deliveries table missing")
    if lo < hi - retention:
        return _unknown("window exceeds delivery retention")
    if missing_open is None or missing_open > 0:
        return _unknown(f"incidents in the window have no open delivery row: {missing_open}")
    rows = inv.execute(
        "SELECT strftime('%Y-%m-%d',updated_at,'unixepoch') AS day,state,COUNT(*) AS n "
        "FROM incident_deliveries WHERE updated_at>=? AND updated_at<? "
        "GROUP BY day,state ORDER BY day,state LIMIT ?",
        (lo, hi, ROW_LIMIT + 1),
    ).fetchall()
    if not rows and gap:
        return _unknown(f"no deliveries: {gap}")
    per_day: dict[str, dict[str, int]] = defaultdict(
        lambda: dict.fromkeys((*DELIVERY_STATES, "other"), 0)
    )
    for row in rows[:ROW_LIMIT]:
        key = row["state"] if row["state"] in DELIVERY_STATES else "other"
        per_day[row["day"]][key] += row["n"]
    return {
        **_status(len(rows) > ROW_LIMIT),
        "truncated": len(rows) > ROW_LIMIT,
        "per_day": {d: per_day[d] for d in sorted(per_day)},
    }


def _reasons_clear(text: str) -> bool:
    """The engine rule (samples_for): `not json.loads(reasons or "[]")`. Malformed is not clear."""
    try:
        return not json.loads(text or "[]")
    except ValueError:
        return False


def coverage_section(inv: sqlite3.Connection | None, lo: int, hi: int) -> Section:
    if inv is None or not _has_table(inv, "coverage_hourly"):
        return _unknown("coverage_hourly table missing")
    rows = inv.execute(
        "SELECT collector_id,hour,reasons FROM coverage_hourly WHERE hour>=? AND hour<? "
        "AND qualified_seconds>=? ORDER BY hour LIMIT ?",
        (lo // 3600 * 3600, hi, QUALIFIED_SECONDS, ROW_LIMIT + 1),
    ).fetchall()
    hours: dict[str, list[int]] = defaultdict(list)
    for row in rows[:ROW_LIMIT]:
        if _reasons_clear(row["reasons"]):
            hours[row["collector_id"]].append(row["hour"])
    if not hours:
        return _unknown("no qualified hours in the window")
    per_collector = {}
    for cid, hs in sorted(hours.items()):
        dates = len({_day(h) for h in hs})
        per_collector[cid] = {
            "qualified_hours": len(hs),
            "distinct_utc_dates": dates,
            "dates_needed": _GATE.minimum_days,
            "collector_dates_met_upper_bound": dates >= _GATE.minimum_days,
        }
    old = ""
    if beyond_incident_retention(lo, hi):  # coverage is pruned on the same 90-day edge
        old = "window exceeds coverage retention: counts are a lower bound"
    return {
        **_status(len(rows) > ROW_LIMIT, old),
        "truncated": len(rows) > ROW_LIMIT,
        "note": COVERAGE_NOTE,
        "per_collector": per_collector,
    }


def current_versions(inv: sqlite3.Connection, lo: int) -> list[str]:
    """Policy versions of the profiles the engine analysed in the window: the current ones."""
    rows = inv.execute(
        "SELECT DISTINCT config_version FROM monitoring_profiles WHERE updated_hour>=? "
        "ORDER BY config_version LIMIT 20",
        (engine_lo(lo),),
    )
    return [r[0] for r in rows]


def _family_from_baselines(inv: sqlite3.Connection, version: str) -> str | None:
    """The family of baselines fitted under exactly this policy version (never another one's)."""
    if not _has_table(inv, "monitoring_baselines"):
        return None
    rows = inv.execute(
        "SELECT DISTINCT algorithm FROM monitoring_baselines WHERE config_version=? LIMIT 5",
        (version,),
    )
    families = {FAMILY_BY_ALGORITHM.get(r[0]) for r in rows}
    return families.pop() if len(families) == 1 else None


def detect_baseline(inv: sqlite3.Connection | None, versions: list[str]) -> str | None:
    """The baseline family of the CURRENT profiles' policy versions: pooled, tod, or None when any
    current version is unresolved, the versions mix families, or there are none. Never read from
    the env: the pipeline's environment is not this process's."""
    if inv is None or not versions:
        return None
    found = {FAMILY_BY_VERSION.get(v) or _family_from_baselines(inv, v) for v in versions}
    return found.pop() if len(found) == 1 and None not in found else None


def profiles_section(
    inv: sqlite3.Connection | None, lo: int, family: str | None, source: str, detected: str | None
) -> Section:
    """Profiles the engine analysed in the window, by state; stale ones are only counted.

    The 20-hour / 14-date pooled floor is shown as `learning_progress` (maxima) for learning
    devices under a pooled baseline, never as a pass: a device at the floor matures on the next
    engine pass. Under tod, an unknown family or several policy versions it is `not_derivable`."""
    if inv is None or not _has_table(inv, "monitoring_profiles"):
        return _unknown("monitoring_profiles table missing")
    start = engine_lo(lo)
    count = "SELECT COUNT(*) FROM monitoring_profiles WHERE "
    stale = inv.execute(count + "updated_hour<?", (start,)).fetchone()[0]
    reset = inv.execute(
        count + "updated_hour>=? AND training_since>=?", (start, lo // 3600 * 3600)
    ).fetchone()[0]
    rows = inv.execute(
        "SELECT state,COUNT(*) AS n,MAX(sample_hours) AS mh,MAX(distinct_days) AS md "
        "FROM monitoring_profiles WHERE updated_hour>=? GROUP BY state LIMIT 20",
        (start,),
    ).fetchall()
    versions = current_versions(inv, lo)
    disclosure = {
        "baseline": family or "unknown",
        "baseline_detected": detected,
        "baseline_source": source,
        "config_versions_in_window": [v[:12] for v in versions],
        "profiles_not_analysed_in_window": stale,
        "profiles_reset_in_window": reset,
    }
    if not rows:
        return {**_unknown("no monitoring profiles analysed in window"), **disclosure}
    changed = len(versions) > 1
    derivable = family == "pooled" and not changed

    def entry(row: sqlite3.Row) -> dict[str, Any]:
        out: dict[str, Any] = {"devices": row["n"]}
        if not derivable:
            out["gate_met"] = NOT_DERIVABLE
        elif row["state"] == "learning":
            out["learning_progress"] = {
                "max_sample_hours": row["mh"],
                "max_distinct_days": row["md"],
            }
        return out

    head: Section = {"status": "ok"}
    if changed:
        head = _unknown("policy version changed in window")
    elif family is None:
        head = {"status": "partial", "reason": "baseline family not established"}
    return {
        **head,
        **disclosure,
        "pooled_gate": {"hours_needed": _GATE.minimum_hours, "dates_needed": _GATE.minimum_days},
        "per_state": {r["state"]: entry(r) for r in rows},
    }


def _lookup(conn: sqlite3.Connection, sql: str, ids: list[str]) -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    for i in range(0, len(ids), CHUNK):
        chunk = ids[i : i + CHUNK]
        marks = ",".join("?" for _ in chunk)
        for row in conn.execute(sql.format(marks), chunk):  # noqa: S608
            out[row[0]] = tuple(row[1:])
    return out


def _unwanted_verdict(
    undecided: int, truncated: bool, missing_open: int | None, sent: int
) -> str | None:
    """Why no verdict can be given, or None when the evidence is complete."""
    if undecided or truncated:
        return "evidence incomplete: undecided or truncated notifications"
    if missing_open is None or missing_open > 0:
        return "evidence incomplete: incidents without an open delivery row"
    if sent == 0:
        return "no notifications sent: verdict vacuous"
    return None


def unwanted_section(  # noqa: PLR0913
    inv: sqlite3.Connection | None,
    ov: sqlite3.Connection | None,
    lo: int,
    hi: int,
    gap: str | None,
    retention: int,
    missing_open: int | None,
) -> Section:
    """Open notifications sent (by completion time) for incidents the owner marked `expected`,
    per network-day; the network is the decision row's collector. It counts by the CURRENT
    decision, not the one in force at send time: a sent notification later acknowledged drops out.

    The verdict (`within_target`) exists only when notifications were sent, every one has a
    decision, nothing was truncated and no incident lacks an open delivery row. Otherwise the
    status is "unknown" and the counts say why.
    """
    if not (_has_table(inv, "incident_deliveries") and _has_table(ov, "incident_decisions")):
        return {"status": NOT_DERIVABLE, "reason": "needs incident_deliveries and decisions"}
    assert inv is not None and ov is not None  # noqa: S101 (narrowing for mypy)
    if lo < hi - retention:
        return _unknown("window exceeds delivery retention")
    rows = inv.execute(
        "SELECT incident_id,strftime('%Y-%m-%d',updated_at,'unixepoch') AS day "
        "FROM incident_deliveries WHERE updated_at>=? AND updated_at<? AND state='sent' "
        "AND kind='open' ORDER BY updated_at,row_id LIMIT ?",
        (lo, hi, ROW_LIMIT + 1),
    ).fetchall()
    if not rows and gap:
        return _unknown(f"no notifications: {gap}")
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
    why = _unwanted_verdict(undecided, truncated, missing_open, len(sent))
    out: Section = {
        "status": "ok" if why is None else "unknown",
        "definition": "sent open notifications for incidents marked expected",
        "target_per_network_day": TARGET_UNWANTED_PER_NETWORK_DAY,
        "truncated": truncated,
        "notifications_sent": len(sent),
        "undecided_total": undecided,
        "incidents_without_open_delivery": missing_open,
        "unwanted_total": sum(unwanted.values()),
        "worst_network_day": worst,
    }
    if why is None:
        out["within_target"] = worst <= TARGET_UNWANTED_PER_NETWORK_DAY
    else:
        out["reason"] = why
    return out


def build_report(  # noqa: PLR0913
    inv_path: Path,
    ov_path: Path,
    since: float,
    now: float,
    baseline: str | None = None,
    delivery_retention_s: int = DELIVERY_RETENTION_S,
) -> dict[str, Any]:
    lo, hi = int(since), int(now)
    done = hi // 3600 * 3600  # complete hours only, like the engine
    inv = ov = None
    try:
        inv = open_ro(inv_path)
        ov = open_ro(ov_path)
        detected = None
        if inv is not None and _has_profiles(inv):
            detected = detect_baseline(inv, current_versions(inv, lo))
        if baseline and detected and baseline != detected:
            raise BaselineConflict(
                f"--baseline {baseline} contradicts the stored {detected} baseline family"
            )
        family = detected or baseline
        source = "database" if detected else "flag" if baseline else "none"
        gap = evidence_gap(inv, lo, done)
        missing_open = incidents_missing_open(inv, lo, hi)
        return {
            "schema": SCHEMA,
            "generated_at": iso_utc(now),
            "since": iso_utc(since),
            "gate": {
                "min_distinct_dates": _GATE.minimum_days,
                "pooled_min_hours": _GATE.minimum_hours,
            },
            "assumed_delivery_retention_s": delivery_retention_s,
            "inventory": "present" if inv is not None else "unknown: file missing",
            "incidents": incidents_section(inv, lo, hi, gap),
            "decisions": decisions_section(ov, lo, hi),
            "deliveries": deliveries_section(inv, lo, hi, gap, delivery_retention_s, missing_open),
            "coverage": coverage_section(inv, lo, done),
            "profiles": profiles_section(inv, lo, family, source, detected),
            "unwanted_notifications": unwanted_section(
                inv, ov, lo, hi, gap, delivery_retention_s, missing_open
            ),
        }
    finally:
        for conn in (inv, ov):
            if conn is not None:
                conn.close()


def _has_profiles(inv: sqlite3.Connection | None) -> bool:
    return _has_table(inv, "monitoring_profiles")
