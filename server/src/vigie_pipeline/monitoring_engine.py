"""Bounded derived monitoring state. Writes inventory only; never changes trust or human intent."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.baselines import BaselineConfig, Sample
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.monitoring_identity import LineageUnavailable, lineage
from vigie_pipeline.monitoring_strategy import strategy_for

MAX_ENTITIES = 20
AGGREGATE_DAYS = 90
DETAIL_DAYS = 7


def revision(inv):
    return inv.execute("SELECT value FROM monitoring_revision WHERE singleton=1").fetchone()[0]


def samples_for(inv, collector, identity, now):
    marks = ",".join("?" for _ in identity.macs)
    if not marks:
        return []
    lower = int(now) // 3600 * 3600 - AGGREGATE_DAYS * 86400
    rows = inv.execute(
        f"SELECT m.hour,SUM(m.bytes_up) AS bytes_up,c.qualified_seconds,c.reasons "  # noqa: S608
        f"FROM measurements_hourly m LEFT JOIN coverage_hourly c "
        f"ON c.collector_id=m.collector_id AND c.hour=m.hour "
        f"WHERE m.collector_id=? AND m.mac IN ({marks}) AND m.hour>=? AND m.hour<? "
        f"GROUP BY m.hour ORDER BY m.hour LIMIT 2161",
        (collector, *identity.macs, lower, int(now) // 3600 * 3600),
    ).fetchall()  # noqa: S608
    if len(rows) > 2160:
        raise LineageUnavailable("hourly sample bound exceeded")
    suspicious = {
        row[0]
        for row in inv.execute(
            "SELECT hour FROM monitoring_suspicious WHERE "
            "collector_id=? AND device_id=? AND lineage=? AND hour>=? LIMIT 2161",
            (collector, identity.device_id, identity.key, lower),
        )
    }
    return [
        Sample(
            row["hour"],
            row["bytes_up"],
            row["qualified_seconds"] is not None
            and row["qualified_seconds"] >= 3420
            and not json.loads(row["reasons"] or "[]"),
            row["hour"] in suspicious,
        )
        for row in rows
    ]


def analyze_entity(inv, ov, collector, device, policy, now):
    strategy = strategy_for(policy)
    deadline = time.monotonic() + 0.5
    inv.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        epoch = revision(inv)
        identity = lineage(inv, ov, device)
        old = inv.execute(
            "SELECT * FROM monitoring_profiles WHERE collector_id=? AND device_id=?",
            (collector, identity.device_id),
        ).fetchone()
        series = samples_for(inv, collector, identity, now)
    finally:
        inv.set_progress_handler(None, 0)
    current_hour = int(now) // 3600 * 3600 - 3600
    changed = old is not None and (
        old["lineage"] != identity.key or old["config_version"] != policy.version
    )
    if changed or (old is None and identity.rule_attached):
        training_since = (int(now) // 3600 + 1) * 3600
    else:
        training_since = (
            old["training_since"] if old else (series[0].hour if series else current_hour + 3600)
        )
    reference = None
    unusable_inputs = False
    if old is not None and not changed and old["baseline_id"]:
        reference_row = inv.execute(
            "SELECT * FROM monitoring_baselines WHERE id=?", (old["baseline_id"],)
        ).fetchone()
        if reference_row is not None:
            reference = strategy.hydrate(dict(reference_row))
            unusable_inputs = reference is None
    quality_reset = False
    if unusable_inputs or reference is not None:
        used = set(json.loads(reference["training_hours"])) if reference else set()
        if unusable_inputs or any(
            s.hour in used
            and (not s.eligible or s.suspicious or s.bytes_up >= policy.large_upload_bytes)
            for s in series
        ):
            quality_reset = True
            changed = True
            reference = None
            training_since = (int(now) // 3600 + 1) * 3600
    training = [s for s in series if s.hour >= training_since]
    if reference is None and identity.versioned:
        reference = strategy.fit(training)
    qualified_training = [
        sample
        for sample in training
        if sample.eligible and not sample.suspicious and sample.bytes_up < policy.large_upload_bytes
    ]
    sample_hours = reference["sample_hours"] if reference else len(qualified_training)
    distinct_days = (
        reference["distinct_days"]
        if reference
        else len({sample.hour // 86400 for sample in qualified_training})
    )
    state = "mature" if reference else "learning" if identity.versioned else "lineage_unavailable"
    if reference is None and (
        quality_reset or (old is not None and old["state"] == "rebuilding_quality")
    ):
        state = "rebuilding_quality"
    baseline_id = old["baseline_id"] if old is not None and not changed else None
    if reference is not None and baseline_id is None:
        baseline_id = hashlib.sha256(
            json.dumps(
                [
                    collector,
                    identity.device_id,
                    identity.key,
                    policy.version,
                    reference["training_hours"],
                ],
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    by_hour = {sample.hour: sample for sample in training}
    current = by_hour.get(current_hour)
    previous = by_hour.get(current_hour - 3600)
    found = strategy.findings(current, previous, reference) if identity.versioned else []
    with immediate(inv):
        # The two DBs cannot form one atomic snapshot. Recheck versioned lineage before publishing;
        # API readers independently label stale-lineage profiles as rebuilding.
        if revision(inv) != epoch or lineage(inv, ov, device).key != identity.key:
            return
        if changed:
            inv.execute(
                "UPDATE monitoring_incidents SET state='superseded' WHERE collector_id"
                "=? AND device_id=? AND state='open'",
                (collector, identity.device_id),
            )
        if reference is not None and (old is None or changed or old["baseline_id"] is None):
            inv.execute(
                "INSERT OR IGNORE INTO monitoring_baselines VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    baseline_id,
                    collector,
                    identity.device_id,
                    identity.key,
                    strategy.algorithm,
                    policy.version,
                    strategy.config_json(reference),
                    reference["median_twice"],
                    reference["sample_hours"],
                    reference["distinct_days"],
                    reference["trained_until"],
                    int(now) // 3600 * 3600,
                    json.dumps(reference["training_hours"]),
                ),
            )
        inv.execute(
            "INSERT INTO monitoring_profiles VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(collector_id,device_id) DO UPDATE SET lineage=excluded.lineage,"
            "config_version=excluded.config_version,training_since=excluded.training_s"
            "ince,state=excluded.state,"
            "baseline_id=excluded.baseline_id,updated_hour=excluded.updated_hour,sampl"
            "e_hours=excluded.sample_hours,distinct_days=excluded.distinct_days",
            (
                collector,
                identity.device_id,
                identity.key,
                policy.version,
                training_since,
                state,
                baseline_id,
                current_hour,
                sample_hours,
                distinct_days,
            ),
        )
        if current is not None and current.eligible:
            threshold = strategy.threshold(current, reference)
            if current.bytes_up >= policy.large_upload_bytes or (
                threshold is not None and current.bytes_up > threshold
            ):
                inv.execute(
                    "INSERT OR IGNORE INTO monitoring_suspicious VALUES (?,?,?,?)",
                    (collector, identity.device_id, identity.key, current.hour),
                )
        for finding in found:
            active = inv.execute(
                "SELECT * FROM monitoring_incidents WHERE collector_id=? AND device_id"
                "=? AND lineage=? AND detector=? AND state='open'",
                (collector, identity.device_id, identity.key, finding["detector"]),
            ).fetchone()
            if active is not None and active["last_hour"] not in (
                current_hour,
                current_hour - 3600,
            ):
                inv.execute(
                    "UPDATE monitoring_incidents SET state='resolved' WHERE id=?", (active["id"],)
                )
                active = None
            start = active["episode_start"] if active else current_hour
            ident = hashlib.sha256(
                json.dumps(
                    [collector, identity.device_id, identity.key, finding["detector"], start]
                ).encode()
            ).hexdigest()
            evidence = {
                "reason_code": finding["reason_code"],
                "hour": current_hour,
                "previous_hour": previous.hour if previous else None,
                "observed_bytes": finding["observed_bytes"],
                "threshold_bytes": finding["threshold_bytes"],
                "baseline_id": baseline_id,
                "algorithm": strategy.algorithm,
                "config_version": policy.version,
                "coverage_required_seconds": 3420,
                "lineage": identity.key,
                "unusual_is_not_malicious": True,
                "multiplier": policy.multiplier,
                "minimum_bytes": policy.minimum_bytes,
                **strategy.evidence(current, reference),
            }
            inv.execute(
                "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,de"
                "tector,state,episode_start,last_hour,"
                "detected_at,baseline_id,observed_bytes,threshold_bytes,evidence) VALU"
                "ES (?,?,?,?,?,'open',?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET last_hour=excluded.last_hour,observed_b"
                "ytes=excluded.observed_bytes,evidence=excluded.evidence",
                (
                    ident,
                    collector,
                    identity.device_id,
                    identity.key,
                    finding["detector"],
                    start,
                    current_hour,
                    iso_utc(now),
                    baseline_id,
                    finding["observed_bytes"],
                    finding["threshold_bytes"],
                    json.dumps(evidence, sort_keys=True),
                ),
            )
        if current is not None and current.eligible:
            firing = {f["detector"] for f in found}
            for active in inv.execute(
                "SELECT id,detector,last_hour FROM monitoring_incidents WHERE collecto"
                "r_id=? AND device_id=? AND lineage=? AND state='open'",
                (collector, identity.device_id, identity.key),
            ).fetchall():
                if active["detector"] not in firing and active["last_hour"] < current_hour:
                    inv.execute(
                        "UPDATE monitoring_incidents SET state='resolved' WHERE id=?",
                        (active["id"],),
                    )
        for mac in identity.macs:
            future = inv.execute(
                "SELECT MIN(hour+3600) FROM measurements_hourly "
                "WHERE collector_id=? AND mac=? AND hour>=?",
                (collector, mac, int(now) // 3600 * 3600),
            ).fetchone()[0]
            if future is None:
                inv.execute(
                    "DELETE FROM monitoring_dirty WHERE collector_id=? AND mac=?", (collector, mac)
                )
            else:
                inv.execute(
                    "INSERT INTO monitoring_dirty VALUES (?,?,?) "
                    "ON CONFLICT(collector_id,mac) DO UPDATE SET queued_at=excluded.queued_at",
                    (collector, mac, future),
                )


def analyze_monitoring(inv, ov, policy: BaselineConfig | TodConfig, now):
    drain_quality_work(inv, now)
    queue = inv.execute(
        "SELECT collector_id,mac FROM monitoring_dirty WHERE queued_at<=? "
        "ORDER BY queued_at,collector_id,mac LIMIT ?",
        (int(now), MAX_ENTITIES),
    ).fetchall()
    seen = set()
    for collector, mac in queue:
        row = inv.execute("SELECT device_id FROM observations WHERE mac=?", (mac,)).fetchone()
        if row is None:
            with immediate(inv):
                inv.execute(
                    "DELETE FROM monitoring_dirty WHERE collector_id=? AND mac=?", (collector, mac)
                )
            continue
        try:
            identity = lineage(inv, ov, row[0])
            scope = (collector, identity.device_id)
            if scope in seen:
                continue
            seen.add(scope)
            analyze_entity(inv, ov, collector, row[0], policy, now)
            with immediate(inv):
                inv.execute(
                    "DELETE FROM monitoring_unavailable WHERE collector_id=? AND device_id=?",
                    (collector, row[0]),
                )
        except (LineageUnavailable, sqlite3.OperationalError, ValueError) as exc:
            # Back off failed subjects so an incomplete component cannot monopolize the queue.
            with immediate(inv):
                inv.execute(
                    "UPDATE monitoring_dirty SET queued_at=? WHERE collector_id=? AND mac=?",
                    (int(now) + 60, collector, mac),
                )
                inv.execute(
                    "INSERT INTO monitoring_unavailable VALUES (?,?,?,?) "
                    "ON CONFLICT(collector_id,device_id) DO UPDATE SET "
                    "reason=excluded.reason,retry_at=excluded.retry_at",
                    (
                        collector,
                        row[0],
                        "lineage_unavailable"
                        if isinstance(exc, LineageUnavailable)
                        else "invalid_input"
                        if isinstance(exc, ValueError)
                        else "read_budget_or_database_unavailable",
                        int(now) + 60,
                    ),
                )
            continue


def prune_monitoring(inv, now):
    """Bound deletion work per table; keep receipts while original batches can replay."""
    detail = iso_utc(now - DETAIL_DAYS * 86400)
    cutoff = int(now) // 3600 * 3600 - AGGREGATE_DAYS * 86400
    with immediate(inv):
        inv.execute(
            "DELETE FROM measurement_batches WHERE rowid IN "
            "(SELECT m.rowid FROM measurement_batches m WHERE received_at<? AND NOT EXISTS "
            "(SELECT 1 FROM batches b WHERE b.collector_id=m.collector_id "
            "AND b.batch_id=m.batch_id) "
            "ORDER BY received_at LIMIT 1000)",
            (detail,),
        )
        for table in ("measurements_hourly", "coverage_hourly", "monitoring_suspicious"):
            inv.execute(  # table comes only from this fixed internal allowlist.
                f"DELETE FROM {table} WHERE rowid IN "  # noqa: S608
                f"(SELECT rowid FROM {table} WHERE hour<? ORDER BY hour LIMIT 1000)",
                (cutoff,),
            )
        inv.execute(
            "DELETE FROM monitoring_incidents WHERE seq IN "
            "(SELECT seq FROM monitoring_incidents WHERE last_hour<? "
            "ORDER BY last_hour LIMIT 1000)",
            (cutoff,),
        )
        inv.execute(
            "DELETE FROM monitoring_baselines WHERE id IN "
            "(SELECT b.id FROM monitoring_baselines b WHERE b.created_hour<? "
            "AND NOT EXISTS (SELECT 1 FROM monitoring_profiles p WHERE p.baseline_id=b.id) "
            "AND NOT EXISTS (SELECT 1 FROM monitoring_incidents i WHERE i.baseline_id=b.id) "
            "LIMIT 1000)",
            (cutoff,),
        )


def drain_quality_work(inv, now):
    """Fan out a collector-hour invalidation incrementally, never dropping a partial tail."""
    work = inv.execute(
        "SELECT collector_id,hour,after_mac FROM monitoring_quality_work "
        "ORDER BY hour,collector_id LIMIT 1"
    ).fetchone()
    if work is None:
        return
    collector, hour, after = work
    rows = inv.execute(
        "SELECT mac FROM measurements_hourly WHERE hour=? AND collector_id=? "
        "AND mac>? ORDER BY mac LIMIT 1000",
        (hour, collector, after),
    ).fetchall()
    with immediate(inv):
        for (mac,) in rows:
            inv.execute(
                "INSERT INTO monitoring_dirty VALUES (?,?,?) "
                "ON CONFLICT(collector_id,mac) DO UPDATE SET "
                "queued_at=MIN(queued_at,excluded.queued_at)",
                (collector, mac, int(now)),
            )
        if len(rows) < 1000:
            inv.execute(
                "DELETE FROM monitoring_quality_work WHERE collector_id=? AND hour=?",
                (collector, hour),
            )
        else:
            inv.execute(
                "UPDATE monitoring_quality_work SET after_mac=? WHERE collector_id=? AND hour=?",
                (rows[-1][0], collector, hour),
            )
