"""DNS monitoring storage, separate from the upload profile and incident lifecycle."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict, dataclass

from vigie_ingest.db import iso_utc
from vigie_pipeline.baselines import InvalidInput
from vigie_pipeline.baselines_dns import (
    ALGORITHM_DNS,
    DAY_S,
    MAX_DAYS,
    MAX_TRAINING_HOURS,
    MAX_UNSATURATED_DEVICE_QUERIES,
    DnsBaselineConfig,
    DnsReference,
    DnsSample,
    dns_findings,
    fit_dns_reference,
)
from vigie_pipeline.detectors import DNS_DEVIATION
from vigie_pipeline.measurements import HOUR_S, MAX_VALUE
from vigie_pipeline.monitoring_identity import Lineage, has_table, lineage

COVERAGE_SECONDS = 3420
MAX_TRAINING_HOURS_JSON = MAX_TRAINING_HOURS * 18 + 2


def _digest(parts) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def _reference_id(collector, device, key, reference: DnsReference) -> str:
    return _digest(
        [
            collector,
            device,
            key,
            reference.config_version,
            reference.training_hours,
            reference.median_twice,
        ]
    )


def _training_eligible(sample: DnsSample) -> bool:
    return sample.eligible and not sample.suspicious and not sample.saturated


def _read_samples(
    inv, collector, identity: Lineage, lower, until, *, only_hours: tuple[int, ...] | None = None
) -> list[DnsSample]:
    if not identity.macs:
        return []
    marks = ",".join("?" for _ in identity.macs)
    hour_filter = "" if only_hours is None else "AND m.hour IN (SELECT value FROM json_each(?))"
    hour_params = () if only_hours is None else (json.dumps(only_hours),)
    rows = inv.execute(
        f"""SELECT m.hour, SUM(m.dns_queries) AS queries, MAX(m.dns_queries) AS max_queries,
                MIN(m.dns_queries) AS min_queries,
                MAX(typeof(m.dns_queries) <> 'integer') AS bad_type,
                c.qualified_seconds, c.reasons, s.hour IS NOT NULL AS suspicious
            FROM measurements_hourly m
            LEFT JOIN coverage_hourly c ON c.collector_id=m.collector_id AND c.hour=m.hour
            LEFT JOIN monitoring_dns_suspicious s ON s.collector_id=m.collector_id
                AND s.device_id=? AND s.lineage=? AND s.hour=m.hour
            WHERE m.collector_id=? AND m.mac IN ({marks}) AND m.hour>=? AND m.hour<?
            {hour_filter} GROUP BY m.hour ORDER BY m.hour LIMIT ?""",  # noqa: S608
        (
            identity.device_id,
            identity.key,
            collector,
            *identity.macs,
            lower,
            until,
            *hour_params,
            MAX_TRAINING_HOURS + 1,
        ),
    ).fetchall()
    if len(rows) > MAX_TRAINING_HOURS:
        raise InvalidInput("DNS hourly sample bound exceeded")

    samples = []
    for row in rows:
        if row["bad_type"] or row["min_queries"] < 0 or row["max_queries"] > MAX_VALUE:
            raise InvalidInput("invalid per-MAC DNS query count")
        eligible = (
            type(row["qualified_seconds"]) is int
            and COVERAGE_SECONDS <= row["qualified_seconds"] <= HOUR_S
            and row["reasons"] == "[]"
        )
        samples.append(
            DnsSample(
                row["hour"],
                row["queries"],
                eligible,
                bool(row["suspicious"]),
                row["max_queries"] == MAX_VALUE,
            )
        )
    return samples


def _load_reference(inv, collector, device, profile) -> DnsReference:
    row = inv.execute(
        """SELECT * FROM monitoring_dns_baselines
           WHERE id=? AND collector_id=? AND device_id=? AND lineage=?""",
        (profile["baseline_id"], collector, device, profile["lineage"]),
    ).fetchone()
    if row is None:
        raise InvalidInput("missing DNS baseline")

    try:
        raw_hours, raw_config, raw_median = (
            row["training_hours"],
            row["config_json"],
            row["median_twice"],
        )
        if not (
            isinstance(raw_hours, str)
            and len(raw_hours) <= MAX_TRAINING_HOURS_JSON
            and isinstance(raw_config, str)
            and len(raw_config) <= 256
            and isinstance(raw_median, str)
            and 1 <= len(raw_median) <= 20
            and raw_median.isascii()
            and raw_median.isdecimal()
        ):
            raise ValueError
        hours = json.loads(raw_hours)
        config = DnsBaselineConfig(**json.loads(raw_config))
        median_twice = int(raw_median)
        if not (
            isinstance(hours, list)
            and config.minimum_hours <= len(hours) <= MAX_TRAINING_HOURS
            and all(type(h) is int and 0 <= h <= 2**53 and h % HOUR_S == 0 for h in hours)
            and hours == sorted(set(hours))
            and type(profile["training_since"]) is int
            and profile["training_since"] <= hours[0]
            and row["trained_until"] == hours[-1]
            and row["sample_hours"] == profile["sample_hours"] == len(hours)
            and row["distinct_days"] == profile["distinct_days"] == len({h // DAY_S for h in hours})
            and row["distinct_days"] >= config.minimum_days
            and row["algorithm"] == ALGORITHM_DNS
            and row["config_version"] == profile["config_version"] == config.version
            and 0 <= median_twice <= 2 * MAX_UNSATURATED_DEVICE_QUERIES
        ):
            raise ValueError
        reference = DnsReference(
            row["algorithm"],
            row["config_version"],
            median_twice,
            len(hours),
            row["distinct_days"],
            row["trained_until"],
            tuple(hours),
        )
        if _reference_id(collector, device, profile["lineage"], reference) != row["id"]:
            raise ValueError
        return reference
    except (ValueError, TypeError, RecursionError) as exc:
        raise InvalidInput("invalid stored DNS baseline") from exc


@dataclass(frozen=True)
class DnsAnalysis:
    hour: int
    state: str
    training_since: int
    reset: bool
    reference: DnsReference | None
    baseline_id: str | None
    sample_hours: int
    distinct_days: int
    current: DnsSample | None
    invalid_episode: tuple[str, int] | None


def prepare_dns(inv, collector, identity: Lineage, policy: DnsBaselineConfig, now) -> DnsAnalysis:
    until = int(now) // HOUR_S * HOUR_S
    lower = until - MAX_DAYS * DAY_S
    profile = inv.execute(
        "SELECT * FROM monitoring_dns_profiles WHERE collector_id=? AND device_id=?",
        (collector, identity.device_id),
    ).fetchone()
    reset = profile is not None and (
        profile["lineage"] != identity.key or profile["config_version"] != policy.version
    )
    retry = inv.execute(
        """SELECT hour FROM monitoring_dns_retries
           WHERE collector_id=? AND device_id=? AND lineage=? AND hour>=? AND hour<?""",
        (collector, identity.device_id, identity.key, lower, until),
    ).fetchone()
    if retry is not None and not reset and (profile is None or retry[0] > profile["updated_hour"]):
        until = retry[0] + HOUR_S
    series = _read_samples(inv, collector, identity, lower, until)
    training_since = profile["training_since"] if profile else series[0].hour if series else until
    reference = None
    baseline_id = None
    quality_reset = False
    by_hour = {sample.hour: sample for sample in series}
    if profile is not None and not reset and profile["baseline_id"]:
        try:
            reference = _load_reference(inv, collector, identity.device_id, profile)
        except InvalidInput:
            quality_reset = True
        else:
            quality_reset = any(
                lower <= stamp < until
                and (stamp not in by_hour or not _training_eligible(by_hour[stamp]))
                for stamp in reference.training_hours
            )
        if quality_reset:
            reference = None
        else:
            baseline_id = profile["baseline_id"]
    # A new continuity can bootstrap from stored qualified measurements. A known assignment,
    # merge, past profile change or quality fault starts a fresh prospective training window.
    known_history_change = identity.rule_attached or identity.aliases or identity.history_changed
    if reset or quality_reset or (profile is None and known_history_change):
        training_since = until + HOUR_S
    training = [sample for sample in series if sample.hour >= training_since]
    if reference is None and identity.versioned:
        reference = fit_dns_reference(training, policy)
        if reference is not None:
            baseline_id = _reference_id(collector, identity.device_id, identity.key, reference)
    state = "lineage_unavailable"
    if reference is not None:
        state = "mature"
        sample_hours, distinct_days = reference.sample_hours, reference.distinct_days
    else:
        qualified = [sample for sample in training if _training_eligible(sample)]
        sample_hours = len(qualified)
        distinct_days = len({sample.hour // DAY_S for sample in qualified})
        if identity.versioned:
            rebuild = quality_reset or (
                profile is not None and profile["state"] == "rebuilding_quality" and not reset
            )
            state = "rebuilding_quality" if rebuild else "learning"
    current = by_hour.get(until - HOUR_S) if until - HOUR_S >= training_since else None
    invalid_episode = None
    if reference is not None and identity.versioned:
        invalid_episode = _invalid_open_episode(
            inv, collector, identity, reference, policy, by_hour, lower, until
        )
    return DnsAnalysis(
        until - HOUR_S,
        state,
        training_since,
        reset or quality_reset,
        reference,
        baseline_id,
        sample_hours,
        distinct_days,
        current,
        invalid_episode,
    )


def _triggered(sample: DnsSample | None, threshold: int) -> bool:
    return (
        sample is not None
        and sample.eligible
        and not sample.saturated
        and sample.dns_queries > threshold
    )


def _invalid_open_episode(inv, collector, identity, reference, policy, samples, lower, until):
    active = inv.execute(
        """SELECT id,episode_start,last_hour FROM monitoring_incidents
           WHERE collector_id=? AND device_id=? AND lineage=? AND detector=? AND state='open'""",
        (collector, identity.device_id, identity.key, DNS_DEVIATION),
    ).fetchone()
    if active is None or active["last_hour"] >= until:
        return None  # an older evaluation cannot change a newer open episode
    start, last = active["episode_start"], active["last_hour"]
    threshold = reference.median_twice * policy.multiplier // 2
    retained = range(max(start, lower), last + HOUR_S, HOUR_S)
    if any(not _triggered(samples.get(hour), threshold) for hour in retained):
        return active["id"], last
    return None


def _median_queries(reference: DnsReference) -> int | float:
    whole, half = divmod(reference.median_twice, 2)
    return whole + 0.5 if half else whole


def publish_dns(
    inv, collector, identity: Lineage, policy: DnsBaselineConfig, now, result: DnsAnalysis
):
    """Publish the prepared DNS update under the caller's inventory transaction."""
    device, key = identity.device_id, identity.key
    current_hour = result.hour
    inv.execute(
        """DELETE FROM monitoring_dns_retries
           WHERE collector_id=? AND device_id=? AND (lineage<>? OR hour<=?)""",
        (collector, device, key, current_hour),
    )
    newer = inv.execute(
        """SELECT 1 FROM monitoring_dns_profiles
           WHERE collector_id=? AND device_id=? AND lineage=? AND updated_hour>?""",
        (collector, device, key, current_hour),
    ).fetchone()
    if newer is not None:
        return
    reference = result.reference
    retired_scopes = (*identity.aliases, device) if result.reset else identity.aliases
    if retired_scopes:
        marks = ",".join("?" for _ in retired_scopes)
        inv.execute(
            "UPDATE monitoring_incidents SET state='superseded'"  # noqa: S608
            f" WHERE collector_id=? AND device_id IN ({marks}) AND detector=? AND state='open'",
            (collector, *retired_scopes, DNS_DEVIATION),
        )
    if reference is not None:
        inv.execute(
            """INSERT INTO monitoring_dns_baselines VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO NOTHING""",
            (
                result.baseline_id,
                collector,
                device,
                key,
                reference.algorithm,
                reference.config_version,
                json.dumps(asdict(policy), sort_keys=True),
                str(reference.median_twice),
                reference.sample_hours,
                reference.distinct_days,
                reference.trained_until,
                current_hour + HOUR_S,
                json.dumps(reference.training_hours),
            ),
        )
    inv.execute(
        """INSERT INTO monitoring_dns_profiles VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(collector_id,device_id) DO UPDATE SET lineage=excluded.lineage,
             config_version=excluded.config_version,training_since=excluded.training_since,
             state=excluded.state,baseline_id=excluded.baseline_id,updated_hour=excluded.updated_hour,
             sample_hours=excluded.sample_hours,distinct_days=excluded.distinct_days""",
        (
            collector,
            device,
            key,
            policy.version,
            result.training_since,
            result.state,
            result.baseline_id,
            current_hour,
            result.sample_hours,
            result.distinct_days,
        ),
    )
    if result.invalid_episode is not None:
        # Late coverage changes retire the decision scope, even without a new eligible hour.
        inv.execute(
            "UPDATE monitoring_incidents SET state='superseded' "
            "WHERE id=? AND last_hour=? AND state='open'",
            result.invalid_episode,
        )

    current = result.current
    if current is None or not identity.versioned:
        return
    findings = dns_findings(current, reference, policy)
    if current.saturated or findings:
        inv.execute(
            "INSERT OR IGNORE INTO monitoring_dns_suspicious VALUES (?,?,?,?)",
            (collector, device, key, current_hour),
        )
    if current.eligible and not current.saturated and reference is not None:
        _publish_episode(
            inv,
            collector,
            device,
            key,
            policy,
            now,
            current_hour,
            reference,
            result.baseline_id,
            findings,
        )


def _publish_episode(
    inv, collector, device, key, policy, now, hour, reference, baseline_id, findings
):
    active = inv.execute(
        """SELECT id,episode_start,last_hour FROM monitoring_incidents
           WHERE collector_id=? AND device_id=? AND lineage=? AND detector=? AND state='open'""",
        (collector, device, key, DNS_DEVIATION),
    ).fetchone()
    if active is not None:
        if active["last_hour"] > hour:
            return
        if active["last_hour"] < hour and (not findings or active["last_hour"] < hour - HOUR_S):
            # A gap followed by a fresh burst ends continuity without showing a recovery.
            if findings:
                inv.execute(
                    "UPDATE monitoring_incidents SET state='superseded' WHERE id=?",
                    (active["id"],),
                )
            else:
                inv.execute(
                    """UPDATE monitoring_incidents SET state='resolved',
                       evidence=json_set(evidence,'$.recovery_hour',?) WHERE id=?""",
                    (hour, active["id"]),
                )
            active = None
    if not findings:
        return

    finding = findings[0]
    start = active["episode_start"] if active else hour
    ident = _digest([collector, device, key, DNS_DEVIATION, baseline_id, start])
    evidence = {
        "reason_code": finding["reason_code"],
        "unit": "queries",
        "hour": hour,
        "observed_bytes": finding["observed_queries"],
        "threshold_bytes": finding["threshold_queries"],
        "baseline_id": baseline_id,
        "algorithm": reference.algorithm,
        "config_version": reference.config_version,
        "coverage_required_seconds": COVERAGE_SECONDS,
        "lineage": key,
        "unusual_is_not_malicious": True,
        "baseline_median_queries": _median_queries(reference),
        "multiplier": policy.multiplier,
        "minimum_queries": policy.minimum_queries,
        "sample_hours": reference.sample_hours,
        "distinct_days": reference.distinct_days,
    }
    inv.execute(
        """INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,
             episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)
           VALUES (?,?,?,?,?,'open',?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET last_hour=excluded.last_hour,
             observed_bytes=excluded.observed_bytes,threshold_bytes=excluded.threshold_bytes,
             evidence=excluded.evidence WHERE monitoring_incidents.state='open'""",
        (
            ident,
            collector,
            device,
            key,
            DNS_DEVIATION,
            start,
            hour,
            iso_utc(now),
            baseline_id,
            finding["observed_queries"],
            finding["threshold_queries"],
            json.dumps(evidence, sort_keys=True),
        ),
    )


def dns_baseline_view(inv, collector, device, key):
    """Expose the current DNS baseline, including on inventories predating its migration."""
    if not has_table(inv, "monitoring_dns_profiles"):
        return None
    profile = inv.execute(
        "SELECT * FROM monitoring_dns_profiles WHERE collector_id=? AND device_id=?",
        (collector, device),
    ).fetchone()
    if profile is None:
        return None

    state, reference = "rebuilding", None
    if profile["lineage"] == key:
        state = profile["state"]
        if state == "mature":
            try:
                reference = _load_reference(inv, collector, device, profile)
            except InvalidInput:
                state = "rebuilding"
            else:
                invalid = inv.execute(
                    """SELECT 1 FROM coverage_hourly WHERE collector_id=? AND hour IN
                       (SELECT value FROM json_each(?))
                       AND (qualified_seconds<? OR reasons<>'[]') LIMIT 1""",
                    (collector, json.dumps(reference.training_hours), COVERAGE_SECONDS),
                ).fetchone()
                if invalid:
                    state, reference = "rebuilding_quality", None
    return {
        "state": state,
        "baseline_id": profile["baseline_id"] if reference else None,
        "algorithm": reference.algorithm if reference else None,
        "config_version": profile["config_version"],
        "sample_hours": profile["sample_hours"],
        "distinct_days": profile["distinct_days"],
        "training_since": profile["training_since"],
        "trained_until": reference.trained_until if reference else None,
        "median_queries": _median_queries(reference) if reference else None,
    }


def dns_notice_deliverable(inv, ov, policy: DnsBaselineConfig, incident_id, kind, now) -> bool:
    """Check the current lineage, frozen cohort, and evidence hours for one due DNS notice."""
    deadline = time.monotonic() + 0.5
    inv.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    try:
        return _dns_notice_deliverable(inv, ov, policy, incident_id, kind, now)
    except (sqlite3.DatabaseError, ValueError, TypeError, RecursionError):
        return False
    finally:
        inv.set_progress_handler(None, 0)


def _dns_notice_deliverable(inv, ov, policy, incident_id, kind, now) -> bool:
    row = inv.execute(
        """SELECT collector_id,device_id,lineage,baseline_id,state,episode_start,last_hour,evidence
           FROM monitoring_incidents WHERE id=? AND detector=?""",
        (incident_id, DNS_DEVIATION),
    ).fetchone()
    expected_state = "open" if kind == "open" else "resolved"
    if row is None or row["state"] != expected_state:
        return False

    collector, device, key = row["collector_id"], row["device_id"], row["lineage"]
    profile = inv.execute(
        """SELECT * FROM monitoring_dns_profiles
           WHERE collector_id=? AND device_id=? AND lineage=? AND state='mature'
             AND baseline_id=? AND config_version=?""",
        (collector, device, key, row["baseline_id"], policy.version),
    ).fetchone()
    if (
        profile is None
        or inv.execute(
            "SELECT 1 FROM monitoring_dns_retries WHERE collector_id=? AND device_id=? "
            "AND lineage=?",
            (collector, device, key),
        ).fetchone()
    ):
        return False

    identity = lineage(inv, ov, device)
    if not (
        identity.versioned and identity.device_id == device and identity.key == key
    ) or _has_due_work(inv, collector, identity.macs, now):
        return False

    reference = _load_reference(inv, collector, device, profile)
    if reference.median_twice < 2 * policy.minimum_queries:
        return False
    return _notice_evidence_qualified(inv, collector, identity, row, reference, policy, kind, now)


def _notice_evidence_qualified(inv, collector, identity, row, reference, policy, kind, now):
    until = int(now) // HOUR_S * HOUR_S
    lower = until - MAX_DAYS * DAY_S
    start, last = row["episode_start"], row["last_hour"]
    if not (
        type(start) is int
        and type(last) is int
        and max(lower, reference.trained_until + HOUR_S) <= start <= last < until
        and start % HOUR_S == last % HOUR_S == 0
    ):
        return False
    trigger_hours = set(range(start, last + HOUR_S, HOUR_S))
    recovery = None
    if kind == "recover":
        evidence = json.loads(row["evidence"])
        recovery = evidence.get("recovery_hour") if isinstance(evidence, dict) else None
        if type(recovery) is not int or recovery <= row["last_hour"]:
            return False
    required = trigger_hours | ({recovery} if recovery is not None else set())
    if recovery is not None and (recovery >= until or recovery % HOUR_S):
        return False

    # Training outside retention has already passed inspection. All retained evidence must
    # still be qualified, even if its invalidation has not reached this device's dirty row.
    training = {hour for hour in reference.training_hours if hour >= lower}
    checked = tuple(sorted(training | required))
    if inv.execute(
        """SELECT 1 FROM monitoring_quality_work WHERE collector_id=?
             AND hour IN (SELECT value FROM json_each(?)) LIMIT 1""",
        (collector, json.dumps(checked)),
    ).fetchone():
        return False
    samples = {
        sample.hour: sample
        for sample in _read_samples(inv, collector, identity, lower, until, only_hours=checked)
    }
    if any(hour not in samples or not _training_eligible(samples[hour]) for hour in training):
        return False
    if any(
        hour not in samples or not samples[hour].eligible or samples[hour].saturated
        for hour in required
    ):
        return False
    threshold = reference.median_twice * policy.multiplier // 2
    return all(_triggered(samples[hour], threshold) for hour in trigger_hours) and (
        recovery is None or samples[recovery].dns_queries <= threshold
    )


def _has_due_work(inv, collector, macs, now) -> bool:
    if not macs:
        return False
    marks = ",".join("?" for _ in macs)
    return (
        inv.execute(
            f"SELECT 1 FROM monitoring_dirty WHERE collector_id=? AND mac IN ({marks}) "  # noqa: S608
            "AND queued_at<=? LIMIT 1",
            (collector, *macs, int(now)),
        ).fetchone()
        is not None
    )


def record_dns_retry(inv, collector, identity: Lineage, hour: int) -> None:
    """Preserve the failed evaluation hour while monitoring_dirty schedules its retry."""
    inv.execute(
        """INSERT INTO monitoring_dns_retries VALUES (?,?,?,?)
           ON CONFLICT(collector_id,device_id) DO UPDATE SET
             hour=CASE WHEN lineage=excluded.lineage THEN MIN(hour,excluded.hour)
                       ELSE excluded.hour END,
             lineage=excluded.lineage""",
        (collector, identity.device_id, identity.key, hour),
    )


def prune_dns(inv, cutoff):
    inv.execute(
        """DELETE FROM monitoring_dns_retries WHERE rowid IN
          (SELECT rowid FROM monitoring_dns_retries WHERE hour<? ORDER BY hour LIMIT 1000)""",
        (cutoff,),
    )
    inv.execute(
        """DELETE FROM monitoring_dns_suspicious WHERE rowid IN
          (SELECT rowid FROM monitoring_dns_suspicious WHERE hour<? ORDER BY hour LIMIT 1000)""",
        (cutoff,),
    )
    inv.execute(
        """DELETE FROM monitoring_dns_baselines WHERE id IN
          (SELECT b.id FROM monitoring_dns_baselines b WHERE b.created_hour<?
           AND NOT EXISTS (SELECT 1 FROM monitoring_dns_profiles p WHERE p.baseline_id=b.id)
           AND NOT EXISTS (SELECT 1 FROM monitoring_incidents i WHERE i.collector_id=b.collector_id
                           AND i.device_id=b.device_id AND i.detector=? AND i.baseline_id=b.id)
           ORDER BY b.created_hour,b.id LIMIT 1000)""",
        (cutoff, DNS_DEVIATION),
    )
