"""Algorithm seam for the monitoring engine: fit, findings and threshold per baseline family.

A reference is a plain dict. Both families fill the columns of `monitoring_baselines`
(`median_twice`, `sample_hours`, `distinct_days`, `trained_until`, `training_hours`); the tod family
also carries the in-memory `tod` model. Its columns are overall figures for display and the quality
checks; the tod threshold itself always comes from the per-cohort refit.

tod persists its inputs (hours in `training_hours`, their bytes in `config_json`) and refits from
them on every pass, so retention pruning of raw measurements can never move a frozen reference.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from vigie_pipeline.baselines import (
    ALGORITHM,
    BaselineConfig,
    Sample,
    findings,
    fit_reference,
    large_upload_finding,
)
from vigie_pipeline.baselines_tod import (
    ALGORITHM as TOD_ALGORITHM,
)
from vigie_pipeline.baselines_tod import (
    CohortFit,
    TodConfig,
    cohort_key,
    deviation_threshold,
    findings_tod,
    fit_tod,
)


def _median_twice(values):
    ranked = sorted(values)
    mid = len(ranked) // 2
    return 2 * ranked[mid] if len(ranked) % 2 else ranked[mid - 1] + ranked[mid]


class PooledStrategy:
    algorithm = ALGORITHM

    def __init__(self, policy: BaselineConfig):
        self.policy = policy

    def fit(self, training):
        return fit_reference(training, self.policy)

    def hydrate(self, row):
        return row

    def config_json(self, reference):
        return json.dumps(asdict(self.policy), sort_keys=True)

    def findings(self, current, previous, reference):
        return findings(current, previous, reference, self.policy)

    def threshold(self, current, reference):
        if not reference:
            return None
        policy = self.policy
        return max(policy.minimum_bytes, reference["median_twice"] * policy.multiplier // 2)

    def evidence(self, current, reference):
        return {
            "baseline_median_upload_bytes": reference["median_twice"] / 2 if reference else None,
            "sample_hours": reference["sample_hours"] if reference else None,
            "distinct_days": reference["distinct_days"] if reference else None,
        }


class TodStrategy:
    algorithm = TOD_ALGORITHM

    def __init__(self, policy: TodConfig):
        self.policy = policy

    def freeze_hour(self, qualified):
        "First hour at which EVERY cohort is mature, so later data is never needed; else None."
        policy = self.policy
        cohorts = 2 * (24 // policy.bucket_hours)
        counts: dict = {}
        days: dict = {}
        mature = set()
        for sample in qualified:
            key = cohort_key(sample.hour, policy.bucket_hours)
            counts[key] = counts.get(key, 0) + 1
            days.setdefault(key, set()).add(sample.hour // 86400)
            if (
                counts[key] >= policy.min_samples_per_cohort
                and len(days[key]) >= policy.min_days_per_cohort
            ):
                mature.add(key)
                if len(mature) == cohorts:
                    return sample.hour
        return None

    def fit(self, training):
        qualified = sorted(
            (
                s
                for s in training
                if s.eligible and not s.suspicious and s.bytes_up < self.policy.large_upload_bytes
            ),
            key=lambda s: s.hour,
        )
        until = self.freeze_hour(qualified)
        if until is None:
            return None
        used = [s for s in qualified if s.hour <= until]
        model = fit_tod(used, self.policy, until)
        return {
            "algorithm": TOD_ALGORITHM,
            "config_version": self.policy.version,
            "median_twice": _median_twice([s.bytes_up for s in used]),
            "sample_hours": len(used),
            "distinct_days": len({s.hour // 86400 for s in used}),
            "trained_until": until,
            "training_hours": [s.hour for s in used],
            "training_bytes": [s.bytes_up for s in used],
            "tod": model,
        }

    def hydrate(self, row):
        "Refit from the stored inputs; None when they are missing, malformed or inconsistent."
        try:
            hours = json.loads(row["training_hours"])
            values = json.loads(row["config_json"])["training_bytes"]
            if len(hours) != len(values) or len(hours) != row["sample_hours"]:
                return None
            used = [Sample(h, v, True) for h, v in zip(hours, values, strict=True)]
            model = fit_tod(used, self.policy, row["trained_until"])
        except (KeyError, TypeError, ValueError):
            return None
        if model.training_hours != len(hours) or model.config_version != row["config_version"]:
            return None
        return {**row, "tod": model}

    def config_json(self, reference):
        return json.dumps(
            {
                "algorithm": TOD_ALGORITHM,
                "policy": asdict(self.policy),
                "trained_until": reference["trained_until"],
                "training_bytes": reference["training_bytes"],
            },
            sort_keys=True,
        )

    def findings(self, current, previous, reference):
        if reference is None:
            if current is None or not current.eligible:
                return []
            large = large_upload_finding(current, self.policy.large_upload_bytes)
            return [large] if large else []
        out = findings_tod(current, previous, reference["tod"], self.policy)
        return [
            {
                "detector": c.detector,
                "observed_bytes": c.observed_bytes,
                "threshold_bytes": c.threshold_bytes,
                "reason_code": c.reason_code,
            }
            for c in out.candidates
        ]

    def threshold(self, current, reference):
        if not reference:
            return None
        return deviation_threshold(current, reference["tod"], self.policy)

    def evidence(self, current, reference):
        fit = None
        if reference and current is not None:
            fit = reference["tod"].cohorts[cohort_key(current.hour, self.policy.bucket_hours)]
        if not isinstance(fit, CohortFit):
            return {
                "baseline_median_upload_bytes": None,
                "sample_hours": None,
                "distinct_days": None,
            }
        return {
            "baseline_median_upload_bytes": fit.median_twice / 2,
            "sample_hours": fit.samples,
            "distinct_days": fit.days,
        }


def strategy_for(policy: BaselineConfig | TodConfig):
    return TodStrategy(policy) if isinstance(policy, TodConfig) else PooledStrategy(policy)
