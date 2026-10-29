"""Time-of-day baseline (tod-median-v1): pure, no database, wall clock or I/O.

Cohort = (is_weekend, hour_of_day // bucket_hours), both read from the sample's epoch hour in UTC.
Local time and DST handling are deliberately deferred. A cohort is mature only with enough valid
samples AND enough distinct UTC days; otherwise it abstains. Ineligible (missing) samples are never
zeros.

The CALLER freezes the baseline: `fit_tod(..., trained_until)` only learns from hours up to
`trained_until`, and `findings_tod` refuses to score any hour at or before it (or at or before a
cohort's last trained hour), so a reference can never normalise the hours it is judging.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from types import MappingProxyType

from vigie_pipeline.baselines import Sample, large_upload_finding

ALGORITHM = "tod-median-v1"
MIB = 1024 * 1024
BUCKET_HOURS = (1, 2, 3, 4, 6, 8, 12, 24)
MAX_TRAINING_HOURS = 24 * 7 * 26
MAX_INT = 2**53
Cohort = tuple[bool, int]


@dataclass(frozen=True)
class TodConfig:
    min_samples_per_cohort: int = 20
    min_days_per_cohort: int = 7
    minimum_bytes: int = 50 * MIB
    multiplier: int = 4
    large_upload_bytes: int = 1024 * MIB
    bucket_hours: int = 4

    def __post_init__(self):
        bounds = (
            (self.min_samples_per_cohort, 1, 10_000),
            (self.min_days_per_cohort, 1, 3650),
            (self.minimum_bytes, 1, 2**50),
            (self.multiplier, 1, 100),
            (self.large_upload_bytes, 1, 2**50),
        )
        if not (
            all(type(v) is int and lo <= v <= hi for v, lo, hi in bounds)
            and type(self.bucket_hours) is int
            and self.bucket_hours in BUCKET_HOURS
        ):
            raise ValueError("time-of-day policy outside supported bounds")

    @property
    def version(self):
        return hashlib.sha256(
            json.dumps({"algorithm": ALGORITHM, **asdict(self)}, sort_keys=True).encode()
        ).hexdigest()


@dataclass(frozen=True)
class CohortFit:
    median_twice: int
    samples: int
    days: int
    last_trained_hour: int


@dataclass(frozen=True)
class CohortAbstain:
    reason: str
    samples: int
    days: int


@dataclass(frozen=True)
class TodReference:
    algorithm: str
    config_version: str
    trained_until: int
    training_hours: int
    cohorts: Mapping[Cohort, CohortFit | CohortAbstain]


@dataclass(frozen=True)
class TodCandidate:
    detector: str
    cohort: Cohort
    observed_bytes: int
    threshold_bytes: int
    reason_code: str


@dataclass(frozen=True)
class TodFindings:
    candidates: tuple[TodCandidate, ...]
    abstain_reason: str | None


def cohort_key(hour: int, bucket_hours: int) -> Cohort:
    "UTC (is_weekend, bucket). Epoch day 0 was a Thursday, so Monday is (day + 3) % 7 == 0."
    day = hour // 86400
    return (day + 3) % 7 >= 5, hour % 86400 // 3600 // bucket_hours


def _check_hour(hour):
    if type(hour) is not int or hour % 3600 or not 0 <= hour <= MAX_INT:
        raise ValueError("invalid hour")


def _check_sample(sample: Sample):
    _check_hour(sample.hour)
    if type(sample.bytes_up) is not int or not 0 <= sample.bytes_up <= MAX_INT:
        raise ValueError("invalid hourly sample")


def _fit_cohort(values, days, last, config: TodConfig):
    if len(values) < config.min_samples_per_cohort:
        return CohortAbstain("immature_samples", len(values), len(days))
    if len(days) < config.min_days_per_cohort:
        return CohortAbstain("immature_days", len(values), len(days))
    ranked = sorted(values)
    mid = len(ranked) // 2
    twice = 2 * ranked[mid] if len(ranked) % 2 else ranked[mid - 1] + ranked[mid]
    return CohortFit(twice, len(values), len(days), last)


def fit_tod(samples: Iterable[Sample], config: TodConfig, trained_until: int) -> TodReference:
    "Fit every cohort from valid samples at or before `trained_until`; order never matters."
    ordered = list(samples)
    _check_hour(trained_until)
    if len(ordered) > MAX_TRAINING_HOURS:
        raise ValueError("too many training samples")
    for sample in ordered:
        _check_sample(sample)
    if len({s.hour for s in ordered}) != len(ordered):
        raise ValueError("baseline input duplicate hour")
    keys = [(w, b) for w in (False, True) for b in range(24 // config.bucket_hours)]
    values, days, last = {k: [] for k in keys}, {k: set() for k in keys}, dict.fromkeys(keys, 0)
    for sample in ordered:
        if sample.hour > trained_until or not sample.eligible or sample.suspicious:
            continue
        if sample.bytes_up >= config.large_upload_bytes:
            continue
        key = cohort_key(sample.hour, config.bucket_hours)
        values[key].append(sample.bytes_up)
        days[key].add(sample.hour // 86400)
        last[key] = max(last[key], sample.hour)
    cohorts = {k: _fit_cohort(values[k], days[k], last[k], config) for k in keys}
    used = sum(len(v) for v in values.values())
    return TodReference(ALGORITHM, config.version, trained_until, used, MappingProxyType(cohorts))


def _threshold(fit: CohortFit, config: TodConfig):
    "The cohort line, capped at the fixed large-upload line so a poisoned cohort cannot lift it."
    line = max(config.minimum_bytes, fit.median_twice * config.multiplier // 2)
    return min(config.large_upload_bytes, line)


def _exceeds(sample: Sample, fit: CohortFit, config: TodConfig):
    "Threshold of the sample's own cohort when the hour is strictly above it, else None."
    threshold = _threshold(fit, config)
    return threshold if sample.bytes_up > threshold else None


def _scorable(sample: Sample, reference: TodReference, config: TodConfig):
    "(fit, None) for a mature, leak-free cohort; (None, reason) otherwise."
    fit = reference.cohorts[cohort_key(sample.hour, config.bucket_hours)]
    if isinstance(fit, CohortAbstain):
        return None, fit.reason
    if sample.hour <= max(reference.trained_until, fit.last_trained_hour):
        return None, "leaks_evaluated_hours"
    return fit, None


def deviation_threshold(sample: Sample, reference: TodReference, config: TodConfig):
    "Capped line of the sample's own mature, leak-free cohort; None when it would abstain."
    if reference.config_version != config.version or sample.hour <= reference.trained_until:
        return None
    fit, _ = _scorable(sample, reference, config)
    return None if fit is None else _threshold(fit, config)


def findings_tod(
    current: Sample | None,
    previous: Sample | None,
    reference: TodReference,
    config: TodConfig,
) -> TodFindings:
    """Fixed large-upload hits first (always, even cold), then two consecutive eligible hours each
    strictly above the threshold of its OWN mature cohort, both after the frozen training window.
    An unusable or immature cohort yields no deviation and an explicit abstain reason."""
    for sample in (current, previous):
        if sample is not None:
            _check_sample(sample)
    if reference.algorithm != ALGORITHM:
        raise ValueError("reference algorithm mismatch")
    if current is None or not current.eligible:
        return TodFindings((), "current_unavailable")
    key = cohort_key(current.hour, config.bucket_hours)
    out = []
    large = large_upload_finding(current, config.large_upload_bytes)
    if large is not None:
        out.append(
            TodCandidate(
                large["detector"],
                key,
                current.bytes_up,
                large["threshold_bytes"],
                large["reason_code"],
            )
        )
    reason = _deviation_reason(current, previous, reference, config, out)
    return TodFindings(tuple(out), reason)


def _deviation_reason(current, previous, reference, config, out):
    "Append a deviation candidate to `out` when warranted; return the abstain reason, if any."
    if reference.config_version != config.version:
        return "config_mismatch"
    if previous is not None and (not previous.eligible or previous.hour != current.hour - 3600):
        previous = None  # not a consecutive pair: it can neither fire nor leak
    if current.hour <= reference.trained_until or (
        previous is not None and previous.hour <= reference.trained_until
    ):
        return "leaks_evaluated_hours"
    now_fit, reason = _scorable(current, reference, config)
    if now_fit is None or previous is None:
        return reason
    before_fit, reason = _scorable(previous, reference, config)
    if before_fit is None:
        return reason if reason == "leaks_evaluated_hours" else f"previous_{reason}"
    threshold = _exceeds(current, now_fit, config)
    if threshold is not None and _exceeds(previous, before_fit, config) is not None:
        key = cohort_key(current.hour, config.bucket_hours)
        out.append(
            TodCandidate(
                "upload_deviation",
                key,
                current.bytes_up,
                threshold,
                "two_qualified_upload_hours_in_cohort",
            )
        )
    return None
