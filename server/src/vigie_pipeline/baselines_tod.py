"""Time-of-day baseline (tod-median-v1): pure, no database, wall clock or I/O.

Cohort = (is_weekend, hour_of_day), both read from the sample's epoch hour in UTC. Local time and
DST handling are deliberately deferred. A cohort is mature only with enough valid samples AND
enough distinct UTC days; otherwise it abstains. Ineligible (missing) samples are never zeros.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from types import MappingProxyType

from vigie_pipeline.baselines import Sample

ALGORITHM = "tod-median-v1"
MIB = 1024 * 1024


@dataclass(frozen=True)
class TodConfig:
    min_samples_per_cohort: int = 20
    min_days_per_cohort: int = 7
    minimum_bytes: int = 50 * MIB
    multiplier: int = 4
    large_upload_bytes: int = 1024 * MIB

    def __post_init__(self):
        if not (
            1 <= self.min_samples_per_cohort <= 10_000
            and 1 <= self.min_days_per_cohort <= 3650
            and 1 <= self.minimum_bytes <= 2**50
            and 1 <= self.multiplier <= 100
            and 1 <= self.large_upload_bytes <= 2**50
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


@dataclass(frozen=True)
class CohortAbstain:
    reason: str
    samples: int
    days: int


@dataclass(frozen=True)
class TodReference:
    algorithm: str
    config_version: str
    cohorts: Mapping[tuple[bool, int], CohortFit | CohortAbstain]


@dataclass(frozen=True)
class TodCandidate:
    detector: str
    cohort: tuple[bool, int]
    observed_bytes: int
    threshold_bytes: int
    reason_code: str


@dataclass(frozen=True)
class TodFindings:
    candidates: tuple[TodCandidate, ...]
    abstain_reason: str | None


def cohort_key(hour: int) -> tuple[bool, int]:
    "UTC (is_weekend, hour_of_day). Epoch day 0 was a Thursday, so Monday is (day + 3) % 7 == 0."
    day = hour // 86400
    return (day + 3) % 7 >= 5, hour % 86400 // 3600


def _fit_cohort(values, days, config: TodConfig):
    if len(values) < config.min_samples_per_cohort:
        return CohortAbstain("immature_samples", len(values), len(days))
    if len(days) < config.min_days_per_cohort:
        return CohortAbstain("immature_days", len(values), len(days))
    ranked = sorted(values)
    mid = len(ranked) // 2
    twice = 2 * ranked[mid] if len(ranked) % 2 else ranked[mid - 1] + ranked[mid]
    return CohortFit(twice, len(values), len(days))


def fit_tod(samples: Iterable[Sample], config: TodConfig) -> TodReference:
    "Fit every cohort from valid samples only; the result never depends on input order."
    ordered = list(samples)
    if len({s.hour for s in ordered}) != len(ordered):
        raise ValueError("baseline input duplicate hour")
    values = {(w, h): [] for w in (False, True) for h in range(24)}
    days = {key: set() for key in values}
    for sample in ordered:
        if sample.hour % 3600 or sample.bytes_up < 0:
            raise ValueError("invalid hourly sample")
        if not sample.eligible or sample.suspicious or sample.bytes_up >= config.large_upload_bytes:
            continue
        key = cohort_key(sample.hour)
        values[key].append(sample.bytes_up)
        days[key].add(sample.hour // 86400)
    cohorts = {key: _fit_cohort(values[key], days[key], config) for key in values}
    return TodReference(ALGORITHM, config.version, MappingProxyType(cohorts))


def _exceeds(sample: Sample | None, fit, config: TodConfig):
    "Threshold when `sample` is an eligible hour strictly above its own mature cohort's line."
    if sample is None or not sample.eligible or not isinstance(fit, CohortFit):
        return None
    threshold = max(config.minimum_bytes, fit.median_twice * config.multiplier // 2)
    return threshold if sample.bytes_up > threshold else None


def findings_tod(
    current: Sample | None, previous: Sample | None, reference: TodReference, config: TodConfig
) -> TodFindings:
    """Two consecutive eligible hours, each strictly above the threshold of its OWN mature cohort.
    An immature or unusable current hour abstains with an explicit reason."""
    if current is None or not current.eligible:
        return TodFindings((), "current_unavailable")
    if reference.config_version != config.version:
        return TodFindings((), "config_mismatch")
    key = cohort_key(current.hour)
    fit = reference.cohorts[key]
    if isinstance(fit, CohortAbstain):
        return TodFindings((), fit.reason)
    threshold = _exceeds(current, fit, config)
    if (
        threshold is None
        or previous is None
        or previous.hour != current.hour - 3600
        or _exceeds(previous, reference.cohorts[cohort_key(previous.hour)], config) is None
    ):
        return TodFindings((), None)
    candidate = TodCandidate(
        "upload_deviation", key, current.bytes_up, threshold, "two_qualified_upload_hours_in_cohort"
    )
    return TodFindings((candidate,), None)
