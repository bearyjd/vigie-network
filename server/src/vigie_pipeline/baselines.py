"""Deterministic monitoring policy, with no database, wall clock, trust or enforcement effects."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

ALGORITHM = "pooled-median-v1"
MIB = 1024 * 1024


class InvalidInput(ValueError):
    "Stored or measured data the baseline code refuses; the engine backs the entity off."


@dataclass(frozen=True)
class BaselineConfig:
    minimum_hours: int = 20
    minimum_days: int = 14
    minimum_bytes: int = 50 * MIB
    multiplier: int = 4
    large_upload_bytes: int = 1024 * MIB

    def __post_init__(self):
        if not (
            1 <= self.minimum_hours <= 2160
            and 1 <= self.minimum_days <= 90
            and 1 <= self.minimum_bytes <= 2**50
            and 1 <= self.multiplier <= 100
            and 1 <= self.large_upload_bytes <= 2**50
        ):
            raise ValueError("monitoring policy outside supported bounds")

    @property
    def version(self):
        return hashlib.sha256(
            json.dumps({"algorithm": ALGORITHM, **asdict(self)}, sort_keys=True).encode()
        ).hexdigest()


@dataclass(frozen=True)
class Sample:
    hour: int
    bytes_up: int
    eligible: bool
    suspicious: bool = False


def fit_reference(samples, config: BaselineConfig):
    "Freeze the first qualified cohort reaching both cold-start floors. Never fit on l"
    "ater data."
    ordered = sorted(samples, key=lambda s: s.hour)
    if len(ordered) > 2160 or len({s.hour for s in ordered}) != len(ordered):
        raise InvalidInput("baseline input bound/duplicate hour")
    values = []
    days = set()
    hours = []
    for sample in ordered:
        if sample.hour % 3600 or sample.bytes_up < 0:
            raise InvalidInput("invalid hourly sample")
        if not sample.eligible or sample.suspicious or sample.bytes_up >= config.large_upload_bytes:
            continue
        values.append(sample.bytes_up)
        days.add(sample.hour // 86400)
        hours.append(sample.hour)
        if len(values) >= config.minimum_hours and len(days) >= config.minimum_days:
            ranked = sorted(values)
            mid = len(ranked) // 2
            twice = 2 * ranked[mid] if len(ranked) % 2 else ranked[mid - 1] + ranked[mid]
            return {
                "algorithm": ALGORITHM,
                "config_version": config.version,
                "median_twice": twice,
                "sample_hours": len(values),
                "distinct_days": len(days),
                "trained_until": sample.hour,
                "training_hours": hours,
            }
    return None


def large_upload_finding(current: Sample, large_upload_bytes: int):
    "The fixed cold-start detector, shared with the time-of-day module. Caller checks eligibility."
    if current.bytes_up < large_upload_bytes:
        return None
    return {
        "detector": "large_upload",
        "observed_bytes": current.bytes_up,
        "threshold_bytes": large_upload_bytes,
        "reason_code": "large_upload_threshold",
    }


def findings(current: Sample | None, previous: Sample | None, reference, config: BaselineConfig):
    if current is None or not current.eligible:
        return []
    out = []
    large = large_upload_finding(current, config.large_upload_bytes)
    if large is not None:
        out.append(large)
    if reference is not None and current.hour > reference["trained_until"]:
        threshold = max(config.minimum_bytes, reference["median_twice"] * config.multiplier // 2)
        if (
            previous is not None
            and previous.eligible
            and previous.hour == current.hour - 3600
            and previous.hour > reference["trained_until"]
            and previous.bytes_up > threshold
            and current.bytes_up > threshold
        ):
            out.append(
                {
                    "detector": "upload_deviation",
                    "observed_bytes": current.bytes_up,
                    "threshold_bytes": threshold,
                    "reason_code": "two_qualified_upload_hours",
                }
            )
    return out
