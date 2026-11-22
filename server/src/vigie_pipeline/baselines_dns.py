"""Pooled per-device DNS volume baseline with no I/O or wall-clock dependency."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from itertools import islice

from vigie_pipeline.baselines import InvalidInput
from vigie_pipeline.detectors import DNS_DEVIATION
from vigie_pipeline.measurements import HOUR_S, MAX_VALUE
from vigie_pipeline.monitoring_identity import MAX_MACS

ALGORITHM_DNS = "pooled-median-dns-v1"
DAY_S = 24 * HOUR_S
MAX_DAYS = 90
MAX_TRAINING_HOURS = MAX_DAYS * 24
MAX_DEVICE_QUERIES = MAX_VALUE * MAX_MACS
MAX_UNSATURATED_DEVICE_QUERIES = (MAX_VALUE - 1) * MAX_MACS


@dataclass(frozen=True)
class DnsBaselineConfig:
    minimum_hours: int = 20
    minimum_days: int = 14
    minimum_queries: int = 200
    multiplier: int = 4

    def __post_init__(self) -> None:
        bounds = (
            (self.minimum_hours, 1, MAX_TRAINING_HOURS),
            (self.minimum_days, 1, MAX_DAYS),
            (self.minimum_queries, 1, MAX_DEVICE_QUERIES),
            (self.multiplier, 1, 100),
        )
        if not all(
            type(value) is int and lower <= value <= upper for value, lower, upper in bounds
        ):
            raise ValueError("DNS baseline policy outside supported bounds")

    @property
    def version(self) -> str:
        return hashlib.sha256(
            json.dumps({"algorithm": ALGORITHM_DNS, **asdict(self)}, sort_keys=True).encode()
        ).hexdigest()


@dataclass(frozen=True)
class DnsSample:
    """A UTC epoch hour and its device-wide query count.

    Set saturated when any constituent per-MAC DNS counter is at measurements.MAX_VALUE.
    An aggregate of several unsaturated counters can exceed that per-MAC cap.
    """

    hour: int
    dns_queries: int
    eligible: bool
    suspicious: bool = False
    saturated: bool = False


@dataclass(frozen=True)
class DnsReference:
    """A fitted cohort produced by fit_dns_reference.

    Any persistence adapter must validate stored fields before reconstructing a reference.
    """

    algorithm: str
    config_version: str
    median_twice: int
    sample_hours: int
    distinct_days: int
    trained_until: int
    training_hours: tuple[int, ...]


def _check_sample(sample: DnsSample) -> None:
    if not (
        isinstance(sample, DnsSample)
        and type(sample.hour) is int
        and 0 <= sample.hour <= 2**53
        and sample.hour % HOUR_S == 0
        and type(sample.dns_queries) is int
        and 0 <= sample.dns_queries <= MAX_DEVICE_QUERIES
        and all(
            type(flag) is bool for flag in (sample.eligible, sample.suspicious, sample.saturated)
        )
        and (sample.saturated or sample.dns_queries <= MAX_UNSATURATED_DEVICE_QUERIES)
    ):
        raise InvalidInput("invalid hourly DNS sample")


def fit_dns_reference(
    samples: Iterable[DnsSample], config: DnsBaselineConfig
) -> DnsReference | None:
    """Freeze the earliest qualified cohort that meets both cold-start floors."""
    ordered = list(islice(samples, MAX_TRAINING_HOURS + 1))
    if len(ordered) > MAX_TRAINING_HOURS:
        raise InvalidInput("too many DNS training samples")
    for sample in ordered:
        _check_sample(sample)
    if len({sample.hour for sample in ordered}) != len(ordered):
        raise InvalidInput("DNS baseline input duplicate hour")
    ordered.sort(key=lambda sample: sample.hour)

    values = []
    days = set()
    hours = []
    for sample in ordered:
        if not sample.eligible or sample.suspicious or sample.saturated:
            continue
        values.append(sample.dns_queries)
        days.add(sample.hour // DAY_S)
        hours.append(sample.hour)
        if len(values) >= config.minimum_hours and len(days) >= config.minimum_days:
            ranked = sorted(values)
            middle = len(ranked) // 2
            median_twice = ranked[middle] + ranked[(len(ranked) - 1) // 2]
            return DnsReference(
                algorithm=ALGORITHM_DNS,
                config_version=config.version,
                median_twice=median_twice,
                sample_hours=len(values),
                distinct_days=len(days),
                trained_until=sample.hour,
                training_hours=tuple(hours),
            )
    return None


def dns_findings(
    current: DnsSample | None, reference: DnsReference | None, config: DnsBaselineConfig
) -> list[dict[str, str | int]]:
    """Flag one eligible post-training hour strictly above the learned threshold.

    A supplied reference must come from fit_dns_reference or validated reconstruction.
    """
    if current is None:
        return []
    _check_sample(current)
    if (
        not current.eligible
        or current.saturated
        or reference is None
        or current.hour <= reference.trained_until
        or reference.algorithm != ALGORITHM_DNS
        or reference.config_version != config.version
        or reference.median_twice < 2 * config.minimum_queries
    ):
        return []

    # An integral count strictly exceeds the exact threshold iff it exceeds its floor.
    threshold = reference.median_twice * config.multiplier // 2
    if current.dns_queries <= threshold:
        return []
    return [
        {
            "detector": DNS_DEVIATION,
            "observed_queries": current.dns_queries,
            "threshold_queries": threshold,
            "reason_code": "dns_deviation_threshold",
        },
    ]
