from dataclasses import FrozenInstanceError, replace

import pytest

from vigie_pipeline.baselines import InvalidInput
from vigie_pipeline.baselines_dns import (
    ALGORITHM_DNS,
    DnsBaselineConfig,
    DnsSample,
    dns_findings,
    fit_dns_reference,
)
from vigie_pipeline.measurements import MAX_VALUE
from vigie_pipeline.monitoring_identity import MAX_MACS

HOUR = 3600
DAY = 24 * HOUR
START = 20_000 * DAY


def samples(hours=20, days=14, queries=200):
    return [
        DnsSample(START + (index % days) * DAY + (index // days) * HOUR, queries, True)
        for index in range(hours)
    ]


def test_fit_requires_both_hour_and_utc_date_floors():
    config = DnsBaselineConfig()
    assert fit_dns_reference([], config) is None
    assert fit_dns_reference(samples(hours=19), config) is None
    assert fit_dns_reference(samples(days=13), config) is None

    reference = fit_dns_reference(samples(), config)
    assert reference.sample_hours == 20
    assert reference.distinct_days == 14
    assert reference.median_twice == 400

    # Hours on either side of UTC midnight count as two dates.
    midnight = DnsBaselineConfig(minimum_hours=2, minimum_days=2)
    adjacent = [DnsSample(START - HOUR, 200, True), DnsSample(START, 200, True)]
    assert fit_dns_reference(adjacent, midnight).distinct_days == 2


def test_fit_freezes_first_qualified_chronological_cohort():
    config = DnsBaselineConfig()
    qualified = samples()
    rejected = [
        DnsSample(START + 2 * HOUR, 9_000, False),
        DnsSample(START + 3 * HOUR, 9_000, True, suspicious=True),
        DnsSample(START + 4 * HOUR, MAX_VALUE, True, saturated=True),
    ]
    late = DnsSample(START + 30 * DAY, 10_000, True)
    assert fit_dns_reference([*qualified[:-1], *rejected], config) is None

    reference = fit_dns_reference(reversed([*qualified, late, *rejected]), config)
    assert reference == fit_dns_reference(qualified, config)
    assert reference.training_hours == tuple(sorted(sample.hour for sample in qualified))
    assert reference.trained_until == reference.training_hours[-1]
    assert reference.algorithm == ALGORITHM_DNS == "pooled-median-dns-v1"
    assert reference.config_version == config.version
    with pytest.raises(FrozenInstanceError):
        reference.median_twice = 0


def test_findings_require_an_eligible_later_hour_strictly_above_threshold():
    config = DnsBaselineConfig()
    reference = fit_dns_reference(samples(), config)
    hour = reference.trained_until + HOUR
    assert dns_findings(DnsSample(hour, 801, True), reference, config) == [
        {
            "detector": "dns_deviation",
            "observed_queries": 801,
            "threshold_queries": 800,
            "reason_code": "dns_deviation_threshold",
        },
    ]
    assert dns_findings(DnsSample(hour, 800, True), reference, config) == []
    assert dns_findings(DnsSample(hour, 0, True), reference, config) == []
    assert dns_findings(DnsSample(hour, 801, False), reference, config) == []
    assert dns_findings(DnsSample(hour, MAX_VALUE, True, saturated=True), reference, config) == []
    assert dns_findings(DnsSample(reference.trained_until, 801, True), reference, config) == []
    assert dns_findings(DnsSample(hour, 801, True), None, config) == []
    assert dns_findings(None, reference, config) == []


def test_saturation_marker_distinguishes_clamped_counters_from_valid_aggregate_counts():
    config = DnsBaselineConfig(minimum_hours=1, minimum_days=1)
    count = MAX_VALUE + 500
    assert fit_dns_reference([DnsSample(START, count, True, saturated=True)], config) is None
    reference = fit_dns_reference([DnsSample(START, count, True)], config)
    assert reference.median_twice == 2 * count
    current = DnsSample(START + HOUR, 4 * count + 1, True)
    assert dns_findings(current, reference, config)[0]["threshold_queries"] == 4 * count


def test_unsaturated_aggregate_cannot_exceed_sum_of_unclamped_counters():
    config = DnsBaselineConfig(minimum_hours=1, minimum_days=1)
    max_unsaturated = MAX_MACS * (MAX_VALUE - 1)
    valid = DnsSample(START, max_unsaturated, True)
    assert fit_dns_reference([valid], config).median_twice == 2 * max_unsaturated

    reference = fit_dns_reference([DnsSample(START, 200, True)], config)
    assert dns_findings(replace(valid, hour=START + HOUR), reference, config)
    impossible = DnsSample(START + HOUR, max_unsaturated + 1, True)
    with pytest.raises(InvalidInput):
        fit_dns_reference([impossible], config)
    with pytest.raises(InvalidInput):
        dns_findings(impossible, reference, config)

    saturated = DnsSample(START + HOUR, MAX_MACS * MAX_VALUE, True, saturated=True)
    assert fit_dns_reference([saturated], config) is None
    assert dns_findings(saturated, reference, config) == []


@pytest.mark.parametrize("queries", [0, 199])
def test_low_median_reference_abstains_even_during_a_large_spike(queries):
    config = DnsBaselineConfig()
    reference = fit_dns_reference(samples(queries=queries), config)
    assert reference.median_twice == 2 * queries
    spike = DnsSample(reference.trained_until + HOUR, 10_000, True)
    assert dns_findings(spike, reference, config) == []


def test_fractional_median_uses_exact_floor_and_multiplier():
    config = DnsBaselineConfig(minimum_hours=2, minimum_days=1, multiplier=3)
    above_floor = [DnsSample(START, 200, True), DnsSample(START + HOUR, 201, True)]
    reference = fit_dns_reference(above_floor, config)
    assert reference.median_twice == 401
    hour = reference.trained_until + HOUR
    assert dns_findings(DnsSample(hour, 601, True), reference, config) == []
    findings = dns_findings(DnsSample(hour, 602, True), reference, config)
    assert findings[0]["threshold_queries"] == 601

    below_floor = [DnsSample(START, 199, True), DnsSample(START + HOUR, 200, True)]
    reference = fit_dns_reference(below_floor, config)
    assert reference.median_twice == 399
    assert dns_findings(DnsSample(hour, 10_000, True), reference, config) == []


def test_config_version_changes_with_policy_and_old_reference_abstains():
    config = DnsBaselineConfig()
    changed = DnsBaselineConfig(multiplier=5)
    assert config.version == DnsBaselineConfig().version
    assert config.version != changed.version
    reference = fit_dns_reference(samples(), config)
    spike = DnsSample(reference.trained_until + HOUR, 10_000, True)
    assert dns_findings(spike, reference, config)
    assert dns_findings(spike, reference, changed) == []
    assert dns_findings(spike, replace(reference, algorithm="unknown"), config) == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"minimum_hours": 0},
        {"minimum_hours": 2161},
        {"minimum_days": 91},
        {"minimum_queries": 0},
        {"minimum_queries": 2**63},
        {"multiplier": 101},
        {"multiplier": True},
        {"minimum_hours": 20.0},
    ],
)
def test_config_rejects_out_of_bounds_values(overrides):
    with pytest.raises(ValueError):
        DnsBaselineConfig(**overrides)


@pytest.mark.parametrize(
    "bad_sample",
    [
        DnsSample(START + 30 * DAY, -1, True),
        DnsSample(START + 30 * DAY + 1, 200, True),
        DnsSample(START + 30 * DAY, True, True),
        DnsSample(START + 30 * DAY, 2**63, True),
        DnsSample(START + 30 * DAY, 200, 1),
    ],
)
def test_malformed_samples_after_the_frozen_cutoff_still_raise(bad_sample):
    config = DnsBaselineConfig()
    qualified = samples()
    reference = fit_dns_reference(qualified, config)
    with pytest.raises(InvalidInput):
        fit_dns_reference([*qualified, bad_sample], config)
    with pytest.raises(InvalidInput):
        dns_findings(bad_sample, reference, config)


def test_fit_rejects_duplicate_hours_and_reads_at_most_one_over_the_bound():
    config = DnsBaselineConfig()
    qualified = samples()
    late = DnsSample(START + 30 * DAY, 200, False)
    with pytest.raises(InvalidInput):
        fit_dns_reference([*qualified, late, late], config)

    def oversized():
        for index in range(2161):
            yield DnsSample(START + index * HOUR, 200, True)
        pytest.fail("fit consumed more than 2161 samples")

    with pytest.raises(InvalidInput):
        fit_dns_reference(oversized(), config)
