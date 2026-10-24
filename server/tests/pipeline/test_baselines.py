"""Independent worked thresholds: 20 hourly samples across 14 days at exactly ten MiB."""

import pytest

from vigie_pipeline.baselines import BaselineConfig, Sample, findings, fit_reference

MIB = 1024 * 1024
START = 1_791_997_200


def samples(n=20, days=14):
    # First fourteen points occupy distinct days; remaining six are separate hours.
    return [
        Sample(START + (i % days) * 86400 + (i // days) * 3600, 10 * MIB, True) for i in range(n)
    ]


def test_coldstart_exact_19_20_samples_and_13_14_days():
    cfg = BaselineConfig()
    assert fit_reference(samples(19), cfg) is None
    assert fit_reference(samples(20, 13), cfg) is None
    reference = fit_reference(samples(), cfg)
    assert reference["median_twice"] == 20 * MIB
    assert reference["sample_hours"] == 20
    assert reference["distinct_days"] == 14


def test_strict_50_51_two_hour_threshold_and_missing_break():
    cfg = BaselineConfig()
    reference = fit_reference(samples(), cfg)
    a = Sample(START + 20 * 86400, 51 * MIB, True)
    b = Sample(a.hour + 3600, 51 * MIB, True)
    assert [r["detector"] for r in findings(b, a, reference, cfg)] == ["upload_deviation"]
    assert findings(Sample(b.hour, 50 * MIB, True), a, reference, cfg) == []
    assert findings(b, None, reference, cfg) == []
    assert findings(b, Sample(a.hour - 3600, 51 * MIB, True), reference, cfg) == []
    assert findings(b, Sample(a.hour, 51 * MIB, False), reference, cfg) == []
    assert findings(b, a, None, cfg) == []


def test_fixed_large_upload_works_during_coldstart_only_with_good_coverage():
    cfg = BaselineConfig()
    assert (
        findings(Sample(START, 1024 * MIB, True), None, None, cfg)[0]["detector"] == "large_upload"
    )
    assert findings(Sample(START, 1024 * MIB, False), None, None, cfg) == []


def test_suspicious_and_bad_quality_samples_do_not_train():
    cfg = BaselineConfig()
    assert (
        fit_reference([*samples(19), Sample(START + 30 * 86400, 10 * MIB, True, True)], cfg) is None
    )
    assert fit_reference([*samples(19), Sample(START + 30 * 86400, 10 * MIB, False)], cfg) is None
    with pytest.raises(ValueError):
        fit_reference([*samples(), samples()[0]], cfg)
