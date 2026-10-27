"""Table-driven rules for the pure time-of-day baseline (tod-median-v1). UTC cohorts only."""

import dataclasses
import hashlib
import json
import random
from datetime import UTC, datetime
from types import MappingProxyType
from zoneinfo import ZoneInfo

import pytest

from vigie_pipeline.baselines import Sample
from vigie_pipeline.baselines_tod import (
    CohortAbstain,
    CohortFit,
    TodConfig,
    cohort_key,
    findings_tod,
    fit_tod,
)

MIB = 1024 * 1024
MONDAY = 20304  # epoch day of a UTC Monday (2026-10-26)
SMALL = TodConfig(min_samples_per_cohort=3, min_days_per_cohort=3)


def at(day, hour, value=10 * MIB, eligible=True, suspicious=False):
    return Sample(day * 86400 + hour * 3600, value, eligible, suspicious)


def span_days(n, first=MONDAY, weekend=False):
    out, day = [], first
    while len(out) < n:
        if ((day + 3) % 7 >= 5) == weekend:
            out.append(day)
        day += 1
    return out


def series(days, hour, value=10 * MIB, **kw):
    return [at(d, hour, value, **kw) for d in days]


def cohort(ref, weekend, hour):
    return ref.cohorts[(weekend, hour)]


def test_calendar_assumption_and_cohort_keys_at_week_boundaries():
    assert datetime.fromtimestamp(MONDAY * 86400, UTC).weekday() == 0
    table = [
        (at(MONDAY, 0), (False, 0)),
        (at(MONDAY + 4, 23), (False, 23)),  # Friday 23:00
        (at(MONDAY + 5, 0), (True, 0)),  # Saturday 00:00
        (at(MONDAY + 6, 23), (True, 23)),  # Sunday 23:00
        (at(MONDAY + 7, 0), (False, 0)),  # Monday 00:00 next week
        (at(MONDAY + 3, 12), (False, 12)),
    ]
    for sample, key in table:
        assert cohort_key(sample.hour) == key


def test_cold_start_abstains_everywhere():
    ref = fit_tod([], SMALL)
    assert len(ref.cohorts) == 48
    assert all(c == CohortAbstain("immature_samples", 0, 0) for c in ref.cohorts.values())
    out = findings_tod(at(MONDAY, 3), at(MONDAY, 2), ref, SMALL)
    assert out.candidates == () and out.abstain_reason == "immature_samples"


@pytest.mark.parametrize(
    ("n", "mature"), [(19, False), (20, True), (21, True)], ids=["min-1", "min", "min+1"]
)
def test_sample_floor_default_config_is_strict(n, mature):
    cfg = TodConfig()
    ref = fit_tod(series(span_days(n), 3), cfg)
    got = cohort(ref, False, 3)
    if mature:
        assert got == CohortFit(20 * MIB, n, n)
    else:
        assert got == CohortAbstain("immature_samples", n, n)


@pytest.mark.parametrize(
    ("n", "expected"),
    [(2, "immature_samples"), (3, "immature_days"), (4, "immature_days"), (5, None)],
)
def test_distinct_day_floor_is_strict_when_days_exceed_samples_floor(n, expected):
    cfg = TodConfig(min_samples_per_cohort=3, min_days_per_cohort=5)
    got = cohort(fit_tod(series(span_days(n), 3), cfg), False, 3)
    if expected is None:
        assert isinstance(got, CohortFit)
    else:
        assert got == CohortAbstain(expected, n, n)


def test_missing_is_not_zero():
    base = series(span_days(3), 3)
    extra = [at(d, 3, 0, eligible=False) for d in span_days(10, MONDAY + 14)]
    assert fit_tod(base + extra, SMALL) == fit_tod(base, SMALL)
    assert cohort(fit_tod(base + extra, SMALL), False, 3) == CohortFit(20 * MIB, 3, 3)
    only_missing = fit_tod(extra, SMALL)
    assert cohort(only_missing, False, 3) == CohortAbstain("immature_samples", 0, 0)


def test_suspicious_and_large_samples_are_excluded_from_fit():
    base = series(span_days(3), 3)
    dirty = [
        at(MONDAY + 14, 3, 900 * MIB, suspicious=True),
        at(MONDAY + 15, 3, 2000 * MIB),  # at/above the fixed large-upload line
        at(MONDAY + 16, 3, 1024 * MIB),
    ]
    assert fit_tod(base + dirty, SMALL) == fit_tod(base, SMALL)
    near = at(MONDAY + 17, 3, 1024 * MIB - 1)
    assert cohort(fit_tod(base + [near], SMALL), False, 3).samples == 4


def test_poisoned_cohort_flips_from_firing_to_abstaining_only_via_maturity_rule():
    prev, cur = at(MONDAY + 14, 2, 130 * MIB), at(MONDAY + 14, 3, 130 * MIB)
    clean = series(span_days(3), 2, 30 * MIB) + series(span_days(3), 3, 30 * MIB)
    assert len(findings_tod(cur, prev, fit_tod(clean, SMALL), SMALL).candidates) == 1
    poisoned = [dataclasses.replace(s, suspicious=(s.hour == clean[5].hour)) for s in clean]
    out = findings_tod(cur, prev, fit_tod(poisoned, SMALL), SMALL)
    assert out.candidates == () and out.abstain_reason == "immature_samples"
    # an extra clean sample restores maturity, so the flip is the documented rule and nothing else
    healed = poisoned + [at(MONDAY + 3, 3, 30 * MIB)]
    healed = [s for s in healed if s.hour != clean[5].hour] + [at(MONDAY + 4, 3, 30 * MIB)]
    assert len(findings_tod(cur, prev, fit_tod(healed, SMALL), SMALL).candidates) == 1


def test_weekday_and_weekend_are_separate_cohorts():
    samples = series(span_days(3), 10, 10 * MIB) + series(span_days(3, weekend=True), 10, 100 * MIB)
    ref = fit_tod(samples, SMALL)
    assert cohort(ref, False, 10) == CohortFit(20 * MIB, 3, 3)
    assert cohort(ref, True, 10) == CohortFit(200 * MIB, 3, 3)
    assert cohort(ref, False, 11).samples == 0


@pytest.mark.parametrize(
    ("values", "twice"),
    [((9, 1, 4), 8), ((4, 9, 2, 1), 6), ((7, 7, 7), 14), ((5, 1, 9, 3, 8), 10)],
)
def test_median_twice_is_exact_for_odd_even_and_unsorted_values(values, twice):
    samples = [at(d, 5, v) for d, v in zip(span_days(len(values)), values, strict=True)]
    assert cohort(fit_tod(samples, SMALL), False, 5).median_twice == twice


def test_order_independence():
    rng = random.Random(7)  # noqa: S311 - seeded test data
    samples = [at(d, h, rng.randrange(1, 90) * MIB) for d in span_days(8) for h in (0, 3, 23)]
    expected = fit_tod(samples, SMALL)
    for _ in range(5):
        shuffled = list(samples)
        rng.shuffle(shuffled)
        assert fit_tod(shuffled, SMALL) == expected


def test_config_version_depends_on_algorithm_and_every_parameter():
    base = TodConfig()
    assert base.version == TodConfig().version and len(base.version) == 64
    for field in dataclasses.fields(TodConfig):
        changed = dataclasses.replace(base, **{field.name: getattr(base, field.name) + 1})
        assert changed.version != base.version, field.name
    payload = {"algorithm": "tod-median-v1", **dataclasses.asdict(base)}
    expected = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    assert base.version == expected


@pytest.mark.parametrize(
    "kw",
    [
        {"min_samples_per_cohort": 0},
        {"min_days_per_cohort": 0},
        {"multiplier": 0},
        {"minimum_bytes": 0},
        {"large_upload_bytes": 0},
        {"min_samples_per_cohort": 10_001},
    ],
)
def test_config_bounds(kw):
    with pytest.raises(ValueError):
        TodConfig(**kw)


def test_invalid_input_is_rejected():
    for bad in (
        [at(MONDAY, 3), at(MONDAY, 3)],
        [Sample(MONDAY * 86400 + 5, 1, True)],
        [at(MONDAY, 3, -1)],
    ):
        with pytest.raises(ValueError):
            fit_tod(bad, SMALL)


def test_inputs_not_mutated_and_outputs_frozen():
    samples = series(span_days(3), 3)
    snapshot = list(samples)
    ref = fit_tod(samples, SMALL)
    assert samples == snapshot
    assert isinstance(ref.cohorts, MappingProxyType)
    with pytest.raises(TypeError):
        ref.cohorts[(False, 3)] = None
    with pytest.raises(dataclasses.FrozenInstanceError):
        ref.algorithm = "x"
    with pytest.raises(dataclasses.FrozenInstanceError):
        cohort(ref, False, 3).samples = 0
    out = findings_tod(at(MONDAY + 14, 3, 99 * MIB), at(MONDAY + 14, 2, 99 * MIB), ref, SMALL)
    assert isinstance(out.candidates, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        out.abstain_reason = "x"
    assert ref.algorithm == "tod-median-v1" and ref.config_version == SMALL.version


def history(value=30 * MIB, hours=(1, 2, 3)):
    return [s for h in hours for s in series(span_days(5), h, value)]


@pytest.mark.parametrize(
    ("prev", "cur", "gap_hours", "fires"),
    [
        (130, 130, 1, True),
        (121, 121, 1, True),
        (120, 130, 1, False),  # equality with the 120 MiB threshold does not fire
        (130, 120, 1, False),
        (130, 130, 2, False),  # previous hour is not adjacent
    ],
)
def test_mature_cohort_detects_sustained_deviation(prev, cur, gap_hours, fires):
    ref = fit_tod(history(), SMALL)
    c = at(MONDAY + 15, 3, cur * MIB)
    p = (
        at(MONDAY + 15, 3 - gap_hours, prev * MIB)
        if gap_hours == 1
        else at(MONDAY + 15, 1, prev * MIB)
    )
    out = findings_tod(c, p, ref, SMALL)
    if not fires:
        assert out.candidates == () and out.abstain_reason is None
        return
    (cand,) = out.candidates
    assert cand.detector == "upload_deviation"
    assert cand.cohort == (False, 3)
    assert cand.observed_bytes == cur * MIB
    assert cand.threshold_bytes == 120 * MIB
    assert cand.reason_code == "two_qualified_upload_hours_in_cohort"
    assert out.abstain_reason is None


@pytest.mark.parametrize(("multiplier", "threshold"), [(2, 60), (5, 150), (8, 240)])
def test_multiplier_scales_threshold(multiplier, threshold):
    cfg = dataclasses.replace(SMALL, multiplier=multiplier)
    ref = fit_tod(history(), cfg)
    p, c = at(MONDAY + 15, 2, (threshold + 1) * MIB), at(MONDAY + 15, 3, (threshold + 1) * MIB)
    (cand,) = findings_tod(c, p, ref, cfg).candidates
    assert cand.threshold_bytes == threshold * MIB
    c_eq = at(MONDAY + 15, 3, threshold * MIB)
    assert findings_tod(c_eq, p, ref, cfg).candidates == ()


def test_threshold_floor_applies_below_minimum_bytes():
    ref = fit_tod(history(5 * MIB), SMALL)  # 4 * 5 MiB = 20 MiB < 50 MiB floor
    p, c = at(MONDAY + 15, 2, 51 * MIB), at(MONDAY + 15, 3, 51 * MIB)
    (cand,) = findings_tod(c, p, ref, SMALL).candidates
    assert cand.threshold_bytes == 50 * MIB
    assert findings_tod(c, at(MONDAY + 15, 2, 50 * MIB), ref, SMALL).candidates == ()


def test_benign_nightly_backup_does_not_fire_but_same_traffic_elsewhere_does():
    backup = history(500 * MIB, hours=(2, 3))  # high every night in both hours
    ref = fit_tod(backup, SMALL)
    p, c = at(MONDAY + 15, 2, 500 * MIB), at(MONDAY + 15, 3, 500 * MIB)
    out = findings_tod(c, p, ref, SMALL)
    assert out.candidates == () and out.abstain_reason is None
    quiet = fit_tod(history(30 * MIB, hours=(2, 3)), SMALL)
    assert len(findings_tod(c, p, quiet, SMALL).candidates) == 1


def test_previous_hour_must_be_mature_eligible_and_exceed_its_own_cohort():
    ref = fit_tod(series(span_days(5), 3, 30 * MIB), SMALL)  # hour 2 has no history
    c, p = at(MONDAY + 15, 3, 130 * MIB), at(MONDAY + 15, 2, 130 * MIB)
    assert findings_tod(c, p, ref, SMALL).candidates == ()
    ref = fit_tod(history(), SMALL)
    assert findings_tod(c, dataclasses.replace(p, eligible=False), ref, SMALL).candidates == ()
    assert findings_tod(c, None, ref, SMALL).candidates == ()


def test_abstain_reasons_for_unusable_current_or_mismatched_reference():
    ref = fit_tod(history(), SMALL)
    c = at(MONDAY + 15, 3, 130 * MIB)
    assert findings_tod(None, None, ref, SMALL).abstain_reason == "current_unavailable"
    ineligible = dataclasses.replace(c, eligible=False)
    assert findings_tod(ineligible, None, ref, SMALL).abstain_reason == "current_unavailable"
    other = dataclasses.replace(SMALL, multiplier=5)
    assert findings_tod(c, None, ref, other).abstain_reason == "config_mismatch"


def test_historical_backfill_fits_by_own_cohort_regardless_of_age():
    old = 14_000  # shift by whole weeks so weekday alignment is preserved
    shift = 7 * ((MONDAY - old) // 7)
    recent = history()
    ancient = [dataclasses.replace(s, hour=s.hour - shift * 86400) for s in recent]
    assert fit_tod(ancient, SMALL).cohorts == fit_tod(recent, SMALL).cohorts
    assert cohort(fit_tod(ancient, SMALL), False, 3) == CohortFit(60 * MIB, 5, 5)


def test_utc_cohorts_ignore_local_dst_shift():
    ny = ZoneInfo("America/New_York")
    fall_back = datetime(2026, 11, 1, 5, 0, tzinfo=UTC)  # 01:00 EDT, then 01:00 EST
    hours = [int(fall_back.timestamp()) + i * 3600 for i in range(3)]
    local = [datetime.fromtimestamp(h, ny) for h in hours]
    assert (local[0].hour, local[1].hour) == (1, 1) and local[0].fold != local[1].fold
    assert [cohort_key(h) for h in hours] == [(True, 5), (True, 6), (True, 7)]


def mature_keys(ref):
    return {k for k, v in ref.cohorts.items() if isinstance(v, CohortFit)}


@pytest.mark.parametrize("seed", range(8))
def test_property_determinism_and_monotonic_maturity(seed):
    rng = random.Random(seed)  # noqa: S311 - seeded test data
    cells = [(d, h) for d in range(MONDAY, MONDAY + 40) for h in (0, 5, 23)]
    rng.shuffle(cells)
    samples = [
        at(
            d,
            h,
            rng.randrange(0, 80) * MIB,
            eligible=rng.random() > 0.2,
            suspicious=rng.random() < 0.1,
        )
        for d, h in cells[:70]
    ]
    ref = fit_tod(samples, SMALL)
    assert fit_tod(list(reversed(samples)), SMALL) == ref
    for d, h in cells[70:]:
        before = fit_tod(samples, SMALL)
        samples = [*samples, at(d, h, rng.randrange(0, 80) * MIB)]
        after = fit_tod(samples, SMALL)
        assert mature_keys(before) <= mature_keys(after)
        for key in mature_keys(before):
            assert after.cohorts[key].samples >= before.cohorts[key].samples
