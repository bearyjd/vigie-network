"""Table-driven rules for the pure time-of-day baseline (tod-median-v1). UTC cohorts only."""

import dataclasses
import hashlib
import json
import math
import random
from datetime import UTC, datetime
from types import MappingProxyType
from zoneinfo import ZoneInfo

import pytest

from vigie_pipeline.baselines import BaselineConfig, Sample, findings
from vigie_pipeline.baselines_tod import (
    MAX_TRAINING_HOURS,
    CohortAbstain,
    CohortFit,
    TodConfig,
    cohort_key,
    findings_tod,
    fit_tod,
)

MIB = 1024 * 1024
MONDAY = 20304  # epoch day of a UTC Monday (2026-10-26)
ALLOWED_BUCKETS = (1, 2, 3, 4, 6, 8, 12, 24)
SMALL = TodConfig(min_samples_per_cohort=3, min_days_per_cohort=3, bucket_hours=1)
LATE = (MONDAY + 15) * 86400  # every evaluated hour in these tests is on or after this


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


def fit(samples, cfg=SMALL, until=None):
    "Freeze the baseline at the last supplied hour unless told otherwise."
    if until is None:
        until = max((s.hour for s in samples), default=0)
    return fit_tod(samples, cfg, until)


def cohort(ref, weekend, hour):
    return ref.cohorts[(weekend, hour)]


def describe(c):
    kind = c.reason if isinstance(c, CohortAbstain) else "fit"
    return kind, c.samples, c.days


def test_calendar_assumption_and_cohort_keys_at_week_boundaries():
    assert datetime.fromtimestamp(MONDAY * 86400, UTC).weekday() == 0
    table = [
        (at(MONDAY, 0), 1, (False, 0)),
        (at(MONDAY + 4, 23), 1, (False, 23)),  # Friday 23:00
        (at(MONDAY + 5, 0), 1, (True, 0)),  # Saturday 00:00
        (at(MONDAY + 6, 23), 1, (True, 23)),  # Sunday 23:00
        (at(MONDAY + 7, 0), 1, (False, 0)),  # Monday 00:00 next week
        (at(MONDAY + 4, 23), 4, (False, 5)),
        (at(MONDAY + 5, 0), 4, (True, 0)),
        (at(MONDAY + 6, 23), 4, (True, 5)),
        (at(MONDAY + 7, 0), 4, (False, 0)),
    ]
    for sample, bucket, key in table:
        assert cohort_key(sample.hour, bucket) == key


@pytest.mark.parametrize("bucket", ALLOWED_BUCKETS)
def test_every_allowed_bucket_size_partitions_the_day(bucket):
    cfg = dataclasses.replace(SMALL, bucket_hours=bucket)
    ref = fit([], cfg)
    assert len(ref.cohorts) == 2 * 24 // bucket
    assert {k[1] for k in ref.cohorts} == set(range(24 // bucket))
    for hour in range(24):
        assert cohort_key(at(MONDAY, hour).hour, bucket) == (False, hour // bucket)
    got = fit([at(MONDAY, 23), at(MONDAY + 5, 0)], cfg)
    assert cohort(got, False, 23 // bucket).samples == 1
    assert cohort(got, True, 0).samples == 1


@pytest.mark.parametrize("bad", [0, -4, 5, 7, 9, 10, 16, 25, True, 2.0, "4"])
def test_invalid_bucket_size_is_rejected(bad):
    with pytest.raises(ValueError):
        TodConfig(bucket_hours=bad)


def test_cold_start_abstains_everywhere():
    ref = fit([], SMALL)
    assert len(ref.cohorts) == 48
    assert all(describe(c) == ("immature_samples", 0, 0) for c in ref.cohorts.values())
    assert (ref.trained_until, ref.training_hours) == (0, 0)
    out = findings_tod(at(MONDAY, 3), at(MONDAY, 2), ref, SMALL)
    assert out.candidates == () and out.abstain_reason == "immature_samples"


def counted(days, counts):
    return [at(d, h) for d, n in zip(days, counts, strict=True) for h in range(n)]


WEEKDAYS7, WEEKDAYS6 = span_days(7), span_days(6)
WEEKENDS4, WEEKENDS3 = span_days(8, weekend=True), span_days(6, weekend=True)


@pytest.mark.parametrize(
    ("days", "counts", "weekend", "expected"),
    [
        (WEEKDAYS7, [3, 3, 3, 3, 3, 3, 2], False, ("fit", 20, 7)),  # exactly both floors
        (WEEKDAYS7, [3, 3, 3, 3, 3, 3, 1], False, ("immature_samples", 19, 7)),  # samples min-1
        (WEEKDAYS6, [4, 4, 4, 4, 4, 4], False, ("immature_days", 24, 6)),  # days min-1
        (WEEKDAYS7, [1] * 7, False, ("immature_samples", 7, 7)),
        (WEEKENDS4, [3] * 8, True, ("fit", 24, 8)),  # four weekends mature
        (WEEKENDS3, [4] * 6, True, ("immature_days", 24, 6)),  # three weekends do not
    ],
)
def test_default_config_maturity_floors_are_strict(days, counts, weekend, expected):
    got = cohort(fit(counted(days, counts), TodConfig()), weekend, 0)
    assert describe(got) == expected


@pytest.mark.parametrize(
    ("n", "expected"),
    [(2, "immature_samples"), (3, "immature_days"), (4, "immature_days"), (5, None)],
)
def test_distinct_day_floor_is_strict_when_days_exceed_samples_floor(n, expected):
    cfg = TodConfig(min_samples_per_cohort=3, min_days_per_cohort=5, bucket_hours=1)
    got = cohort(fit(series(span_days(n), 3), cfg), False, 3)
    assert describe(got) == (expected or "fit", n, n)


def test_missing_is_not_zero():
    base = series(span_days(3), 3)
    extra = [at(d, 3, 0, eligible=False) for d in span_days(10, MONDAY + 14)]
    until = (MONDAY + 30) * 86400
    assert fit(base + extra, SMALL, until) == fit(base, SMALL, until)
    assert describe(cohort(fit(base + extra), False, 3)) == ("fit", 3, 3)
    only_missing = fit(extra)
    assert describe(cohort(only_missing, False, 3)) == ("immature_samples", 0, 0)
    assert only_missing.training_hours == 0


def test_suspicious_and_large_samples_are_excluded_from_fit():
    base = series(span_days(3), 3)
    dirty = [
        at(MONDAY + 14, 3, 900 * MIB, suspicious=True),
        at(MONDAY + 15, 3, 2000 * MIB),  # above the fixed large-upload line
        at(MONDAY + 16, 3, 1024 * MIB),  # exactly at it
    ]
    until = (MONDAY + 30) * 86400
    assert fit(base + dirty, SMALL, until) == fit(base, SMALL, until)
    near = at(MONDAY + 17, 3, 1024 * MIB - 1)
    assert cohort(fit(base + [near]), False, 3).samples == 4


def test_poisoned_cohort_flips_from_firing_to_abstaining_only_via_maturity_rule():
    prev, cur = at(MONDAY + 14, 2, 130 * MIB), at(MONDAY + 14, 3, 130 * MIB)
    clean = series(span_days(3), 2, 30 * MIB) + series(span_days(3), 3, 30 * MIB)
    assert len(findings_tod(cur, prev, fit(clean), SMALL).candidates) == 1
    victim = clean[5].hour
    poisoned = [dataclasses.replace(s, suspicious=(s.hour == victim)) for s in clean]
    out = findings_tod(cur, prev, fit(poisoned), SMALL)
    assert out.candidates == () and out.abstain_reason == "immature_samples"
    healed = [s for s in poisoned if s.hour != victim] + [at(MONDAY + 4, 3, 30 * MIB)]
    assert len(findings_tod(cur, prev, fit(healed), SMALL).candidates) == 1


def test_weekday_and_weekend_are_separate_cohorts():
    samples = series(span_days(3), 10, 10 * MIB) + series(span_days(3, weekend=True), 10, 100 * MIB)
    ref = fit(samples)
    assert cohort(ref, False, 10).median_twice == 20 * MIB
    assert cohort(ref, True, 10).median_twice == 200 * MIB
    assert cohort(ref, False, 11).samples == 0


@pytest.mark.parametrize(
    ("values", "twice"),
    [((9, 1, 4), 8), ((4, 9, 2, 1), 6), ((7, 7, 7), 14), ((5, 1, 9, 3, 8), 10)],
)
def test_median_twice_is_exact_for_odd_even_and_unsorted_values(values, twice):
    samples = [at(d, 5, v) for d, v in zip(span_days(len(values)), values, strict=True)]
    assert cohort(fit(samples), False, 5).median_twice == twice


def test_order_independence():
    rng = random.Random(7)  # noqa: S311 - seeded test data
    samples = [at(d, h, rng.randrange(1, 90) * MIB) for d in span_days(8) for h in (0, 3, 23)]
    expected = fit(samples)
    for _ in range(5):
        shuffled = list(samples)
        rng.shuffle(shuffled)
        assert fit(shuffled) == expected


def test_config_version_depends_on_algorithm_and_every_parameter():
    base = TodConfig()
    assert base.version == TodConfig().version and len(base.version) == 64
    changed_values = {
        "min_samples_per_cohort": 21,
        "min_days_per_cohort": 8,
        "minimum_bytes": 51 * MIB,
        "multiplier": 5,
        "large_upload_bytes": 1025 * MIB,
        "bucket_hours": 6,
    }
    assert set(changed_values) == {f.name for f in dataclasses.fields(TodConfig)}
    for name, value in changed_values.items():
        assert dataclasses.replace(base, **{name: value}).version != base.version, name
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


@pytest.mark.parametrize(
    "bad",
    [
        [at(MONDAY, 3), at(MONDAY, 3)],
        [Sample(MONDAY * 86400 + 5, 1, True)],
        [at(MONDAY, 3, -1)],
        [Sample(True, 1, True)],
        [Sample(float(MONDAY * 86400), 1, True)],
        [Sample(MONDAY * 86400, True, True)],
        [Sample(MONDAY * 86400, 1.5, True)],
        [Sample(MONDAY * 86400, math.nan, True)],
        [Sample(MONDAY * 86400, math.inf, True)],
        [Sample(MONDAY * 86400, 2**53 + 1, True)],
        [Sample(MONDAY * 86400, math.nan, False)],
        [Sample((2**53 // 3600 + 1) * 3600, 1, True)],
        [Sample(-3600, 1, True)],
    ],
    ids=lambda s: None,
)
def test_invalid_fit_input_is_rejected(bad):
    with pytest.raises(ValueError):
        fit_tod(bad, SMALL, 2**52 // 3600 * 3600)


@pytest.mark.parametrize("bad", [5, -3600, True, 3600.0, 2**53 + 3600, None])
def test_invalid_trained_until_is_rejected(bad):
    with pytest.raises(ValueError):
        fit_tod([], SMALL, bad)


def test_training_input_is_capped_at_26_weeks_of_hours():
    assert MAX_TRAINING_HOURS == 24 * 7 * 26
    start = MONDAY * 86400
    rows = [Sample(start + i * 3600, 1, True) for i in range(MAX_TRAINING_HOURS + 1)]
    until = rows[-1].hour
    assert fit_tod(rows[:-1], SMALL, until).training_hours == MAX_TRAINING_HOURS
    with pytest.raises(ValueError, match="too many"):
        fit_tod(rows, SMALL, until)


def test_trained_until_is_recorded_and_later_samples_are_ignored():
    history = series(span_days(5), 3)
    until = history[-1].hour
    future = series(span_days(5, MONDAY + 14), 3, 500 * MIB) + [at(MONDAY + 14, 4, 1)]
    ref = fit_tod(history + future, SMALL, until)
    assert ref == fit_tod(history, SMALL, until)
    assert (ref.trained_until, ref.training_hours) == (until, 5)
    assert cohort(ref, False, 3).last_trained_hour == until
    assert cohort(ref, False, 3).samples == 5
    assert cohort(ref, False, 4).samples == 0


def test_inputs_not_mutated_and_outputs_frozen():
    samples = series(span_days(3), 3)
    snapshot = list(samples)
    ref = fit(samples)
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
    ref = fit(history())
    c = at(MONDAY + 15, 3, cur * MIB)
    p = at(MONDAY + 15, 3 - gap_hours, prev * MIB)
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
    ref = fit(history(), cfg)
    p, c = at(MONDAY + 15, 2, (threshold + 1) * MIB), at(MONDAY + 15, 3, (threshold + 1) * MIB)
    (cand,) = findings_tod(c, p, ref, cfg).candidates
    assert cand.threshold_bytes == threshold * MIB
    c_eq = at(MONDAY + 15, 3, threshold * MIB)
    assert findings_tod(c_eq, p, ref, cfg).candidates == ()


def test_threshold_floor_applies_below_minimum_bytes():
    ref = fit(history(5 * MIB))  # 4 * 5 MiB = 20 MiB < 50 MiB floor
    p, c = at(MONDAY + 15, 2, 51 * MIB), at(MONDAY + 15, 3, 51 * MIB)
    (cand,) = findings_tod(c, p, ref, SMALL).candidates
    assert cand.threshold_bytes == 50 * MIB
    assert findings_tod(c, at(MONDAY + 15, 2, 50 * MIB), ref, SMALL).candidates == ()


def test_benign_nightly_backup_does_not_fire_but_same_traffic_elsewhere_does():
    ref = fit(history(500 * MIB, hours=(2, 3)))  # high every night in both hours
    p, c = at(MONDAY + 15, 2, 500 * MIB), at(MONDAY + 15, 3, 500 * MIB)
    out = findings_tod(c, p, ref, SMALL)
    assert out.candidates == () and out.abstain_reason is None
    quiet = fit(history(30 * MIB, hours=(2, 3)))
    assert len(findings_tod(c, p, quiet, SMALL).candidates) == 1


def window_history(entries):
    "entries: (weekend, hour, value_mib) -> three days of that cohort at that value."
    return [
        s
        for weekend, hour, mib in entries
        for s in series(span_days(3, weekend=weekend), hour, mib * MIB)
    ]


@pytest.mark.parametrize(
    ("prev_day", "prev_key", "cur_key"),
    [
        (MONDAY + 14, (False, 23), (False, 0)),  # Monday 23:00 -> Tuesday 00:00
        (MONDAY + 18, (False, 23), (True, 0)),  # Friday 23:00 -> Saturday 00:00
        (MONDAY + 20, (True, 23), (False, 0)),  # Sunday 23:00 -> Monday 00:00
    ],
)
@pytest.mark.parametrize(
    ("prev_line", "cur_line", "prev_obs", "cur_obs", "fires"),
    [
        (100, 30, 130, 130, False),  # previous line 400 MiB: only the wrong cohort would fire
        (30, 100, 130, 500, True),  # current line 400 MiB, previous line 120 MiB
        (30, 100, 130, 399, False),
    ],
)
def test_each_hour_is_judged_against_its_own_cohort(
    prev_day, prev_key, cur_key, prev_line, cur_line, prev_obs, cur_obs, fires
):
    ref = fit(
        window_history([(*prev_key, prev_line), (*cur_key, cur_line)]),
    )
    p = at(prev_day, 23, prev_obs * MIB)
    c = at(prev_day + 1, 0, cur_obs * MIB)
    assert (cohort_key(p.hour, 1), cohort_key(c.hour, 1)) == (prev_key, cur_key)
    out = findings_tod(c, p, ref, SMALL)
    assert [x.cohort for x in out.candidates] == ([cur_key] if fires else [])
    assert out.abstain_reason is None


@pytest.mark.parametrize(
    ("cfg", "weekdays", "weekends", "reason", "fires"),
    [
        (SMALL, 3, 3, None, True),  # both cohorts mature
        (SMALL, 3, 2, "previous_immature_samples", False),
        (TodConfig(3, 5, bucket_hours=1), 5, 3, "previous_immature_days", False),
    ],
)
def test_immature_previous_cohort_surfaces_as_a_reason(cfg, weekdays, weekends, reason, fires):
    "Sunday 23:00 (weekend cohort) -> Monday 00:00 (weekday cohort, mature in every row)."
    ref = fit(
        series(span_days(weekdays), 0, 30 * MIB)
        + series(span_days(weekends, weekend=True), 23, 30 * MIB),
        cfg,
    )
    c, p = at(MONDAY + 21, 0, 130 * MIB), at(MONDAY + 20, 23, 130 * MIB)
    assert (cohort_key(p.hour, 1), cohort_key(c.hour, 1)) == ((True, 23), (False, 0))
    out = findings_tod(c, p, ref, cfg)
    assert len(out.candidates) == fires
    assert out.abstain_reason == reason


def test_immature_current_cohort_reports_its_own_reason_first():
    ref = fit(window_history([(True, 23, 30)]))  # Monday 00:00 cohort has no history
    c, p = at(MONDAY + 21, 0, 130 * MIB), at(MONDAY + 20, 23, 130 * MIB)
    assert findings_tod(c, p, ref, SMALL).abstain_reason == "immature_samples"


def test_unusable_previous_hour_is_not_an_abstain():
    ref = fit(history())
    c = at(MONDAY + 15, 3, 130 * MIB)
    for p in (None, at(MONDAY + 15, 2, 130 * MIB, eligible=False), at(MONDAY + 15, 1, 130 * MIB)):
        out = findings_tod(c, p, ref, SMALL)
        assert out.candidates == () and out.abstain_reason is None


def test_abstain_reasons_for_unusable_current_or_mismatched_reference():
    ref = fit(history())
    c = at(MONDAY + 15, 3, 130 * MIB)
    assert findings_tod(None, None, ref, SMALL).abstain_reason == "current_unavailable"
    ineligible = dataclasses.replace(c, eligible=False)
    assert findings_tod(ineligible, None, ref, SMALL).abstain_reason == "current_unavailable"
    other = dataclasses.replace(SMALL, multiplier=5)
    assert findings_tod(c, None, ref, other).abstain_reason == "config_mismatch"


def test_findings_validate_their_inputs():
    ref = fit(history())
    good = at(MONDAY + 15, 3, 130 * MIB)
    for bad in (
        Sample(good.hour + 1, 1, True),
        Sample(True, 1, True),
        Sample(good.hour, math.nan, True),
        Sample(good.hour, 2.5, True),
        Sample(good.hour, 2**53 + 1, True),
        Sample(good.hour, -1, True),
    ):
        with pytest.raises(ValueError):
            findings_tod(bad, None, ref, SMALL)
        with pytest.raises(ValueError):
            findings_tod(good, bad, ref, SMALL)
    with pytest.raises(ValueError):
        findings_tod(good, None, dataclasses.replace(ref, algorithm="pooled-median-v1"), SMALL)


def test_reference_that_includes_the_evaluated_hours_cannot_produce_a_finding():
    clean = history()
    pair = [at(MONDAY + 15, 2, 130 * MIB), at(MONDAY + 15, 3, 130 * MIB)]
    p, c = pair
    ref = fit(clean)
    assert len(findings_tod(c, p, ref, SMALL).candidates) == 1
    # fit through (and beyond) the evaluated hours: scoring them is retroactive
    for until in (c.hour, c.hour + 5 * 86400):
        leaky = fit(clean + pair + [at(MONDAY + 16, 3, 130 * MIB)], SMALL, until)
        out = findings_tod(c, p, leaky, SMALL)
        assert out.candidates == () and out.abstain_reason == "leaks_evaluated_hours"


@pytest.mark.parametrize("which", ["current", "previous"])
def test_trained_until_boundary_is_strictly_after(which):
    clean = history()
    p, c = at(MONDAY + 15, 2, 130 * MIB), at(MONDAY + 15, 3, 130 * MIB)
    edge = c.hour if which == "current" else p.hour
    out = findings_tod(c, p, fit(clean, SMALL, edge), SMALL)
    assert out.candidates == () and out.abstain_reason == "leaks_evaluated_hours"
    assert len(findings_tod(c, p, fit(clean, SMALL, p.hour - 3600), SMALL).candidates) == 1


@pytest.mark.parametrize("offset", [0, 3600])
def test_leak_reason_outranks_immaturity_at_the_window_edge(offset):
    p, c = at(MONDAY + 15, 2, 130 * MIB), at(MONDAY + 15, 3, 130 * MIB)
    ref = fit_tod([], SMALL, p.hour + offset)  # edge is the previous (0) or current (3600) hour
    out = findings_tod(c, p, ref, SMALL)
    assert out.candidates == () and out.abstain_reason == "leaks_evaluated_hours"
    alone = findings_tod(c, None, fit_tod([], SMALL, c.hour), SMALL)
    assert alone.abstain_reason == "leaks_evaluated_hours"
    clear = fit_tod([], SMALL, p.hour - 3600)
    assert findings_tod(c, p, clear, SMALL).abstain_reason == "immature_samples"


@pytest.mark.parametrize("which", ["current", "previous"])
def test_cohort_provenance_must_also_precede_the_scored_hours(which):
    p, c = at(MONDAY + 15, 2, 130 * MIB), at(MONDAY + 15, 3, 130 * MIB)
    ref = fit(history())
    scored = c if which == "current" else p
    key = cohort_key(scored.hour, 1)
    tainted = dataclasses.replace(cohort(ref, *key), last_trained_hour=scored.hour)
    forged = dataclasses.replace(ref, cohorts=MappingProxyType({**ref.cohorts, key: tainted}))
    out = findings_tod(c, p, forged, SMALL)
    assert out.candidates == () and out.abstain_reason == "leaks_evaluated_hours"
    assert len(findings_tod(c, p, ref, SMALL).candidates) == 1


def test_gradual_drift_is_caught_only_by_a_frozen_baseline():
    cfg = TodConfig(20, 7, bucket_hours=1)
    clean_days = span_days(20)
    attack_days = span_days(20, clean_days[-1] + 1)
    clean = [s for h in (2, 3) for s in series(clean_days, h, 30 * MIB)]
    attack = [s for h in (2, 3) for s in series(attack_days, h, 200 * MIB)]
    frozen = fit_tod(clean, cfg, clean[-1].hour)
    day = attack_days[0]
    p, c = at(day, 2, 200 * MIB), at(day, 3, 200 * MIB)
    (cand,) = findings_tod(c, p, frozen, cfg).candidates
    assert (cand.cohort, cand.threshold_bytes) == ((False, 3), 120 * MIB)
    # a baseline that keeps learning the attack either leaks or normalises it
    refit = fit_tod(clean + attack, cfg, attack[-1].hour)
    assert cohort(refit, False, 3).median_twice == 230 * MIB  # threshold 460 MiB
    assert findings_tod(c, p, refit, cfg).abstain_reason == "leaks_evaluated_hours"


def test_freeze_the_same_reference_scores_identically_after_future_history_appears():
    clean = history()
    until = max(s.hour for s in clean)
    pair = (at(MONDAY + 15, 3, 130 * MIB), at(MONDAY + 15, 2, 130 * MIB))
    before = fit_tod(clean, SMALL, until)
    future = series(span_days(10, MONDAY + 16), 3, 900 * MIB) + [pair[0]]
    after = fit_tod([*clean, *future], SMALL, until)
    assert after == before
    assert findings_tod(*pair, after, SMALL) == findings_tod(*pair, before, SMALL)
    assert len(findings_tod(*pair, after, SMALL).candidates) == 1
    # only an explicit re-freeze (a caller decision) redefines normality
    moved = fit_tod([*clean, *future], SMALL, max(s.hour for s in future))
    assert cohort(moved, False, 3) != cohort(before, False, 3)


@pytest.mark.parametrize(
    "ref_samples",
    [[], series(span_days(1), 3), history()],
    ids=["cold-start", "immature-cohort", "mature-cohort"],
)
def test_large_upload_fires_before_and_independent_of_maturity(ref_samples):
    ref = fit(ref_samples)
    c = at(MONDAY + 15, 3, 5000 * MIB)
    p = at(MONDAY + 15, 2, 10 * MIB)
    expected = [
        {
            "detector": "large_upload",
            "observed_bytes": 5000 * MIB,
            "threshold_bytes": 1024 * MIB,
            "reason_code": "large_upload_threshold",
        }
    ]
    assert [d for d in findings(c, p, None, BaselineConfig()) if d] == expected
    out = findings_tod(c, p, ref, TodConfig(3, 3, bucket_hours=1, large_upload_bytes=1024 * MIB))
    (cand,) = out.candidates
    assert (cand.detector, cand.observed_bytes, cand.threshold_bytes, cand.reason_code) == (
        "large_upload",
        5000 * MIB,
        1024 * MIB,
        "large_upload_threshold",
    )
    assert cand.cohort == (False, 3)


def test_large_upload_boundary_leak_mismatch_and_eligibility():
    ref = fit(history())
    at_line = at(MONDAY + 15, 3, 1024 * MIB)
    assert [x.detector for x in findings_tod(at_line, None, ref, SMALL).candidates] == [
        "large_upload"
    ]
    below = at(MONDAY + 15, 3, 1024 * MIB - 1)
    assert findings_tod(below, None, ref, SMALL).candidates == ()
    in_training = at(MONDAY, 3, 2000 * MIB)  # inside the frozen window: still a fixed-line hit
    out = findings_tod(in_training, None, ref, SMALL)
    assert [x.detector for x in out.candidates] == ["large_upload"]
    assert out.abstain_reason == "leaks_evaluated_hours" or out.abstain_reason is None
    other = dataclasses.replace(SMALL, multiplier=5)
    assert len(findings_tod(at_line, None, ref, other).candidates) == 1
    ineligible = dataclasses.replace(at_line, eligible=False)
    assert findings_tod(ineligible, None, ref, SMALL).candidates == ()


def test_large_upload_and_deviation_can_both_be_reported():
    ref = fit(history())
    p, c = at(MONDAY + 15, 2, 2000 * MIB), at(MONDAY + 15, 3, 2000 * MIB)
    assert [x.detector for x in findings_tod(c, p, ref, SMALL).candidates] == [
        "large_upload",
        "upload_deviation",
    ]


def test_historical_backfill_fits_by_own_cohort_regardless_of_age():
    shift = 7 * ((MONDAY - 14_000) // 7)  # whole weeks keep the weekday alignment
    recent = history()
    ancient = [dataclasses.replace(s, hour=s.hour - shift * 86400) for s in recent]
    assert fit(ancient).cohorts == {
        k: dataclasses.replace(v, last_trained_hour=v.last_trained_hour - shift * 86400)
        if isinstance(v, CohortFit)
        else v
        for k, v in fit(recent).cohorts.items()
    }
    assert cohort(fit(ancient), False, 3).median_twice == 60 * MIB


def test_utc_cohorts_ignore_local_dst_shift():
    ny = ZoneInfo("America/New_York")
    fall_back = datetime(2026, 11, 1, 5, 0, tzinfo=UTC)  # 01:00 EDT, then 01:00 EST
    first, second = (int(fall_back.timestamp()) + i * 3600 for i in range(2))
    assert datetime.fromtimestamp(first, ny).hour == datetime.fromtimestamp(second, ny).hour == 1
    assert cohort_key(first, 1) != cohort_key(second, 1)
    assert [cohort_key(first, 1), cohort_key(second, 1)] == [(True, 5), (True, 6)]


def test_samples_built_like_the_engine_cross_a_cohort_boundary():
    "Mirror monitoring_engine.samples_for: epoch-second hours, one row per hour."
    now = (MONDAY + 28) * 86400 + 1234  # a Monday 00:20 pass
    top = now // 3600 * 3600
    rows = [  # (hour, bytes_up, qualified_seconds, reasons)
        (top - n * 3600, (30 if n > 48 else 140) * MIB, 3600, "[]") for n in range(24 * 21, 0, -1)
    ]
    rows = [r for r in rows if r[0] % 86400 // 3600 in (22, 23, 0, 1)]
    samples = [Sample(h, b, q >= 3420 and not json.loads(r or "[]"), False) for h, b, q, r in rows]
    cfg = TodConfig(10, 3, bucket_hours=4)
    train_end = top - 49 * 3600
    ref = fit_tod(samples, cfg, train_end)
    current = next(s for s in samples if s.hour == top - 3600)  # Sunday 23:00
    previous = next(s for s in samples if s.hour == top - 7200)  # Sunday 22:00
    assert cohort_key(current.hour, 4) == cohort_key(previous.hour, 4) == (True, 5)
    assert current.hour > train_end
    nxt = Sample(top, 140 * MIB, True)  # Monday 00:00: weekday bucket 0
    cross = findings_tod(nxt, current, ref, cfg)
    assert cohort_key(nxt.hour, 4) == (False, 0)
    assert cross.candidates == () and cross.abstain_reason is not None


def mature_keys(ref):
    return {k for k, v in ref.cohorts.items() if isinstance(v, CohortFit)}


@pytest.mark.parametrize("seed", range(8))
def test_property_noise_never_unmatures_or_changes_a_fit(seed):
    rng = random.Random(seed)  # noqa: S311 - seeded test data
    cfg = TodConfig(3, 2, bucket_hours=rng.choice(ALLOWED_BUCKETS))
    cells = [(d, h) for d in range(MONDAY, MONDAY + 30) for h in (0, 5, 11, 23)]
    rng.shuffle(cells)
    base = [at(d, h, rng.randrange(1, 80) * MIB) for d, h in cells[:50]]
    noise = [
        at(d, h, 0, eligible=False)
        if i % 3 == 0
        else at(d, h, rng.randrange(1, 80) * MIB, suspicious=True)
        if i % 3 == 1
        else at(d, h, 2000 * MIB)
        for i, (d, h) in enumerate(cells[50:])
    ]
    until = (MONDAY + 60) * 86400
    expected = fit_tod(base, cfg, until)
    mixed = [*base, *noise]
    rng.shuffle(mixed)
    assert fit_tod(mixed, cfg, until) == expected
    assert mature_keys(expected)  # the loop is not vacuous
    extra = [at(d, h, rng.randrange(1, 80) * MIB) for d, h in cells[50:]]
    assert mature_keys(expected) <= mature_keys(fit_tod([*base, *extra], cfg, until))


@pytest.mark.parametrize("seed", range(10))
def test_property_cohort_matures_exactly_at_the_boundary(seed):
    rng = random.Random(seed)  # noqa: S311 - seeded test data
    n = rng.randrange(2, 9)
    d = rng.randrange(1, n + 1)
    bucket = rng.choice((1, 4, 24))
    cfg = TodConfig(n, d, bucket_hours=bucket)
    days = span_days(40)
    added, per_day = [], min(bucket, 3)
    flips = []
    for i, day in enumerate(days):
        added += [at(day, h, rng.randrange(1, 50) * MIB) for h in range(per_day)]
        got = cohort(fit(added, cfg), False, 0)
        flips.append(isinstance(got, CohortFit))
        samples, ndays = (i + 1) * per_day, i + 1
        assert flips[-1] == (samples >= n and ndays >= d)
    first = flips.index(True)
    assert all(flips[first:]) and not any(flips[:first])
