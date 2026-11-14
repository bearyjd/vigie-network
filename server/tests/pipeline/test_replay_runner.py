"""The replay runner drives the real analyze_monitoring over a throwaway DB, injected clock."""

import random

import pytest

from tests.pipeline.replay_fixtures import (
    BASE,
    DAYS,
    GIB,
    MIB,
    POLICY,
    hr,
    labels,
    scenario,
    steady,
)
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.replay.errors import ReplayInputError
from vigie_pipeline.replay.runner import MAX_TICKS, hourly_clock, replay
from vigie_pipeline.replay.series import DeviceSeries

pytestmark = pytest.mark.timeout(120)


@pytest.fixture(scope="module")
def outcomes():
    return replay(
        tuple(scenario().values()), POLICY, extra_hours=[(x.device, x.hour) for x in labels()]
    )


def pick(rows, device, day, hour, detector):
    found = [o for o in rows if (o.device, o.hour, o.detector) == (device, hr(day, hour), detector)]
    assert len(found) == 1
    return found[0]


def test_backup_fires_deviation_on_second_hour_only(outcomes):
    first = pick(outcomes, "dev-backup", 5, 2, "upload_deviation")
    second = pick(outcomes, "dev-backup", 5, 3, "upload_deviation")
    assert first.status == "quiet"  # needs two consecutive hours
    assert second.status == "fired" and second.episode
    assert pick(outcomes, "dev-backup", 5, 3, "large_upload").status == "quiet"
    assert pick(outcomes, "dev-backup", 5, 4, "upload_deviation").status == "quiet"


def test_large_upload_fires_during_learning_while_deviation_abstains(outcomes):
    big = pick(outcomes, "dev-big", 1, 5, "large_upload")
    dev = pick(outcomes, "dev-big", 1, 5, "upload_deviation")
    assert big.status == "fired"
    assert (dev.status, dev.reason) == ("abstained", "learning")


def test_training_hour_then_evaluated(outcomes):
    steady_dev = [
        o for o in outcomes if o.device == "2001:db8::1" and o.detector == "upload_deviation"
    ]
    reasons = [o.reason for o in steady_dev if o.status == "abstained"]
    assert set(reasons) == {"learning", "in_training", "previous_unavailable"}
    assert reasons.count("in_training") == 1
    # the first hour after freezing has a training hour as its pair: it cannot be scored
    assert reasons[reasons.index("in_training") + 1] == "previous_unavailable"
    assert reasons.count("previous_unavailable") == 1
    assert steady_dev[-1].status == "quiet"


def test_sleeping_gap_restart_and_missing_hours_abstain_with_reasons(outcomes):
    for detector in ("large_upload", "upload_deviation"):
        assert pick(outcomes, "dev-sleep", 5, 2, detector).reason == "no_sample"
        assert pick(outcomes, "dev-gap", 4, 5, detector).reason == "no_sample"
        restart = pick(outcomes, "dev-restart", 4, 6, detector)
        assert (restart.status, restart.reason) == ("abstained", "unqualified")
    # the hour after a missing or unqualified hour cannot form a consecutive pair
    after_gap = pick(outcomes, "dev-gap", 4, 8, "upload_deviation")
    assert (after_gap.status, after_gap.reason) == ("abstained", "previous_unavailable")
    assert pick(outcomes, "dev-gap", 4, 8, "large_upload").status == "quiet"
    after_restart = pick(outcomes, "dev-restart", 4, 7, "upload_deviation")
    assert after_restart.reason == "previous_unavailable"


def test_ipv6_device_replays_like_any_other(outcomes):
    assert pick(outcomes, "2001:db8::1", 5, 12, "large_upload").status == "quiet"


def test_clock_gap_hour_is_never_evaluated_but_later_hours_still_are():
    devices = (scenario()["dev-backup"],)
    ticks = [now for now in hourly_clock(hr(0, 0), hr(DAYS - 1, 23)) if now != hr(5, 3) + 3601]
    rows = replay(devices, POLICY, clock=iter(ticks))
    gap = pick(rows, "dev-backup", 5, 3, "upload_deviation")
    assert (gap.status, gap.reason) == ("abstained", "clock_gap")
    assert pick(rows, "dev-backup", 5, 4, "upload_deviation").status == "quiet"


def test_deterministic_for_shuffled_input():
    base = tuple(scenario().values())
    expected = replay(base, POLICY)
    rng = random.Random(7)  # noqa: S311 - a test shuffle, not security
    for _ in range(2):
        shuffled = []
        for d in rng.sample(base, len(base)):
            rows = list(d.samples)
            rng.shuffle(rows)
            shuffled.append(DeviceSeries(d.device, tuple(rows)))
        assert replay(tuple(shuffled), POLICY) == expected


def test_runner_never_touches_the_given_series_or_live_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", None)
    rows = replay((DeviceSeries("d", steady()[:30]),), POLICY)
    assert rows
    assert list(tmp_path.iterdir()) == []  # the throwaway directory is removed


def test_tod_strategy_replays_and_reports_cohort_abstention():
    cfg = TodConfig(min_samples_per_cohort=2, min_days_per_cohort=2, bucket_hours=24)
    rows = replay((DeviceSeries("d", steady()),), cfg)
    kinds = {(o.detector, o.status, o.reason) for o in rows}
    assert ("upload_deviation", "abstained", "learning") in kinds
    assert ("large_upload", "quiet", None) in kinds


def test_clock_validation():
    d = (DeviceSeries("d", steady()[:5]),)
    with pytest.raises(ReplayInputError):
        replay(d, POLICY, clock=iter([7200 + 5, 3600 + 5]))  # not increasing
    with pytest.raises(ReplayInputError):
        replay(d, POLICY, clock=iter(range(3600, 3600 * (MAX_TICKS + 5), 3600)))
    with pytest.raises(ReplayInputError):
        replay(d, POLICY, clock=iter([-1]))
    with pytest.raises(ReplayInputError):
        list(hourly_clock(0, 3600 * (MAX_TICKS + 5)))


def test_large_bytes_constant_sanity():
    assert GIB == 1024 * MIB and BASE < POLICY.minimum_bytes
