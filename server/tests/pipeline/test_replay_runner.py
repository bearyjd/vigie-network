"""The replay runner drives the real analyze_monitoring over a throwaway DB, injected clock."""

import random

import pytest
from replay_fixtures import (
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
        o for o in outcomes if o.device == "dev-update" and o.detector == "upload_deviation"
    ][: 5 * 24 + 4]  # before the update hours
    reasons = [o.reason for o in steady_dev if o.status == "abstained"]
    assert set(reasons) == {"learning", "in_training", "previous_unavailable"}
    assert reasons.count("in_training") == 1
    # the first hour after freezing has a training hour as its pair: it cannot be scored
    assert reasons[reasons.index("in_training") + 1] == "previous_unavailable"
    assert reasons.count("previous_unavailable") == 1
    assert steady_dev[-1].status == "quiet"
    assert {o.status for o in steady_dev} == {"abstained", "quiet"}


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
    assert pick(outcomes, "dev-restart", 4, 7, "large_upload").status == "quiet"
    # the zero-counter restart hour never produces an alert and the device recovers afterwards
    restart_rows = [o for o in outcomes if o.device == "dev-restart"]
    assert not [o for o in restart_rows if o.status == "fired"]
    assert pick(outcomes, "dev-restart", 4, 9, "upload_deviation").status == "quiet"


def test_ipv6_device_replays_like_any_other_and_its_spike_is_caught(outcomes):
    v6 = "2001:db8::1"
    assert pick(outcomes, v6, 5, 12, "large_upload").status == "quiet"
    assert pick(outcomes, v6, 5, 12, "upload_deviation").status == "quiet"
    assert pick(outcomes, v6, 5, 14, "upload_deviation").status == "quiet"  # needs a pair
    assert pick(outcomes, v6, 5, 15, "upload_deviation").status == "fired"
    assert pick(outcomes, v6, 5, 16, "upload_deviation").status == "quiet"
    # the fixed ceiling is far above the spike
    assert pick(outcomes, v6, 5, 15, "large_upload").status == "quiet"


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


def test_tod_strategy_abstains_while_a_cohort_cannot_mature_then_evaluates():
    seven = DeviceSeries("d", steady())
    # the weekend cohort can only ever hold 2 distinct days, so 3 is never reached: no verdicts
    never = TodConfig(min_samples_per_cohort=2, min_days_per_cohort=3, bucket_hours=24)
    rows = [o for o in replay((seven,), never) if o.detector == "upload_deviation"]
    assert {(o.status, o.reason) for o in rows} == {("abstained", "learning")}
    ok = TodConfig(min_samples_per_cohort=2, min_days_per_cohort=2, bucket_hours=24)
    rows = replay((seven,), ok)
    dev = [o for o in rows if o.detector == "upload_deviation"]
    assert [o.reason for o in dev if o.status == "abstained"].count("learning") == 6 * 24
    assert {o.reason for o in dev if o.status == "abstained"} == {
        "learning",
        "in_training",
        "previous_unavailable",
    }
    assert dev[-1].status == "quiet"
    assert {o.status for o in rows if o.detector == "large_upload"} == {"quiet"}


TOD = TodConfig(min_samples_per_cohort=2, min_days_per_cohort=2, bucket_hours=24)


def _live(tmp_path, series, policy):
    """Drive analyze_monitoring by hand, one pass per sample hour, and record per hour what the
    engine itself did: which detectors have an open incident ending that hour, and the facts
    its deviation detector needed (profile state, frozen baseline, scorable samples)."""
    from vigie_api.schema import open_overrides
    from vigie_pipeline.baselines_tod import findings_tod
    from vigie_pipeline.monitoring_engine import analyze_monitoring, samples_for
    from vigie_pipeline.monitoring_identity import lineage
    from vigie_pipeline.monitoring_strategy import strategy_for
    from vigie_pipeline.schema import open_pipeline_inventory

    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    ov = open_overrides(tmp_path / "overrides.db")
    seen: dict = {}
    try:
        inv.execute("INSERT INTO collectors(id,key_id) VALUES ('c1','k1')")
        inv.execute("INSERT INTO devices(id,first_seen,last_seen) VALUES ('d1','x','x')")
        mac = "aa:bb:cc:00:00:01"
        inv.execute(
            "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,"
            "last_seen) VALUES (?, 'd1', 0, 'self', 'x', 'x')",
            (mac,),
        )
        for row in series.samples:
            inv.execute(
                "INSERT INTO measurements_hourly VALUES ('c1',?,?,?,0,1,0)",
                (mac, row.hour, row.bytes_up),
            )
            inv.execute(
                "INSERT OR REPLACE INTO coverage_hourly VALUES ('c1',?,?,?,'[]')",
                (row.hour, row.qualified_seconds, row.qualified_seconds),
            )
            inv.execute("INSERT OR REPLACE INTO monitoring_dirty VALUES ('c1',?,0)", (mac,))
            now = row.hour + 3601
            analyze_monitoring(inv, ov, policy, now)
            fired = {
                r["detector"]
                for r in inv.execute(
                    "SELECT detector FROM monitoring_incidents WHERE last_hour=?", (row.hour,)
                )
            }
            profile = inv.execute("SELECT state,baseline_id FROM monitoring_profiles").fetchone()
            reason = "not_mature"
            if profile["state"] == "mature":
                base = inv.execute(
                    "SELECT * FROM monitoring_baselines WHERE id=?", (profile["baseline_id"],)
                ).fetchone()
                strategy = strategy_for(policy)
                ref = strategy.hydrate(dict(base))
                by = {s.hour: s for s in samples_for(inv, "c1", lineage(inv, ov, "d1"), now)}
                cur, prev = by.get(row.hour), by.get(row.hour - 3600)
                ok = cur.eligible and prev is not None and prev.eligible
                ok = ok and prev.hour > ref["trained_until"]
                if ok and isinstance(policy, TodConfig):
                    ok = findings_tod(cur, prev, ref["tod"], policy).abstain_reason is None
                reason = None if ok else "engine_abstains"
            seen[row.hour] = (fired, reason)
    finally:
        inv.close()
        ov.close()
    return seen


@pytest.mark.parametrize(
    ("name", "policy"),
    [
        ("dev-backup", POLICY),
        ("dev-restart", POLICY),
        ("dev-gap", POLICY),
        ("dev-big", POLICY),
        ("2001:db8::1", POLICY),
        ("dev-backup", TOD),
        ("dev-gap", TOD),
    ],
)
def test_harness_matches_the_live_engine_hour_by_hour(tmp_path, name, policy):
    "Every sampled hour: same fired detectors, and 'not abstained' only where the engine scores."
    series = scenario()[name]
    live = _live(tmp_path, series, policy)
    rows = [o for o in replay((series,), policy) if o.hour in live]
    assert rows
    for o in rows:
        fired, engine_reason = live[o.hour]
        assert (o.status == "fired") == (o.detector in fired), (o.hour, o.detector)
        if o.detector == "upload_deviation" and o.status != "abstained":
            assert engine_reason is None, o.hour  # the harness never scores what the engine won't
        if o.detector == "upload_deviation" and engine_reason is None:
            assert o.status != "abstained", o.hour  # ...nor abstains where the engine scores
    assert any(o.status == "fired" for o in rows) == any(f for f, _ in live.values())


def test_open_failure_closes_the_inventory_connection(tmp_path, monkeypatch):
    import sqlite3

    from vigie_pipeline.replay import runner

    opened = []
    real = runner.open_pipeline_inventory

    def tracking(*a, **k):
        opened.append(real(*a, **k))
        return opened[-1]

    def broken(_path):
        raise sqlite3.OperationalError("boom")

    monkeypatch.setattr(runner, "open_pipeline_inventory", tracking)
    monkeypatch.setattr(runner, "open_overrides", broken)
    with pytest.raises(sqlite3.OperationalError):
        runner._open(tmp_path)
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute("SELECT 1")  # closed


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


def test_engine_alerts_are_never_dropped_when_the_harness_would_abstain():
    from vigie_pipeline.replay.runner import _outcome

    with pytest.raises(ReplayInputError, match="disagree"):
        _outcome("d", 0, "large_upload", "unqualified", {"large_upload": "inc"})
    assert _outcome("d", 0, "upload_deviation", "learning", {"large_upload": "i"}).status == (
        "abstained"
    )


def test_abstention_rules_for_training_start_rebuilding_and_unscorable_cohorts():
    from types import SimpleNamespace as NS

    from vigie_pipeline.replay.runner import _deviation_abstention, _large_abstention

    ok = NS(eligible=True, hour=7200)
    assert _large_abstention(None, True) == "before_training_since"
    assert _large_abstention(ok, False) is None
    assert _deviation_abstention(None, POLICY, None, None, None, True) == "before_training_since"
    rebuilding = {"state": "rebuilding_quality", "baseline_id": None}
    assert _deviation_abstention(None, POLICY, ok, ok, rebuilding, False) == "rebuilding_quality"
    assert _deviation_abstention(None, POLICY, ok, ok, None, False) == "learning"
