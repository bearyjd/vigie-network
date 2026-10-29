"""Engine wiring of the opt-in tod-median-v1 baseline (pooled default: test_monitoring_engine)."""

import json

import pytest
from test_monitoring_engine import HOUR, MAC, MIB, hour, seeded

from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.monitoring_engine import analyze_monitoring
from vigie_pipeline.processor import monitoring_policy

DAY = 86400
TOD = TodConfig(min_samples_per_cohort=3, min_days_per_cohort=3, bucket_hours=24)
# HOUR is Wednesday 17:00 UTC: day 10 is the third weekend day, where every cohort first matures.
FROZEN = HOUR + 10 * DAY
CURRENT = HOUR + 20 * DAY  # a Tuesday


def daily(inv, days, value=10 * MIB):
    for d in days:
        hour(inv, HOUR + d * DAY, value)


def run(inv, ov, now, policy=TOD):
    analyze_monitoring(inv, ov, policy, now)


def baseline_rows(inv):
    return [dict(r) for r in inv.execute("SELECT * FROM monitoring_baselines")]


def mature(inv, ov, value=10 * MIB):
    daily(inv, range(14), value)
    run(inv, ov, CURRENT - 7200)


def test_cohort_abstain_until_every_cohort_is_mature_then_freeze(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        daily(inv, range(10))  # only two weekend days: the weekend cohort cannot be fitted
        run(inv, ov, HOUR + 9 * DAY + 3610)
        assert tuple(
            inv.execute("SELECT state,baseline_id FROM monitoring_profiles").fetchone()
        ) == (
            "learning",
            None,
        )
        daily(inv, range(10, 14))
        run(inv, ov, HOUR + 13 * DAY + 3610)
        [row] = baseline_rows(inv)
        assert (row["algorithm"], row["trained_until"]) == ("tod-median-v1", FROZEN)
        assert row["sample_hours"] == 11 and row["median_twice"] == 20 * MIB
        assert json.loads(row["training_hours"]) == [HOUR + d * DAY for d in range(11)]
        stored = json.loads(row["config_json"])
        assert stored["policy"]["bucket_hours"] == 24 and stored["algorithm"] == "tod-median-v1"
    finally:
        inv.close()
        ov.close()


def test_trained_until_is_frozen_and_later_data_is_never_fitted(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        before = baseline_rows(inv)
        profile = inv.execute("SELECT baseline_id,sample_hours FROM monitoring_profiles").fetchone()
        for d in range(14, 20):
            hour(inv, HOUR + d * DAY, 40 * MIB)  # later, higher traffic must not move normality
        run(inv, ov, CURRENT - 3000)
        assert baseline_rows(inv) == before
        after = inv.execute("SELECT baseline_id,sample_hours FROM monitoring_profiles").fetchone()
        assert tuple(after) == tuple(profile)
    finally:
        inv.close()
        ov.close()


def test_sustained_deviation_uses_tod_evidence_and_cohort_threshold(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        hour(inv, CURRENT - 3600, 60 * MIB)
        hour(inv, CURRENT, 60 * MIB)
        run(inv, ov, CURRENT + 3610)
        row = inv.execute(
            "SELECT detector,threshold_bytes,evidence FROM monitoring_incidents"
        ).fetchone()
        evidence = json.loads(row["evidence"])
        assert (row["detector"], row["threshold_bytes"]) == ("upload_deviation", 50 * MIB)
        assert evidence["algorithm"] == "tod-median-v1"
        assert evidence["reason_code"] == "two_qualified_upload_hours_in_cohort"
        assert evidence["baseline_median_upload_bytes"] == 10 * MIB
        assert evidence["config_version"] == TOD.version
    finally:
        inv.close()
        ov.close()


def test_deviation_hour_is_marked_suspicious_through_the_same_cohort_threshold(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        hour(inv, CURRENT, 60 * MIB)  # one hour above its cohort line: marked, but no pair yet
        run(inv, ov, CURRENT + 3610)
        assert [r[0] for r in inv.execute("SELECT hour FROM monitoring_suspicious")] == [CURRENT]
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 0
        hour(inv, HOUR + 21 * DAY, 20 * MIB)  # below the line: not marked
        run(inv, ov, HOUR + 21 * DAY + 3610)
        assert inv.execute("SELECT COUNT(*) FROM monitoring_suspicious").fetchone()[0] == 1
    finally:
        inv.close()
        ov.close()


def test_cold_start_large_upload_is_still_emitted(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        hour(inv, HOUR + 3600, 1100 * MIB)
        run(inv, ov, HOUR + 7210)
        row = inv.execute(
            "SELECT detector,baseline_id,threshold_bytes FROM monitoring_incidents"
        ).fetchone()
        assert tuple(row) == ("large_upload", None, 1024 * MIB)
        assert inv.execute("SELECT state FROM monitoring_profiles").fetchone()[0] == "learning"
    finally:
        inv.close()
        ov.close()


def test_poisoned_cohort_threshold_cannot_exceed_the_large_upload_line(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov, value=900 * MIB)  # 4 * 900 MiB would put the line at 3600 MiB
        hour(inv, CURRENT - 3600, 1100 * MIB)
        hour(inv, CURRENT, 1100 * MIB)
        run(inv, ov, CURRENT + 3610)
        rows = {
            r["detector"]: r["threshold_bytes"]
            for r in inv.execute("SELECT detector,threshold_bytes FROM monitoring_incidents")
        }
        assert rows == {"large_upload": 1024 * MIB, "upload_deviation": 1024 * MIB}
    finally:
        inv.close()
        ov.close()


def test_selector_change_changes_policy_version_and_resets_to_learning(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        daily(inv, range(14))
        run(inv, ov, CURRENT - 7200, BaselineConfig(minimum_hours=3, minimum_days=3))
        assert inv.execute("SELECT state FROM monitoring_profiles").fetchone()[0] == "mature"
        assert baseline_rows(inv)[0]["algorithm"] == "pooled-median-v1"
        hour(inv, CURRENT - 7200, 10 * MIB)
        run(inv, ov, CURRENT - 3000, TOD)
        row = inv.execute(
            "SELECT state,baseline_id,config_version FROM monitoring_profiles"
        ).fetchone()
        assert tuple(row) == ("learning", None, TOD.version)
    finally:
        inv.close()
        ov.close()


def test_frozen_reference_survives_pruned_and_rewritten_measurements(tmp_path):
    from vigie_pipeline.monitoring_strategy import strategy_for

    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        [row] = baseline_rows(inv)
        strategy = strategy_for(TOD)
        assert strategy.hydrate(dict(row)) == strategy.hydrate(dict(row))
        inv.execute("DELETE FROM measurements_hourly WHERE hour<?", (FROZEN - 5 * DAY,))
        hour(inv, HOUR + 7 * DAY, 900 * MIB)  # a used training hour rewritten, still below the line
        hour(inv, CURRENT - 3600, 45 * MIB)
        hour(inv, CURRENT, 45 * MIB)
        run(inv, ov, CURRENT + 3610)
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 0
        wednesday = HOUR + 21 * DAY
        hour(inv, wednesday - 3600, 60 * MIB)
        hour(inv, wednesday, 60 * MIB)
        run(inv, ov, wednesday + 3610)
        found = inv.execute("SELECT detector,threshold_bytes FROM monitoring_incidents").fetchall()
        assert [tuple(r) for r in found] == [("upload_deviation", 50 * MIB)]
        state = inv.execute("SELECT state,baseline_id FROM monitoring_profiles").fetchone()
        assert tuple(state) == ("mature", row["id"])
    finally:
        inv.close()
        ov.close()


def test_corrupt_stored_inputs_drop_the_reference_into_rebuilding_quality(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        inv.execute("UPDATE monitoring_baselines SET config_json='{}'")
        hour(inv, CURRENT, 10 * MIB)
        run(inv, ov, CURRENT + 3610)
        row = inv.execute("SELECT state,baseline_id FROM monitoring_profiles").fetchone()
        assert tuple(row) == ("rebuilding_quality", None)
    finally:
        inv.close()
        ov.close()


def test_training_hour_quality_loss_resets_tod_reference_like_pooled(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        inv.execute(
            "UPDATE coverage_hourly SET qualified_seconds=0,reasons=? WHERE hour=?",
            ('["overlapping_window"]', HOUR),
        )
        inv.execute("INSERT OR IGNORE INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, CURRENT))
        hour(inv, CURRENT, 10 * MIB)
        run(inv, ov, CURRENT + 3610)
        row = inv.execute("SELECT state,baseline_id FROM monitoring_profiles").fetchone()
        assert tuple(row) == ("rebuilding_quality", None)
    finally:
        inv.close()
        ov.close()


def test_api_baseline_view_reports_the_stored_algorithm(tmp_path):
    from vigie_api.monitoring import baseline_view

    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        view = baseline_view(
            inv, "c1", "d1", inv.execute("SELECT lineage FROM monitoring_profiles").fetchone()[0]
        )
        assert view["state"] == "mature" and view["algorithm"] == "tod-median-v1"
        assert view["median_upload_bytes"] is None and view["trained_until"] == FROZEN
    finally:
        inv.close()
        ov.close()


def test_selector_defaults_to_pooled_and_rejects_unknown_values():
    assert PipelineConfig.from_env({}).monitoring_baseline == "pooled"
    assert isinstance(monitoring_policy(PipelineConfig.from_env({})), BaselineConfig)
    tod = PipelineConfig.from_env({"VIGIE_MONITORING_BASELINE": "tod"})
    policy = monitoring_policy(tod)
    assert isinstance(policy, TodConfig) and policy.large_upload_bytes == 1024**3
    for bad in ("", "TOD", " tod", "pooled-median-v1", "none"):
        with pytest.raises(ValueError, match="monitoring_baseline"):
            PipelineConfig.from_env({"VIGIE_MONITORING_BASELINE": bad})
        with pytest.raises(ValueError, match="monitoring_baseline"):
            PipelineConfig(data_dir=tod.data_dir, monitoring_baseline=bad)
    custom = PipelineConfig.from_env(
        {"VIGIE_MONITORING_BASELINE": "tod", "VIGIE_MONITORING_LARGE_UPLOAD_BYTES": "2097152"}
    )
    assert monitoring_policy(custom).large_upload_bytes == 2097152


def test_default_bucket_hours_engine_learns_and_fires(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        for i in range(28 * 24):
            hour(inv, HOUR + i * 3600, 10 * MIB)
        run(inv, ov, HOUR + 28 * DAY + 3610, TodConfig())
        assert inv.execute("SELECT state FROM monitoring_profiles").fetchone()[0] == "mature"
        hour(inv, HOUR + 28 * DAY, 60 * MIB)
        hour(inv, HOUR + 28 * DAY + 3600, 60 * MIB)
        run(inv, ov, HOUR + 28 * DAY + 7210, TodConfig())
        evidence = json.loads(
            inv.execute("SELECT evidence FROM monitoring_incidents").fetchone()[0]
        )
        assert evidence["bucket_hours"] == 4 and evidence["cohort_bucket"] == 4
        assert evidence["cohort_is_weekend"] is False and evidence["cap_applied"] is False
    finally:
        inv.close()
        ov.close()


def test_never_mature_cohort_keeps_learning_with_only_the_fixed_detector(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        daily(inv, [d for d in range(14) if (d + 2) % 7 < 5 and d not in (3, 4, 10, 11)])
        daily(inv, [3, 4])  # weekend: only two days, below the 3-day floor
        hour(inv, CURRENT - 3600, 60 * MIB)
        hour(inv, CURRENT, 60 * MIB)
        run(inv, ov, CURRENT + 3610)
        assert tuple(
            inv.execute("SELECT state,baseline_id FROM monitoring_profiles").fetchone()
        ) == (
            "learning",
            None,
        )
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 0
        hour(inv, CURRENT + 3600, 1100 * MIB)
        run(inv, ov, CURRENT + 7210)
        found = [r[0] for r in inv.execute("SELECT detector FROM monitoring_incidents")]
        assert found == ["large_upload"]
    finally:
        inv.close()
        ov.close()


@pytest.mark.parametrize(
    "column,value",
    [
        pytest.param("config_json", '{"training_bytes": [1, 2]}', id="length-mismatch"),
        pytest.param("config_json", '{"training_bytes": ["x"]}', id="bad-bytes"),
        pytest.param("config_json", "[" * 100000 + "]" * 100000, id="recursion-bomb"),
        pytest.param("sample_hours", 99, id="wrong-sample-hours"),
        pytest.param("training_hours", "not json", id="hours-not-json"),
        pytest.param("training_hours", "[1.5]", id="hours-float"),
        pytest.param("training_hours", '{"a": 1}', id="hours-object"),
        pytest.param("training_hours", "5", id="hours-scalar"),
    ],
)
def test_malformed_stored_inputs_fall_to_rebuilding_quality(tmp_path, column, value):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        inv.execute(f"UPDATE monitoring_baselines SET {column}=?", (value,))  # noqa: S608
        hour(inv, CURRENT, 10 * MIB)
        run(inv, ov, CURRENT + 3610)
        row = inv.execute("SELECT state,baseline_id FROM monitoring_profiles").fetchone()
        assert tuple(row) == ("rebuilding_quality", None)
    finally:
        inv.close()
        ov.close()


def test_oversized_hour_still_emits_large_upload_under_tod(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        hour(inv, CURRENT - 3600, 2**60)
        hour(inv, CURRENT, 2**60)
        run(inv, ov, CURRENT + 3610)
        found = [r[0] for r in inv.execute("SELECT detector FROM monitoring_incidents")]
        assert found == ["large_upload"]
    finally:
        inv.close()
        ov.close()


def test_plain_value_error_is_a_bug_and_still_escapes(tmp_path, monkeypatch):
    from vigie_pipeline import monitoring_engine

    inv, ov = seeded(tmp_path)
    try:
        hour(inv, HOUR, 10 * MIB)

        def boom(*args):
            raise ValueError("programming bug")

        monkeypatch.setattr(monitoring_engine, "analyze_entity", boom)
        with pytest.raises(ValueError, match="programming bug"):
            run(inv, ov, HOUR + 3610)
    finally:
        inv.close()
        ov.close()


def test_invalid_input_is_logged_backed_off_and_does_not_block_other_entities(tmp_path):
    import logging

    from vigie_pipeline import monitoring_engine

    records = []
    handler = logging.Handler(logging.ERROR)
    handler.emit = records.append  # own handler: immune to propagation state of other tests
    monitoring_engine.logger.addHandler(handler)
    monitoring_engine.logger.disabled = False
    inv, ov = seeded(tmp_path)
    try:
        other = "aa:bb:cc:00:00:02"
        inv.execute(
            "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,last_seen)"
            " VALUES (?, 'd2', 0, 'self', 't', 't')",
            (other,),
        )
        pooled = BaselineConfig(minimum_hours=3, minimum_days=3)
        daily(inv, range(5))
        run(inv, ov, HOUR + 5 * DAY, pooled)
        inv.execute("UPDATE monitoring_baselines SET training_hours='not json'")
        hour(inv, HOUR + 5 * DAY, 10 * MIB)  # re-queues d1
        inv.execute(
            "INSERT INTO measurements_hourly VALUES ('c1',?,?,?,0,1,0)",
            (other, HOUR + 5 * DAY, 1100 * MIB),
        )
        inv.execute(
            "INSERT OR REPLACE INTO coverage_hourly VALUES ('c1',?,3600,3600,'[]')",
            (HOUR + 5 * DAY,),
        )
        inv.execute("INSERT INTO monitoring_dirty VALUES ('c1',?,?)", (other, HOUR + 5 * DAY))
        now = HOUR + 5 * DAY + 3610
        run(inv, ov, now, pooled)
        record = next(r for r in records if r.getMessage() == "monitoring_invalid_input")
        assert record.fields["device"] == "d1" and "training_hours" in record.fields["error"]
        row = inv.execute("SELECT reason,retry_at FROM monitoring_unavailable").fetchone()
        assert tuple(row) == ("invalid_input", now + 60)
        found = inv.execute("SELECT device_id,detector FROM monitoring_incidents").fetchall()
        assert [tuple(r) for r in found] == [("d2", "large_upload")]
    finally:
        monitoring_engine.logger.removeHandler(handler)
        inv.close()
        ov.close()


@pytest.mark.parametrize("bad", [1.5e300, None, 2**60, -5])
def test_odd_byte_values_fall_to_the_fixed_detector_without_raising(bad):
    from vigie_pipeline.baselines import Sample
    from vigie_pipeline.monitoring_strategy import strategy_for

    strategy = strategy_for(TOD)
    reference = strategy.fit([Sample(HOUR + d * DAY, 10 * MIB, True) for d in range(14)])
    current = Sample(CURRENT, bad, True)
    previous = Sample(CURRENT - 3600, bad, True)
    found = strategy.findings(current, previous, reference)
    assert [f["detector"] for f in found] == (
        ["large_upload"] if bad == bad and bad and bad > 2**30 else []
    )
    assert strategy.findings(Sample(CURRENT, 10 * MIB, True), previous, reference) == []


def test_pooled_default_golden_literals(tmp_path):
    "Captured from origin/main (242fa6c): the default path must stay byte-for-byte identical."
    from test_monitoring_engine import history

    inv, ov = seeded(tmp_path)
    try:
        history(inv)
        cur = HOUR + 20 * DAY
        hour(inv, cur - 3600, 51 * MIB)
        hour(inv, cur, 51 * MIB)
        run(inv, ov, cur + 3610, BaselineConfig())
        row = inv.execute("SELECT config_json,config_version,algorithm FROM monitoring_baselines")
        assert tuple(row.fetchone()) == (
            '{"large_upload_bytes": 1073741824, "minimum_bytes": 52428800, "minimum_days": 14, '
            '"minimum_hours": 20, "multiplier": 4}',
            "f2326b78a3286c8b26efcdbeeb33597e010c3976ab519047e27c8a5b62d915bc",
            "pooled-median-v1",
        )
        incident = inv.execute(
            "SELECT detector,state,observed_bytes,threshold_bytes,baseline_id,evidence "
            "FROM monitoring_incidents"
        ).fetchone()
        baseline_id = "524e7c1cc2b616d59df50c97f2fb323f86f272cb3140e8391debfc827ac9c714"
        assert tuple(incident)[:5] == ("upload_deviation", "open", 53477376, 52428800, baseline_id)
        assert json.loads(incident["evidence"]) == {
            "algorithm": "pooled-median-v1",
            "baseline_id": baseline_id,
            "baseline_median_upload_bytes": 10485760.0,
            "config_version": "f2326b78a3286c8b26efcdbeeb33597e010c3976ab519047e27c8a5b62d915bc",
            "coverage_required_seconds": 3420,
            "distinct_days": 14,
            "hour": 1793725200,
            "lineage": "edc7c6c12cee21cd517973e3f9a3b777201f3eead52c9b649d92ff8ba2392e0c",
            "minimum_bytes": 52428800,
            "multiplier": 4,
            "observed_bytes": 53477376,
            "previous_hour": 1793721600,
            "reason_code": "two_qualified_upload_hours",
            "sample_hours": 20,
            "threshold_bytes": 52428800,
            "unusual_is_not_malicious": True,
        }
    finally:
        inv.close()
        ov.close()


def test_cli_config_carries_the_monitoring_settings(monkeypatch):
    from vigie_pipeline.cli import _config, _parser

    monkeypatch.setenv("VIGIE_MONITORING_BASELINE", "tod")
    monkeypatch.setenv("VIGIE_MONITORING_LARGE_UPLOAD_BYTES", "2097152")
    config = _config(_parser().parse_args(["run", "--once"]))
    assert config.monitoring_baseline == "tod"
    assert config.monitoring_large_upload_bytes == 2097152


def test_stored_json_over_the_length_cap_is_rejected_even_when_valid(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        mature(inv, ov)
        inv.execute("UPDATE monitoring_baselines SET config_json=config_json||?", (" " * 300000,))
        hour(inv, CURRENT, 10 * MIB)
        run(inv, ov, CURRENT + 3610)
        row = inv.execute("SELECT state,baseline_id FROM monitoring_profiles").fetchone()
        assert tuple(row) == ("rebuilding_quality", None)
    finally:
        inv.close()
        ov.close()


def test_continued_incident_threshold_follows_the_latest_cohort(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        for d in range(14):
            hour(inv, HOUR + d * DAY, 25 * MIB if (d + 2) % 7 >= 5 else 10 * MIB)
        friday_22 = HOUR + 16 * DAY + 5 * 3600
        hour(inv, friday_22, 70 * MIB)
        hour(inv, friday_22 + 3600, 70 * MIB)
        run(inv, ov, friday_22 + 7210)
        thresholds = inv.execute("SELECT threshold_bytes,state FROM monitoring_incidents")
        assert [tuple(r) for r in thresholds] == [(50 * MIB, "open")]
        hour(inv, friday_22 + 7200, 110 * MIB)  # Saturday 00:00: weekend line is 100 MiB
        run(inv, ov, friday_22 + 7200 + 3610)
        row = inv.execute(
            "SELECT threshold_bytes,observed_bytes,evidence FROM monitoring_incidents"
        )
        [only] = row.fetchall()
        assert (only["threshold_bytes"], only["observed_bytes"]) == (100 * MIB, 110 * MIB)
        assert json.loads(only["evidence"])["threshold_bytes"] == 100 * MIB
    finally:
        inv.close()
        ov.close()


def test_pooled_continued_incident_threshold_is_unchanged(tmp_path):
    from test_monitoring_engine import history

    inv, ov = seeded(tmp_path)
    try:
        history(inv)
        cur = HOUR + 20 * DAY
        hour(inv, cur - 3600, 51 * MIB)
        hour(inv, cur, 51 * MIB)
        run(inv, ov, cur + 3610, BaselineConfig())
        hour(inv, cur + 3600, 52 * MIB)
        run(inv, ov, cur + 7210, BaselineConfig())
        row = inv.execute(
            "SELECT threshold_bytes,observed_bytes FROM monitoring_incidents"
        ).fetchall()
        assert [tuple(r) for r in row] == [(50 * MIB, 52 * MIB)]
    finally:
        inv.close()
        ov.close()
