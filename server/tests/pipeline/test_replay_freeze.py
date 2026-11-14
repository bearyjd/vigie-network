"""Pilot freeze test: the replay harness must not move the monitoring policy versions or the
coverage-qualification output. The constants were computed on main at ba2f3e0, before this change;
a diff here means a policy or lineage change that restarts every profile in `learning`."""

from tests.pipeline.test_monitoring_engine import MAC, hour, seeded
from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.monitoring_engine import samples_for
from vigie_pipeline.monitoring_identity import lineage

POOLED_VERSION = "f2326b78a3286c8b26efcdbeeb33597e010c3976ab519047e27c8a5b62d915bc"
TOD_VERSION = "eb1f1e884ce34d9157d70c402002c110d6255b0417f20a86ed88a36807937337"
BASE = 1_791_997_200 // 3600 * 3600


def test_policy_versions_are_byte_identical_to_main():
    assert BaselineConfig().version == POOLED_VERSION
    assert TodConfig().version == TOD_VERSION


def test_coverage_qualification_output_is_byte_identical_to_main(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        for i, (coverage, reasons) in enumerate(
            [(3600, None), (3419, None), (3420, None), (0, None), (3599, '["gap"]')]
        ):
            hour(inv, BASE + i * 3600, 1000 + i, coverage)
            if reasons:
                inv.execute(
                    "UPDATE coverage_hourly SET reasons=? WHERE hour=?", (reasons, BASE + i * 3600)
                )
        inv.execute(
            "INSERT INTO measurements_hourly VALUES ('c1',?,?,7,0,1,0)", (MAC, BASE + 18000)
        )
        rows = samples_for(inv, "c1", lineage(inv, ov, "d1"), BASE + 10 * 3600)
        assert [(s.hour - BASE, s.bytes_up, s.eligible, s.suspicious) for s in rows] == [
            (0, 1000, True, False),
            (3600, 1001, False, False),  # 3419 s: below the 3420 s floor
            (7200, 1002, True, False),  # exactly 3420 s
            (10800, 1003, False, False),
            (14400, 1004, False, False),  # a degradation reason disqualifies the hour
            (18000, 7, False, False),  # a measurement with no coverage row is not eligible
        ]
    finally:
        inv.close()
        ov.close()
