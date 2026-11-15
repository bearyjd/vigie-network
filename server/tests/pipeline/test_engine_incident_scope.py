"""The upload engine owns only upload incidents: it never closes another detector's row.

F5 (new_device) adds a detector the upload engine must not resolve or supersede. No such detector
exists yet, so the foreign row here is inserted directly. The freeze test pins the policy versions
and the open-incident output (its pins and goldens are shared with test_probe_freeze; never
regenerate them). The golden fixture ends with one open incident, so it does not exercise
resolve/supersede: those are pinned by the scope tests below, for each upload detector.
"""

from __future__ import annotations

import pytest
from probe_helpers import build_fixture, digest, dump, run_fixture
from test_monitoring_engine import HOUR, MAC, MIB, history, hour, seeded
from test_probe_freeze import GOLDEN_TABLES, POOLED_VERSION, TOD_VERSION, tables

from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.monitoring_engine import analyze_monitoring
from vigie_pipeline.processor import monitoring_policy

CURRENT = HOUR + 20 * 86400


def test_policy_versions_and_golden_tables_are_unchanged_by_engine_scoping(tmp_path):
    assert monitoring_policy(PipelineConfig.from_env({})).version == POOLED_VERSION
    tod = PipelineConfig.from_env({"VIGIE_MONITORING_BASELINE": "tod"})
    assert monitoring_policy(tod).version == TOD_VERSION
    build_fixture(tmp_path)
    run_fixture(tmp_path)
    snap = dump(tmp_path)
    assert digest(tables(snap)) == GOLDEN_TABLES
    assert [r[5] for r in snap["monitoring_incidents"]] == ["upload_deviation"]


# (detector under test, current-hour bytes that open it through the engine's own path)
UPLOAD_CASES = [("upload_deviation", 51 * MIB), ("large_upload", 1100 * MIB)]


def open_upload_incident_and_foreign_row(inv, ov, detector, current_bytes):
    """An open upload incident plus a cloned open row of a detector the engine does not own."""
    history(inv)
    hour(inv, CURRENT - 3600, current_bytes)
    hour(inv, CURRENT, current_bytes)
    analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3610)
    assert states(inv)[detector] == "open"
    inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)"
        " SELECT 'foreign-1',collector_id,device_id,lineage,'new_device','open',episode_start,"
        "last_hour,detected_at,NULL,0,0,'{}' FROM monitoring_incidents WHERE detector=?",
        (detector,),
    )
    assert states(inv)["new_device"] == "open"


def states(inv):
    rows = inv.execute("SELECT detector,state FROM monitoring_incidents ORDER BY seq").fetchall()
    return {r["detector"]: r["state"] for r in rows}


@pytest.mark.parametrize(("detector", "current_bytes"), UPLOAD_CASES)
def test_upload_incident_resolves_and_foreign_survives_a_quiet_eligible_hour(
    tmp_path, detector, current_bytes
):
    inv, ov = seeded(tmp_path)
    try:
        open_upload_incident_and_foreign_row(inv, ov, detector, current_bytes)
        hour(inv, CURRENT + 3600, 10 * MIB)  # eligible, below every threshold: nothing fires
        analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 7210)
        after = states(inv)
        assert after[detector] == "resolved"
        assert after["new_device"] == "open"
    finally:
        inv.close()
        ov.close()


@pytest.mark.parametrize(("detector", "current_bytes"), UPLOAD_CASES)
def test_upload_incident_is_superseded_and_foreign_survives_a_profile_change(
    tmp_path, detector, current_bytes
):
    inv, ov = seeded(tmp_path)
    try:
        open_upload_incident_and_foreign_row(inv, ov, detector, current_bytes)
        inv.execute(
            "UPDATE coverage_hourly SET qualified_seconds=0,reasons=? WHERE hour=?",
            ('["overlapping_window"]', HOUR),
        )
        inv.execute("INSERT OR IGNORE INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, CURRENT))
        analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3620)
        profile = inv.execute("SELECT state FROM monitoring_profiles").fetchone()[0]
        assert profile == "rebuilding_quality"
        after = states(inv)
        assert after[detector] == "superseded"
        assert after["new_device"] == "open"
    finally:
        inv.close()
        ov.close()
