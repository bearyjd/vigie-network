"""The upload engine owns only upload incidents: it never closes another detector's row.

F5 (new_device) adds a detector the upload engine must not resolve or supersede. No such detector
exists yet, so the foreign row here is inserted directly. The freeze test proves the scoping is a
no-op for upload incidents; its pins and goldens are shared with test_probe_freeze (never
regenerate them).
"""

from __future__ import annotations

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


def open_upload_incident_and_foreign_row(inv, ov):
    """An open upload incident plus a cloned open row of a detector the engine does not own."""
    history(inv)
    hour(inv, CURRENT - 3600, 51 * MIB)
    hour(inv, CURRENT, 51 * MIB)
    analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3610)
    inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)"
        " SELECT 'foreign-1',collector_id,device_id,lineage,'new_device','open',episode_start,"
        "last_hour,detected_at,NULL,0,0,'{}' FROM monitoring_incidents"
    )
    return {r["detector"]: r["state"] for r in states(inv)}


def states(inv):
    return inv.execute("SELECT detector,state FROM monitoring_incidents ORDER BY seq").fetchall()


def test_foreign_incident_survives_an_eligible_hour_where_no_detector_fired(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        before = open_upload_incident_and_foreign_row(inv, ov)
        assert before == {"upload_deviation": "open", "new_device": "open"}
        hour(inv, CURRENT + 3600, 10 * MIB)  # eligible, below every threshold: nothing fires
        analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 7210)
        assert {r["detector"]: r["state"] for r in states(inv)} == {
            "upload_deviation": "resolved",
            "new_device": "open",
        }
    finally:
        inv.close()
        ov.close()


def test_foreign_incident_survives_a_profile_change(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        open_upload_incident_and_foreign_row(inv, ov)
        inv.execute(
            "UPDATE coverage_hourly SET qualified_seconds=0,reasons=? WHERE hour=?",
            ('["overlapping_window"]', HOUR),
        )
        inv.execute("INSERT OR IGNORE INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, CURRENT))
        analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3620)
        assert inv.execute("SELECT state FROM monitoring_profiles").fetchone()[0] == (
            "rebuilding_quality"
        )
        assert {r["detector"]: r["state"] for r in states(inv)} == {
            "upload_deviation": "superseded",
            "new_device": "open",
        }
    finally:
        inv.close()
        ov.close()
