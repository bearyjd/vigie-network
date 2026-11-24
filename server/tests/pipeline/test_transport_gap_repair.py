"""M1-Q review follow-ups: order-independent reasons, real transitions only, real ingest path,
and zero-second placeholder rows that never count as coverage evidence."""

import json

import pytest
from test_monitoring_engine import HOUR, MAC
from test_transport_gap_quality import _receipt, coverage, measured, queued

from vigie_api import pilot_report
from vigie_ingest.db import open_inventory
from vigie_pipeline import monitoring_engine
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.measurements import apply_measurements
from vigie_pipeline.processor import run_once
from vigie_pipeline.schema import open_pipeline_inventory

DEGRADED = ("flow_degraded",)
BOTH = ["flow_degraded", "overlapping_window"]


def _big():
    return measured("big", HOUR, HOUR + 3500, (), {MAC: (5, 0, 1, 0)})


@pytest.mark.parametrize("nested_first", [False, True])
def test_a_nested_degraded_minute_keeps_both_reasons_in_either_order(tmp_path, nested_first):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    try:
        nested = measured("nested", HOUR + 100, HOUR + 160, DEGRADED)
        for item in [nested, _big()] if nested_first else [_big(), nested]:
            apply_measurements(inv, item)
        assert coverage(inv, HOUR)[2] == BOTH
    finally:
        inv.close()


def test_a_second_nested_degraded_receipt_is_not_a_new_transition(tmp_path):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    try:
        apply_measurements(inv, _big())
        apply_measurements(inv, measured("n1", HOUR + 100, HOUR + 160, DEGRADED))
        assert queued(inv) == [(HOUR,)]
        inv.execute("DELETE FROM monitoring_quality_work")  # the repair drained
        apply_measurements(inv, measured("n2", HOUR + 200, HOUR + 260, DEGRADED))
        assert queued(inv) == [], "same reasons, already zero qualified: nothing to repair"
        assert coverage(inv, HOUR)[2] == BOTH
    finally:
        inv.close()


def _recording_drain(monkeypatch):
    """Records the queued collector-hours each time the engine drains the repair queue."""
    seen: list[list[int]] = []
    real = monitoring_engine.drain_quality_work

    def drain(inv, now):
        seen.append(
            [r[0] for r in inv.execute("SELECT hour FROM monitoring_quality_work ORDER BY hour")]
        )
        return real(inv, now)

    monkeypatch.setattr(monitoring_engine, "drain_quality_work", drain)
    return seen


@pytest.mark.parametrize(
    ("start", "end", "hours"),
    [(HOUR + 3500, HOUR + 3560, [HOUR]), (HOUR + 3570, HOUR + 3630, [HOUR, HOUR + 3600])],
    ids=["late_rowless_in_hour", "cross_hour"],
)
def test_a_signed_bit_4_receipt_queues_and_drains_repair_through_ingest(
    tmp_path, monkeypatch, start, end, hours
):
    seen = _recording_drain(monkeypatch)
    _receipt(tmp_path, 1, HOUR, HOUR + 3500, 1, {})
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3501)
    assert all(not s for s in seen), "a clean receipt queues nothing"
    _receipt(tmp_path, 2, start, end, 0, {"source_flags": 4})
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3700)
    assert [HOUR] in [s[:1] for s in seen], f"repair was queued for the trained hour: {seen}"
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        for stamp in hours:
            assert "flow_degraded" in coverage(inv, stamp)[2], stamp
        quality = inv.execute("SELECT quality FROM measurement_batches WHERE batch_id LIKE '%2'")
        derived = json.loads(quality.fetchone()[0])
        assert "flow_degraded" in derived and ("cross_hour" in derived) == (len(hours) == 2)
        for tick in range(3):
            run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3701 + tick)
        assert queued(inv) == []
    finally:
        inv.close()


def test_placeholder_rows_are_not_coverage_evidence(tmp_path):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    try:
        apply_measurements(
            inv, measured("span", HOUR - 30, HOUR + 30, ("cross_hour", "flow_degraded"))
        )
        assert coverage(inv, HOUR) == (0, 0, ["flow_degraded"])
        gap = pilot_report.evidence_gap(inv, HOUR - 3600, HOUR + 7200)
        assert gap == "no coverage evidence in the window"
        assert pilot_report.liveness(inv)[1] is None
        apply_measurements(inv, measured("good", HOUR + 60, HOUR + 120, (), {MAC: (5, 0, 1, 0)}))
        assert pilot_report.liveness(inv)[1] == HOUR, "a real receipt is evidence again"
    finally:
        inv.close()
