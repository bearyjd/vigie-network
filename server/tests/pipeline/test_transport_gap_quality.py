"""M1-Q: a collector transport gap (signed source_flags bit 4, flow_degraded) refuses its hours.

A late rowless receipt and a cross-hour window must still invalidate a mature reference through
monitoring_quality_work, in either receipt order, idempotently under replay and duplicates.
Clean receipts keep their exact coverage bytes.
"""

import json

import pytest
from test_monitoring_engine import HOUR, MAC, MIB, history, hour, seeded

from vigie_ingest.db import iso_utc, open_inventory
from vigie_ingest.models import Batch
from vigie_ingest.store import apply_batch, provision_collector
from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.measurements import Measurements, apply_measurements
from vigie_pipeline.monitoring_engine import analyze_monitoring
from vigie_pipeline.processor import run_once
from vigie_pipeline.schema import open_pipeline_inventory

DEGRADED = ("flow_degraded",)
CURRENT = HOUR + 20 * 86400


def measured(batch_id, start, end, reasons=(), counters=None):
    return Measurements("c1", batch_id, start, end, iso_utc(end), reasons, counters or {})


def coverage(inv, stamp):
    row = inv.execute(
        "SELECT observed_seconds,qualified_seconds,reasons FROM coverage_hourly "
        "WHERE collector_id='c1' AND hour=?",
        (stamp,),
    ).fetchone()
    return None if row is None else (row[0], row[1], json.loads(row[2]))


def queued(inv):
    return [tuple(r) for r in inv.execute("SELECT hour FROM monitoring_quality_work ORDER BY hour")]


def mature(tmp_path):
    inv, ov = seeded(tmp_path)
    history(inv)
    hour(inv, CURRENT - 3600, 10 * MIB)
    hour(inv, CURRENT, 10 * MIB)
    analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3610)
    assert inv.execute("SELECT state FROM monitoring_profiles").fetchone()[0] == "mature"
    return inv, ov


def profile_state(inv):
    return inv.execute("SELECT state FROM monitoring_profiles").fetchone()[0]


@pytest.mark.parametrize(
    ("start", "end", "reasons"),
    [
        (HOUR + 60, HOUR + 120, DEGRADED),
        (HOUR + 3570, HOUR + 3630, ("cross_hour", "flow_degraded")),
    ],
    ids=["late_rowless_in_hour", "cross_hour"],
)
def test_a_late_degraded_receipt_repairs_a_mature_reference(tmp_path, start, end, reasons):
    inv, ov = mature(tmp_path)
    try:
        late = measured("late", start, end, reasons)
        apply_measurements(inv, late)
        assert coverage(inv, HOUR)[2] == ["flow_degraded"]
        assert queued(inv) == sorted({(HOUR,), ((end - 1) // 3600 * 3600,)})
        analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3620)
        assert profile_state(inv) == "rebuilding_quality"
        # One collector-hour drains per pass; replayed passes stay put once the queue is empty.
        for tick in range(3):
            analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3630 + tick)
        assert queued(inv) == []
        assert profile_state(inv) == "rebuilding_quality"
        apply_measurements(inv, late)  # duplicate delivery, with no work item to hide behind
        assert queued(inv) == []
        assert coverage(inv, HOUR)[2] == ["flow_degraded"]
    finally:
        inv.close()
        ov.close()


def test_cross_hour_degradation_marks_every_spanned_hour(tmp_path):
    inv, ov = mature(tmp_path)
    try:
        apply_measurements(
            inv, measured("span", HOUR + 3570, HOUR + 3630, ("cross_hour", "flow_degraded"))
        )
        first, second = coverage(inv, HOUR), coverage(inv, HOUR + 3600)
        assert first == (3600, 3600, ["flow_degraded"]), "seconds are kept, reasons refuse it"
        assert second == (3600, 3600, ["flow_degraded"])
        assert coverage(inv, HOUR + 7200) is None, "no hour outside the window is touched"
    finally:
        inv.close()
        ov.close()


@pytest.mark.parametrize("cross_hour", [False, True])
def test_degraded_first_then_clean_never_qualifies(tmp_path, cross_hour):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    try:
        if cross_hour:
            bad = measured("bad", HOUR - 30, HOUR + 30, ("cross_hour", "flow_degraded"))
        else:
            bad = measured("bad", HOUR, HOUR + 60, DEGRADED)
        apply_measurements(inv, bad)
        assert queued(inv) == [], "no prior row: nothing trained on the hour yet"
        apply_measurements(inv, measured("good", HOUR + 60, HOUR + 3600, (), {MAC: (5, 0, 1, 0)}))
        observed, qualified, reasons = coverage(inv, HOUR)
        assert reasons == ["flow_degraded"]
        assert observed == (3540 if cross_hour else 3600)
        assert qualified == 3540
    finally:
        inv.close()


def test_a_clean_cross_hour_window_still_leaves_coverage_alone(tmp_path):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    try:
        apply_measurements(inv, measured("good", HOUR, HOUR + 3540, (), {MAC: (5, 0, 1, 0)}))
        before = coverage(inv, HOUR)
        apply_measurements(inv, measured("span", HOUR + 3570, HOUR + 3630, ("cross_hour",)))
        assert coverage(inv, HOUR) == before == (3540, 3540, [])
        assert coverage(inv, HOUR + 3600) is None
        assert queued(inv) == []
    finally:
        inv.close()


def test_a_clean_late_receipt_queues_no_repair(tmp_path):
    inv, ov = mature(tmp_path)
    try:
        apply_measurements(inv, measured("late", HOUR + 60, HOUR + 120, ()))
        assert queued(inv) == []
        assert coverage(inv, HOUR)[2] == []
    finally:
        inv.close()
        ov.close()


def _receipt(root, seq, start, end, rows, truncated):
    inv = open_inventory(root / "inventory.db")
    if inv.execute("SELECT 1 FROM collectors WHERE id='c1'").fetchone() is None:
        provision_collector(inv, "c1", "k1", False)
    inv.close()
    conntrack = [
        {
            "mac": MAC,
            "dst_ip": "93.184.216.34",
            "dst_port": 443,
            "proto": "tcp",
            "bytes_up": 10,
            "bytes_down": 2,
            "flows": 1,
        }
    ][:rows]
    batch = Batch.model_validate(
        {
            "collector_id": "c1",
            "key_id": "k1",
            "boot_id": "boot1",
            "seq": seq,
            "batch_id": f"01927f3e-8a1b-7c2d-9e4f-{seq:012x}",
            "window_start": start,
            "window_end": end,
            "sent_ts": end,
            "observation_kind": "observation",
            "conntrack": conntrack,
            "health": {"dns_log_quiet": True},
            "truncated": truncated,
        }
    )
    assert apply_batch(root / "inventory.db", root, batch, end + 1, 900) == "applied"
    return batch


def test_a_signed_bit_4_rowless_receipt_degrades_the_hour_through_ingest(tmp_path):
    _receipt(tmp_path, 1, HOUR, HOUR + 3500, 1, {})
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3501)
    late = _receipt(tmp_path, 2, HOUR + 3500, HOUR + 3560, 0, {"source_flags": 4})
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3601)
    assert apply_batch(tmp_path / "inventory.db", tmp_path, late, HOUR + 3602, 900) == "duplicate"
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3603)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        observed, qualified, reasons = coverage(inv, HOUR)
        assert "flow_degraded" in reasons
        assert (observed, qualified) == (3560, 3500)
        assert queued(inv) == []
        assert inv.execute("SELECT bytes_up FROM measurements_hourly").fetchone()[0] == 10
    finally:
        inv.close()


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (
            measured("late1", HOUR + 60, HOUR + 120, DEGRADED),
            measured("late2", HOUR + 180, HOUR + 240, DEGRADED),
        ),
        (
            measured("span1", HOUR + 3570, HOUR + 3630, ("cross_hour", "flow_degraded")),
            measured("span2", HOUR + 3580, HOUR + 3640, ("cross_hour", "flow_degraded")),
        ),
    ],
    ids=["in_hour", "cross_hour"],
)
def test_a_second_degraded_receipt_for_an_already_degraded_hour_queues_nothing(
    tmp_path, first, second
):
    inv, ov = mature(tmp_path)
    try:
        apply_measurements(inv, first)
        for tick in range(4):
            analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3620 + tick)
        assert queued(inv) == []
        apply_measurements(inv, second)  # a distinct batch: no measurement_batches early return
        assert queued(inv) == []
        assert coverage(inv, HOUR)[2] == ["flow_degraded"]
    finally:
        inv.close()
        ov.close()
