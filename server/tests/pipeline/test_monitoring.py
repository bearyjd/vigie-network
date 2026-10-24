"""Worked measurement examples through real ingest and pipeline, never derived from SQL code."""

from pathlib import Path

import pytest

from vigie_ingest.db import open_inventory
from vigie_ingest.models import Batch
from vigie_ingest.store import apply_batch, provision_collector
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

HOUR = 1_791_997_200
MAC = "aa:bb:cc:00:00:01"


def recorded(
    root: Path, seq: int, start: int, end: int, upload: int, *, collector="c1", kind="observation"
):
    inv = open_inventory(root / "inventory.db")
    if inv.execute("SELECT 1 FROM collectors WHERE id=?", (collector,)).fetchone() is None:
        provision_collector(inv, collector, "k1", False)
    inv.close()
    batch = Batch.model_validate(
        {
            "collector_id": collector,
            "key_id": "k1",
            "boot_id": "boot1",
            "seq": seq,
            "batch_id": f"01927f3e-8a1b-7c2d-9e4f-{seq:012x}",
            "window_start": start,
            "window_end": end,
            "sent_ts": end,
            "observation_kind": kind,
            "conntrack": [
                {
                    "mac": MAC,
                    "dst_ip": "93.184.216.34",
                    "dst_port": 443,
                    "proto": "tcp",
                    "bytes_up": upload,
                    "bytes_down": 2,
                    "flows": 1,
                }
            ],
            "health": {"dns_log_quiet": True},
        }
    )
    assert apply_batch(root / "inventory.db", root, batch, end + 1, 900) == "applied"
    return batch


def test_two_real_batches_sum_350_and_replay_never_adds_again(tmp_path):
    first = recorded(tmp_path, 1, HOUR, HOUR + 60, 100)
    recorded(tmp_path, 2, HOUR + 60, HOUR + 120, 250)
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3601)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        row = inv.execute(
            "SELECT bytes_up, bytes_down, flows FROM measurements_hourly "
            "WHERE collector_id=? AND mac=? AND hour=?",
            ("c1", MAC, HOUR),
        ).fetchone()
        assert tuple(row) == (350, 4, 2)
        metadata = inv.execute(
            "SELECT window_start,window_end FROM batches WHERE batch_id=?", (first.batch_id,)
        ).fetchone()
        assert tuple(metadata) == (HOUR, HOUR + 60)
        assert (
            apply_batch(tmp_path / "inventory.db", tmp_path, first, HOUR + 121, 900) == "duplicate"
        )
        run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3602)
        assert inv.execute("SELECT SUM(bytes_up) FROM measurements_hourly").fetchone()[0] == 350
    finally:
        inv.close()


def test_scope_stays_per_collector_not_a_sum_of_overlapping_sensors(tmp_path):
    recorded(tmp_path, 1, HOUR, HOUR + 60, 100)
    recorded(tmp_path, 1, HOUR, HOUR + 60, 250, collector="c2")
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3601)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        rows = inv.execute(
            "SELECT collector_id,bytes_up FROM measurements_hourly ORDER BY collector_id"
        ).fetchall()
        assert [tuple(row) for row in rows] == [("c1", 100), ("c2", 250)]
    finally:
        inv.close()


def test_exact_hour_boundary_is_prior_hour_crossing_is_excluded(tmp_path):
    recorded(tmp_path, 1, HOUR + 3540, HOUR + 3600, 100)
    recorded(tmp_path, 2, HOUR + 3590, HOUR + 3610, 250)
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 7201)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        assert [
            tuple(row) for row in inv.execute("SELECT hour,bytes_up FROM measurements_hourly")
        ] == [(HOUR, 100)]
        assert (
            "cross_hour"
            in inv.execute(
                "SELECT quality FROM measurement_batches WHERE batch_id LIKE '%0002'"
            ).fetchone()[0]
        )
    finally:
        inv.close()


def test_probe_never_counts_as_coverage_or_traffic(tmp_path):
    recorded(tmp_path, 1, HOUR, HOUR + 60, 0, kind="probe")
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3601)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        assert inv.execute("SELECT COUNT(*) FROM coverage_hourly").fetchone()[0] == 0
        assert inv.execute("SELECT COUNT(*) FROM measurements_hourly").fetchone()[0] == 0
    finally:
        inv.close()


def test_measurement_and_cursor_crash_roll_back_together(tmp_path, monkeypatch):
    import vigie_pipeline.processor as processor

    recorded(tmp_path, 1, HOUR, HOUR + 60, 100)
    original = processor._advance_cursor

    def fail(*_args):
        raise RuntimeError("injected before cursor commit")

    monkeypatch.setattr(processor, "_advance_cursor", fail)
    with pytest.raises(RuntimeError, match="injected"):
        run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3601)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        assert inv.execute("SELECT COUNT(*) FROM measurement_batches").fetchone()[0] == 0
        assert inv.execute("SELECT COUNT(*) FROM measurements_hourly").fetchone()[0] == 0
    finally:
        inv.close()
    monkeypatch.setattr(processor, "_advance_cursor", original)
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3601)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        assert inv.execute("SELECT bytes_up FROM measurements_hourly").fetchone()[0] == 100
    finally:
        inv.close()


def test_extreme_counters_stay_integer_and_disqualify_hour(tmp_path):
    from vigie_pipeline.measurements import Measurements, apply_measurements
    from vigie_pipeline.schema import open_pipeline_inventory

    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    for seq in range(2):
        apply_measurements(
            inv,
            Measurements(
                "c1",
                str(seq),
                HOUR + seq * 60,
                HOUR + (seq + 1) * 60,
                "2026-10-24T00:00:00Z",
                (),
                {MAC: (2**63 - 1, 0, 1, 0)},
            ),
        )
    value, kind = inv.execute(
        "SELECT bytes_up,typeof(bytes_up) FROM measurements_hourly"
    ).fetchone()
    assert kind == "integer"
    assert value == (2**63 - 1) // 64
    row = inv.execute("SELECT reasons FROM coverage_hourly").fetchone()
    assert "counter_overflow" in row[0]
    inv.close()
