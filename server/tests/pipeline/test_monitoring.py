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


def test_distinct_overlap_degrades_hour_but_same_receipt_replay_does_not(tmp_path):
    import json

    from vigie_pipeline.measurements import Measurements, apply_measurements
    from vigie_pipeline.schema import open_pipeline_inventory

    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    first = Measurements(
        "c1", "first", HOUR, HOUR + 3500, "2026-10-24T00:00:00Z", (), {MAC: (100, 0, 1, 0)}
    )
    apply_measurements(inv, first)
    apply_measurements(inv, first)
    assert tuple(
        inv.execute(
            "SELECT observed_seconds,qualified_seconds,reasons FROM coverage_hourly"
        ).fetchone()
    ) == (3500, 3500, "[]")
    apply_measurements(
        inv,
        Measurements(
            "c1",
            "overlap",
            HOUR + 3400,
            HOUR + 3600,
            "2026-10-24T00:01:00Z",
            (),
            {MAC: (250, 0, 1, 0)},
        ),
    )
    row = inv.execute(
        "SELECT observed_seconds,qualified_seconds,reasons FROM coverage_hourly"
    ).fetchone()
    assert tuple(row[:2]) == (3500, 0)
    assert json.loads(row[2]) == ["overlapping_window"]
    assert inv.execute("SELECT bytes_up FROM measurements_hourly").fetchone()[0] == 100
    inv.close()


def test_idle_time_only_pass_closes_qualified_upload_hour(tmp_path):
    recorded(tmp_path, 1, HOUR, HOUR + 3540, 1024**3)
    config = PipelineConfig(data_dir=tmp_path)
    run_once(config, now=HOUR + 3541)
    inv = open_inventory(tmp_path / "inventory.db")
    assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 0
    run_once(config, now=HOUR + 3601)
    row = inv.execute("SELECT detector,observed_bytes FROM monitoring_incidents").fetchone()
    assert row is not None and tuple(row) == ("large_upload", 1024**3)
    inv.close()


def test_midnight_dns_uses_query_day_and_end_day_without_double_count(tmp_path):
    midnight = (HOUR // 86400 + 1) * 86400
    inv = open_inventory(tmp_path / "inventory.db")
    provision_collector(inv, "c1", "k1", False)
    inv.close()
    batch = Batch.model_validate(
        dict(
            collector_id="c1",
            key_id="k1",
            boot_id="boot1",
            seq=1,
            batch_id="01927f3e-8a1b-7c2d-9e4f-000000000001",
            window_start=midnight - 3600,
            window_end=midnight,
            sent_ts=midnight,
            observation_kind="observation",
            health={},
            dns=[dict(mac=MAC, qname="example.com", qtype="A", ts=midnight - 30)],
        )
    )
    apply_batch(tmp_path / "inventory.db", tmp_path, batch, midnight + 1, 900)
    run_once(PipelineConfig(data_dir=tmp_path), now=midnight + 2)
    inv = open_inventory(tmp_path / "inventory.db")
    row = inv.execute("SELECT dns_queries FROM measurements_hourly").fetchone()
    assert row is not None and row[0] == 1
    run_once(PipelineConfig(data_dir=tmp_path), now=midnight + 3)
    assert inv.execute("SELECT SUM(dns_queries) FROM measurements_hourly").fetchone()[0] == 1
    inv.close()


def test_retired_query_day_is_unknown_quality_even_when_flow_day_survives(tmp_path):
    from vigie_ingest.db import shard_name, utc_day

    midnight = (HOUR // 86400 + 1) * 86400
    inv = open_inventory(tmp_path / "inventory.db")
    provision_collector(inv, "c1", "k1", False)
    inv.close()
    batch = Batch.model_validate(
        dict(
            collector_id="c1",
            key_id="k1",
            boot_id="boot1",
            seq=1,
            batch_id="01927f3e-8a1b-7c2d-9e4f-000000000001",
            window_start=midnight - 3600,
            window_end=midnight,
            sent_ts=midnight,
            observation_kind="observation",
            health={},
            dns=[dict(mac=MAC, qname="example.com", qtype="A", ts=midnight - 30)],
            conntrack=[
                dict(
                    mac=MAC,
                    dst_ip="93.184.216.34",
                    dst_port=443,
                    proto="tcp",
                    bytes_up=100,
                    bytes_down=2,
                    flows=1,
                )
            ],
        )
    )
    apply_batch(tmp_path / "inventory.db", tmp_path, batch, midnight + 1, 900)
    (tmp_path / shard_name(utc_day(midnight - 30))).unlink()
    run_once(PipelineConfig(data_dir=tmp_path), now=midnight + 2)
    inv = open_inventory(tmp_path / "inventory.db")
    row = inv.execute("SELECT qualified_seconds,reasons FROM coverage_hourly").fetchone()
    assert row[0] == 0 and "raw_missing" in row[1]
    inv.close()


@pytest.mark.parametrize("probe_first", [False, True])
def test_probe_arrival_order_never_degrades_observation_coverage(tmp_path, probe_first):
    from vigie_pipeline.measurements import Measurements, apply_measurements
    from vigie_pipeline.schema import open_pipeline_inventory

    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    observation = Measurements(
        "c1", "observation", HOUR, HOUR + 3500, "2026-10-24T00:00:00Z", (), {MAC: (100, 0, 1, 0)}
    )
    probe = Measurements(
        "c1", "probe", HOUR + 3400, HOUR + 3600, "2026-10-24T00:01:00Z", ("probe",), {}
    )
    for item in [probe, observation] if probe_first else [observation, probe]:
        apply_measurements(inv, item)
    assert tuple(
        inv.execute(
            "SELECT observed_seconds,qualified_seconds,reasons FROM coverage_hourly"
        ).fetchone()
    ) == (3500, 3500, "[]")
    assert inv.execute("SELECT bytes_up FROM measurements_hourly").fetchone()[0] == 100
    assert inv.execute("SELECT COUNT(*) FROM monitoring_quality_work").fetchone()[0] == 0
    inv.close()
