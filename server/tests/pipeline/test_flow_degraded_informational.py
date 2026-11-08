"""Repro: informational ct_unmapped_* counts must not disqualify an otherwise healthy hour.

Expected to FAIL on current code (the blanket ct_* rule in measurements.py marks the hour
`flow_degraded`, qualified_seconds=0) and to PASS once informational keys stop degrading coverage.
"""

import json

import pytest
from test_monitoring import HOUR, MAC

from vigie_ingest.db import open_inventory
from vigie_ingest.models import Batch
from vigie_ingest.store import apply_batch, provision_collector
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once


def _record(root, truncated):
    inv = open_inventory(root / "inventory.db")
    provision_collector(inv, "c1", "k1", False)
    inv.close()
    batch = Batch.model_validate(
        {
            "collector_id": "c1",
            "key_id": "k1",
            "boot_id": "boot1",
            "seq": 1,
            "batch_id": "01927f3e-8a1b-7c2d-9e4f-000000000001",
            "window_start": HOUR,
            "window_end": HOUR + 3540,
            "sent_ts": HOUR + 3540,
            "observation_kind": "observation",
            "conntrack": [
                {
                    "mac": MAC,
                    "dst_ip": "93.184.216.34",
                    "dst_port": 443,
                    "proto": "tcp",
                    "bytes_up": 10,
                    "bytes_down": 2,
                    "flows": 1,
                }
            ],
            "health": {"dns_log_quiet": True},
            "truncated": truncated,
        }
    )
    assert apply_batch(root / "inventory.db", root, batch, HOUR + 3541, 900) == "applied"


def _hour(tmp_path):
    run_once(PipelineConfig(data_dir=tmp_path), now=HOUR + 3601)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        row = inv.execute("SELECT qualified_seconds,reasons FROM coverage_hourly").fetchone()
        return row[0], json.loads(row[1])
    finally:
        inv.close()


def test_control_empty_truncated_qualifies(tmp_path):
    _record(tmp_path, {})
    assert _hour(tmp_path) == (3540, [])


def test_informational_ct_unmapped_counts_do_not_degrade_the_hour(tmp_path):
    _record(tmp_path, {"ct_unmapped_bytes": 4096, "ct_unmapped_flows": 3})
    qualified, reasons = _hour(tmp_path)
    assert "flow_degraded" not in reasons
    assert qualified == 3540


INFO = {"ct_unmapped_bytes": 4096, "ct_unmapped_flows": 3}


@pytest.mark.parametrize(
    "extra",
    [
        {"ct_errors": 1},
        {"source_flags": 1},
        {"ct_new_thing": 1},
        {"ct_dropped_keys": 2},
        {"ct_recounted": 1},
        {"conntrack_lost": 1},
    ],
)
def test_informational_keys_never_mask_a_real_degradation(tmp_path, extra):
    _record(tmp_path, {**INFO, **extra})
    qualified, reasons = _hour(tmp_path)
    assert "flow_degraded" in reasons
    assert qualified == 0


def test_informational_keys_never_mask_dropped_batches(tmp_path):
    _record(tmp_path, INFO)
    inv = open_inventory(tmp_path / "inventory.db")
    inv.execute("UPDATE batches SET dropped_batches=1")
    inv.commit()
    inv.close()
    qualified, reasons = _hour(tmp_path)
    assert "flow_degraded" in reasons
    assert qualified == 0
