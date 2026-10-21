"""Generated fixtures through the real ingest app and the real pipeline `run_once`."""

from __future__ import annotations

import sqlite3

import pytest
from conftest import FIXTURES
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

from trafficgen.generator import load_emissions

FIXTURE_NAMES = sorted(p.stem for p in FIXTURES.glob("*.jsonl"))


def process(ingest, name: str) -> dict[str, int | list]:
    ems = load_emissions(FIXTURES / f"{name}.jsonl")
    results = ingest.replay(ems)
    assert all(r.ok for r in results)
    stats = run_once(PipelineConfig(data_dir=ingest.data_dir), now=float(ems[-1].arrival_ts))
    conn = sqlite3.connect(ingest.data_dir / "inventory.db")
    try:
        devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        kinds = conn.execute("SELECT kind, COUNT(*) FROM events GROUP BY kind").fetchall()
    finally:
        conn.close()
    return {
        "batches": stats.batches,
        "devices": devices,
        "events": events,
        "kinds": sorted(kinds),
    }


# (devices, {event kind: count}) the current pipeline produces. Rolling profiles stay one device per
# MAC because no human-approved identity rule exists; mac_clone is detected only when the clone
# keeps its own fingerprint (the same_fingerprint blind spot is the point of that variant).
EXPECTED: dict[str, tuple[int, dict[str, int]]] = {
    "baseline": (7, {"new_device": 7}),
    "doh_user": (8, {"new_device": 8}),
    "flood": (8, {"new_device": 8}),
    "hostname_spoof": (8, {"new_device": 8}),
    "hostname_spoof_full_fingerprint": (8, {"new_device": 8}),
    "ip_flap": (8, {"new_device": 8}),
    "mac_clone": (7, {"new_device": 7, "identity_conflict": 2}),
    "mac_clone_same_fingerprint": (7, {"new_device": 7}),
    "out_of_order": (7, {"new_device": 7}),
    "replay": (7, {"new_device": 7}),
    "rolling_fingerprint_copy_away": (11, {"new_device": 11}),
    "rolling_fingerprint_copy_present": (13, {"new_device": 13}),
    "rolling_mac": (11, {"new_device": 11}),
    "rolling_overlap_veto": (15, {"new_device": 15}),
    "stale_ts": (7, {"new_device": 7}),
}


def test_expected_table_covers_every_fixture():
    assert set(EXPECTED) == set(FIXTURE_NAMES)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_flows_through_ingest_and_pipeline(ingest, name):
    out = process(ingest, name)
    accepted = sum(1 for e in load_emissions(FIXTURES / f"{name}.jsonl") if e.expect_status == 200)
    devices, kinds = EXPECTED[name]
    assert out["batches"] == accepted - (name == "replay")  # the duplicate is not stored twice
    assert (out["devices"], dict(out["kinds"])) == (devices, kinds)
