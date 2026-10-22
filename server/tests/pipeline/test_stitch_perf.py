"""H2 (review 3): stitching CPU is bounded inside BEGIN IMMEDIATE (reviewer's measured cases)."""

from __future__ import annotations

import time

import pytest
from pipeline_helpers import data  # noqa: F401
from stitch_helpers import appear, kinds, run

from vigie_ingest.db import open_inventory
from vigie_pipeline import stitch as stitch_mod
from vigie_pipeline.config import MAX_OVERLAP_OPS_PER_PASS, PipelineConfig
from vigie_pipeline.schema import apply_pipeline_migrations
from vigie_pipeline.snapshot import EMPTY
from vigie_pipeline.stitch import stitch

NOW = 1_800_000_000


def build(tmp_path, groups: int, per_group: int, intervals: int):
    """groups name groups of per_group self MACs, each with `intervals` disjoint stamps."""
    inv = open_inventory(tmp_path / "inventory.db")
    apply_pipeline_migrations(inv)
    n = 0
    inv.execute("BEGIN")  # one transaction: autocommit would fsync every row
    for g in range(groups):
        for k in range(per_group):
            m = f"ae:{n >> 16 & 255:02x}:{n >> 8 & 255:02x}:{n & 255:02x}:00:00"
            fs = f"2026-12-01T00:{(n // 60) % 60:02d}:{n % 60:02d}Z"
            inv.execute(
                "INSERT INTO devices (id, first_seen, last_seen) VALUES (?,?,?)", (f"d{n}", fs, fs)
            )
            inv.execute(
                "INSERT INTO observations (mac, device_id, is_randomized, dhcp_fingerprint,"
                " vendor_class, hostname, mdns_name, link_source, first_seen, last_seen)"
                " VALUES (?,?,1,'1,2,3','x',?,NULL,'self',?,?)",
                (m, f"d{n}", f"host{g}", fs, fs),
            )
            inv.executemany(
                'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
                [(m, s, s) for i in range(intervals)
                 for s in [NOW - 6 * 86400 + (i * per_group + k) * 400]],
            )  # fmt: skip
            n += 1
    inv.execute("COMMIT")
    return inv


@pytest.mark.parametrize("shape", [(16, 64, 50), (1, 64, 200)])
def test_reviewer_worst_cases_finish_under_three_seconds(tmp_path, shape):
    inv = build(tmp_path, *shape)
    start = time.perf_counter()
    stitch(inv, EMPTY, PipelineConfig(data_dir=tmp_path), NOW)
    assert time.perf_counter() - start < 3.0


def test_budget_exhaustion_stops_new_candidates_emits_once_and_resumes(data, monkeypatch):
    for i in range(6):  # six name groups, each an old and a new MAC: one overlap check apiece
        appear(data, 2 * i, 0, 60, opt55=f"[{i}]")
        appear(data, 2 * i + 1, 400, 460, opt55=f"[{i}]")
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 14)
    run(data)
    assert len(kinds(data, "stitch_budget_exhausted")) == 1
    done = data.q("SELECT COUNT(*) FROM identity_candidates")[0][0]
    assert 0 < done < 6  # progress made, nothing half-decided
    run(data)
    assert len(kinds(data, "stitch_budget_exhausted")) == 1  # once per UTC day
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", MAX_OVERLAP_OPS_PER_PASS)
    run(data)
    assert data.q("SELECT COUNT(*) FROM identity_candidates")[0][0] == 6


def test_candidate_pass_stops_when_the_row_cap_is_reached(tmp_path, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_ROWS_PER_PASS", 5)
    inv = build(tmp_path, 1, 40, 3)
    stats = stitch(inv, EMPTY, PipelineConfig(data_dir=tmp_path), NOW)
    assert 0 < stats.candidates < 39 and stats.capped >= 1
