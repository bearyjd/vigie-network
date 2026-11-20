"""The prune ages a device from the SERVER moment it was retired (transient_state.since), never
from a collector stamp, and only while the activity frontier proves the server clock sane."""

from __future__ import annotations

import logging
import re

import pytest
from pipeline_helpers import T0, data  # noqa: F401
from test_prune_guards import (
    FRONTIER,
    LATER,
    PROTECTIONS,
    RETENTION,
    RETIRED_AT,
    STAMP,
    migrated_overrides,
    prune,
    retire,
    rows,
    set_frontier,
    sql,
)

from vigie_ingest.db import iso_utc
from vigie_pipeline import processor
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once, sweep_transients

CONFIG = PipelineConfig(data_dir=None)  # type: ignore[arg-type]  # sweep reads only the windows


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def stamp(data):
    return [tuple(r) for r in data.q("SELECT device_id, since FROM transient_state")]


def test_the_retirement_is_stamped_with_the_server_clock_and_kept(data):
    (device,) = retire(data).values()
    assert stamp(data) == [(device, iso_utc(RETIRED_AT))]
    assert data.q("SELECT status FROM devices")[0][0] == "retired"


def test_an_ancient_collector_last_seen_with_a_fresh_retirement_is_not_pruned(data):
    retire(data)
    migrated_overrides(data.root)
    data.inv.execute("UPDATE observations SET last_seen='2001-01-01T00:00:00Z'")
    assert prune(data, RETIRED_AT + 10 * 86400) == 0
    assert rows(data) == 1


def test_a_server_clock_stepped_forward_with_an_old_frontier_prunes_nothing(data):
    retire(data)
    migrated_overrides(data.root)
    set_frontier(data, RETIRED_AT + 3600)  # no stamp has been accepted since
    assert prune(data, RETIRED_AT + 365 * 86400) == 0
    assert rows(data) == 1


def test_a_server_clock_stepped_back_trusts_the_server_clock(data):
    retire(data)
    migrated_overrides(data.root)
    set_frontier(data, FRONTIER)  # the frontier is ahead of `now`
    assert prune(data, RETIRED_AT + 30 * 86400) == 0
    assert rows(data) == 1


def test_no_activity_at_all_prunes_nothing(data):
    retire(data)
    migrated_overrides(data.root)
    set_frontier(data, None)
    assert prune(data, LATER) == 0
    assert rows(data) == 1


def test_the_boundary_is_exclusive_on_the_stamp_and_the_frontier_cutoff(data):
    retire(data)
    migrated_overrides(data.root)
    set_frontier(data, RETIRED_AT + RETENTION)  # min(now, frontier) is the frontier
    assert prune(data, LATER) == 0  # frontier - 90d == the stamp: kept
    set_frontier(data, RETIRED_AT + RETENTION + 1)
    assert prune(data, LATER) == 1  # one second further: pruned


def test_a_legacy_retired_device_without_a_stamp_is_not_prunable_until_90_days_after_backfill(
    data,
):
    (device,) = retire(data).values()
    migrated_overrides(data.root)
    data.inv.execute("DELETE FROM transient_state")  # retired before the stamp existed
    data.inv.execute("DELETE FROM stitch_state WHERE key=?", (processor.BACKFILL_KEY,))
    assert prune(data, LATER) == 0  # no stamp: not old
    sweep_transients(data.inv, LATER, CONFIG)
    assert stamp(data) == [(device, iso_utc(LATER))]
    assert prune(data, LATER + RETENTION) == 0
    assert prune(data, LATER + RETENTION + 1) == 1


def test_the_backfill_never_moves_an_existing_stamp(data):
    retire(data)
    sweep_transients(data.inv, LATER, CONFIG)
    assert stamp(data)[0][1] == iso_utc(RETIRED_AT)


def test_a_promoted_device_drops_its_stamp_but_a_retired_one_keeps_it(data):
    retire(data)
    data.inv.execute("UPDATE devices SET status='active'")
    sweep_transients(data.inv, LATER, CONFIG)
    assert stamp(data) == []


def test_a_revived_then_retired_again_device_restarts_the_clock(data):
    ((mac, device),) = retire(data).items()
    migrated_overrides(data.root)
    revived = RETIRED_AT + 60 * 86400
    data.add_batch(revived, neigh=[mac])
    run_once(PipelineConfig(data_dir=data.root), now=revived)
    assert data.q("SELECT status FROM devices")[0][0] == "transient"
    again = revived + 86400
    run_once(PipelineConfig(data_dir=data.root), now=again)
    assert stamp(data) == [(device, iso_utc(again))]
    set_frontier(data, FRONTIER)
    assert prune(data, again + RETENTION) == 0  # the first retirement's clock would be long up
    assert prune(data, again + RETENTION + 1) == 1


def test_a_protected_oldest_device_cannot_starve_the_batch(data, monkeypatch):
    macs = retire(data, count=2)
    protected, _ = sorted(macs)
    path = migrated_overrides(data.root)
    sql(path, PROTECTIONS["device_overrides"], macs[protected], STAMP)
    data.inv.execute(  # the protected device has the oldest retirement: first in line
        "UPDATE transient_state SET since=? WHERE device_id=?", (iso_utc(T0), macs[protected])
    )
    monkeypatch.setattr(processor, "PRUNE_BATCH_ROWS", 1)
    assert prune(data, LATER) == 1
    assert [r[0] for r in data.q("SELECT mac FROM observations")] == [protected]


def lock_statements(data, now):
    seen, inside = [], False

    def trace(statement):
        nonlocal inside
        if statement.startswith("BEGIN"):
            inside = True
        elif statement.startswith(("COMMIT", "ROLLBACK")):
            inside = False
        elif inside:
            seen.append(statement)

    data.inv.set_trace_callback(trace)
    try:
        prune(data, now)
    finally:
        data.inv.set_trace_callback(None)
    return seen


def test_no_statement_inside_the_write_lock_scans_inventory(data):
    retire(data, count=3)
    migrated_overrides(data.root)
    statements = lock_statements(data, LATER)
    assert any("DELETE FROM observations" in s for s in statements)
    scans = []
    for statement in statements:
        if not re.match(r"\s*(SELECT|DELETE|UPDATE|INSERT)", statement):
            continue
        plan = data.inv.execute("EXPLAIN QUERY PLAN " + statement).fetchall()
        scans += [r[3] for r in plan if r[3].startswith("SCAN")]
    # the exclusions probe the collector set (a handful of rows, never inventory-sized)
    assert [s for s in scans if not s.startswith("SCAN c USING COVERING INDEX")] == []


# ---- the clock must be corroborated by EVERY collector, not by the one that agrees ----------


def second_collector(data, window_end):
    """A second collector whose newest batch ends at `window_end`."""
    data.add_batch(T0, collector="rtr-2", neigh=["02:00:5e:00:00:31"])
    data.inv.execute("UPDATE batches SET window_end=? WHERE collector_id='rtr-2'", (window_end,))


def test_one_collector_sharing_a_forward_step_does_not_corroborate_a_wrong_clock(data):
    retire(data)
    migrated_overrides(data.root)
    stepped = RETIRED_AT + 100 * 86400  # the server clock jumped; one collector followed it
    set_frontier(data, stepped)
    second_collector(data, RETIRED_AT + 3600)  # the other collector still tells the true time
    assert prune(data, stepped) == 0
    assert rows(data) == 1


def test_every_collector_agreeing_on_the_later_time_lets_the_prune_through(data):
    retire(data)
    migrated_overrides(data.root)
    set_frontier(data, FRONTIER)
    second_collector(data, FRONTIER)
    assert prune(data, LATER) == 1
    assert rows(data) == 0


def test_a_collector_with_no_recorded_batch_is_ignored(data):
    retire(data)
    migrated_overrides(data.root)
    data.inv.execute("INSERT INTO collectors (id, key_id) VALUES ('idle', 'k9')")
    assert prune(data, LATER) == 1


def test_a_batch_without_a_window_end_counts_from_its_receipt(data):
    retire(data)
    migrated_overrides(data.root)
    data.inv.execute("UPDATE batches SET window_end=NULL")  # legacy row: receipt time T0
    assert prune(data, LATER) == 0
    assert rows(data) == 1


def test_no_recorded_batch_at_all_prunes_nothing(data):
    retire(data)
    migrated_overrides(data.root)
    data.inv.execute("DELETE FROM batches")  # activity rows outlive their batches
    assert prune(data, LATER) == 0
    assert rows(data) == 1


def test_a_collector_is_judged_by_its_newest_batch_not_an_older_one(data):
    retire(data)
    migrated_overrides(data.root)
    data.add_batch(T0, received=T0 - 100, neigh=["02:00:5e:00:00:31"])
    data.inv.execute(  # an older, lagging batch of the same collector
        "UPDATE batches SET window_end=? WHERE rowid=2", (RETIRED_AT + 3600,)
    )
    assert prune(data, LATER) == 1


def test_the_prune_lock_of_a_real_pass_never_scans_observations_devices_or_batches(
    data, monkeypatch
):
    retire(data, count=3)
    migrated_overrides(data.root)
    windows, current = [], None
    real_open = processor.open_pipeline_inventory

    def trace(statement):
        nonlocal current
        if statement.startswith("BEGIN"):
            current = []
        elif statement.startswith(("COMMIT", "ROLLBACK")):
            windows.append(current)
            current = None
        elif current is not None:
            current.append(statement)

    def traced_open(*args, **kwargs):
        conn = real_open(*args, **kwargs)
        conn.set_trace_callback(trace)
        return conn

    monkeypatch.setattr(processor, "open_pipeline_inventory", traced_open)
    run_once(PipelineConfig(data_dir=data.root), now=LATER)
    (lock,) = [w for w in windows if any("DELETE FROM observations" in s for s in w)]
    data.inv.execute("CREATE TEMP TABLE IF NOT EXISTS prune_protected (id TEXT PRIMARY KEY)")
    scans = []
    for statement in lock:
        if re.match(r"\s*(SELECT|DELETE|UPDATE|INSERT)", statement):
            plan = data.inv.execute("EXPLAIN QUERY PLAN " + statement).fetchall()
            scans += [r[3] for r in plan if r[3].startswith("SCAN")]
    # only the collector set (a handful of rows) may be walked
    assert [s for s in scans if not s.startswith("SCAN c USING COVERING INDEX")] == []
    assert rows(data) == 0
