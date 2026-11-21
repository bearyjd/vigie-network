"""The retirement stamp is the prune's clock: written when a device is retired, by every path
that retires one, never earlier than the newest batch receipt, and the backfill for retired
devices without one rescans devices at most once a day."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from pipeline_helpers import T0, data  # noqa: F401
from stitch_helpers import appear, run, seeded
from test_prune_guards import (
    FRONTIER,
    LATER,
    RETENTION,
    RETIRED_AT,
    migrated_overrides,
    prune,
    retire,
    rows,
    set_clock,
)

from vigie_ingest.db import iso_utc
from vigie_pipeline import processor
from vigie_pipeline.config import RETIRED_BACKFILL_INTERVAL_S, PipelineConfig
from vigie_pipeline.processor import BACKFILL_KEY, sweep_transients

CONFIG = PipelineConfig(data_dir=None)  # type: ignore[arg-type]  # sweep reads only the windows


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def stamps(data):
    return {r[0]: r[1] for r in data.q("SELECT device_id, since FROM transient_state")}


def test_the_backfill_stamps_legacy_retired_devices_once(data):
    (device,) = retire(data).values()
    set_clock(data, None)  # no send floor: these sweeps are driven by the clock they are given
    data.inv.execute("DELETE FROM transient_state")
    data.inv.execute("DELETE FROM stitch_state WHERE key=?", (BACKFILL_KEY,))
    sweep_transients(data.inv, LATER, CONFIG)
    assert stamps(data) == {device: iso_utc(LATER)}
    assert data.q("SELECT 1 FROM stitch_state WHERE key=?", BACKFILL_KEY) != []


def test_a_second_sweep_does_not_backfill_again(data):
    (device,) = retire(data).values()
    sweep_transients(data.inv, LATER, CONFIG)  # the first pass marked the backfill done
    data.inv.execute("DELETE FROM transient_state WHERE device_id=?", (device,))
    sweep_transients(data.inv, LATER + 60, CONFIG)
    assert stamps(data) == {}  # an unstamped retired device stays unprunable until restamped


def test_the_sweep_does_not_scan_devices_for_a_backfill_within_the_interval(data):
    retire(data)
    set_clock(data, None)  # no send floor: these sweeps are driven by the clock they are given
    seen = []
    data.inv.set_trace_callback(seen.append)
    try:
        sweep_transients(data.inv, RETIRED_AT + RETIRED_BACKFILL_INTERVAL_S - 1, CONFIG)
    finally:
        data.inv.set_trace_callback(None)
    assert not [s for s in seen if "INSERT OR IGNORE INTO transient_state" in s]


def test_a_retirement_is_stamped_at_the_transition_time_not_the_pass_start(data):
    data.add_batch(T0, neigh=["02:00:5e:00:00:41"])
    processor.run_once(PipelineConfig(data_dir=data.root), now=RETIRED_AT - 3600)  # transient
    sweep_transients(data.inv, RETIRED_AT, CONFIG, retired_at=RETIRED_AT + 7)
    assert set(stamps(data).values()) == {iso_utc(RETIRED_AT + 7)}


def test_run_once_stamps_with_a_fresh_clock_read(data, monkeypatch):
    data.add_batch(T0, neigh=["02:00:5e:00:00:41"])
    processor.run_once(PipelineConfig(data_dir=data.root), now=T0 + 60)
    ticks = iter(range(int(RETIRED_AT), int(RETIRED_AT) + 100_000))
    monkeypatch.setattr(processor, "time", SimpleNamespace(time=lambda: float(next(ticks))))
    processor.run_once(PipelineConfig(data_dir=data.root))  # pass start = the first tick
    (since,) = stamps(data).values()
    assert since > iso_utc(RETIRED_AT)  # read after the pass began


def test_a_rule_retired_orphan_is_stamped_when_it_is_retired(data):
    ov, dev = seeded(data)
    appear(data, 2, 400, 1100)
    data.inv.execute(
        "INSERT OR IGNORE INTO stitch_state (key, value) VALUES (?, '1')", (BACKFILL_KEY,)
    )
    run(data)
    (orphan,) = [r[0] for r in data.q("SELECT id FROM devices WHERE status='retired'")]
    assert orphan != dev
    assert stamps(data)[orphan] > iso_utc(T0 + 1100)  # not the creation time it was stamped with
    ov.close()


def test_the_retirement_path_that_never_stamped_is_not_prunable(data):
    retire(data)
    migrated_overrides(data.root)
    data.inv.execute("DELETE FROM transient_state")
    processor.run_once(PipelineConfig(data_dir=data.root), now=LATER)
    assert rows(data) == 1
    assert FRONTIER > LATER


# ---- stamps erased by a rolled-back build are derived again --------------------------------


def test_stamps_erased_by_a_rollback_are_derived_again_once_the_interval_passed(data):
    (device,) = retire(data).values()
    set_clock(data, None)  # no send floor: these sweeps are driven by the clock they are given
    data.inv.execute("DELETE FROM transient_state")  # the previous build's sweep erased them
    sweep_transients(data.inv, RETIRED_AT + RETIRED_BACKFILL_INTERVAL_S - 1, CONFIG)
    assert stamps(data) == {}  # bounded: not on every pass
    due = RETIRED_AT + RETIRED_BACKFILL_INTERVAL_S
    sweep_transients(data.inv, due, CONFIG)
    assert stamps(data) == {device: iso_utc(due)}


def test_a_rederived_stamp_makes_the_device_prunable_90_days_later(data):
    retire(data)
    migrated_overrides(data.root)
    set_clock(data, None)  # no send floor: these sweeps are driven by the clock they are given
    data.inv.execute("DELETE FROM transient_state")
    due = RETIRED_AT + RETIRED_BACKFILL_INTERVAL_S
    sweep_transients(data.inv, due, CONFIG)
    set_clock(data, FRONTIER)
    assert prune(data, due + RETENTION) == 0
    assert prune(data, due + RETENTION + 1) == 1


def test_a_backfill_marker_from_the_future_counts_as_due(data):
    (device,) = retire(data).values()
    set_clock(data, None)  # no send floor: these sweeps are driven by the clock they are given
    data.inv.execute("DELETE FROM transient_state")
    data.inv.execute(  # the clock was set back since the last scan
        "UPDATE stitch_state SET value=? WHERE key=?", (iso_utc(LATER + 86400), BACKFILL_KEY)
    )
    sweep_transients(data.inv, LATER, CONFIG)
    assert stamps(data) == {device: iso_utc(LATER)}


# all sort before the stamp, so they reach the parse
@pytest.mark.parametrize("junk", ["", "0", "2026-99-99T99:00:00Z"])
def test_an_unreadable_backfill_marker_counts_as_due_and_is_rewritten(data, junk):
    (device,) = retire(data).values()
    set_clock(data, None)  # no send floor: these sweeps are driven by the clock they are given
    data.inv.execute("DELETE FROM transient_state")
    data.inv.execute(
        "INSERT OR REPLACE INTO stitch_state (key, value) VALUES (?, ?)", (BACKFILL_KEY, junk)
    )
    sweep_transients(data.inv, LATER, CONFIG)
    assert stamps(data) == {device: iso_utc(LATER)}
    assert data.q("SELECT value FROM stitch_state WHERE key=?", BACKFILL_KEY)[0][0] == iso_utc(
        LATER
    )


# ---- a clock set back cannot backdate a stamp ----------------------------------------------


def make_transient(data):
    data.add_batch(T0, neigh=["02:00:5e:00:00:41"])
    processor.run_once(PipelineConfig(data_dir=data.root), now=RETIRED_AT - 3600)  # transient


def test_a_retirement_is_not_backdated_before_the_newest_batch_receipt(data):
    make_transient(data)
    newest = RETIRED_AT + 5 * 86400
    data.add_batch(newest, neigh=[])  # received on a clock that has since been set back
    sweep_transients(data.inv, RETIRED_AT, CONFIG)
    assert set(stamps(data).values()) == {iso_utc(newest)}


def test_with_no_batch_recorded_the_stamp_is_the_clock(data):
    make_transient(data)
    data.inv.execute("DELETE FROM batches")
    sweep_transients(data.inv, RETIRED_AT, CONFIG)
    assert set(stamps(data).values()) == {iso_utc(RETIRED_AT)}


def test_a_clock_ahead_of_every_batch_is_stamped_as_it_is(data):
    make_transient(data)
    sweep_transients(data.inv, RETIRED_AT + 9, CONFIG)
    assert set(stamps(data).values()) == {iso_utc(RETIRED_AT + 9)}


def test_the_backfill_stamp_is_clamped_too(data):
    (device,) = retire(data).values()
    set_clock(data, None)  # no send floor: these sweeps are driven by the clock they are given
    data.inv.execute("DELETE FROM transient_state")
    data.inv.execute("DELETE FROM stitch_state WHERE key=?", (BACKFILL_KEY,))
    newest = LATER + 7 * 86400
    data.add_batch(newest, neigh=[])
    sweep_transients(data.inv, LATER, CONFIG)
    assert stamps(data) == {device: iso_utc(newest)}


def test_a_rule_retired_orphan_stamp_is_clamped_too(data):
    ov, dev = seeded(data)
    appear(data, 2, 400, 1100)
    data.inv.execute(
        "INSERT OR IGNORE INTO stitch_state (key, value) VALUES (?, '1')", (BACKFILL_KEY,)
    )
    newest = T0 + 30 * 86400
    data.add_batch(newest, neigh=[])
    run(data)
    (orphan,) = [r[0] for r in data.q("SELECT id FROM devices WHERE status='retired'")]
    assert stamps(data)[orphan] >= iso_utc(newest)
    ov.close()


def test_a_retired_device_leaves_no_transient_hours_behind(data):
    """The sweep clears the hours of every device that is no longer transient, retired ones too."""
    retire(data)
    assert data.q("SELECT 1 FROM transient_hours") == []


def test_the_stamp_floor_survives_purged_batch_rows(data):
    """purge_batches deletes the receipts the floor reads; `last_sent_ts` is never purged."""
    make_transient(data)
    sent = RETIRED_AT + 5 * 86400
    data.inv.execute("DELETE FROM batches")
    data.inv.execute("UPDATE collectors SET last_sent_ts=?", (sent,))
    sweep_transients(data.inv, RETIRED_AT, CONFIG)
    assert set(stamps(data).values()) == {iso_utc(sent)}


def test_a_junk_last_sent_ts_does_not_move_the_stamp(data):
    make_transient(data)
    data.inv.execute("DELETE FROM batches")
    data.inv.execute("UPDATE collectors SET last_sent_ts='zzz'")
    sweep_transients(data.inv, RETIRED_AT, CONFIG)
    assert set(stamps(data).values()) == {iso_utc(RETIRED_AT)}


@pytest.mark.parametrize(
    ("ahead_s", "warned"), [(86400, False), (86401, True)], ids=["exactly-a-day", "past-a-day"]
)
def test_a_stamp_pushed_ahead_by_a_stepped_clock_is_named_in_a_warning(
    data, caplog, ahead_s, warned
):
    """A batch received under a forward-stepped clock makes every later retirement unprunable
    until that date; say so once per sweep that retires something."""
    make_transient(data)
    data.inv.execute("DELETE FROM batches")
    data.inv.execute("UPDATE collectors SET last_sent_ts=?", (RETIRED_AT + ahead_s,))
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        sweep_transients(data.inv, RETIRED_AT, CONFIG)
    assert ("retirement_stamp_ahead" in [r.getMessage() for r in caplog.records]) is warned


def test_no_stamp_warning_when_nothing_is_retired(data, caplog):
    make_transient(data)  # still inside its window: nothing is due
    data.inv.execute("UPDATE collectors SET last_sent_ts=?", (RETIRED_AT + 30 * 86400,))
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        sweep_transients(data.inv, RETIRED_AT - 3000, CONFIG)
    assert data.q("SELECT status FROM devices")[0][0] == "transient"
    assert "retirement_stamp_ahead" not in caplog.text
