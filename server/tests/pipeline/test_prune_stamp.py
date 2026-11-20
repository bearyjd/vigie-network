"""The retirement stamp is the prune's clock: written when a device is retired, by every path
that retires one, and the one-off backfill for legacy rows never rescans devices again."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from pipeline_helpers import T0, data  # noqa: F401
from stitch_helpers import appear, run, seeded
from test_prune_guards import FRONTIER, LATER, RETIRED_AT, migrated_overrides, retire, rows

from vigie_ingest.db import iso_utc
from vigie_pipeline import processor
from vigie_pipeline.config import PipelineConfig
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


def test_the_sweep_never_scans_devices_for_a_backfill_after_the_first_pass(data):
    retire(data)
    seen = []
    data.inv.set_trace_callback(seen.append)
    try:
        sweep_transients(data.inv, LATER, CONFIG)
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
