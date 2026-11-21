"""The retention, warning and backfill windows are pinned as literal numbers of days: a test that
reads the constant back from config would follow any change of it."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_clock import add_collector
from test_prune_guards import RETIRED_AT, migrated_overrides, prune, retire, set_clock
from test_prune_stamp import CONFIG, stamps

from vigie_ingest.db import iso_utc
from vigie_pipeline.processor import BACKFILL_KEY, sweep_transients

DAY = 86400


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def test_a_retired_device_is_kept_for_exactly_90_days(data):
    retire(data)
    migrated_overrides(data.root)
    set_clock(data, RETIRED_AT + 90 * DAY)
    assert prune(data, RETIRED_AT + 400 * DAY) == 0
    set_clock(data, RETIRED_AT + 90 * DAY + 1)
    assert prune(data, RETIRED_AT + 400 * DAY) == 1


@pytest.mark.parametrize(
    ("silent_s", "named"), [(7 * DAY - 1, False), (7 * DAY + 1, True)], ids=["under", "over"]
)
def test_a_binding_collector_is_named_after_exactly_7_silent_days(data, caplog, silent_s, named):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "silent-rtr", RETIRED_AT)
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        prune(data, RETIRED_AT + silent_s)
    assert ("prune_clock_held_back" in caplog.text) is named


@pytest.mark.parametrize(("later_s", "rescanned"), [(DAY - 1, False), (DAY, True)])
def test_the_stamp_backfill_rescans_devices_once_a_day(data, later_s, rescanned):
    (device,) = retire(data).values()
    data.inv.execute("DELETE FROM transient_state")
    data.inv.execute(
        "INSERT OR REPLACE INTO stitch_state (key, value) VALUES (?, ?)",
        (BACKFILL_KEY, iso_utc(RETIRED_AT)),
    )
    sweep_transients(data.inv, RETIRED_AT + later_s, CONFIG, retired_at=RETIRED_AT + later_s)
    assert (stamps(data) != {}) is rescanned
    assert not rescanned or device in stamps(data)
