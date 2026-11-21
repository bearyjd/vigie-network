"""The prune's clock is the oldest `collectors.last_sent_ts` of the live collectors (never past the
server's own time): ingest keeps it as a never-purged running maximum of accepted send times,
and accepts one only within the skew window of the server clock, so neither a stepped server
clock nor a purged batch row can move it."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import T0, data  # noqa: F401
from test_prune_guards import (
    LATER,
    RETENTION,
    RETIRED_AT,
    migrated_overrides,
    prune,
    retire,
    rows,
    set_clock,
)

from vigie_ingest import store
from vigie_ingest.config import Settings
from vigie_ingest.db import iso_utc
from vigie_ingest.retention import purge_batches

SILENT_DAYS = 8  # past the 7 days after which a collector that holds the clock back is named
SKEW = Settings.__dataclass_fields__["max_clock_skew_s"].default


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def add_collector(data, name, last_sent_ts, revoked=0):
    data.inv.execute("INSERT OR IGNORE INTO collectors (id, key_id) VALUES (?, 'k9')", (name,))
    data.inv.execute(
        "UPDATE collectors SET last_sent_ts=?, revoked=? WHERE id=?", (last_sent_ts, revoked, name)
    )


def test_the_oldest_live_collector_holds_the_clock_back(data):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "stalled", RETIRED_AT + 3600)  # alive on paper, silent since
    assert prune(data, LATER) == 0
    assert rows(data) == 1


def test_a_revoked_collector_no_longer_holds_it(data):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "gone", RETIRED_AT + 3600, revoked=1)
    assert prune(data, LATER) == 1


def test_a_collector_that_never_sent_is_not_evidence_either_way(data):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "fresh", 0)
    assert prune(data, LATER) == 1


def test_only_collectors_that_never_sent_prune_nothing(data):
    retire(data)
    migrated_overrides(data.root)
    set_clock(data, None)
    assert prune(data, LATER) == 0
    assert rows(data) == 1


def test_a_server_clock_ahead_of_every_collector_prunes_nothing(data):
    retire(data)
    migrated_overrides(data.root)
    set_clock(data, RETIRED_AT + 3600)
    assert prune(data, RETIRED_AT + 365 * 86400) == 0


def test_the_collectors_clock_sets_the_90_day_boundary_when_it_trails_the_server(data):
    retire(data)
    migrated_overrides(data.root)
    set_clock(data, RETIRED_AT + RETENTION + 1)  # one second past the stamp's 90 days
    assert prune(data, LATER) == 1
    set_clock(data, RETIRED_AT + RETENTION)  # exactly 90 days: not yet
    assert prune(data, LATER) == 0


def test_a_stepped_server_clock_with_one_collector_that_kept_true_time_prunes_nothing(data):
    """Round-3 probe: the server clock jumps 100 days; collector A follows it, collector B (true
    time) is rejected as out of range and its batch rows age out of purge_batches."""
    retire(data)
    migrated_overrides(data.root)
    stepped = RETIRED_AT + 100 * 86400
    set_clock(data, stepped)  # A, accepted because it follows the stepped clock
    data.add_batch(T0, collector="rtr-b", neigh=["02:00:5e:00:00:31"])
    add_collector(data, "rtr-b", RETIRED_AT + 3600)
    row = store.get_collector(data.inv, "rtr-b")
    assert (
        store.check_state(data.inv, row, "b2", "boot", 1, RETIRED_AT + 7200, stepped, SKEW)
        == "bad_ts"
    )  # B's true-time batch is turned away: its last_sent_ts cannot move
    assert purge_batches(data.inv, stepped, 7) > 0
    assert data.q("SELECT 1 FROM batches WHERE collector_id='rtr-b'") == []
    assert prune(data, stepped + RETENTION) == 0
    assert rows(data) == 1


def test_a_collector_whose_clock_is_far_ahead_cannot_raise_its_last_sent_ts(data):
    add_collector(data, "ahead", T0)
    row = store.get_collector(data.inv, "ahead")
    assert store.check_state(data.inv, row, "b1", "boot", 1, T0 + 100 * 86400, T0, SKEW) == "bad_ts"


def test_a_binding_collector_silent_for_over_a_week_is_named_in_a_warning(data, caplog):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "silent-rtr", RETIRED_AT)
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        prune(data, RETIRED_AT + SILENT_DAYS * 86400)
    (warning,) = [r for r in caplog.records if r.getMessage() == "prune_clock_held_back"]
    assert warning.levelno == logging.WARNING
    assert warning.fields["collector"] == "silent-rtr"


def test_a_collector_silent_for_under_a_week_is_not_named(data, caplog):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "recent", RETIRED_AT)
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        prune(data, RETIRED_AT + 6 * 86400)
    assert "prune_clock_held_back" not in caplog.text


def test_no_warning_when_the_server_clock_is_the_binding_minimum(data, caplog):
    retire(data)
    migrated_overrides(data.root)
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        prune(data, LATER)  # every collector is ahead of the server
    assert "prune_clock_held_back" not in caplog.text


@pytest.mark.parametrize("junk", ["not-a-time", b"\x00\x01"], ids=["text", "blob"])
def test_a_last_sent_ts_that_is_not_a_number_skips_the_pass_instead_of_dropping_out(
    data, caplog, junk
):
    """Sorted among numbers it would sit last and silently leave the minimum; compared with a
    number it would crash the pass."""
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "junk-rtr", junk)
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data, LATER) == 0
    assert rows(data) == 1
    assert any(r.getMessage() == "prune_skipped" for r in caplog.records)


def test_a_revoked_collector_with_a_junk_last_sent_ts_is_ignored(data):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "junk-rtr", "not-a-time", revoked=1)
    assert prune(data, LATER) == 1


def test_a_fractional_last_sent_ts_is_still_a_time(data):
    retire(data)
    migrated_overrides(data.root)
    set_clock(data, RETIRED_AT + RETENTION + 1.5)
    assert prune(data, LATER) == 1


def held_back_warnings(caplog):
    return [r for r in caplog.records if r.getMessage() == "prune_clock_held_back"]


def test_the_held_back_warning_repeats_at_most_once_a_day(data, caplog):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "silent-rtr", RETIRED_AT)
    first = RETIRED_AT + SILENT_DAYS * 86400
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        prune(data, first)
        prune(data, first + 60)
        prune(data, first + 86400 - 1)
        assert len(held_back_warnings(caplog)) == 1
        prune(data, first + 86400)
        assert len(held_back_warnings(caplog)) == 2


def test_a_held_back_warning_marker_from_the_future_does_not_silence_it(data, caplog):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "silent-rtr", RETIRED_AT)
    now = RETIRED_AT + SILENT_DAYS * 86400
    data.inv.execute(  # the clock was set back since the last warning
        "INSERT INTO stitch_state (key, value) VALUES ('prune_clock_warned', ?)",
        (iso_utc(now + 10 * 86400),),
    )
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        prune(data, now)
    assert len(held_back_warnings(caplog)) == 1
