"""Boundary, log-level and resource guards of the prune and the retirement stamp, one test each."""

from __future__ import annotations

import logging
import sqlite3
from types import SimpleNamespace

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_clock import SILENT_DAYS, add_collector, held_back_warnings
from test_prune_guards import (
    RETIRED_AT,
    migrated_overrides,
    prune,
    retire,
    set_clock,
)
from test_prune_stamp import CONFIG, make_transient, stamps

from vigie_ingest.db import iso_utc
from vigie_pipeline import processor
from vigie_pipeline import prune as prune_module
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.processor import BACKFILL_KEY, sweep_transients
from vigie_pipeline.retirement import retirement_stamp


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def test_a_real_last_sent_ts_moves_the_stamp_floor(data):
    """The prune's own clock check accepts a REAL `last_sent_ts`; so must the stamp floor."""
    retire(data)
    sent = RETIRED_AT + 5 * 86400 + 0.5  # a fractional value keeps REAL storage
    data.inv.execute("DELETE FROM batches")
    data.inv.execute("UPDATE collectors SET last_sent_ts=?", (sent,))
    assert data.q("SELECT typeof(last_sent_ts) FROM collectors")[0][0] == "real"
    assert retirement_stamp(data.inv, RETIRED_AT) == iso_utc(sent)


def test_the_backfill_never_stamps_a_transient_device(data):
    """Only a retired device lacks a stamp by design; a transient one without a row is left."""
    make_transient(data)
    data.inv.execute("DELETE FROM transient_state")
    data.inv.execute("DELETE FROM stitch_state WHERE key=?", (BACKFILL_KEY,))
    sweep_transients(data.inv, RETIRED_AT - 3600, CONFIG)
    assert stamps(data) == {}


def test_a_revival_clears_the_hours_the_device_had_earned(data):
    ((mac, device),) = retire(data).items()
    data.inv.execute("INSERT INTO transient_hours (device_id, hour) VALUES (?, 'h')", (device,))
    act = SimpleNamespace(last_ts=RETIRED_AT)
    processor._revive_if_retired(data.inv, device, mac, act, iso_utc(RETIRED_AT))
    assert data.q("SELECT status FROM devices")[0][0] == "transient"
    assert data.q("SELECT 1 FROM transient_hours") == []


def test_a_held_back_marker_one_second_ahead_does_not_silence_the_warning(data, caplog):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "silent-rtr", RETIRED_AT)
    now = RETIRED_AT + SILENT_DAYS * 86400
    data.inv.execute(
        "INSERT INTO stitch_state (key, value) VALUES ('prune_clock_warned', ?)",
        (iso_utc(now + 1),),
    )
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        prune(data, now)
    assert len(held_back_warnings(caplog)) == 1


def test_the_held_back_warning_names_the_collectors_own_last_send(data, caplog):
    retire(data)
    migrated_overrides(data.root)
    add_collector(data, "silent-rtr", RETIRED_AT)
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        prune(data, RETIRED_AT + SILENT_DAYS * 86400)
    (warning,) = held_back_warnings(caplog)
    assert warning.fields["last_sent_ts"] == RETIRED_AT


class _Spy:
    """A connection stand-in that delegates and notes whether it was closed."""

    def __init__(self, conn):
        self.conn, self.closed = conn, False

    def __getattr__(self, name):
        return getattr(self.conn, name)

    def close(self):
        self.closed = True
        self.conn.close()


def test_a_failed_first_read_closes_the_overrides_connection(data, monkeypatch):
    retire(data)
    path = migrated_overrides(data.root)
    spies = []

    def spying_open(p):
        spies.append(_Spy(open_overrides_ro(p)))
        return spies[-1]

    def broken(_conn):
        raise sqlite3.OperationalError("busy")

    monkeypatch.setattr(prune_module, "open_overrides_ro", spying_open)
    monkeypatch.setattr(prune_module, "overrides_data_version", broken)
    assert prune_module.prune_retired_macs(data.inv, path, RETIRED_AT) == 0
    assert [s.closed for s in spies] == [True]


def test_the_overrides_connection_waits_for_a_busy_writer(data):
    path = migrated_overrides(data.root)
    conn = open_overrides_ro(path)
    try:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    finally:
        conn.close()


def test_a_stamp_pushed_ahead_is_logged_at_warning_level(data, caplog):
    make_transient(data)
    data.inv.execute("DELETE FROM batches")
    set_clock(data, RETIRED_AT + 86401)
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        sweep_transients(data.inv, RETIRED_AT, CONFIG)
    (record,) = [r for r in caplog.records if r.getMessage() == "retirement_stamp_ahead"]
    assert record.levelno == logging.WARNING


def test_a_locked_inventory_while_overrides_db_is_missing_skips_only_the_prune(data, monkeypatch):
    retire(data)  # no overrides.db: the missing-file branch reads the markers from inventory

    def locked(*_args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(prune_module, "state_get", locked)
    assert prune(data) == 0
