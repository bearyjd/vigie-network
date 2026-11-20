"""A human decision committed to overrides.db between the prune's protected-set read and its
commit defers the prune: nothing is deleted, nothing is logged but the count-free deferral."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, STAMP, migrated_overrides, prune, retire, rows

from vigie_pipeline import processor
from vigie_pipeline import prune as prune_module

ESSENTIAL = (
    "INSERT INTO essential_devices (device_id, updated_at, updated_by, version)"
    " VALUES (?, ?, 'u', 1)"
)
NAME = "INSERT INTO device_overrides (device_id, name, updated_at, updated_by) VALUES (?,'Kitchen',?,'u')"  # noqa: E501


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def commit_after_protected_read(monkeypatch, path, statement, device_id):
    """Seam: a second connection commits right after the protected set was read."""
    real = prune_module.protected_device_ids

    def read_then_race(conn):
        protected = real(conn)
        writer = sqlite3.connect(path)
        writer.execute(statement, (device_id, STAMP))
        writer.commit()
        writer.close()
        return protected

    monkeypatch.setattr(prune_module, "protected_device_ids", read_then_race)


@pytest.mark.parametrize("statement", [ESSENTIAL, NAME], ids=["essential_mark", "device_name"])
def test_a_decision_committed_mid_prune_defers_it(data, monkeypatch, caplog, statement):
    macs = retire(data)
    path = migrated_overrides(data.root)
    commit_after_protected_read(monkeypatch, path, statement, next(iter(macs.values())))
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1
    assert "prune_deferred" in caplog.text
    assert not any(mac in caplog.text for mac in macs)
    assert data.q("SELECT 1 FROM pipeline_meta WHERE key=?", prune_module.PRUNED_COUNTER_KEY) == []


def test_the_next_pass_sees_the_decision_and_still_protects_the_row(data, monkeypatch):
    macs = retire(data)
    path = migrated_overrides(data.root)
    with monkeypatch.context() as m:
        commit_after_protected_read(m, path, ESSENTIAL, next(iter(macs.values())))
        assert prune(data) == 0
    assert prune(data) == 0  # the committed mark is now in the protected set
    assert rows(data) == 1


def test_an_untouched_overrides_db_still_prunes(data):
    retire(data)
    migrated_overrides(data.root)
    assert prune(data, LATER) == 1


def test_a_re_check_that_cannot_read_overrides_defers_the_prune(data, monkeypatch):
    retire(data)
    migrated_overrides(data.root)
    real = prune_module.overrides_data_version
    calls = []

    def second_read_fails(conn):
        calls.append(1)
        if len(calls) > 1:
            raise sqlite3.OperationalError("database is locked")
        return real(conn)

    monkeypatch.setattr(prune_module, "overrides_data_version", second_read_fails)
    assert prune(data, LATER) == 0
    assert len(calls) == 2
    assert rows(data) == 1


def test_the_names_the_race_tests_patch_are_the_ones_the_prune_calls(data, monkeypatch):
    """A patch that lands on a module the prune does not read from would silently do nothing, and
    every injected-race test above would pass for nothing."""
    retire(data)
    migrated_overrides(data.root)
    called = []
    for name in ("open_overrides_ro", "overrides_data_version", "protected_device_ids"):
        real = getattr(prune_module, name)

        def spy(*args, _name=name, _real=real, **kwargs):
            called.append(_name)
            return _real(*args, **kwargs)

        monkeypatch.setattr(prune_module, name, spy)
    select = prune_module._prune_candidates

    def spy_select(*args):
        called.append("_prune_candidates")
        return select(*args)

    monkeypatch.setattr(prune_module, "_prune_candidates", spy_select)
    monkeypatch.setattr(prune_module, "PRUNE_BATCH_ROWS", 0)  # the cap is read from this module
    assert prune(data) == 0
    assert set(called) == {
        "open_overrides_ro",
        "overrides_data_version",
        "protected_device_ids",
        "_prune_candidates",
    }
    assert rows(data) == 1  # the zero cap held: the patched constant is the one in effect


def test_the_processor_no_longer_exposes_the_names_the_prune_reads_through():
    for name in ("protected_device_ids", "overrides_data_version", "PRUNE_BATCH_ROWS"):
        assert not hasattr(processor, name), name  # a stale patch on processor fails loudly
