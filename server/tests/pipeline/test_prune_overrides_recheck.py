"""A human decision committed to overrides.db between the prune's protected-set read and its
commit defers the prune: nothing is deleted, nothing is logged but the count-free deferral."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, STAMP, migrated_overrides, prune, retire, rows

from vigie_pipeline import processor

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
    real = processor.protected_device_ids

    def read_then_race(conn):
        protected = real(conn)
        writer = sqlite3.connect(path)
        writer.execute(statement, (device_id, STAMP))
        writer.commit()
        writer.close()
        return protected

    monkeypatch.setattr(processor, "protected_device_ids", read_then_race)


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
    assert data.q("SELECT 1 FROM pipeline_meta WHERE key=?", processor.PRUNED_COUNTER_KEY) == []


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
    real = processor.overrides_data_version
    calls = []

    def second_read_fails(conn):
        calls.append(1)
        if len(calls) > 1:
            raise sqlite3.OperationalError("database is locked")
        return real(conn)

    monkeypatch.setattr(processor, "overrides_data_version", second_read_fails)
    assert prune(data, LATER) == 0
    assert len(calls) == 2
    assert rows(data) == 1
