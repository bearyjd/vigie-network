"""The DELETE inside the write lock repeats the whole prunable predicate: a candidate that came
back to life, was stamped anew or gained a protection between the select and the lock is kept.
Each case hooks the candidate select, selects for real, then changes the world."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_exclusions import INVENTORY_SOURCES, _seed
from test_prune_guards import LATER, migrated_overrides, prune, retire, rows

from vigie_ingest.db import iso_utc
from vigie_pipeline import prune as prune_module


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def after_select(monkeypatch, change):
    """Run `change()` right after the real candidate select, before the write lock."""
    real = prune_module._prune_candidates

    def hooked(inv, protected, args):
        picked = real(inv, protected, args)
        assert picked  # the device really was a candidate when it was selected
        change()
        return picked

    monkeypatch.setattr(prune_module, "_prune_candidates", hooked)


def test_the_hook_sees_an_untouched_candidate_deleted(data, monkeypatch):
    retire(data)
    migrated_overrides(data.root)
    after_select(monkeypatch, lambda: None)
    assert prune(data) == 1


CHANGES = {
    "revived": "UPDATE devices SET status='active'",
    "last_seen_refreshed": "UPDATE observations SET last_seen='{later}'",
    "restamped": "UPDATE transient_state SET since='{later}'",
    "no_longer_self_linked": "UPDATE observations SET link_source='rule'",
    "protected_meanwhile": "INSERT INTO prune_protected (id) VALUES ('{dev}')",
}


@pytest.mark.parametrize("change", CHANGES)
def test_a_candidate_that_changed_after_the_select_is_not_deleted(data, monkeypatch, change):
    ((mac, device),) = retire(data).items()
    migrated_overrides(data.root)
    statement = CHANGES[change].format(later=iso_utc(LATER), dev=device)
    after_select(monkeypatch, lambda: data.inv.execute(statement))
    assert prune(data) == 0
    assert rows(data) == 1
    assert mac in [r["mac"] for r in data.q("SELECT mac FROM observations")]


@pytest.mark.parametrize("source", INVENTORY_SOURCES)
def test_an_exclusion_that_appears_after_the_select_keeps_the_row(data, monkeypatch, source):
    ((mac, device),) = retire(data).items()
    migrated_overrides(data.root)
    after_select(monkeypatch, lambda: _seed(data, INVENTORY_SOURCES[source], mac, device))
    assert prune(data) == 0
    assert rows(data) == 1
