"""A lost or recreated overrides.db must not look like "no decisions": once a protected read has
found a decision, a later read that finds none skips the prune."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import (
    LATER,
    PROTECTIONS,
    STAMP,
    migrated_overrides,
    prune,
    retire,
    rows,
    sql,
)

from vigie_api.schema import open_overrides
from vigie_pipeline.prune import OVERRIDES_SEEN_KEY


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def marker(data):
    return data.q("SELECT value FROM stitch_state WHERE key=?", OVERRIDES_SEEN_KEY)


def test_an_install_that_never_had_a_decision_prunes_as_usual(data):
    retire(data)
    migrated_overrides(data.root)
    assert prune(data, LATER) == 1
    assert marker(data) == []


def test_a_decision_sets_the_marker_even_when_it_protects_another_device(data):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, PROTECTIONS["device_overrides"], "some-other-device", STAMP)
    assert prune(data, LATER) == 1
    assert [r[0] for r in marker(data)] == ["1"]


def test_an_overrides_db_recreated_empty_after_a_decision_skips_the_prune(data, caplog):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, PROTECTIONS["device_overrides"], "some-other-device", STAMP)
    assert prune(data, LATER) == 1  # reads the decision, sets the marker
    retire(data, count=2)
    path.unlink()
    open_overrides(path).close()  # a fresh, empty file of the right schema
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data, LATER) == 0
    assert rows(data) == 2
    assert any(r.fields.get("reason") == "overrides_lost_decisions" for r in caplog.records)


def test_a_fresh_install_whose_file_is_empty_is_not_mistaken_for_a_lost_one(data):
    retire(data, count=2)
    migrated_overrides(data.root)
    assert prune(data, LATER) == 2
