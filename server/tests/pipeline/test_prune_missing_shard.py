"""Ingest retention removes raw shards before it purges batch records. In that gap a recorded
batch reads as empty: its cursor advances and no MAC in it is seen, so the prune must wait."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, migrated_overrides, retire, rows

from vigie_ingest.retention import purge_shards
from vigie_pipeline import processor, sources
from vigie_pipeline.config import PipelineConfig

DAY = 86400


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def run(data, now=LATER):
    return processor.run_once(PipelineConfig(data_dir=data.root), now=now)


def test_a_recorded_batch_whose_shard_is_gone_defers_the_prune(data, caplog):
    ((mac, _),) = retire(data).items()
    migrated_overrides(data.root)
    data.add_batch(LATER, neigh=[mac])
    assert purge_shards(data.root, LATER + 8 * DAY, 7)  # shards gone, the batch row remains
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        assert run(data).batches == 1  # read as empty: the cursor advanced
    assert "prune_deferred" in caplog.text
    assert rows(data) == 1


def test_present_shards_do_not_defer(data):
    retire(data)
    migrated_overrides(data.root)
    data.add_batch(LATER)
    run(data)
    assert rows(data) == 0


def test_the_gap_is_judged_from_the_batch_window_not_only_its_receipt(data):
    retire(data)
    migrated_overrides(data.root)
    data.add_batch(LATER)
    data.inv.execute("UPDATE batches SET window_start=? WHERE rowid=2", (LATER - 3 * DAY,))
    for path in sources.shard_paths(data.root)[:-1]:
        path.unlink()  # older shards gone, the receipt day's shard remains
    run(data)
    assert rows(data) == 1
