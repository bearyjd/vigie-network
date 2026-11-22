"""A pass that could not read one of its batches prunes nothing: the unread batch may carry a
retired MAC that is returning."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, migrated_overrides, retire, rows

from vigie_ingest.db import connect, shard_name, utc_day
from vigie_pipeline import processor
from vigie_pipeline import prune as prune_module
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.sources import ShardReadError


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def run(data, now=LATER):
    return processor.run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=now)


def test_a_quiet_pass_still_prunes(data):
    retire(data)
    migrated_overrides(data.root)
    run(data)
    assert rows(data) == 0


def test_an_unreadable_batch_skips_the_prune_and_the_next_clean_pass_prunes(data):
    ((mac, _),) = retire(data).items()
    migrated_overrides(data.root)
    data.add_batch(LATER, neigh=[mac])
    path = data.root / shard_name(utc_day(LATER))
    conn = connect(path)
    conn.execute("ALTER TABLE raw_neigh RENAME TO raw_neigh_gone")
    conn.close()
    with pytest.raises(ShardReadError):
        run(data)
    assert rows(data) == 1
    conn = connect(path)
    conn.execute("ALTER TABLE raw_neigh_gone RENAME TO raw_neigh")
    conn.close()
    run(data, LATER + 60)  # the batch is read: the MAC is revived, so nothing is left to prune
    assert rows(data) == 1


def test_a_prune_skipped_for_an_unread_batch_says_so_without_naming_a_mac(data, caplog):
    ((mac, _),) = retire(data).items()
    migrated_overrides(data.root)
    data.add_batch(LATER, neigh=[mac])
    conn = connect(data.root / shard_name(utc_day(LATER)))
    conn.execute("ALTER TABLE raw_neigh RENAME TO raw_neigh_gone")
    conn.close()
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"), pytest.raises(ShardReadError):
        run(data)
    (skipped,) = [r for r in caplog.records if r.getMessage() == "prune_skipped"]
    assert skipped.levelno == logging.INFO
    assert skipped.fields == {"reason": "failed_read", "failed_collectors": 1}


@pytest.mark.parametrize("overrides", ["usable", "unreadable"])
def test_a_pass_without_a_failed_read_logs_no_failed_read_skip(data, caplog, overrides):
    retire(data)
    if overrides == "usable":
        migrated_overrides(data.root)
    else:
        (data.root / "overrides.db").write_bytes(b"not a database")
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        run(data)
    assert not [r for r in caplog.records if r.getMessage() == "prune_skipped"]


# ---- a locked or busy database does not stop the rest of the pass ---------------------------


def test_a_busy_database_during_the_prune_skips_it_and_delivery_still_runs(
    data, monkeypatch, caplog
):
    retire(data)
    migrated_overrides(data.root)
    delivered = []

    def busy(*args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(prune_module, "_prune_candidates", busy)
    monkeypatch.setattr(processor, "run_delivery_stage", lambda *a, **k: delivered.append(1))
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        run(data)
    assert delivered == [1]
    (skipped,) = [r for r in caplog.records if r.getMessage() == "prune_skipped"]
    assert skipped.fields == {"error": "database is locked"}
    assert rows(data) == 1
