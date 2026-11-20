"""The prune is deferred while ingest or an unread batch may still carry a retired MAC: pruning
first would turn a returning MAC into a brand-new device instead of a revived one."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, migrated_overrides, retire, rows

from vigie_ingest.db import connect, shard_name, utc_day
from vigie_pipeline import processor
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.sources import ShardReadError


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def run(data, now=LATER):
    return processor.run_once(PipelineConfig(data_dir=data.root), now=now)


def after_batches_processed(monkeypatch, action):
    """Seam: `action` runs once the pass has read its batches, before the prune."""
    real = processor.sweep_transients

    def sweep_then_act(*args, **kwargs):
        result = real(*args, **kwargs)
        action()
        return result

    monkeypatch.setattr(processor, "sweep_transients", sweep_then_act)


def events(data, kind):
    return len(data.q("SELECT 1 FROM events WHERE kind=?", kind))


def test_a_quiet_pass_still_prunes(data):
    retire(data)
    migrated_overrides(data.root)
    run(data)
    assert rows(data) == 0


def test_a_batch_arriving_mid_pass_defers_and_the_mac_is_revived_not_recreated(
    data, monkeypatch, caplog
):
    ((mac, device),) = retire(data).items()
    migrated_overrides(data.root)
    new_devices = events(data, "new_device")
    with monkeypatch.context() as m, caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        after_batches_processed(m, lambda: data.add_batch(LATER, neigh=[mac]))
        run(data)
    assert rows(data) == 1
    assert "prune_deferred" in caplog.text
    assert mac not in caplog.text
    run(data, LATER + 60)  # the next pass reads the batch: the old device comes back
    assert data.q("SELECT device_id FROM observations")[0][0] == device
    assert events(data, "device_reappeared") == 1
    assert events(data, "new_device") == new_devices


def test_an_unreadable_batch_defers_the_prune(data):
    ((mac, _),) = retire(data).items()
    migrated_overrides(data.root)
    data.add_batch(LATER, neigh=[mac])
    conn = connect(data.root / shard_name(utc_day(LATER)))
    conn.execute("DROP TABLE raw_neigh")
    conn.close()
    with pytest.raises(ShardReadError):
        run(data)
    assert rows(data) == 1


@pytest.mark.parametrize("refill", [False, True], ids=["purged", "purged_and_rowid_reused"])
def test_purged_batches_defer_the_prune(data, monkeypatch, refill):
    ((mac, _),) = retire(data).items()
    migrated_overrides(data.root)

    def purge():
        data.inv.execute("DELETE FROM batches")
        if refill:
            data.add_batch(LATER, neigh=[mac])  # takes the freed rowid: not above the mark

    with monkeypatch.context() as m:
        after_batches_processed(m, purge)
        run(data)
    assert rows(data) == 1
