"""The prune is deferred while ingest or an unread batch may still carry a retired MAC: pruning
first would turn a returning MAC into a brand-new device instead of a revived one."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from pipeline_helpers import T0, data  # noqa: F401
from test_prune_guards import FRONTIER, LATER, RETIRED_AT, migrated_overrides, retire, rows

from vigie_ingest.db import connect, iso_utc, shard_name, utc_day
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


# ---- the cursor must prove a batch above the mark was already processed ------------------

OTHER = "02:00:5e:00:00:21"


def device_of(data, mac):
    return data.q("SELECT device_id FROM observations WHERE mac=?", mac)[0][0]


def test_a_stale_cursor_and_a_reused_low_rowid_defer_and_the_mac_is_revived(data, monkeypatch):
    data.add_batch(T0, neigh=[OTHER])
    data.add_batch(T0, neigh=[OTHER])
    macs = retire(data)  # three processed batches: the cursor sits at rowid 3
    mac = "aa:bb:cc:00:00:01"
    device = macs[mac]
    migrated_overrides(data.root)
    data.inv.execute("DELETE FROM batches")  # retention emptied the table; the cursor stays
    new_devices = events(data, "new_device")
    with monkeypatch.context() as m:
        after_batches_processed(m, lambda: data.add_batch(LATER, neigh=[mac]))  # takes rowid 1
        run(data)
    assert data.q("SELECT last_batch_rowid FROM pipeline_cursor")[0][0] == 3
    assert data.q("SELECT rowid FROM batches")[0][0] == 1  # at or below the stale cursor
    assert rows(data) == 2  # not pruned
    run(data, LATER + 60)  # the next pass resets the stale cursor and reads the batch
    assert device_of(data, mac) == device
    assert events(data, "device_reappeared") == 1
    assert events(data, "new_device") == new_devices


def test_a_stale_cursor_of_one_collector_defers_while_another_collectors_mark_survives(
    data, monkeypatch
):
    data.add_batch(T0, collector="rtr-2", neigh=[OTHER])  # rowid 1: the mark that survives
    macs = retire(data)  # rtr-1 batches take rowids 2..: its cursor is ahead of rowid 1
    data.add_batch(T0, neigh=[OTHER])
    data.add_batch(T0, neigh=[OTHER])
    run(data, RETIRED_AT + 60)
    mac = "aa:bb:cc:00:00:01"
    migrated_overrides(data.root)
    data.inv.execute("DELETE FROM batches WHERE collector_id='rtr-1'")  # its tail is purged
    cursor = data.q("SELECT last_batch_rowid FROM pipeline_cursor WHERE collector_id='rtr-1'")
    assert cursor[0][0] > 2
    with monkeypatch.context() as m:
        after_batches_processed(m, lambda: data.add_batch(LATER, neigh=[mac]))  # rowid 2
        run(data)
    assert data.q("SELECT rowid FROM batches WHERE collector_id='rtr-1'")[0][0] == 2
    assert device_of(data, mac) == macs[mac]
    assert rows(data) == 2


def test_a_cursor_row_purged_mid_pass_while_the_collector_keeps_older_rows_defers(
    data, monkeypatch
):
    data.add_batch(T0, neigh=[OTHER])  # rtr-1 rowid 1
    retire(data)  # rtr-1 rowid 2 is its cursor
    data.add_batch(T0, collector="rtr-2", neigh=[OTHER])  # rowid 3: the mark
    migrated_overrides(data.root)
    data.inv.execute("UPDATE batches SET window_end=?", (FRONTIER,))

    def purge_the_cursor_row():
        data.inv.execute("DELETE FROM batches WHERE collector_id='rtr-1' AND rowid=2")

    with monkeypatch.context() as m:
        after_batches_processed(m, purge_the_cursor_row)
        run(data)
    assert data.q("SELECT rowid FROM batches WHERE collector_id='rtr-1'")[0][0] == 1
    assert rows(data) == 2


def test_a_collector_without_batches_keeps_a_stale_cursor_that_blocks_nothing(data):
    retire(data)
    migrated_overrides(data.root)
    data.inv.execute("INSERT INTO collectors (id, key_id) VALUES ('gone', 'k9')")
    data.inv.execute(
        "INSERT INTO pipeline_cursor (collector_id, last_batch_rowid, last_batch_id, updated_at)"
        " VALUES ('gone', 9, 'old', ?)",
        (iso_utc(T0),),
    )
    run(data)
    assert rows(data) == 0


def test_a_purged_mark_row_defers_even_when_every_cursor_is_intact(data, monkeypatch):
    retire(data)  # rtr-1 rowid 1
    data.add_batch(T0, collector="rtr-2", neigh=[OTHER])  # rowid 2: the mark
    migrated_overrides(data.root)
    data.inv.execute("UPDATE batches SET window_end=?", (FRONTIER,))
    with monkeypatch.context() as m:
        after_batches_processed(
            m, lambda: data.inv.execute("DELETE FROM batches WHERE collector_id='rtr-2'")
        )
        run(data)
    assert rows(data) == 2


# ---- batch_mark is required ----------------------------------------------------------------


def test_the_batch_mark_is_a_required_argument(data):
    retire(data)
    migrated_overrides(data.root)
    with pytest.raises(TypeError):
        processor.prune_retired_macs(data.inv, data.root / "overrides.db", LATER)  # type: ignore[call-arg]
    assert rows(data) == 1


def test_a_none_mark_defers(data):
    retire(data)
    migrated_overrides(data.root)
    assert processor.prune_retired_macs(data.inv, data.root / "overrides.db", LATER, None) == 0
    assert rows(data) == 1


# ---- a locked or busy database does not stop the rest of the pass ---------------------------


def test_a_busy_database_during_the_prune_skips_it_and_delivery_still_runs(
    data, monkeypatch, caplog
):
    retire(data)
    migrated_overrides(data.root)
    delivered = []

    def busy(*args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(processor, "_prune_candidates", busy)
    monkeypatch.setattr(processor, "run_delivery_stage", lambda *a, **k: delivered.append(1))
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        run(data)
    assert delivered == [1]
    (skipped,) = [r for r in caplog.records if r.getMessage() == "prune_skipped"]
    assert skipped.fields == {"error": "database is locked"}
    assert rows(data) == 1
