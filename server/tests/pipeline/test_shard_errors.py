from __future__ import annotations

import logging

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401

from vigie_ingest.db import connect, shard_name, utc_day
from vigie_pipeline import sources
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once
from vigie_pipeline.sources import ShardReadError

NIC = "00:11:22:33:44:55"
NIC2 = "00:11:22:33:44:66"


def run(data: Data):
    return run_once(PipelineConfig(data_dir=data.root), now=T0 + 10)


def shard(data: Data):
    return data.root / shard_name(utc_day(T0))


def test_missing_table_raises_and_cursor_does_not_advance(data, caplog):
    data.add_batch(neigh=[NIC], flows=[NIC2])
    conn = connect(shard(data))
    conn.execute("DROP TABLE raw_neigh")
    conn.close()
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"), pytest.raises(ShardReadError):
        run(data)
    assert "shard_read_failed" in caplog.text
    assert data.q("SELECT * FROM pipeline_cursor") == []
    assert data.q("SELECT * FROM devices") == []  # nothing from the failed batch was applied


def test_failed_batch_blocks_later_batches_until_recovered(data):
    data.add_batch(T0, neigh=[NIC])
    data.add_batch(T0 + 60, neigh=[NIC2])
    conn = connect(shard(data))
    conn.execute("ALTER TABLE raw_neigh RENAME TO raw_neigh_gone")
    conn.close()
    with pytest.raises(ShardReadError):
        run(data)
    assert data.q("SELECT * FROM observations") == []
    conn = connect(shard(data))
    conn.execute("ALTER TABLE raw_neigh_gone RENAME TO raw_neigh")
    conn.close()
    assert run(data).batches == 2
    assert len(data.q("SELECT * FROM observations")) == 2


def test_other_collectors_are_still_processed(data):
    data.add_batch(collector="a", neigh=[NIC])
    conn = connect(shard(data))
    conn.execute("ALTER TABLE raw_neigh RENAME TO raw_neigh_gone")
    conn.execute("CREATE TABLE raw_neigh AS SELECT * FROM raw_neigh_gone WHERE 0")
    conn.close()
    data.add_batch(collector="b", flows=[NIC2])
    conn = connect(shard(data))
    conn.execute("DROP TABLE raw_neigh")
    conn.close()
    with pytest.raises(ShardReadError):
        run(data)
    assert data.q("SELECT * FROM pipeline_cursor") == []


def test_cli_once_exits_nonzero_on_unreadable_shard(data):
    from vigie_pipeline import cli

    data.add_batch(neigh=[NIC])
    conn = connect(shard(data))
    conn.execute("DROP TABLE raw_neigh")
    conn.close()
    assert cli.main(["run", "--once", "--data-dir", str(data.root)]) == 1


def test_corrupt_shard_raises(data):
    data.add_batch(neigh=[NIC])
    shard(data).write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(ShardReadError):
        run(data)
    assert data.q("SELECT * FROM pipeline_cursor") == []


def test_missing_shard_file_is_skipped_silently(data, caplog, monkeypatch):
    data.add_batch(neigh=[NIC])
    gone = data.root / "raw-20200101.db"  # listed, then deleted by retention before open
    real = sources.shard_paths
    monkeypatch.setattr(sources, "shard_paths", lambda d: [gone, *real(d)])
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        assert run(data).batches == 1
    assert "shard_read_failed" not in caplog.text and "shard_unreadable" not in caplog.text
    assert not gone.exists()  # the read-only open did not create it
