from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401

from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import open_overrides_ro, overrides_uri
from vigie_pipeline.processor import run_once

NIC = "00:11:22:33:44:55"
ROW = ("a", "b", "m", "t", "u")


def make_wal_overrides(data: Data) -> Path:
    path = data.make_overrides()
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    conn.execute("INSERT INTO identity_links VALUES (?,?,?,?,?)", ROW)
    conn.commit()
    conn.close()
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_uri_is_mode_ro(tmp_path):
    uri = overrides_uri(tmp_path / "overrides.db")
    assert uri.startswith("file:") and uri.endswith("?mode=ro")


def test_query_only_layer_is_on(data):
    conn = open_overrides_ro(data.make_overrides())
    assert conn.execute("PRAGMA query_only").fetchone()[0] == 1


def test_mode_ro_layer_alone_blocks_writes(data):
    conn = open_overrides_ro(data.make_overrides())
    conn.execute("PRAGMA query_only=OFF")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("INSERT INTO identity_links VALUES (?,?,?,?,?)", ROW)


def test_query_only_layer_alone_blocks_writes(data):
    conn = sqlite3.connect(data.make_overrides())  # a read-write connection
    conn.execute("PRAGMA query_only=ON")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("INSERT INTO identity_links VALUES (?,?,?,?,?)", ROW)


def test_wal_overrides_data_is_never_written_by_a_pipeline_run(data):
    path = make_wal_overrides(data)
    before_db = digest(path)
    data.add_batch(neigh=[NIC])
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 10)
    check = sqlite3.connect(path)
    assert check.execute("SELECT * FROM identity_links").fetchall() == [ROW]
    assert check.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    check.close()
    # No data page was written. Reading a WAL database may create/touch the -shm/-wal sidecar
    # files, which is why pipeline and api must run as the same uid/group (see README).
    assert digest(path) == before_db


def test_wal_overrides_links_are_read(data):
    path = make_wal_overrides(data)
    conn = open_overrides_ro(path)
    assert conn.execute("SELECT into_device FROM identity_links").fetchone()[0] == "b"
