from __future__ import annotations

import sqlite3

import pytest

from vigie_ingest.db import open_inventory
from vigie_pipeline.schema import PIPELINE_TABLES, open_pipeline_inventory

EVENT_SQL = (
    "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
    " VALUES (?, 'd', 't', ?, 'info', 's')"
)


def tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_fresh_database_gets_all_tables(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db")
    assert set(PIPELINE_TABLES) <= tables(conn)
    assert {"devices", "observations", "batches", "collectors"} <= tables(conn)


def test_applies_on_database_already_at_ingest_latest(tmp_path):
    path = tmp_path / "inventory.db"
    ing = open_inventory(path)
    version = ing.execute("PRAGMA user_version").fetchone()[0]
    ing.close()
    conn = open_pipeline_inventory(path)
    assert set(PIPELINE_TABLES) <= tables(conn)
    # pipeline never touches ingest's user_version
    assert conn.execute("PRAGMA user_version").fetchone()[0] == version


def test_reapply_is_noop(tmp_path):
    path = tmp_path / "inventory.db"
    open_pipeline_inventory(path).close()
    conn = open_pipeline_inventory(path)
    assert conn.execute("SELECT COUNT(*) FROM pipeline_schema").fetchone()[0] == 1


def test_new_device_event_unique_per_device(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db")
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    conn.execute(EVENT_SQL, ("e1", "new_device"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(EVENT_SQL, ("e2", "new_device"))
    conn.execute(EVENT_SQL, ("e3", "anomaly"))


def test_delete_trigger_blocks_device_delete(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db")
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
        conn.execute("DELETE FROM devices WHERE id='d'")


def test_device_status_check(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO devices (id, first_seen, last_seen, status) VALUES ('d','t','t','bogus')"
        )


def test_link_source_check(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db")
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO observations (mac, device_id, is_randomized, link_source, first_seen,"
            " last_seen) VALUES ('m','d',0,'bogus','t','t')"
        )
