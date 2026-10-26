import sqlite3

import pytest

from vigie_api.schema import open_overrides

BASE = ("i1", "c1", "d1", "line", "large_upload", 100)


def insert(ov, status, until, version=1):
    ov.execute(
        "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,detector,"
        "episode_start,status,snooze_until,version,decided_by,decided_at,id)"
        " VALUES (?,?,?,?,?,?,?,?,?,'app:t','2026-01-01T00:00:00Z','x')",
        (*BASE, status, until, version),
    )


def test_table_enforces_status_and_snooze_pairing(tmp_path):
    ov = open_overrides(tmp_path / "o.db")
    insert(ov, "acknowledged", None)
    with pytest.raises(sqlite3.IntegrityError):
        insert(ov, "snoozed", None)
    ov.execute("DELETE FROM incident_decisions")
    insert(ov, "snoozed", 5)
    ov.execute("DELETE FROM incident_decisions")
    with pytest.raises(sqlite3.IntegrityError):
        insert(ov, "acknowledged", 5)
    with pytest.raises(sqlite3.IntegrityError):
        insert(ov, "bogus", None)
    assert ov.execute("PRAGMA index_list(incident_decisions)").fetchall()
