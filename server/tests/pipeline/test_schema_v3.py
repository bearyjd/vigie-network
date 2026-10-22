from __future__ import annotations

import sqlite3

import pytest

from vigie_pipeline import schema
from vigie_pipeline.schema import open_pipeline_inventory

INS = (
    "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
    " VALUES (?, 'd', 't', ?, 'info', 's')"
)


def _v2(path, monkeypatch):
    """A database whose pipeline schema stops at v2, holding data."""
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:2])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    conn.execute(INS, ("zzz", "new_device"))  # id order differs from insertion order
    conn.execute(INS, ("aaa", "anomaly"))
    conn.execute(INS, ("mmm", "drift"))
    conn.close()
    monkeypatch.undo()


def _fresh(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    return conn


def test_upgrade_preserves_rows_in_rowid_order(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    _v2(path, monkeypatch)
    conn = open_pipeline_inventory(path)
    rows = conn.execute("SELECT seq, id, kind FROM events ORDER BY seq").fetchall()
    assert [(r[0], r[1]) for r in rows] == [(1, "zzz"), (2, "aaa"), (3, "mmm")]
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 9
    cols = [r[1] for r in conn.execute("PRAGMA table_info(events)")]
    assert {"seq", "id", "device_id", "ts", "kind", "severity", "summary"} <= set(cols)


def test_upgrade_keeps_new_device_unique_index(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    _v2(path, monkeypatch)
    conn = open_pipeline_inventory(path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INS, ("again", "new_device"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INS, ("aaa", "anomaly"))  # id stays unique


def test_fresh_events_has_autoincrement_seq_and_unique_id(tmp_path):
    conn = _fresh(tmp_path)
    sql = conn.execute("SELECT sql FROM sqlite_master WHERE name='events'").fetchone()[0]
    assert "AUTOINCREMENT" in sql.upper()
    conn.execute(INS, ("e1", "new_device"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INS, ("e1", "anomaly"))


def test_seq_not_reused_after_deleting_newest(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INS, ("e1", "anomaly"))
    conn.execute(INS, ("e2", "anomaly"))
    conn.execute("DELETE FROM events WHERE id='e2'")
    conn.execute(INS, ("e3", "anomaly"))
    assert conn.execute("SELECT seq FROM events WHERE id='e3'").fetchone()[0] == 3


def test_vacuum_does_not_renumber_seq(tmp_path):
    conn = _fresh(tmp_path)
    for i in range(4):
        conn.execute(INS, (f"e{i}", "anomaly"))
    conn.execute("DELETE FROM events WHERE id IN ('e0','e1')")
    before = conn.execute("SELECT seq, id FROM events ORDER BY seq").fetchall()
    conn.execute("VACUUM")
    after = conn.execute("SELECT seq, id FROM events ORDER BY seq").fetchall()
    assert [tuple(r) for r in after] == [tuple(r) for r in before] == [(3, "e2"), (4, "e3")]


def _suggest(conn, action="label", sid="s1"):
    conn.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, reason_text,"
        " basis, created_at, expires_at) VALUES (?,?,'[\"d\"]','{}','rc',NULL,'{}','t','t')",
        (sid, action),
    )


def test_suggestions_exists_fresh_and_check_rejects_bad_action(tmp_path):
    conn = _fresh(tmp_path)
    for i, action in enumerate(("label", "move_group", "quarantine", "merge_identity")):
        _suggest(conn, action, f"s{i}")
    with pytest.raises(sqlite3.IntegrityError):
        _suggest(conn, "delete_everything", "bad")


def test_suggestions_exists_after_upgrade(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    _v2(path, monkeypatch)
    conn = open_pipeline_inventory(path)
    _suggest(conn)
    with pytest.raises(sqlite3.IntegrityError):
        _suggest(conn, "nope", "s2")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(suggestions)")}
    assert cols == {"id", "action", "device_ids", "payload", "reason_code", "reason_text",
                    "basis", "created_at", "expires_at"}  # fmt: skip
