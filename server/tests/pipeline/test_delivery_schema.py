from __future__ import annotations

import sqlite3

import pytest

from vigie_pipeline import schema
from vigie_pipeline.schema import apply_pipeline_migrations, open_pipeline_inventory

INSERT = (
    "INSERT INTO incident_deliveries (delivery_id, incident_id, kind, state, created_at,"
    " updated_at) VALUES (?, ?, ?, ?, 't', 't')"
)


def _fresh(tmp_path):
    return open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)


def test_fresh_install_has_the_table_and_the_due_index(tmp_path):
    conn = _fresh(tmp_path)
    cols = {r[1]: r for r in conn.execute("PRAGMA table_info(incident_deliveries)")}
    assert list(cols) == [
        "delivery_id",
        "incident_id",
        "kind",
        "state",
        "attempts",
        "next_attempt_at",
        "last_error",
        "created_at",
        "updated_at",
    ]
    assert cols["delivery_id"][5] == 1  # primary key
    assert cols["attempts"][4] == "0"  # default
    indexes = {
        r[1]: [c[2] for c in conn.execute(f"PRAGMA index_info({r[1]})")]
        for r in conn.execute("PRAGMA index_list(incident_deliveries)")
    }
    assert ["state", "next_attempt_at"] in indexes.values()


def test_defaults_and_valid_rows(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, ("a", "inc", "open", "pending"))
    row = conn.execute("SELECT attempts, next_attempt_at, last_error FROM incident_deliveries")
    assert tuple(row.fetchone()) == (0, None, None)


@pytest.mark.parametrize(
    "kind,state", [("page", "pending"), ("open", "queued"), ("OPEN", "pending"), ("open", "")]
)
def test_kind_and_state_are_checked(tmp_path, kind, state):
    conn = _fresh(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, ("a", "inc", kind, state))


@pytest.mark.parametrize("state", ["pending", "sent", "failed", "suppressed", "expired"])
def test_every_documented_state_is_accepted(tmp_path, state):
    _fresh(tmp_path).execute(INSERT, ("a", "inc", "recover", state))


def test_incident_and_kind_are_unique_but_kinds_coexist(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, ("a", "inc", "open", "pending"))
    conn.execute(INSERT, ("b", "inc", "recover", "pending"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, ("c", "inc", "open", "sent"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, ("a", "other", "open", "pending"))  # delivery_id is the key


def test_last_error_is_length_bounded(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, ("a", "inc", "open", "failed"))
    upd = "UPDATE incident_deliveries SET last_error=? WHERE delivery_id='a'"
    conn.execute(upd, ("x" * 200,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(upd, ("x" * 201,))


def test_not_null_columns_are_enforced(tmp_path):
    conn = _fresh(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO incident_deliveries (delivery_id, incident_id, kind, state)"
            " VALUES ('a','i','open','pending')"
        )


def _v10(path, monkeypatch):
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:10])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    conn.execute("INSERT INTO pipeline_cursor VALUES ('collector', 42, 'batch', 'time')")
    conn.execute("INSERT INTO mac_last_ip VALUES ('m', '10.0.0.1', 5, 'lease')")
    assert not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name='incident_deliveries'"
    ).fetchone()
    conn.close()
    monkeypatch.undo()


def test_upgrade_from_v10_keeps_rows_and_adds_the_table(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    _v10(path, monkeypatch)
    conn = open_pipeline_inventory(path)
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 11
    assert conn.execute("SELECT id FROM devices").fetchone()[0] == "d"
    assert tuple(conn.execute("SELECT * FROM pipeline_cursor").fetchone()) == (
        "collector",
        42,
        "batch",
        "time",
    )
    assert conn.execute("SELECT ip FROM mac_last_ip").fetchone()[0] == "10.0.0.1"
    assert conn.execute("SELECT COUNT(*) FROM incident_deliveries").fetchone()[0] == 0


def test_rerunning_the_migration_is_idempotent_and_keeps_deliveries(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, ("a", "inc", "open", "sent"))
    assert apply_pipeline_migrations(conn) == 11
    assert apply_pipeline_migrations(conn) == 11
    assert conn.execute("SELECT COUNT(*) FROM pipeline_schema").fetchone()[0] == 11
    assert conn.execute("SELECT state FROM incident_deliveries").fetchone()[0] == "sent"


def test_a_newer_schema_is_still_refused(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute("INSERT INTO pipeline_schema (version) VALUES (12)")
    with pytest.raises(RuntimeError, match="newer"):
        apply_pipeline_migrations(conn)
