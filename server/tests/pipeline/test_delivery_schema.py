from __future__ import annotations

import sqlite3

import pytest

from vigie_pipeline import schema
from vigie_pipeline.schema import apply_pipeline_migrations, open_pipeline_inventory

A, B, C = "a" * 32, "b" * 32, "c" * 32
INSERT = (
    "INSERT INTO incident_deliveries (delivery_id, incident_id, kind, state, next_attempt_at,"
    " created_at, updated_at) VALUES (?, ?, ?, ?, 5, 10, 10)"
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
        "version",
    ]
    assert cols["delivery_id"][5] == 1  # primary key
    assert cols["attempts"][4] == "0"  # default
    indexes = {
        r[1]: [c[2] for c in conn.execute(f"PRAGMA index_info({r[1]})")]
        for r in conn.execute("PRAGMA index_list(incident_deliveries)")
    }
    assert ["state", "next_attempt_at"] in indexes.values()


def test_version_starts_at_zero(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "open", "pending"))
    assert conn.execute("SELECT version FROM incident_deliveries").fetchone()[0] == 0
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE incident_deliveries SET version=NULL")


def test_defaults_and_valid_rows(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "open", "pending"))
    row = conn.execute("SELECT attempts, last_error FROM incident_deliveries")
    assert tuple(row.fetchone()) == (0, None)


@pytest.mark.parametrize(
    "kind,state", [("page", "pending"), ("open", "queued"), ("OPEN", "pending"), ("open", "")]
)
def test_kind_and_state_are_checked(tmp_path, kind, state):
    conn = _fresh(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, (A, "inc", kind, state))


@pytest.mark.parametrize(
    "state", ["pending", "sent", "failed", "suppressed", "expired", "withdrawn"]
)
def test_every_documented_state_is_accepted(tmp_path, state):
    _fresh(tmp_path).execute(INSERT, (A, "inc", "recover", state))


def test_incident_and_kind_are_unique_but_kinds_coexist(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "open", "pending"))
    conn.execute(INSERT, (B, "inc", "recover", "pending"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, (C, "inc", "open", "sent"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, (A, "other", "open", "pending"))  # delivery_id is the key


def test_last_error_is_length_bounded(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "open", "failed"))
    upd = "UPDATE incident_deliveries SET last_error=? WHERE delivery_id=?"
    conn.execute(upd, ("x" * 200, A))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(upd, ("x" * 201, A))


def test_not_null_columns_are_enforced(tmp_path):
    conn = _fresh(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO incident_deliveries (delivery_id, incident_id, kind, state)"
            " VALUES (?,'i','open','sent')",
            (A,),
        )


def test_timestamps_are_integer_epoch_columns(tmp_path):
    conn = _fresh(tmp_path)
    types = {r[1]: r[2] for r in conn.execute("PRAGMA table_info(incident_deliveries)")}
    assert {types[c] for c in ("created_at", "updated_at", "next_attempt_at")} == {"INTEGER"}


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE incident_deliveries SET attempts=-1",
        "UPDATE incident_deliveries SET version=-1",
        "UPDATE incident_deliveries SET next_attempt_at=NULL",  # row is pending
        "UPDATE incident_deliveries SET updated_at=9",  # before created_at (10)
        "UPDATE incident_deliveries SET delivery_id='short'",
        "UPDATE incident_deliveries SET delivery_id='" + "a" * 33 + "'",
    ],
)
def test_row_checks(tmp_path, sql):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "open", "pending"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(sql)


def test_a_null_or_wrong_length_delivery_id_is_refused(tmp_path):
    conn = _fresh(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, (None, "inc", "open", "sent"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, ("a" * 31, "inc", "open", "sent"))
    assert conn.execute("SELECT COUNT(*) FROM incident_deliveries").fetchone()[0] == 0


@pytest.mark.parametrize(
    "column", ["attempts", "next_attempt_at", "created_at", "updated_at", "version"]
)
def test_numeric_columns_only_hold_integers(tmp_path, column):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "open", "pending"))
    for bad in (5.5, "soon"):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(f"UPDATE incident_deliveries SET {column}=?", (bad,))  # noqa: S608


def test_only_a_recover_can_be_withdrawn(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "recover", "withdrawn"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT, (B, "inc", "open", "withdrawn"))


def test_a_sending_row_needs_its_lease_end(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "open", "sending"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE incident_deliveries SET next_attempt_at=NULL")


def test_only_pending_rows_need_a_next_attempt(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute(INSERT, (A, "inc", "open", "sent"))
    conn.execute("UPDATE incident_deliveries SET next_attempt_at=NULL")
    conn.execute("UPDATE incident_deliveries SET updated_at=10, attempts=0")


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
    conn.execute(INSERT, (A, "inc", "open", "sent"))
    assert apply_pipeline_migrations(conn) == 11
    assert apply_pipeline_migrations(conn) == 11
    assert conn.execute("SELECT COUNT(*) FROM pipeline_schema").fetchone()[0] == 11
    assert conn.execute("SELECT state FROM incident_deliveries").fetchone()[0] == "sent"


def test_a_newer_schema_is_still_refused(tmp_path):
    conn = _fresh(tmp_path)
    conn.execute("INSERT INTO pipeline_schema (version) VALUES (12)")
    with pytest.raises(RuntimeError, match="newer"):
        apply_pipeline_migrations(conn)
