from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from vigie_api.schema import open_inventory_ro, open_overrides


def test_groups_seeded_with_auto_inherit_defaults(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "overrides.db")
    rows = {r[0]: r[1] for r in conn.execute("SELECT id, auto_inherit FROM groups")}
    assert rows == {"trusted": 0, "kids": 0, "iot": 1, "guest": 1, "quarantine": 0}


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "overrides.db"
    open_overrides(path).close()
    conn = open_overrides(path)
    assert conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0] == 5
    assert conn.execute("PRAGMA user_version").fetchone()[0] >= 1


def test_expected_tables_exist(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "groups", "device_overrides", "identity_links", "identity_rules", "identity_merges",
        "suggestion_decisions", "audit_log", "api_tokens",
    } <= names  # fmt: skip


def test_delete_trigger_aborts(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    conn.execute(
        "INSERT INTO device_overrides (device_id, updated_at, updated_by) VALUES ('d','t','u')"
    )
    with pytest.raises(sqlite3.DatabaseError, match="never deleted"):
        conn.execute("DELETE FROM device_overrides WHERE device_id='d'")
    assert conn.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 1


def test_identity_link_self_reference_rejected(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO identity_links (from_device,into_device,merge_id,created_at,created_by)"
            " VALUES ('a','a','m','t','u')"
        )


def test_override_group_fk_enforced(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO device_overrides (device_id, group_id, updated_at, updated_by)"
            " VALUES ('d','nope','t','u')"
        )


def test_newer_schema_refused(tmp_path: Path) -> None:
    path = tmp_path / "o.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version=999")
    conn.close()
    with pytest.raises(RuntimeError, match="newer"):
        open_overrides(path)


def _inventory(tmp_path: Path) -> Path:
    path = tmp_path / "inventory.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    return path


def test_inventory_connection_cannot_write(tmp_path: Path) -> None:
    conn = open_inventory_ro(_inventory(tmp_path))
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO t VALUES (1)")


def test_inventory_query_only_pragma_is_on(tmp_path: Path) -> None:
    conn = open_inventory_ro(_inventory(tmp_path))
    assert conn.execute("PRAGMA query_only").fetchone()[0] == 1


def test_inventory_uri_mode_ro_blocks_write_even_with_query_only_off(tmp_path: Path) -> None:
    conn = open_inventory_ro(_inventory(tmp_path))
    conn.execute("PRAGMA query_only=OFF")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("INSERT INTO t VALUES (1)")


def test_inventory_missing_is_not_created(tmp_path: Path) -> None:
    assert open_inventory_ro(tmp_path / "inventory.db") is None
    assert not (tmp_path / "inventory.db").exists()
