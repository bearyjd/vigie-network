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


def test_overrides_schema_is_at_version_8(tmp_path: Path) -> None:
    from vigie_api.schema import OVERRIDES_MIGRATIONS

    conn = open_overrides(tmp_path / "o.db")
    assert len(OVERRIDES_MIGRATIONS) == 8
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 8


SHA = "a" * 64
IMPORT_SQL = (
    "INSERT INTO dataset_imports (id,source,version,licence,sha256,entry_count,created_at,"
    "created_by{}) VALUES (?,?,'v','l',?,?,'t','u'{})"
)


def _import(conn, id_="i1", source="kev", sha=SHA, count=1, **extra):
    names = "".join(f",{k}" for k in extra)
    marks = ",?" * len(extra)
    conn.execute(IMPORT_SQL.format(names, marks), (id_, source, sha, count, *extra.values()))


def test_dataset_staging_tables_enforce_their_checks(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    conn.execute("PRAGMA foreign_keys=ON")
    _import(conn)
    row = conn.execute("SELECT status, skipped_count, accepted_by FROM dataset_imports").fetchone()
    assert tuple(row) == ("staged", 0, None)
    with pytest.raises(sqlite3.IntegrityError):  # unknown source
        _import(conn, "i2", source="x")
    with pytest.raises(sqlite3.IntegrityError):  # unknown status
        _import(conn, "i3", status="bad")
    with pytest.raises(sqlite3.IntegrityError):  # entries need their import
        conn.execute("INSERT INTO dataset_entries_staging VALUES ('nope','k','{}')")
    with pytest.raises(sqlite3.IntegrityError):  # one row per (import, key)
        conn.execute("INSERT INTO dataset_entries_staging VALUES ('i1','k','{}')")
        conn.execute("INSERT INTO dataset_entries_staging VALUES ('i1','k','{}')")


@pytest.mark.parametrize(
    "extra",
    [{"skipped_count": -1}, {"sha": "abc"}, {"sha": "a" * 65}, {"count": -1}],
)
def test_dataset_import_numeric_and_hash_checks(tmp_path: Path, extra) -> None:
    conn = open_overrides(tmp_path / "o.db")
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, **{k: v for k, v in extra.items()})


def test_accepted_status_needs_an_accept_record(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    for n, extra in enumerate(
        [{"status": "accepted"}, {"status": "accepted", "accepted_by": "u"},
         {"status": "accepted", "accepted_at": "t"}]
    ):  # fmt: skip
        with pytest.raises(sqlite3.IntegrityError):
            _import(conn, f"x{n}", sha=f"{n}" * 64, **extra)
    with pytest.raises(sqlite3.IntegrityError):  # an empty accept record is no record
        _import(conn, "e1", sha="e" * 64, status="accepted", accepted_by="", accepted_at="t")
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, "e2", sha="f" * 64, status="accepted", accepted_by="u", accepted_at="")
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, "e3", sha="d" * 64, accepted_by="")
    _import(conn, "ok", status="accepted", accepted_by="u", accepted_at="t")
    _import(conn, "st", sha="b" * 64, accepted_by="u")  # staged rows may carry a stray value


def test_dataset_import_is_unique_per_source_and_hash(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    _import(conn, "a")
    _import(conn, "b", source="urlhaus")  # same hash under another source is fine
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, "c")
