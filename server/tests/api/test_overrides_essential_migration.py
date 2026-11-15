"""F6-a migration: overrides.db user_version 9 -> 10 adds essential_devices, additive only."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides

PREVIOUS = 9


def _v9_db(path: Path) -> None:
    conn = sqlite3.connect(path, isolation_level=None)
    for index in range(PREVIOUS):
        for statement in OVERRIDES_MIGRATIONS[index]:
            if callable(statement):
                statement(conn)
            else:
                conn.execute(statement)
    conn.execute(f"PRAGMA user_version={PREVIOUS}")
    conn.execute(
        "INSERT INTO device_overrides (device_id,name,version,updated_at,updated_by)"
        " VALUES ('d1','Cam',3,'2026-01-01T00:00:00Z','x')"
    )
    conn.execute(
        "INSERT INTO audit_log (id,ts,principal,action) VALUES ('a','2026-01-01T00:00:00Z','p','x')"
    )
    conn.close()


def _dump(conn: sqlite3.Connection, skip: set[str]) -> dict[str, list]:
    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    return {
        n: [tuple(r) for r in conn.execute(f"SELECT * FROM {n} ORDER BY 1")]  # noqa: S608
        for n in names
        if n not in skip
    }


def test_this_build_is_exactly_one_version_past_the_live_one() -> None:
    assert len(OVERRIDES_MIGRATIONS) == PREVIOUS + 1


def test_upgrade_from_previous_version_keeps_rows_and_adds_table(tmp_path: Path) -> None:
    path = tmp_path / "overrides.db"
    _v9_db(path)
    before = sqlite3.connect(path)
    snapshot = _dump(before, set())
    before.close()
    conn = open_overrides(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == PREVIOUS + 1
    assert _dump(conn, {"essential_devices"}) == snapshot
    assert conn.execute("SELECT COUNT(*) FROM essential_devices").fetchone()[0] == 0
    version = conn.execute("SELECT version FROM device_overrides WHERE device_id='d1'")
    assert version.fetchone()[0] == 3


def test_fresh_db_and_upgraded_db_have_identical_schema(tmp_path: Path) -> None:
    _v9_db(tmp_path / "old.db")
    old = open_overrides(tmp_path / "old.db")
    new = open_overrides(tmp_path / "new.db")
    sql = "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
    assert [tuple(r) for r in old.execute(sql)] == [tuple(r) for r in new.execute(sql)]


def test_migration_is_idempotent_and_reopen_is_a_noop(tmp_path: Path) -> None:
    path = tmp_path / "overrides.db"
    _v9_db(path)
    open_overrides(path).close()
    conn = open_overrides(path)
    conn.execute("INSERT INTO essential_devices VALUES ('d1',3600,'2026-01-01T00:00:00Z','x',1)")
    conn.close()
    conn = open_overrides(path)
    assert conn.execute("SELECT absent_after_s FROM essential_devices").fetchone()[0] == 3600
    assert conn.execute("PRAGMA user_version").fetchone()[0] == PREVIOUS + 1


def test_newer_than_build_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "overrides.db"
    open_overrides(path).close()
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version={len(OVERRIDES_MIGRATIONS) + 1}")
    raw.close()
    with pytest.raises(RuntimeError, match="newer than this build"):
        open_overrides(path)


@pytest.mark.parametrize("value", [0, 3599, 604801, -1, "abc", 7200.5, 1e400])
def test_table_checks_reject_out_of_range_and_wrong_types(tmp_path: Path, value) -> None:
    conn = open_overrides(tmp_path / "o.db")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO essential_devices VALUES ('d',?,'t','x',1)", (value,))


def test_version_must_increase_on_update(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    conn.execute("INSERT INTO essential_devices VALUES ('d',3600,'t','x',2)")
    for lower in (2, 1):
        with pytest.raises(sqlite3.DatabaseError, match="version must increase"):
            conn.execute("UPDATE essential_devices SET version=? WHERE device_id='d'", (lower,))
    conn.execute("UPDATE essential_devices SET version=3, absent_after_s=NULL WHERE device_id='d'")
    assert conn.execute("SELECT version FROM essential_devices").fetchone()[0] == 3


def test_null_row_cannot_be_deleted_and_version_must_be_positive(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    conn.execute("INSERT INTO essential_devices VALUES ('d',NULL,'t','x',1)")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM essential_devices WHERE device_id='d'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO essential_devices VALUES ('e',3600,'t','x',0)")
