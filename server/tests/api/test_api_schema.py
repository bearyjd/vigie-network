from __future__ import annotations

import json
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


def test_overrides_schema_is_at_version_9(tmp_path: Path) -> None:
    from vigie_api.schema import OVERRIDES_MIGRATIONS

    conn = open_overrides(tmp_path / "o.db")
    assert len(OVERRIDES_MIGRATIONS) == 9
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 9


SHA = "a" * 64


def _open_raw(tmp_path: Path) -> sqlite3.Connection:
    """A migrated db without the state-machine triggers, to probe the CHECKs on their own."""
    conn = open_overrides(tmp_path / "o.db")
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
        if name.startswith("trg_dataset"):
            conn.execute(f"DROP TRIGGER {name}")  # noqa: S608
    return conn


IMPORT_SQL = (
    "INSERT INTO dataset_imports (id,source,version,licence,sha256,entry_count,created_at,"
    "created_by{}) VALUES (?,?,'v','l',?,?,'t','u'{})"
)


def _import(conn, id_="i1", source="kev", sha=SHA, count=1, **extra):
    names = "".join(f",{k}" for k in extra)
    marks = ",?" * len(extra)
    conn.execute(IMPORT_SQL.format(names, marks), (id_, source, sha, count, *extra.values()))


def test_dataset_staging_tables_enforce_their_checks(tmp_path: Path) -> None:
    conn = _open_raw(tmp_path)
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
    conn = _open_raw(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, **{k: v for k, v in extra.items()})


def test_accepted_status_needs_an_accept_record(tmp_path: Path) -> None:
    conn = _open_raw(tmp_path)
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
    conn = _open_raw(tmp_path)
    _import(conn, "a")
    _import(conn, "b", source="urlhaus")  # same hash under another source is fine
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, "c")


@pytest.mark.parametrize(
    "column", ["version", "licence", "created_by", "created_at", "accepted_by", "accepted_at"]
)
@pytest.mark.parametrize(
    "blank", ["", " ", "\t", "\n", "\x0b", "\x0c", "\r", "\u00a0", " \t\n\x0b\x0c\r\u00a0"]
)
def test_dataset_text_columns_reject_blank_values(tmp_path: Path, column, blank) -> None:
    conn = _open_raw(tmp_path)
    row = {
        "version": "v", "licence": "l", "created_by": "u", "created_at": "t",
        "accepted_by": None, "accepted_at": None,
    }  # fmt: skip
    row[column] = blank
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO dataset_imports (id,source,version,licence,sha256,entry_count,"
            "created_at,created_by,accepted_by,accepted_at) VALUES ('i','kev',?,?,?,1,?,?,?,?)",
            (row["version"], row["licence"], SHA, row["created_at"], row["created_by"],
             row["accepted_by"], row["accepted_at"]),
        )  # fmt: skip


def _v8_db(path: Path) -> sqlite3.Connection:
    from vigie_api.schema import OVERRIDES_MIGRATIONS

    conn = sqlite3.connect(path, isolation_level=None)
    for index in range(8):
        for statement in OVERRIDES_MIGRATIONS[index]:
            conn.execute(statement)
    conn.execute("PRAGMA user_version=8")
    return conn


def test_migration_9_upgrades_a_v8_db_with_staged_accepted_and_rejected_rows(
    tmp_path: Path,
) -> None:
    raw = _v8_db(tmp_path / "o.db")
    sql = IMPORT_SQL.format(",status,accepted_by,accepted_at", ",?,?,?")
    raw.execute(sql, ("old", "kev", SHA, 1, "accepted", "u", "t"))
    raw.execute(sql, ("stg", "kev", "b" * 64, 1, "staged", None, None))
    raw.execute(sql, ("rej", "kev", "c" * 64, 1, "rejected", None, None))
    raw.execute("INSERT INTO dataset_entries_staging VALUES ('rej','k','{}')")
    raw.close()
    conn = open_overrides(tmp_path / "o.db")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 9
    rows = {r["id"]: r for r in conn.execute("SELECT * FROM dataset_imports")}
    assert (rows["old"]["status"], rows["old"]["rejected_by"]) == ("accepted", None)
    assert (rows["stg"]["status"], rows["stg"]["content_sha256"]) == ("staged", None)
    rej = rows["rej"]  # backfilled, not lost and not blocking startup
    assert (rej["status"], rej["rejected_by"], rej["rejected_at"]) == (
        "rejected",
        "migration-9",
        "t",
    )
    assert conn.execute("SELECT COUNT(*) FROM dataset_entries_staging").fetchone()[0] == 1
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'trg_dataset%'"
        ).fetchone()[0]
        >= 2
    )
    assert not conn.execute("SELECT name FROM sqlite_temp_master").fetchall()
    conn.close()
    open_overrides(tmp_path / "o.db").close()  # reopening is a no-op


def test_rejected_status_needs_a_reject_record(tmp_path: Path) -> None:
    conn = _open_raw(tmp_path)
    bad = [
        {"status": "rejected"},
        {"status": "rejected", "rejected_by": "u"},
        {"status": "rejected", "rejected_at": "t"},
        {"status": "rejected", "rejected_by": "", "rejected_at": "t"},
        {"status": "rejected", "rejected_by": "u", "rejected_at": " "},
        {"rejected_by": "u", "rejected_at": "t"},  # a reject record on a staged row
        {"reject_reason": "r"},  # a reason without a rejection
        {"status": "rejected", "rejected_by": "u", "rejected_at": "t", "reject_reason": ""},
        {"status": "rejected", "rejected_by": "u", "rejected_at": "t", "reject_reason": "x" * 201},
    ]
    for n, extra in enumerate(bad):
        with pytest.raises(sqlite3.IntegrityError):
            _import(conn, f"r{n}", sha=f"{n}" * 64, **extra)
    _import(
        conn, "ok", status="rejected", rejected_by="u", rejected_at="t", reject_reason="x" * 200
    )


def test_supersede_columns_are_paired_and_only_for_accepted(tmp_path: Path) -> None:
    conn = _open_raw(tmp_path)
    acc = {"status": "accepted", "accepted_by": "u", "accepted_at": "t"}
    _import(conn, "b0", sha="9" * 64, source="urlhaus")  # a live target for superseded_by
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, "a", **acc, superseded_by="b0")
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, "b", sha="b" * 64, **acc, superseded_at="t")
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, "c", sha="c" * 64, superseded_by="b0", superseded_at="t")  # not accepted
    with pytest.raises(sqlite3.IntegrityError):  # the FK: superseded_by must exist
        _import(conn, "e", sha="e" * 64, **acc, superseded_by="nope", superseded_at="t")
    _import(conn, "d", sha="d" * 64, **acc, superseded_by="b0", superseded_at="t")


def test_one_live_accepted_import_per_source(tmp_path: Path) -> None:
    conn = _open_raw(tmp_path)
    acc = {"status": "accepted", "accepted_by": "u", "accepted_at": "t"}
    _import(conn, "a", **acc)
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, "b", sha="b" * 64, **acc)
    _import(conn, "c", sha="c" * 64, source="urlhaus", **acc)


def _entry(raw, import_id, key="CVE-2024-1000"):
    payload = json.dumps(
        {"cveID": key, "dateAdded": "2024-01-01", "product": "P", "vendorProject": "V"},
        sort_keys=True,
        separators=(",", ":"),
    )
    raw.execute("INSERT INTO dataset_entries_staging VALUES (?,?,?)", (import_id, key, payload))
    return key, payload


def _v8_with_entries(tmp_path: Path):
    raw = _v8_db(tmp_path / "o.db")
    sql = (
        "INSERT INTO dataset_imports (id,source,version,licence,sha256,entry_count,status,"
        "created_at,created_by,accepted_by,accepted_at) VALUES (?,?,?,'l',?,2,?,'t','u',?,?)"
    )
    raw.execute(sql, ("acc", "kev", "2024.01.01", "a" * 64, "accepted", "u", "t"))
    raw.execute(sql, ("stg", "kev", "2024.02.01", "b" * 64, "staged", None, None))
    raw.execute(sql, ("bare", "kev", "2024.03.01", "c" * 64, "staged", None, None))
    rows = {i: [_entry(raw, i, "CVE-2024-1001"), _entry(raw, i)] for i in ("acc", "stg")}
    raw.close()
    return rows


def test_migration_9_backfills_the_content_digest_with_the_stage_framing(tmp_path: Path) -> None:
    from vigie_api import dataset_writes

    rows = _v8_with_entries(tmp_path)
    conn = open_overrides(tmp_path / "o.db")
    got = {r["id"]: r["content_sha256"] for r in conn.execute("SELECT * FROM dataset_imports")}
    assert got["acc"] == dataset_writes.content_digest(sorted(rows["acc"]))
    assert got["stg"] == dataset_writes.content_digest(sorted(rows["stg"]))
    assert got["bare"] is None  # no entries to digest: stays unacceptable


def test_a_migrated_v8_staged_import_is_acceptable_and_a_bare_one_says_restage(
    tmp_path: Path,
) -> None:
    from vigie_api import dataset_writes
    from vigie_api.errors import ApiError

    _v8_with_entries(tmp_path)
    conn = open_overrides(tmp_path / "o.db")
    now = "2026-10-31T00:00:00Z"
    dataset_writes.accept(conn, "stg", "cli:local", "cli:local", now)
    live = dataset_writes.latest_accepted(conn, "kev")
    assert live["id"] == "stg"
    assert (
        conn.execute("SELECT superseded_by FROM dataset_imports WHERE id='acc'").fetchone()[0]
        == "stg"
    )
    with pytest.raises(ApiError) as exc:
        dataset_writes.accept(conn, "bare", "cli:local", "cli:local", now)
    assert exc.value.code == "dataset_digest_missing" and "restage" in exc.value.message


def _real(tmp_path: Path) -> sqlite3.Connection:
    return open_overrides(tmp_path / "o.db")


STAGED = dict(content_sha256="d" * 64)


@pytest.mark.parametrize(
    "extra",
    [
        {"status": "accepted", "accepted_by": "u", "accepted_at": "t"},
        {"status": "rejected", "rejected_by": "u", "rejected_at": "t"},
        {"accepted_by": "u"},
        {"accepted_at": "t"},
        {},  # no content digest
    ],
)
def test_insert_trigger_allows_only_clean_staged_rows_with_a_digest(tmp_path: Path, extra) -> None:
    conn = _real(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        _import(conn, **({**STAGED, **extra} if extra else {}))
    _import(conn, "ok", sha="e" * 64, **STAGED)


def test_import_rows_cannot_be_deleted(tmp_path: Path) -> None:
    conn = _real(tmp_path)
    _import(conn, "x", **STAGED)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM dataset_imports WHERE id='x'")
    assert conn.execute("SELECT COUNT(*) FROM dataset_imports").fetchone()[0] == 1


def test_staging_entries_are_insert_only_and_only_for_staged_imports(tmp_path: Path) -> None:
    conn = _real(tmp_path)
    _import(conn, "x", **STAGED)
    conn.execute("INSERT INTO dataset_entries_staging VALUES ('x','k','{}')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE dataset_entries_staging SET payload='{\"a\":1}'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM dataset_entries_staging")
    conn.execute("UPDATE dataset_imports SET status='rejected', rejected_by='u', rejected_at='t'")
    with pytest.raises(sqlite3.IntegrityError):  # the parent is no longer staged
        conn.execute("INSERT INTO dataset_entries_staging VALUES ('x','k2','{}')")
    with pytest.raises(sqlite3.IntegrityError):  # and an unknown parent is no parent
        conn.execute("INSERT INTO dataset_entries_staging VALUES ('nope','k','{}')")
    assert conn.execute("SELECT COUNT(*) FROM dataset_entries_staging").fetchone()[0] == 1
