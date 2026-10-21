"""Review fixes: revoked NOT NULL, CLI audit trail, overrides.db permissions."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn

from vigie_api import cli, tokens
from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides


@pytest.fixture
def keep_umask() -> Iterator[None]:
    saved = os.umask(0o022)
    yield
    os.umask(saved)


def _v1_database(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    for statement in OVERRIDES_MIGRATIONS[0]:
        conn.execute(statement)
    conn.execute("PRAGMA user_version=1")
    return conn


def test_fresh_schema_forbids_null_revoked_and_defaults_to_zero(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO api_tokens (id, token_hash, scope, revoked) VALUES ('a','h','app',NULL)"
        )
    conn.execute("INSERT INTO api_tokens (id, token_hash, scope) VALUES ('b','h','app')")
    assert conn.execute("SELECT revoked FROM api_tokens WHERE id='b'").fetchone()[0] == 0


def test_migration_rebuilds_existing_column_and_fails_closed_on_null(tmp_path: Path) -> None:
    legacy = _v1_database(tmp_path / "o.db")
    legacy.executemany(
        "INSERT INTO api_tokens (id, token_hash, scope, revoked) VALUES (?,?,?,?)",
        [("live", "h1", "app", 0), ("dead", "h2", "app", 1), ("null", "h3", "app", None)],
    )
    legacy.close()
    conn = open_overrides(tmp_path / "o.db")
    state = dict(conn.execute("SELECT id, revoked FROM api_tokens").fetchall())
    assert state == {"live": 0, "dead": 1, "null": 1}
    column = next(r for r in conn.execute("PRAGMA table_info(api_tokens)") if r[1] == "revoked")
    assert column["notnull"] == 1 and column["dflt_value"] == "0"


def test_verify_rejects_a_null_revoked_row_even_on_a_legacy_table() -> None:
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE api_tokens (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL,"
                 " scope TEXT NOT NULL, revoked INTEGER DEFAULT 0)")  # fmt: skip
    token = "vgt_t.abcdefgh"
    conn.execute("INSERT INTO api_tokens VALUES ('t', ?, 'app', NULL)", (tokens._hash(token),))
    assert tokens.verify_token(conn, token) is None
    conn.execute("UPDATE api_tokens SET revoked=0")
    assert tokens.verify_token(conn, token) is not None


def _audit(tmp_path: Path) -> list[sqlite3.Row]:
    conn = open_overrides(tmp_path / "overrides.db")
    return conn.execute("SELECT * FROM audit_log ORDER BY rowid").fetchall()


def test_cli_token_create_and_revoke_are_audited_without_token_material(
    tmp_path: Path, capsys
) -> None:
    base = ["tokens", "--data-dir", str(tmp_path)]
    assert cli.main([*base, "create", "--id", "app1"]) == 0
    token = capsys.readouterr().out.strip()
    assert cli.main([*base, "revoke", "app1"]) == 0
    assert cli.main([*base, "revoke", "ghost"]) == 1  # nothing revoked, nothing audited
    log = _audit(tmp_path)
    assert [(r["principal"], r["action"], r["target"]) for r in log] == [
        ("cli", "token.create", "app1"),
        ("cli", "token.revoke", "app1"),
    ]
    assert token not in json.dumps([dict(r) for r in log])
    assert token.rsplit(".", 1)[1] not in json.dumps([dict(r) for r in log])


def test_failed_token_create_is_not_audited(tmp_path: Path) -> None:
    base = ["tokens", "--data-dir", str(tmp_path), "create", "--id", "dup"]
    assert cli.main(base) == 0 and cli.main(base) == 2
    assert [r["action"] for r in _audit(tmp_path)] == ["token.create"]


def test_overrides_db_is_created_0600(tmp_path: Path, keep_umask: None) -> None:
    conn = open_overrides(tmp_path / "o.db")
    conn.execute("INSERT INTO audit_log (id, ts, principal, action) VALUES ('1','t','p','a')")
    for suffix in ("", "-wal", "-shm"):
        path = tmp_path / f"o.db{suffix}"
        if path.exists():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name


def test_existing_world_readable_db_is_tightened(tmp_path: Path, keep_umask: None) -> None:
    open_overrides(tmp_path / "o.db").close()
    (tmp_path / "o.db").chmod(0o644)
    open_overrides(tmp_path / "o.db").close()
    assert stat.S_IMODE((tmp_path / "o.db").stat().st_mode) == 0o600


def test_cli_runs_with_umask_077_and_restores_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, keep_umask: None
) -> None:
    seen: list[int] = []

    def fake_run(app, **kw) -> None:
        current = os.umask(0)
        os.umask(current)
        seen.append(current)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    assert cli.main(["--insecure-dev"]) == 0
    assert seen == [0o077]
    current = os.umask(0)
    os.umask(current)
    assert current == 0o022
