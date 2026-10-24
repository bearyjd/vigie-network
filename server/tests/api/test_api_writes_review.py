"""Review fixes for the write path: TOCTOU, audit atomicity, strict If-Match."""

from __future__ import annotations

import sqlite3

import pytest
from api_helpers import NOW, Env, env, ts  # noqa: F401
from fastapi.testclient import TestClient

from vigie_api import writes
from vigie_api.app import create_app
from vigie_api.errors import ApiError
from vigie_api.schema import open_overrides


class HookedConnection:
    """Delegates to a real connection; runs `hook` just before BEGIN IMMEDIATE."""

    def __init__(self, conn: sqlite3.Connection, hook) -> None:
        self._conn, self._hook = conn, hook

    def execute(self, sql: str, *args):
        if sql.startswith("BEGIN IMMEDIATE") and self._hook:
            hook, self._hook = self._hook, None
            hook()
        return self._conn.execute(sql, *args)

    def __getattr__(self, name: str):
        return getattr(self._conn, name)


def _patch(env: Env, ov, device_id: str = "a") -> dict:
    return writes.patch_override(
        env.inv, ov, device_id=device_id, expected_version=0,
        changes={"name": "x"}, principal="app:test", now_iso=ts(),
    )  # fmt: skip


def test_merge_landing_between_check_and_write_is_409_not_a_stale_write(env: Env) -> None:
    env.device("a")
    env.device("c")

    def concurrent_merge() -> None:
        other = open_overrides(env.root / "overrides.db")
        other.execute(
            "INSERT INTO identity_links (from_device,into_device,merge_id,created_at,created_by)"
            " VALUES ('a','c','m',?,'t')",
            (ts(),),
        )
        other.close()

    with pytest.raises(ApiError) as caught:
        _patch(env, HookedConnection(env.ov, concurrent_merge))
    assert caught.value.status == 409 and caught.value.code == "device_merged"
    assert env.ov.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 0
    assert env.ov.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0


def test_group_deleted_between_validate_and_write_is_422(env: Env) -> None:
    env.device("a")

    def drop_group() -> None:
        other = open_overrides(env.root / "overrides.db")
        other.execute("DELETE FROM groups WHERE id='kids'")
        other.close()

    with pytest.raises(ApiError) as caught:
        writes.patch_override(
            env.inv, HookedConnection(env.ov, drop_group), device_id="a", expected_version=0,
            changes={"group_id": "kids"}, principal="p", now_iso=ts(),
        )  # fmt: skip
    assert caught.value.code == "unknown_group"


def test_audit_failure_rolls_back_the_override(env: Env) -> None:
    env.device("a")
    env.ov.execute(
        "CREATE TRIGGER audit_boom BEFORE INSERT ON audit_log"
        " BEGIN SELECT RAISE(ABORT, 'audit down'); END"
    )
    app = create_app(env.settings, clock=lambda: NOW)
    with TestClient(app, raise_server_exceptions=False) as client:
        r = client.patch("/devices/a", json={"name": "x"}, headers={**env.auth, "If-Match": "0"})
    assert r.status_code == 500 and r.json()["error"]["code"] == "internal_error"
    assert "audit down" not in r.text
    assert env.ov.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 0
    assert env.get("/devices/a").headers["etag"] == '"0"'


@pytest.mark.parametrize("header", ["0", '"0"', "12", '"12"'])
def test_if_match_accepts_exactly_n_or_quoted_n(header: str) -> None:
    assert writes.parse_if_match(header) == int(header.strip('"'))


@pytest.mark.parametrize(
    "header",
    ['W/"1"', 'w/"1"', '"1', '1"', '""', '"1","2"', '"1", "2"', "*", "1 2", "-1", "+1", "1.0",
     "0x1", '""1""', "'1'", "١", "1" * 13, " 1x", '"1" ,'],
)  # fmt: skip
def test_if_match_rejects_everything_else(header: str) -> None:
    with pytest.raises(ApiError) as caught:
        writes.parse_if_match(header)
    assert caught.value.status == 400


def test_if_match_missing_or_blank_is_428() -> None:
    for header in (None, "", "   "):
        with pytest.raises(ApiError) as caught:
            writes.parse_if_match(header)
        assert caught.value.status == 428


def test_weak_if_match_over_http_is_400_and_changes_nothing(env: Env) -> None:
    env.device("a")
    r = env.patch("/devices/a", {"name": "x"}, 'W/"0"')
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_if_match"
    assert env.ov.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 0
