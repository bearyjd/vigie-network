"""F6-a: PUT/DELETE/GET /devices/{id}/essential and GET /essential-devices (overrides.db only)."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from fastapi.testclient import TestClient

from vigie_api import tokens
from vigie_api.app import create_app
from vigie_api.schema import open_overrides

DAY = 86400


def put(env: Env, device_id: str, body, version: str | None = "0", token: str | None = None):
    headers = {"Authorization": f"Bearer {token or env.token}"}
    if version is not None:
        headers["If-Match"] = version
    if isinstance(body, bytes):
        headers["Content-Type"] = "application/json"
        return env.client.put(f"/devices/{device_id}/essential", content=body, headers=headers)
    return env.client.put(f"/devices/{device_id}/essential", json=body, headers=headers)


def delete(env: Env, device_id: str, version: str | None = "1", token: str | None = None):
    headers = {"Authorization": f"Bearer {token or env.token}"}
    if version is not None:
        headers["If-Match"] = version
    return env.client.delete(f"/devices/{device_id}/essential", headers=headers)


def row(env: Env, device_id: str):
    return env.ov.execute(
        "SELECT * FROM essential_devices WHERE device_id=?", (device_id,)
    ).fetchone()


def audits(env: Env, action: str):
    return env.ov.execute(
        "SELECT * FROM audit_log WHERE action=? ORDER BY seq", (action,)
    ).fetchall()


def test_put_marks_device_version_1_with_etag_and_audit(env: Env) -> None:
    env.device("d1")
    r = put(env, "d1", {"absent_after_s": DAY})
    assert r.status_code == 200 and r.headers["etag"] == '"1"'
    assert r.json()["data"] == {"device_id": "d1", "absent_after_s": DAY, "version": 1}
    assert row(env, "d1")["absent_after_s"] == DAY
    (entry,) = audits(env, "device.essential.set")
    assert entry["target"] == "d1" and entry["principal"].endswith(":test")
    detail = json.loads(entry["detail"])
    assert detail["after"] == DAY and detail["before"] is None and detail["version"] == 1


def test_marking_does_not_touch_device_overrides_or_their_version(env: Env) -> None:
    env.device("d1")
    env.patch("/devices/d1", {"name": "Cam"}, '"0"')
    assert put(env, "d1", {"absent_after_s": DAY}).status_code == 200
    ov = env.ov.execute("SELECT version, name FROM device_overrides WHERE device_id='d1'")
    assert tuple(ov.fetchone()) == (1, "Cam")
    assert env.get("/devices/d1").headers["etag"] == '"1"'


def test_replay_of_same_put_is_412_and_changes_nothing(env: Env) -> None:
    env.device("d1")
    assert put(env, "d1", {"absent_after_s": DAY}).status_code == 200
    r = put(env, "d1", {"absent_after_s": DAY})
    assert r.status_code == 412 and r.headers["etag"] == '"1"'
    assert row(env, "d1")["version"] == 1 and len(audits(env, "device.essential.set")) == 1


def test_missing_if_match_428_and_garbage_400(env: Env) -> None:
    env.device("d1")
    assert put(env, "d1", {"absent_after_s": DAY}, None).status_code == 428
    for bad in ("abc", "*", 'W/"0"', '"0", "1"', "-1", "9" * 40):
        assert put(env, "d1", {"absent_after_s": DAY}, bad).status_code == 400, bad
    assert row(env, "d1") is None


def test_update_threshold_bumps_version(env: Env) -> None:
    env.device("d1")
    put(env, "d1", {"absent_after_s": DAY})
    r = put(env, "d1", {"absent_after_s": 3600}, '"1"')
    assert r.status_code == 200 and r.headers["etag"] == '"2"'
    assert row(env, "d1")["absent_after_s"] == 3600


@pytest.mark.parametrize(
    "value",
    [0, 1, 3599, 604801, -3600, 10**30, 7200.0, 7200.5, True, False, "7200", None, [7200], {}],
)
def test_threshold_bounds_and_types_422(env: Env, value) -> None:
    env.device("d1")
    r = put(env, "d1", {"absent_after_s": value})
    assert r.status_code == 422 and row(env, "d1") is None


@pytest.mark.parametrize(
    "raw",
    [
        b'{"absent_after_s": NaN}',
        b'{"absent_after_s": Infinity}',
        b'{"absent_after_s": -Infinity}',
        b"[]",
        b"7200",
        b"{",
        b"",
        b'{"absent_after_s": 1e400}',
    ],
)
def test_nonfinite_and_malformed_bodies_never_500(env: Env, raw: bytes) -> None:
    env.device("d1")
    r = put(env, "d1", raw)
    assert r.status_code in (400, 422) and row(env, "d1") is None


def test_huge_digit_string_is_rejected_not_500(env: Env) -> None:
    env.device("d1")
    r = put(env, "d1", b'{"absent_after_s": ' + b"9" * 5000 + b"}")
    assert r.status_code in (400, 413, 422) and row(env, "d1") is None


def test_bounds_inclusive_edges_accepted(env: Env) -> None:
    env.device("d1")
    env.device("d2")
    assert put(env, "d1", {"absent_after_s": 3600}).status_code == 200
    assert put(env, "d2", {"absent_after_s": 604800}).status_code == 200


def test_extra_and_missing_fields_422(env: Env) -> None:
    env.device("d1")
    assert put(env, "d1", {}).status_code == 422
    assert put(env, "d1", {"absent_after_s": DAY, "x": 1}).status_code == 422
    assert row(env, "d1") is None


def test_oversized_body_413(env: Env) -> None:
    env.device("d1")
    r = put(env, "d1", {"absent_after_s": DAY, "pad": "x" * 200_000})
    assert r.status_code == 413 and row(env, "d1") is None


def test_unknown_device_404_and_no_row(env: Env) -> None:
    assert put(env, "nope", {"absent_after_s": DAY}).status_code == 404
    assert delete(env, "nope", "0").status_code == 404
    assert env.get("/devices/nope/essential").status_code == 404
    assert env.ov.execute("SELECT COUNT(*) FROM essential_devices").fetchone()[0] == 0


def test_merged_alias_is_409_canonical_is_ok(env: Env) -> None:
    env.device("canon")
    env.device("alias")
    env.link("alias", "canon")
    r = put(env, "alias", {"absent_after_s": DAY})
    assert r.status_code == 409 and r.json()["error"]["code"] == "device_merged"
    assert put(env, "canon", {"absent_after_s": DAY}).status_code == 200


@pytest.mark.parametrize("scope", ["read-only", "service", "integration"])
def test_non_writer_token_is_403(env: Env, scope: str) -> None:
    env.device("d1")
    _, token = tokens.create_token(env.ov, "other", scope=scope)
    assert put(env, "d1", {"absent_after_s": DAY}, token=token).status_code == 403
    assert delete(env, "d1", "0", token=token).status_code == 403
    assert row(env, "d1") is None and not audits(env, "device.essential.set")


def test_no_or_bad_token_is_401_even_for_unknown_device(env: Env) -> None:
    for headers in ({}, {"Authorization": "Bearer nope"}):
        r = env.client.put("/devices/zz/essential", json={"absent_after_s": DAY}, headers=headers)
        assert r.status_code == 401
        assert env.client.delete("/devices/zz/essential", headers=headers).status_code == 401
        assert env.client.get("/devices/zz/essential", headers=headers).status_code == 401
        assert env.client.get("/essential-devices", headers=headers).status_code == 401


def test_overlong_device_id_422(env: Env) -> None:
    assert put(env, "x" * 65, {"absent_after_s": DAY}).status_code == 422


def test_delete_nulls_value_keeps_row_and_bumps_version(env: Env) -> None:
    env.device("d1")
    put(env, "d1", {"absent_after_s": DAY})
    r = delete(env, "d1", '"1"')
    assert r.status_code == 200 and r.headers["etag"] == '"2"'
    assert r.json()["data"] == {"device_id": "d1", "absent_after_s": None, "version": 2}
    assert tuple(row(env, "d1")[k] for k in ("absent_after_s", "version")) == (None, 2)
    (entry,) = audits(env, "device.essential.clear")
    assert json.loads(entry["detail"])["before"] == DAY
    # replay is refused, and a re-mark continues the version sequence
    assert delete(env, "d1", '"1"').status_code == 412
    assert put(env, "d1", {"absent_after_s": DAY}, '"2"').headers["etag"] == '"3"'


def test_delete_requires_if_match_and_a_marked_device(env: Env) -> None:
    env.device("d1")
    assert delete(env, "d1", None).status_code == 428
    r = delete(env, "d1", "0")
    assert r.status_code == 409 and r.json()["error"]["code"] == "not_essential"
    put(env, "d1", {"absent_after_s": DAY})
    delete(env, "d1", "1")
    assert delete(env, "d1", "2").status_code == 409  # already unmarked: no write, no audit
    assert len(audits(env, "device.essential.clear")) == 1


def test_essential_rows_cannot_be_deleted_by_sql(env: Env) -> None:
    env.device("d1")
    put(env, "d1", {"absent_after_s": DAY})
    with pytest.raises(sqlite3.DatabaseError):
        env.ov.execute("DELETE FROM essential_devices")


def test_cap_of_32_is_409_and_updates_and_unmark_still_work(env: Env) -> None:
    for i in range(33):
        env.device(f"d{i}")
    for i in range(32):
        assert put(env, f"d{i}", {"absent_after_s": DAY}).status_code == 200
    r = put(env, "d32", {"absent_after_s": DAY})
    assert r.status_code == 409 and r.json()["error"]["code"] == "too_many_essential"
    assert row(env, "d32") is None
    assert put(env, "d0", {"absent_after_s": 7200}, '"1"').status_code == 200  # update, not new
    assert delete(env, "d1", '"1"').status_code == 200
    assert put(env, "d32", {"absent_after_s": DAY}).status_code == 200  # a slot freed


def _race(env: Env, calls: list[tuple[str, dict, str]]) -> list[int]:
    codes: list[int] = []
    gate = threading.Barrier(len(calls))

    def go(path: str, body: dict, if_match: str) -> None:
        with TestClient(create_app(env.settings, clock=lambda: NOW)) as client:
            gate.wait()
            r = client.put(path, json=body, headers={**env.auth, "If-Match": if_match})
            codes.append(r.status_code)

    threads = [threading.Thread(target=go, args=call) for call in calls]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sorted(codes)


def test_cap_is_atomic_under_concurrency(env: Env) -> None:
    for i in range(40):
        env.device(f"c{i}")
    for i in range(30):
        assert put(env, f"c{i}", {"absent_after_s": DAY}).status_code == 200
    calls = [(f"/devices/c{30 + i}/essential", {"absent_after_s": DAY}, "0") for i in range(10)]
    codes = _race(env, calls)
    assert codes.count(200) == 2 and codes.count(409) == 8, codes
    n = env.ov.execute("SELECT COUNT(*) FROM essential_devices WHERE absent_after_s IS NOT NULL")
    assert n.fetchone()[0] == 32


def test_concurrent_same_version_puts_only_one_wins(env: Env) -> None:
    env.device("d1")
    calls = [("/devices/d1/essential", {"absent_after_s": 3600 + i}, "0") for i in range(6)]
    assert _race(env, calls) == [200, 412, 412, 412, 412, 412]
    assert row(env, "d1")["version"] == 1


def test_get_state_and_list(env: Env) -> None:
    for d in ("d1", "d2", "d3"):
        env.device(d)
    r = env.get("/devices/d1/essential")
    assert r.status_code == 200 and r.headers["etag"] == '"0"'
    assert r.json()["data"] == {
        "device_id": "d1",
        "essential": False,
        "absent_after_s": None,
        "version": 0,
        "updated_at": None,
        "updated_by": None,
    }
    put(env, "d1", {"absent_after_s": DAY})
    put(env, "d2", {"absent_after_s": 7200})
    put(env, "d3", {"absent_after_s": 7200})
    delete(env, "d3", "1")
    data = env.get("/devices/d1/essential").json()["data"]
    assert data["essential"] is True and data["absent_after_s"] == DAY and data["version"] == 1
    assert env.get("/devices/d3/essential").json()["data"]["essential"] is False
    listing = env.get("/essential-devices").json()["data"]
    assert [i["device_id"] for i in listing] == ["d1", "d2"]
    assert listing[0].keys() == {"device_id", "absent_after_s", "version", "updated_at"}


def test_empty_list_when_nothing_marked(env: Env) -> None:
    r = env.get("/essential-devices")
    assert r.status_code == 200 and r.json()["data"] == []


def test_nothing_ships_pre_marked(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "overrides.db")
    assert conn.execute("SELECT COUNT(*) FROM essential_devices").fetchone()[0] == 0
