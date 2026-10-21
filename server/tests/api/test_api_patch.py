from __future__ import annotations

import json

import pytest
from api_helpers import Env, env  # noqa: F401


def override(env: Env, device_id: str):
    return env.ov.execute(
        "SELECT * FROM device_overrides WHERE device_id=?", (device_id,)
    ).fetchone()


def test_missing_if_match_is_428_and_changes_nothing(env: Env) -> None:
    env.device("d1")
    r = env.patch("/devices/d1", {"name": "TV"})
    assert r.status_code == 428 and r.json()["error"]["code"] == "precondition_required"
    assert override(env, "d1") is None


def test_stale_if_match_is_412_with_current_etag(env: Env) -> None:
    env.device("d1")
    assert env.patch("/devices/d1", {"name": "A"}, '"0"').status_code == 200
    r = env.patch("/devices/d1", {"name": "B"}, '"0"')
    assert r.status_code == 412 and r.headers["etag"] == '"1"'
    assert override(env, "d1")["name"] == "A"


def test_first_patch_creates_override_version_1_and_bumps_after(env: Env) -> None:
    env.device("d1")
    r = env.patch("/devices/d1", {"name": "A", "owner": "me"}, '"0"')
    assert r.status_code == 200 and r.headers["etag"] == '"1"'
    assert r.json()["data"] == {"device_id": "d1", "version": 1}
    r = env.patch("/devices/d1", {"owner": "you"}, '"1"')
    assert r.headers["etag"] == '"2"' and override(env, "d1")["version"] == 2
    assert env.get("/devices/d1").headers["etag"] == '"2"'


@pytest.mark.parametrize("header", ["1", '"1"'])
def test_if_match_forms_accepted(env: Env, header: str) -> None:
    env.device("d1")
    env.patch("/devices/d1", {"name": "A"}, "0")
    assert env.patch("/devices/d1", {"name": "B"}, header).status_code == 200


def test_garbage_if_match_is_400(env: Env) -> None:
    env.device("d1")
    assert env.patch("/devices/d1", {"name": "A"}, "abc").status_code == 400
    assert env.patch("/devices/d1", {"name": "A"}, "*").status_code == 400


def test_null_clears_only_that_field_and_row_is_never_deleted(env: Env) -> None:
    env.device("d1")
    env.patch("/devices/d1", {"name": "A", "owner": "me", "type": "tv", "group_id": "kids"}, "0")
    env.patch("/devices/d1", {"name": None}, "1")
    row = override(env, "d1")
    assert (row["name"], row["owner"], row["type"], row["group_id"]) == (None, "me", "tv", "kids")
    env.patch("/devices/d1", {"owner": None, "type": None, "group_id": None}, "2")
    row = override(env, "d1")
    assert row is not None and row["version"] == 3
    assert [row[f] for f in ("name", "owner", "type", "group_id")] == [None] * 4


def test_unknown_group_and_bad_type_rejected(env: Env) -> None:
    env.device("d1")
    r = env.patch("/devices/d1", {"group_id": "nope"}, "0")
    assert r.status_code == 422 and r.json()["error"]["code"] == "unknown_group"
    assert env.patch("/devices/d1", {"type": "toaster"}, "0").status_code == 422
    assert override(env, "d1") is None


def test_every_seeded_group_is_assignable(env: Env) -> None:
    env.device("d1")
    version = 0
    for group in ("trusted", "kids", "iot", "guest", "quarantine"):
        assert env.patch("/devices/d1", {"group_id": group}, str(version)).status_code == 200
        version += 1


@pytest.mark.parametrize("body", [{}, {"nope": 1}, {"name": "x" * 129}, {"name": 5}])
def test_invalid_bodies_rejected(env: Env, body: dict) -> None:
    env.device("d1")
    assert env.patch("/devices/d1", body, "0").status_code == 422
    assert override(env, "d1") is None


def test_unknown_device_404_and_merged_alias_409(env: Env) -> None:
    assert env.patch("/devices/ghost", {"name": "A"}, "0").status_code == 404
    env.device("canon")
    env.device("alias")
    env.link("alias", "canon")
    r = env.patch("/devices/alias", {"name": "A"}, "0")
    assert r.status_code == 409 and r.json()["error"]["code"] == "device_merged"


def test_patch_is_audited_with_principal_and_diff(env: Env) -> None:
    env.device("d1")
    env.patch("/devices/d1", {"name": "A"}, "0")
    env.patch("/devices/d1", {"name": "B"}, "1")
    rows = env.ov.execute("SELECT * FROM audit_log ORDER BY ts, rowid").fetchall()
    assert len(rows) == 2
    assert {r["principal"] for r in rows} == {"app:test"}
    assert {r["action"] for r in rows} == {"device.patch"} and rows[0]["target"] == "d1"
    detail = json.loads(rows[1]["detail"])
    assert detail["version"] == 2 and detail["changes"]["name"] == {"from": "A", "to": "B"}
    assert override(env, "d1")["updated_by"] == "app:test"


def test_rejected_patch_writes_no_audit(env: Env) -> None:
    env.device("d1")
    env.patch("/devices/d1", {"name": "A"})  # 428
    env.patch("/devices/d1", {"name": "A"}, "7")  # 412
    assert env.ov.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0


def test_patch_does_not_touch_inventory(env: Env) -> None:
    env.device("d1")
    before = env.inv.execute("SELECT * FROM devices").fetchall()
    env.patch("/devices/d1", {"name": "A", "type": "tv"}, "0")
    assert [tuple(r) for r in env.inv.execute("SELECT * FROM devices")] == [
        tuple(r) for r in before
    ]


def test_patched_values_show_in_effective_view(env: Env) -> None:
    env.device("d1", inferred_type="iot", source="ml", confidence=0.5)
    env.patch(
        "/devices/d1", {"name": "Plug", "owner": "me", "type": "tv", "group_id": "guest"}, "0"
    )
    d = env.get("/devices/d1").json()["data"]
    assert (d["name"], d["owner"], d["type"], d["group_id"]) == ("Plug", "me", "tv", "guest")
    assert d["type_provenance"] == {"source": "human", "confidence": 1.0}
    assert d["override_version"] == 1
