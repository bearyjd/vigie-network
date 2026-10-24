"""Bound the complete standing-rule history without losing tied timestamps."""

import json

import pytest
from api_helpers import env, ts  # noqa: F401

from vigie_api.effective import encode_cursor
from vigie_api.openapi_export import render


def history(e, count=3):
    for index in range(count):
        e.ov.execute(
            "INSERT INTO identity_rules"
            " (id,device_id,signature,created_at,created_by,expires_at,revoked_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (
                f"r{index:03}",
                "d",
                "{}",
                ts(-100),
                "app:test",
                ts(-1 if index == 1 else 100),
                ts(-10) if index == 2 else None,
            ),
        )


def test_limit_one_pages_expired_and_revoked_history(env):
    history(env)
    cursor = None
    found = []
    for index in range(3):
        params = {"limit": 1}
        if cursor:
            params["cursor"] = cursor
        response = env.get("/identity/rules", **params)
        assert response.status_code == 200, response.text
        body = response.json()
        assert len(body["data"]) == 1
        found.append(body["data"][0])
        cursor = body["page"]["next_cursor"]
        assert bool(cursor) == (index < 2)
    assert [row["id"] for row in found] == ["r000", "r001", "r002"]
    assert [row["active"] for row in found] == [True, False, False]


def test_rules_default_and_maximum_page_size(env):
    history(env, 201)
    assert len(env.get("/identity/rules").json()["data"]) == 50
    assert len(env.get("/identity/rules", limit=200).json()["data"]) == 200
    for limit in (0, 201):
        assert env.get("/identity/rules", limit=limit).status_code == 422


@pytest.mark.parametrize(
    "cursor",
    [
        "!",
        encode_cursor("{}"),
        encode_cursor('[1,"r"]'),
        encode_cursor(json.dumps(["\ud800", "r"])),
        encode_cursor(json.dumps([ts(), "\ud800"])),
    ],
)
def test_malformed_rule_cursor_is_enveloped(env, cursor):
    response = env.get("/identity/rules", cursor=cursor)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_cursor"


def test_empty_rule_history_has_no_cursor(env):
    body = env.get("/identity/rules", limit=1).json()
    assert body["data"] == [] and body["page"] == {"next_cursor": None}


def test_patch_forbidden_and_rules_pagination_are_documented():
    spec = json.loads(render())
    forbidden = spec["paths"]["/devices/{device_id}"]["patch"]["responses"]["403"]
    assert forbidden["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorEnvelope"
    }
    parameters = {p["name"]: p for p in spec["paths"]["/identity/rules"]["get"]["parameters"]}
    assert parameters["limit"]["schema"]["default"] == 50
    assert parameters["limit"]["schema"]["maximum"] == 200
    assert "cursor" in parameters
