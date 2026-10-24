"""Transactional identity write contracts, authored before routes exist."""

import json

import pytest
from api_helpers import Env, env, ts  # noqa: F401

from vigie_api import tokens


def suggestion(e, action="merge_identity", *, expired=False, candidate_state="suggested"):
    e.device("a")
    e.device("b")
    e.inv.execute(
        "INSERT INTO identity_candidates VALUES (?,?,?,?,?,?,?)",
        ("c", "a", "b", 0.8, "{}", candidate_state, ts(-100)),
    )
    ids = ["a", "b"] if action == "merge_identity" else ["a"]
    payload = {"from_device": "a", "into_device": "b", "evidence_summary": {"candidate_id": "c"}}
    if action == "label":
        payload = {"name": "Laptop", "type": "laptop"}
    if action == "move_group":
        payload = {"group_id": "kids"}
    if action == "quarantine":
        payload = {}
    e.inv.execute(
        "INSERT INTO suggestions VALUES (?,?,?,?,?,?,?,?,?)",
        (
            "s",
            action,
            json.dumps(ids),
            json.dumps(payload),
            "test",
            None,
            json.dumps(dict.fromkeys(ids, 0)),
            ts(-20),
            ts(-1 if expired else 100),
        ),
    )


def post(e, path, body=None, headers=None):
    return e.client.post(
        path,
        json=body or {"expected_versions": {"a": 0, "b": 0}},
        headers=headers or {**e.auth, "X-Request-ID": "request-1"},
    )


def count(e, table):
    return e.ov.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608


def test_merge_and_replay_atomic_then_undo(env):
    suggestion(env)
    result = post(env, "/suggestions/s/accept")
    assert result.status_code == 200, result.text
    merge = result.json()["data"]["merge_id"]
    assert [
        count(env, t)
        for t in ["identity_links", "identity_merges", "suggestion_decisions", "audit_log"]
    ] == [1] * 4
    assert post(env, "/suggestions/s/accept").json() == result.json()
    assert count(env, "audit_log") == 1
    detail = json.loads(env.ov.execute("SELECT detail FROM audit_log").fetchone()[0])
    assert detail["request_id"] == "request-1" and "before" in detail and "after" in detail
    body = {"expected_versions": {"a": 1, "b": 1}}
    undo = post(env, f"/identity/merges/{merge}/undo", body)
    assert undo.status_code == 200, undo.text
    assert env.ov.execute("SELECT revoked_at FROM identity_links").fetchone()[0]
    assert env.get("/devices/a").json()["data"]["merged_into"] is None
    assert post(env, f"/identity/merges/{merge}/undo", body).json() == undo.json()
    assert count(env, "audit_log") == 2


@pytest.mark.parametrize("action", ["label", "move_group", "quarantine"])
def test_other_actions_and_stale(env, action):
    suggestion(env, action)
    assert post(env, "/suggestions/s/accept", {"expected_version": 2}).status_code == 409
    r = post(env, "/suggestions/s/accept", {"expected_version": 0})
    assert r.status_code == 200, r.text
    row = dict(env.ov.execute("SELECT * FROM device_overrides WHERE device_id='a'").fetchone())
    assert row["version"] == 1
    assert (
        row["name" if action == "label" else "group_id"]
        == {"label": "Laptop", "move_group": "kids", "quarantine": "quarantine"}[action]
    )


@pytest.mark.parametrize("state", ["vetoed", "ambiguous", "dismissed"])
def test_invalid_candidate_state_rejects_accept(env, state):
    suggestion(env, candidate_state=state)
    assert post(env, "/suggestions/s/accept").status_code == 409
    assert count(env, "audit_log") == 0


def test_expired_orphan_and_reject_replay(env):
    suggestion(env, expired=True)
    assert post(env, "/suggestions/s/accept").status_code == 410
    env.inv.execute("UPDATE suggestions SET expires_at=? WHERE id='s'", (ts(100),))
    env.inv.execute("UPDATE devices SET status='retired' WHERE id='b'")
    assert post(env, "/suggestions/s/accept").status_code == 409
    env.inv.execute("UPDATE devices SET status='active' WHERE id='b'")
    r = post(env, "/suggestions/s/reject")
    assert r.status_code == 200
    assert post(env, "/suggestions/s/reject").json() == r.json()
    assert post(env, "/suggestions/s/accept").status_code == 409
    assert count(env, "audit_log") == 1


def test_audit_failure_rolls_back_everything(env):
    suggestion(env)
    env.ov.execute(
        "CREATE TRIGGER audit_fail BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'fail'); END"
    )
    response = post(env, "/suggestions/s/accept")
    assert response.status_code == 500
    assert [
        count(env, t)
        for t in ["identity_links", "identity_merges", "suggestion_decisions", "audit_log"]
    ] == [0] * 4


def test_rules_require_explicit_privilege_and_validate_whole_signature(env):
    env.device("a")
    body = {
        "device_id": "a",
        "expected_version": 0,
        "signature": {"opt55": "1,3", "opt60": "vendor", "hostname": "Host"},
    }
    assert post(env, "/identity/rules", body).status_code == 403
    _, token = tokens.create_token(env.ov, "human", rules_write=True)
    auth = {"Authorization": f"Bearer {token}"}
    for bad in [{"hostname": None}, {"opt60": 123}, {"hostname": "x" * 129}, {"surprise": "x"}]:
        assert (
            post(
                env, "/identity/rules", {**body, "signature": {**body["signature"], **bad}}, auth
            ).status_code
            == 422
        )
    r = post(env, "/identity/rules", body, auth)
    assert r.status_code == 200, r.text
    rid = r.json()["data"]["id"]
    assert env.get("/identity/rules").json()["data"][0]["id"] == rid
    assert (
        env.client.request(
            "DELETE", f"/identity/rules/{rid}", json={"expected_version": 0}, headers=auth
        ).status_code
        == 409
    )
    r = env.client.request(
        "DELETE", f"/identity/rules/{rid}", json={"expected_version": 1}, headers=auth
    )
    assert r.status_code == 200
    assert env.ov.execute("SELECT revoked_at FROM identity_rules").fetchone()[0]


def test_clear_veto_only_writes_override_decision(env):
    suggestion(env, candidate_state="vetoed")
    r = post(env, "/identity/candidates/c/clear-veto")
    assert r.status_code == 200, r.text
    assert env.inv.execute("SELECT state FROM identity_candidates").fetchone()[0] == "vetoed"
    assert count(env, "candidate_decisions") == 1 and count(env, "identity_links") == 0
    assert post(env, "/identity/candidates/c/clear-veto").json() == r.json()
    assert count(env, "audit_log") == 1


@pytest.mark.parametrize(
    "path",
    [
        "/suggestions/s/accept",
        "/suggestions/s/reject",
        "/identity/merges/m/undo",
        "/identity/rules",
        "/identity/candidates/c/clear-veto",
    ],
)
def test_auth_before_invalid_body(env, path):
    assert (
        env.client.post(
            path, content="{bad", headers={"Content-Type": "application/json"}
        ).status_code
        == 401
    )
    assert post(env, path, {"expected_versions": {"a": True}}).status_code == 422


WRITE_CASES = [
    ("POST", "/suggestions/s/accept", {"expected_versions": {"a": 0, "b": 0}}),
    ("POST", "/suggestions/s/reject", {"expected_versions": {"a": 0, "b": 0}}),
    ("POST", "/identity/merges/m/undo", {"expected_versions": {"a": 0, "b": 0}}),
    ("POST", "/identity/candidates/c/clear-veto", {"expected_versions": {"a": 0, "b": 0}}),
    (
        "POST",
        "/identity/rules",
        {
            "device_id": "a",
            "expected_version": 0,
            "signature": {"opt55": "1,3", "opt60": "v", "hostname": "h"},
        },
    ),
    ("DELETE", "/identity/rules/r", {"expected_version": 0}),
]


@pytest.mark.parametrize("scope", ["service", "integration", "read-only"])
@pytest.mark.parametrize("method,path,body", WRITE_CASES)
def test_valid_non_control_tokens_cannot_write(env, scope, method, path, body):
    _, token = tokens.create_token(env.ov, "restricted", scope=scope)
    r = env.client.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403, r.text
    assert count(env, "audit_log") == 0 and count(env, "device_overrides") == 0


@pytest.mark.parametrize("scope", ["service", "integration", "read-only"])
def test_restricted_tokens_cannot_patch(env, scope):
    env.device("a")
    _, token = tokens.create_token(env.ov, "restricted", scope=scope)
    r = env.client.patch(
        "/devices/a",
        json={"name": "x"},
        headers={"Authorization": f"Bearer {token}", "If-Match": "0"},
    )
    assert r.status_code == 403
    assert count(env, "device_overrides") == 0


@pytest.mark.parametrize("method,path,body", WRITE_CASES)
def test_write_body_and_rate_limits(env, method, path, body):
    from api_helpers import NOW
    from fastapi.testclient import TestClient

    from vigie_api.app import create_app
    from vigie_api.config import Settings

    _, token = tokens.create_token(env.ov, "limited", rules_write=True)
    auth = {"Authorization": f"Bearer {token}"}
    settings = Settings(data_dir=env.root, rate_limit_per_window=1, max_body_bytes=512)
    with TestClient(create_app(settings, clock=lambda: NOW)) as client:
        oversized = client.request(method, path, content=b"x" * 513, headers=auth)
        assert oversized.status_code == 413
        invalid = client.request(method, path, json={"expected_version": True}, headers=auth)
        assert invalid.status_code == 422
        limited = client.request(method, path, json=body, headers=auth)
        assert limited.status_code == 429
        assert limited.headers["Retry-After"]


def test_replay_with_new_request_id_or_principal_is_noop(env):
    suggestion(env)
    result = post(env, "/suggestions/s/accept")
    _, token = tokens.create_token(env.ov, "other")
    headers = {"Authorization": f"Bearer {token}", "X-Request-ID": "request-2"}
    assert post(env, "/suggestions/s/accept", headers=headers).json() == result.json()
    merge = result.json()["data"]["merge_id"]
    body = {"expected_versions": {"a": 1, "b": 1}}
    undo = post(env, f"/identity/merges/{merge}/undo", body)
    assert post(env, f"/identity/merges/{merge}/undo", body, headers).json() == undo.json()
    assert count(env, "audit_log") == 2


def test_undo_refuses_to_clobber_later_override(env):
    suggestion(env)
    r = post(env, "/suggestions/s/accept")
    merge = r.json()["data"]["merge_id"]
    assert env.patch("/devices/b", {"name": "New"}, "1").status_code == 200
    r = post(env, f"/identity/merges/{merge}/undo", {"expected_versions": {"a": 1, "b": 2}})
    assert r.status_code == 409
    assert env.get("/devices/b").json()["data"]["name"] == "New"
    assert env.ov.execute("SELECT revoked_at FROM identity_links").fetchone()[0] is None


@pytest.mark.parametrize("corruption", ["missing", "pair", "accepted", "rejected"])
def test_merge_candidate_reference_is_revalidated(env, corruption):
    suggestion(env)
    if corruption == "missing":
        env.inv.execute("DELETE FROM identity_candidates")
    elif corruption == "pair":
        env.inv.execute("UPDATE identity_candidates SET device_b='else'")
    else:
        env.inv.execute("UPDATE identity_candidates SET state=?", (corruption,))
    assert post(env, "/suggestions/s/accept").status_code == 409
    assert count(env, "identity_links") == 0


def test_overlap_and_orphan_are_checked_at_accept(env):
    from api_helpers import NOW

    suggestion(env)
    env.mac("02:00:00:00:00:01", "a")
    env.mac("02:00:00:00:00:02", "b")
    env.inv.executemany(
        "INSERT INTO mac_activity VALUES (?,?,?)",
        [
            ("02:00:00:00:00:01", int(NOW) - 2000, int(NOW)),
            ("02:00:00:00:00:02", int(NOW) - 2000, int(NOW)),
        ],
    )
    assert post(env, "/suggestions/s/accept").status_code == 409
    assert count(env, "identity_links") == 0
    env.inv.execute("DELETE FROM mac_activity")
    env.inv.execute('UPDATE suggestions SET device_ids=\'["missing","b"]\'')
    assert post(env, "/suggestions/s/accept").status_code == 409


def test_remember_uses_candidate_signature_and_requires_rules_privilege(env):
    suggestion(env)
    env.inv.execute(
        "UPDATE identity_candidates SET evidence=?",
        (
            json.dumps(
                {
                    "from_mac": "02:00:00:00:00:01",
                    "opt55": "1,3",
                    "opt60": "vendor",
                    "hostname": "Host",
                    "mdns_name": None,
                }
            ),
        ),
    )
    body = {"expected_versions": {"a": 0, "b": 0}, "remember": True}
    assert post(env, "/suggestions/s/accept", body).status_code == 403
    _, token = tokens.create_token(env.ov, "remember-human", rules_write=True)
    r = post(env, "/suggestions/s/accept", body, {"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    rule = env.ov.execute("SELECT * FROM identity_rules").fetchone()
    assert json.loads(rule["signature"]) == {"opt55": "1,3", "opt60": "vendor", "hostname": "host"}
    assert rule["expires_at"] is not None and rule["device_id"] == "b"


def test_rule_expiry_replay_and_later_clear_have_new_versions(env):
    suggestion(env, candidate_state="vetoed")
    _, token = tokens.create_token(env.ov, "rules-human", rules_write=True)
    auth = {"Authorization": f"Bearer {token}"}
    body = {
        "device_id": "a",
        "expected_version": 0,
        "signature": {"opt55": "1,3", "opt60": "v", "hostname": "h"},
        "expires_at": ts(-1),
    }
    assert post(env, "/identity/rules", body, auth).status_code == 422
    body["expires_at"] = ts(10)
    r = post(env, "/identity/rules", body, auth)
    assert r.status_code == 200
    assert post(env, "/identity/rules", body, auth).json() == r.json()
    result = post(env, "/identity/candidates/c/clear-veto", {"expected_versions": {"a": 1, "b": 0}})
    assert result.status_code == 200
    old_id = result.json()["data"]["id"]
    fresh = post(
        env,
        "/identity/candidates/c/clear-veto",
        {"expected_versions": {"a": 2, "b": 1}},
        {**env.auth, "X-Request-ID": "fresh-clear"},
    )
    assert fresh.status_code == 200
    assert fresh.json()["data"]["id"] != old_id


def test_remembered_rule_undo_requires_rule_privilege_and_revokes(env):
    suggestion(env)
    env.inv.execute(
        "UPDATE identity_candidates SET evidence=?",
        (json.dumps({"opt55": "1,3", "opt60": "vendor", "hostname": "Host"}),),
    )
    _, token = tokens.create_token(env.ov, "remember-human", rules_write=True)
    auth = {"Authorization": f"Bearer {token}"}
    body = {"expected_versions": {"a": 0, "b": 0}, "remember": True}
    result = post(env, "/suggestions/s/accept", body, auth)
    merge = result.json()["data"]["merge_id"]
    body = {"expected_versions": {"a": 1, "b": 1}}
    assert post(env, f"/identity/merges/{merge}/undo", body).status_code == 403
    assert env.ov.execute("SELECT revoked_at FROM identity_rules").fetchone()[0] is None
    assert count(env, "audit_log") == 1
    assert post(env, f"/identity/merges/{merge}/undo", body, auth).status_code == 200
    assert env.ov.execute("SELECT revoked_at FROM identity_rules").fetchone()[0]
    assert count(env, "audit_log") == 2


def test_existing_aliases_flatten_and_restore_on_undo(env):
    suggestion(env)
    env.device("child")
    env.link("child", "a")
    result = post(env, "/suggestions/s/accept")
    assert result.status_code == 200
    assert (
        env.ov.execute(
            "SELECT into_device FROM identity_links WHERE from_device='child'"
        ).fetchone()[0]
        == "b"
    )
    merge = result.json()["data"]["merge_id"]
    result = post(env, f"/identity/merges/{merge}/undo", {"expected_versions": {"a": 1, "b": 1}})
    assert result.status_code == 200
    assert (
        env.ov.execute(
            "SELECT into_device FROM identity_links WHERE from_device='child'"
        ).fetchone()[0]
        == "a"
    )


def test_merge_link_read_projection_and_undo(env):
    suggestion(env)
    env.mac("02:00:00:00:00:01", "a")
    result = post(env, "/suggestions/s/accept")
    merge = result.json()["data"]["merge_id"]
    assert env.get("/macs/02:00:00:00:00:01").json()["data"]["link_source"] == "human"
    assert env.get("/devices/b").json()["data"]["macs"][0]["link_source"] == "human"
    assert (
        post(
            env, f"/identity/merges/{merge}/undo", {"expected_versions": {"a": 1, "b": 1}}
        ).status_code
        == 200
    )
    assert env.get("/macs/02:00:00:00:00:01").json()["data"]["link_source"] == "self"
    assert env.get("/devices/a").json()["data"]["macs"][0]["link_source"] == "self"


def test_revoke_rule_resolves_merged_target_and_allows_retired(env):
    suggestion(env)
    _, token = tokens.create_token(env.ov, "rules-human", rules_write=True)
    auth = {"Authorization": f"Bearer {token}"}
    body = {
        "device_id": "a",
        "expected_version": 0,
        "signature": {"opt55": "1,3", "opt60": "v", "hostname": "h"},
    }
    rule = post(env, "/identity/rules", body, auth).json()["data"]["id"]
    env.inv.execute("UPDATE suggestions SET basis=?", (json.dumps({"a": 1, "b": 0}),))
    merge = post(env, "/suggestions/s/accept", {"expected_versions": {"a": 1, "b": 0}})
    assert merge.status_code == 200
    env.inv.execute("UPDATE devices SET status='retired' WHERE id='b'")
    path = f"/identity/rules/{rule}"
    stale = env.client.request("DELETE", path, json={"expected_version": 0}, headers=auth)
    assert stale.status_code == 409
    assert env.ov.execute("SELECT revoked_at FROM identity_rules").fetchone()[0] is None
    result = env.client.request("DELETE", path, json={"expected_version": 1}, headers=auth)
    assert result.status_code == 200
    assert result.json()["data"]["device_id"] == "b"
    assert env.ov.execute("SELECT revoked_at FROM identity_rules").fetchone()[0]


@pytest.mark.parametrize("retired", ["a", "b"])
def test_undo_remains_available_after_device_retirement(env, retired):
    suggestion(env)
    result = post(env, "/suggestions/s/accept")
    merge = result.json()["data"]["merge_id"]
    env.inv.execute("UPDATE devices SET status='retired' WHERE id=?", (retired,))
    result = post(env, f"/identity/merges/{merge}/undo", {"expected_versions": {"a": 1, "b": 1}})
    assert result.status_code == 200, result.text
    assert env.ov.execute("SELECT revoked_at FROM identity_links").fetchone()[0]
    assert result.json()["data"]["versions"] == {"a": 2, "b": 2}


def test_rule_can_be_revoked_while_inventory_is_unavailable(env):
    env.device("a")
    _, token = tokens.create_token(env.ov, "rules-human", rules_write=True)
    auth = {"Authorization": f"Bearer {token}"}
    body = {
        "device_id": "a",
        "expected_version": 0,
        "signature": {"opt55": "1,3", "opt60": "v", "hostname": "h"},
    }
    rule = post(env, "/identity/rules", body, auth).json()["data"]["id"]
    env.settings.inventory_path.rename(env.root / "inventory-offline.db")
    result = env.client.request(
        "DELETE", f"/identity/rules/{rule}", json={"expected_version": 1}, headers=auth
    )
    assert result.status_code == 200, result.text
    assert env.ov.execute("SELECT revoked_at FROM identity_rules").fetchone()[0]
