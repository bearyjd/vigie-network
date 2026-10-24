"""Regressions found by the independent identity API review."""

import json

import pytest
from api_helpers import NOW, env, ts  # noqa: F401
from test_api_identity_writes import post, suggestion

from vigie_api import identity_writes as domain
from vigie_api import tokens
from vigie_api.models import RuleCreate, SuggestionDecision, VersionedWrite
from vigie_pipeline.config import PipelineConfig


@pytest.mark.parametrize("short_device", ["a", "b"])
def test_merge_blocks_fully_contained_activity_in_either_component(env, short_device):
    suggestion(env)
    for device, mac in [("a", "02:00:00:00:00:01"), ("b", "02:00:00:00:00:02")]:
        env.mac(mac, device)
        start, end = (-500, -200) if device == short_device else (-2000, 0)
        env.inv.execute("INSERT INTO mac_activity VALUES (?,?,?)", (mac, NOW + start, NOW + end))

    response = post(env, "/suggestions/s/accept")

    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "active_overlap"
    assert env.ov.execute("SELECT count(*) FROM identity_links").fetchone()[0] == 0
    assert env.ov.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0


@pytest.mark.parametrize("action", ["create", "revoke", "undo", "clear", "label"])
def test_identity_write_lock_work_ignores_unrelated_links(env, action):
    suggestion(
        env,
        "label" if action == "label" else "merge_identity",
        candidate_state="vetoed" if action == "clear" else "suggested",
    )
    principal = tokens.Principal("human", tokens.SCOPE_RULES)
    common = {"principal": principal, "now": ts(), "request_id": "bounded"}
    if action == "undo":
        accepted = domain.decide(
            env.inv,
            env.ov,
            sid="s",
            accept=True,
            body=SuggestionDecision(expected_versions={"a": 0, "b": 0}),
            config=PipelineConfig(data_dir=env.root),
            **common,
        )
    elif action == "revoke":
        env.ov.execute(
            "INSERT INTO identity_rules (id,device_id,signature,created_at,created_by)"
            " VALUES ('rule','a','{}',?,'app:human')",
            (ts(),),
        )
    env.ov.execute("BEGIN")
    env.ov.executemany(
        "INSERT INTO identity_links (from_device,into_device,merge_id,created_at,created_by)"
        " VALUES (?,?,'old',?,'test')",
        [(f"unrelated-{n}", f"other-{n}", ts()) for n in range(10000)],
    )
    env.ov.execute("COMMIT")
    locked, steps = False, 0

    def trace(sql):
        nonlocal locked
        if sql == "BEGIN IMMEDIATE":
            locked = True
        elif sql in {"COMMIT", "ROLLBACK"}:
            locked = False

    def progress():
        nonlocal steps
        steps += int(locked)
        return int(steps > 10000)

    env.ov.set_trace_callback(trace)
    env.ov.set_progress_handler(progress, 1)
    try:
        if action == "create":
            domain.create_rule(
                env.inv,
                env.ov,
                body=RuleCreate(
                    device_id="a",
                    expected_version=0,
                    signature={"opt55": "1,3", "opt60": "v", "hostname": "h"},
                ),
                **common,
            )
        elif action == "revoke":
            domain.revoke_rule(
                env.inv,
                env.ov,
                rule_id="rule",
                body=VersionedWrite(expected_version=0),
                **common,
            )
        elif action == "undo":
            domain.undo(
                env.inv,
                env.ov,
                merge_id=accepted["merge_id"],
                body=VersionedWrite(expected_versions={"a": 1, "b": 1}),
                **common,
            )
        elif action == "clear":
            domain.clear_veto(
                env.inv,
                env.ov,
                candidate_id="c",
                body=VersionedWrite(expected_versions={"a": 0, "b": 0}),
                **common,
            )
        else:
            domain.decide(
                env.inv,
                env.ov,
                sid="s",
                accept=True,
                body=SuggestionDecision(expected_version=0),
                config=PipelineConfig(data_dir=env.root),
                **common,
            )
    finally:
        env.ov.set_trace_callback(None)
        env.ov.set_progress_handler(None, 0)
    assert steps < 10000


@pytest.mark.parametrize("graph", ["cycle", "too_deep"])
def test_rule_revoke_fails_closed_on_unresolvable_identity(env, graph):
    env.device("a")
    _, token = tokens.create_token(env.ov, "rules", rules_write=True)
    env.ov.execute(
        "INSERT INTO identity_rules (id,device_id,signature,created_at,created_by)"
        " VALUES ('rule','a','{}',?,'app:human')",
        (ts(),),
    )
    if graph == "cycle":
        env.link("a", "b")
        env.link("b", "a")
    else:
        previous = "a"
        for n in range(33):
            current = f"alias-{n}"
            env.link(previous, current)
            previous = current

    response = env.client.request(
        "DELETE",
        "/identity/rules/rule",
        json={"expected_version": 0},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 409, response.text
    assert env.ov.execute("SELECT revoked_at FROM identity_rules").fetchone()[0] is None
    assert env.ov.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0


def test_undo_uses_participant_versions_discovered_from_device_details(env):
    suggestion(env)
    changed = env.patch("/devices/b", {"group_id": "iot"}, '"0"')
    assert changed.status_code == 200, changed.text
    target_version = changed.json()["data"]["version"]
    env.inv.execute(
        "UPDATE suggestions SET basis=? WHERE id='s'",
        (json.dumps({"a": 0, "b": target_version}),),
    )
    accepted = post(
        env, "/suggestions/s/accept", {"expected_versions": {"a": 0, "b": target_version}}
    )
    assert accepted.status_code == 200, accepted.text
    merge = accepted.json()["data"]["merge_id"]
    versions = {}
    for device, expected_own in [("a", 1), ("b", 2)]:
        response = env.get(f"/devices/{device}")
        detail = response.json()["data"]
        assert detail["override_version"] == 2
        assert response.headers["ETag"] == '"2"'
        assert detail["identity_override_version"] == expected_own
        versions[device] = detail["identity_override_version"]

    undone = post(env, f"/identity/merges/{merge}/undo", {"expected_versions": versions})

    assert undone.status_code == 200, undone.text
    assert env.get("/devices/a").json()["data"]["merged_into"] is None


@pytest.mark.parametrize("expires_at", ["0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"])
def test_rule_expiry_utc_overflow_is_a_validation_error_without_writes(env, expires_at):
    env.device("a")
    _, token = tokens.create_token(env.ov, "expiry-human", rules_write=True)
    response = env.client.post(
        "/identity/rules",
        json={
            "device_id": "a",
            "expected_version": 0,
            "signature": {"opt55": "1,3", "opt60": "vendor", "hostname": "host"},
            "expires_at": expires_at,
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "invalid_timestamp"
    for table in ("identity_rules", "device_overrides", "audit_log", "api_write_receipts"):
        assert env.ov.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0  # noqa: S608
