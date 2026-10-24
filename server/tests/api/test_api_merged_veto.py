"""Historical veto endpoints remain clearable after their devices are merged."""

import json

import pytest
from api_helpers import NOW, env, ts  # noqa: F401
from test_api_identity_roundtrip import ALIAS_MAC, SIGNATURE, _pair, _run

from vigie_api import tokens


def merged_veto(env, *, retired=False, source_alias=False, overlap=False):
    _pair(env)
    env.device("old-alias", status="retired" if retired else "active")
    env.link("old-alias", "target")
    source = "alias"
    if source_alias:
        source = "old-source"
        env.device(source, status="retired" if retired else "active")
        env.link(source, "alias")
    assert env.patch("/devices/target", {"group_id": "iot"}, "0").status_code == 200
    _, token = tokens.create_token(env.ov, "rule-human", rules_write=True)
    created = env.client.post(
        "/identity/rules",
        json={"device_id": "target", "signature": SIGNATURE, "expected_version": 1},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert created.status_code == 200, created.text
    env.inv.execute(
        "INSERT INTO identity_candidates"
        " (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES ('historical-veto',?,'old-alias',0.8,'{}','vetoed',?)",
        (source, ts(-100)),
    )
    if overlap:
        env.inv.execute(
            'UPDATE mac_activity SET start=?,"end"=? WHERE mac<>?',
            (int(NOW - 3000), int(NOW), ALIAS_MAC),
        )
    devices = list(dict.fromkeys([source, "old-alias", "alias", "target"]))
    versions = {
        device: env.get(f"/devices/{device}").json()["data"]["identity_override_version"]
        for device in devices
    }
    return source, versions


@pytest.mark.parametrize("retired", [False, True])
@pytest.mark.parametrize("source_alias", [False, True])
@pytest.mark.parametrize("overlap", [False, True])
def test_historical_alias_clear_is_exact_one_shot_intent_then_fresh_rule_evaluation(
    env, retired, source_alias, overlap
):
    source, versions = merged_veto(env, retired=retired, source_alias=source_alias, overlap=overlap)
    assert versions["old-alias"] == 0 and versions["target"] == 2
    _run(env)
    assert env.get(f"/macs/{ALIAS_MAC}").json()["data"]["device_id"] == "alias"
    audits = env.ov.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    response = env.client.post(
        "/identity/candidates/historical-veto/clear-veto",
        json={"expected_versions": versions},
        headers={**env.auth, "X-Request-ID": "historical-clear"},
    )

    assert response.status_code == 200, response.text
    result = response.json()["data"]
    assert result["versions"] == {device: version + 1 for device, version in versions.items()}
    decision = env.ov.execute("SELECT * FROM candidate_decisions").fetchone()
    assert (decision["device_a"], decision["device_b"]) == (source, "old-alias")
    assert (
        env.inv.execute(
            "SELECT state FROM identity_candidates WHERE id='historical-veto'"
        ).fetchone()[0]
        == "vetoed"
    )
    assert env.get(f"/macs/{ALIAS_MAC}").json()["data"]["device_id"] == "alias"
    audit = json.loads(
        env.ov.execute("SELECT detail FROM audit_log ORDER BY seq DESC").fetchone()[0]
    )
    assert set(audit["before"]["overrides"]) == set(versions)
    assert set(audit["after"]["overrides"]) == set(versions)
    replay = env.client.post(
        "/identity/candidates/historical-veto/clear-veto",
        json={"expected_versions": versions},
        headers={**env.auth, "X-Request-ID": "historical-clear"},
    )
    assert replay.json() == response.json()
    assert env.ov.execute("SELECT count(*) FROM audit_log").fetchone()[0] == audits + 1

    _run(env)

    resolved = env.get(f"/macs/{ALIAS_MAC}").json()["data"]
    assert (resolved["device_id"], resolved["link_source"]) == (
        ("alias", "self") if overlap else ("target", "rule")
    )
    assert (
        env.inv.execute(
            "SELECT state FROM identity_candidates WHERE id='historical-veto'"
        ).fetchone()[0]
        == "cleared"
    )
    receipt = f"candidate-clear:{result['id']}"
    assert env.inv.execute("SELECT value FROM stitch_state WHERE key=?", (receipt,)).fetchone()[0]
    # A consumed intent cannot clear this historical pair again after a later veto.
    env.inv.execute("UPDATE identity_candidates SET state='vetoed' WHERE id='historical-veto'")
    _run(env)
    assert (
        env.inv.execute(
            "SELECT state FROM identity_candidates WHERE id='historical-veto'"
        ).fetchone()[0]
        == "vetoed"
    )


@pytest.mark.parametrize("bad_versions", ["omit_root", "stale_root", "canonical_for_alias"])
def test_alias_clear_requires_current_own_versions_for_historical_and_canonical_devices(
    env, bad_versions
):
    _, versions = merged_veto(env)
    if bad_versions == "omit_root":
        del versions["target"]
    elif bad_versions == "stale_root":
        versions["target"] -= 1
    else:
        versions["old-alias"] = versions["target"]
    response = env.client.post(
        "/identity/candidates/historical-veto/clear-veto",
        json={"expected_versions": versions},
        headers=env.auth,
    )
    assert response.status_code == (422 if bad_versions == "omit_root" else 409), response.text
    assert response.json()["error"]["code"] == (
        "versions_required" if bad_versions == "omit_root" else "version_mismatch"
    )
    assert env.ov.execute("SELECT count(*) FROM candidate_decisions").fetchone()[0] == 0


@pytest.mark.parametrize(
    "corruption",
    [
        "missing_endpoint",
        "missing_root",
        "retired_root",
        "retired_incoming",
        "retired_unlinked",
        "cycle",
        "too_deep",
    ],
)
def test_alias_clear_rejects_orphans_retired_roots_and_unresolvable_graphs(env, corruption):
    _, versions = merged_veto(env)
    if corruption == "missing_endpoint":
        env.inv.execute("UPDATE identity_candidates SET device_b='missing'")
        env.link("missing", "target")
        versions["missing"] = versions.pop("old-alias")
    elif corruption == "missing_root":
        env.ov.execute(
            "UPDATE identity_links SET into_device='missing' WHERE from_device='old-alias'"
        )
    elif corruption in {"retired_root", "retired_incoming"}:
        device = "target" if corruption == "retired_root" else "alias"
        env.inv.execute("UPDATE devices SET status='retired' WHERE id=?", (device,))
    elif corruption == "retired_unlinked":
        env.inv.execute("UPDATE devices SET status='retired' WHERE id='old-alias'")
        env.ov.execute("UPDATE identity_links SET revoked_at=?", (ts(),))
    elif corruption == "cycle":
        env.link("target", "old-alias")
    else:
        previous = "target"
        for n in range(33):
            current = f"chain-{n}"
            env.link(previous, current)
            previous = current
    audits = env.ov.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    response = env.client.post(
        "/identity/candidates/historical-veto/clear-veto",
        json={"expected_versions": versions},
        headers=env.auth,
    )

    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == {
        "cycle": "invalid_identity",
        "too_deep": "identity_too_large",
    }.get(corruption, "orphaned_device")
    assert env.ov.execute("SELECT count(*) FROM candidate_decisions").fetchone()[0] == 0
    assert env.ov.execute("SELECT count(*) FROM audit_log").fetchone()[0] == audits


def test_alias_clear_audit_failure_rolls_back_all_four_versions_and_intent(env):
    _, versions = merged_veto(env, source_alias=True)
    env.ov.execute(
        "CREATE TRIGGER audit_fail BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'fail'); END"
    )
    response = env.client.post(
        "/identity/candidates/historical-veto/clear-veto",
        json={"expected_versions": versions},
        headers=env.auth,
    )

    assert response.status_code == 500, response.text
    assert env.ov.execute("SELECT count(*) FROM candidate_decisions").fetchone()[0] == 0
    assert {
        device: env.get(f"/devices/{device}").json()["data"]["identity_override_version"]
        for device in versions
    } == versions
