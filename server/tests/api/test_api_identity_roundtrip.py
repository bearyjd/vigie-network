"""Human API decisions survive a real pipeline pass and remain reversible."""

from __future__ import annotations

import json

import pytest
from api_helpers import NOW, Env, env, ts  # noqa: F401

from vigie_api import tokens
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.processor import run_once
from vigie_pipeline.snapshot import load_snapshot

SIGNATURE = {"opt55": "1,2,3", "opt60": "x", "hostname": "victim"}
TARGET_MAC = "ae:00:00:00:00:01"
ALIAS_MAC = "ae:00:00:00:00:02"


def _pair(env: Env) -> None:
    for device, mac, start, end, randomized in (
        ("target", TARGET_MAC, -90000, -80000, 0),
        ("alias", ALIAS_MAC, -3000, 0, 1),
    ):
        env.device(device)
        env.inv.execute(
            "UPDATE devices SET first_seen=?, last_seen=? WHERE id=?",
            (ts(start), ts(end), device),
        )
        env.inv.execute(
            "INSERT INTO observations (mac,device_id,is_randomized,dhcp_fingerprint,"
            "vendor_class,hostname,hostname_fold,link_source,first_seen,last_seen)"
            " VALUES (?,?,?,'1,2,3','x','victim','victim','self',?,?)",
            (mac, device, randomized, ts(start), ts(end)),
        )
        env.inv.execute(
            'INSERT INTO mac_activity (mac,start,"end") VALUES (?,?,?)',
            (mac, int(NOW + start), int(NOW + end)),
        )
        env.inv.execute(
            "INSERT INTO mac_first_received (mac,received) VALUES (?,?)",
            (mac, int(NOW - 10**6)),
        )


def _versions(env: Env) -> dict[str, int]:
    rows = env.ov.execute("SELECT device_id,version FROM device_overrides").fetchall()
    versions = {"target": 0, "alias": 0}
    versions.update({row["device_id"]: row["version"] for row in rows})
    return versions


def _rule(env: Env) -> str:
    _, token = tokens.create_token(env.ov, "rule-human", rules_write=True)
    response = env.client.post(
        "/identity/rules",
        json={
            "device_id": "target",
            "signature": SIGNATURE,
            "expected_version": _versions(env)["target"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code in (200, 201), response.text
    row = env.ov.execute("SELECT id FROM identity_rules").fetchone()
    assert row is not None
    return row["id"]


def _run(env: Env) -> None:
    run_once(PipelineConfig(data_dir=env.root), now=NOW)


def test_api_rule_is_applied_by_pipeline_and_visible_in_mac_resolution(env: Env) -> None:
    _pair(env)
    assert env.patch("/devices/target", {"group_id": "iot"}, "0").status_code == 200
    rule_id = _rule(env)
    assert env.get(f"/macs/{ALIAS_MAC}").json()["data"]["device_id"] == "alias"

    _run(env)

    resolved = env.get(f"/macs/{ALIAS_MAC}").json()["data"]
    assert resolved["device_id"] == "target"
    assert resolved["link_source"] == "rule"
    detail = env.get("/devices/target").json()["data"]
    assert detail["group_id"] == "iot"
    attached = next(row for row in detail["macs"] if row["mac"] == ALIAS_MAC)
    assert attached["link_rule_id"] == rule_id


def test_api_merge_then_pipeline_then_undo_preserves_observation_ownership(env: Env) -> None:
    _pair(env)
    env.inv.execute(
        "INSERT INTO identity_candidates"
        " (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES ('merge-candidate','alias','target',0.8,?,'suggested',?)",
        (json.dumps(SIGNATURE), ts(-10)),
    )
    env.inv.execute(
        "INSERT INTO suggestions VALUES (?,?,?,?,?,?,?,?,?)",
        (
            "merge-roundtrip",
            "merge_identity",
            json.dumps(["alias", "target"]),
            json.dumps(
                {
                    "from_device": "alias",
                    "into_device": "target",
                    "signature": SIGNATURE,
                    "evidence_summary": {"candidate_id": "merge-candidate"},
                }
            ),
            "fingerprint_match",
            None,
            json.dumps(_versions(env)),
            ts(-10),
            ts(3600),
        ),
    )
    response = env.client.post(
        "/suggestions/merge-roundtrip/accept",
        json={"expected_versions": _versions(env), "remember": False},
        headers=env.auth,
    )
    assert response.status_code == 200, response.text
    merge_id = env.ov.execute("SELECT id FROM identity_merges").fetchone()["id"]

    _run(env)

    assert env.get(f"/macs/{ALIAS_MAC}").json()["data"]["device_id"] == "target"
    assert env.get("/devices/alias").json()["data"]["merged_into"] == "target"
    assert (
        env.inv.execute("SELECT device_id FROM observations WHERE mac=?", (ALIAS_MAC,)).fetchone()[
            "device_id"
        ]
        == "alias"
    )
    response = env.client.post(
        f"/identity/merges/{merge_id}/undo",
        json={"expected_versions": _versions(env)},
        headers=env.auth,
    )
    assert response.status_code == 200, response.text

    _run(env)

    assert env.get(f"/macs/{ALIAS_MAC}").json()["data"]["device_id"] == "alias"
    assert env.get("/devices/alias").json()["data"]["merged_into"] is None
    assert (
        env.inv.execute("SELECT device_id FROM observations WHERE mac=?", (ALIAS_MAC,)).fetchone()[
            "device_id"
        ]
        == "alias"
    )


def test_api_veto_clearance_allows_fresh_pipeline_rule_evaluation(env: Env) -> None:
    _pair(env)
    assert env.patch("/devices/target", {"group_id": "iot"}, "0").status_code == 200
    _rule(env)
    env.inv.execute(
        "INSERT INTO identity_candidates"
        " (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES ('old-veto','alias','target',0.8,'{}','vetoed',?)",
        (ts(-100),),
    )
    _run(env)
    assert env.get(f"/macs/{ALIAS_MAC}").json()["data"]["device_id"] == "alias"
    response = env.client.post(
        "/identity/candidates/old-veto/clear-veto",
        json={"expected_versions": _versions(env)},
        headers=env.auth,
    )
    assert response.status_code == 200, response.text
    # Clearance records intent in overrides.db; only the pipeline changes its own inventory.
    assert (
        env.inv.execute("SELECT state FROM identity_candidates WHERE id='old-veto'").fetchone()[
            "state"
        ]
        == "vetoed"
    )

    _run(env)

    resolved = env.get(f"/macs/{ALIAS_MAC}").json()["data"]
    assert resolved["device_id"] == "target" and resolved["link_source"] == "rule"


def test_api_reads_preserve_pipeline_snapshot_identity_version(env: Env) -> None:
    _pair(env)
    _, token = tokens.create_token(env.ov, "version-human", rules_write=True)
    privileged = {"Authorization": f"Bearer {token}"}
    observer = open_overrides_ro(env.root / "overrides.db")
    assert observer is not None
    try:
        baseline = load_snapshot(observer, NOW).identity_version
        audit_before = list(env.ov.execute("SELECT * FROM audit_log"))
        writes_before = list(env.ov.execute("SELECT * FROM api_write_receipts"))
        decisions_before = list(env.ov.execute("SELECT * FROM candidate_decisions"))
        receipts_before = list(env.inv.execute("SELECT * FROM stitch_state"))
        for _ in range(3):
            for path in ("/identity/rules", "/suggestions", "/devices", "/healthz"):
                assert env.get(path).status_code == 200
        assert load_snapshot(observer, NOW).identity_version == baseline
        assert list(env.ov.execute("SELECT * FROM audit_log")) == audit_before
        assert list(env.ov.execute("SELECT * FROM api_write_receipts")) == writes_before
        assert list(env.ov.execute("SELECT * FROM candidate_decisions")) == decisions_before
        assert list(env.inv.execute("SELECT * FROM stitch_state")) == receipts_before

        body = {"device_id": "target", "signature": SIGNATURE, "expected_version": 0}
        write_headers = {**privileged, "X-Request-Id": "version-rule-create"}
        response = env.client.post("/identity/rules", json=body, headers=write_headers)
        assert response.status_code in (200, 201), response.text
        after_write = load_snapshot(observer, NOW).identity_version
        assert after_write != baseline
        audit_after_write = list(env.ov.execute("SELECT * FROM audit_log"))
        writes_after = list(env.ov.execute("SELECT * FROM api_write_receipts"))

        replay = env.client.post("/identity/rules", json=body, headers=write_headers)
        assert replay.status_code == response.status_code and replay.json() == response.json()
        stale = env.client.post(
            "/identity/rules",
            json=body,
            headers={**privileged, "X-Request-Id": "version-rule-stale"},
        )
        assert stale.status_code == 409, stale.text
        for _ in range(3):
            assert env.get("/identity/rules").status_code == 200
            assert env.get("/devices/target").status_code == 200
        assert load_snapshot(observer, NOW).identity_version == after_write
        assert list(env.ov.execute("SELECT * FROM audit_log")) == audit_after_write
        assert list(env.ov.execute("SELECT * FROM api_write_receipts")) == writes_after
        assert list(env.ov.execute("SELECT * FROM candidate_decisions")) == decisions_before
        assert list(env.inv.execute("SELECT * FROM stitch_state")) == receipts_before
    finally:
        observer.close()


@pytest.mark.parametrize("active_rule_with_overlap", [False, True])
def test_api_clear_needs_rule_and_fresh_nonoverlap_before_attachment(
    env: Env,
    active_rule_with_overlap: bool,
) -> None:
    _pair(env)
    if active_rule_with_overlap:
        assert env.patch("/devices/target", {"group_id": "iot"}, "0").status_code == 200
        _rule(env)
        env.inv.execute(
            'UPDATE mac_activity SET start=?, "end"=? WHERE mac=?',
            (int(NOW - 6000), int(NOW), TARGET_MAC),
        )
    env.inv.execute(
        "INSERT INTO identity_candidates"
        " (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES ('blocked-veto','alias','target',0.8,'{}','vetoed',?)",
        (ts(-100),),
    )
    response = env.client.post(
        "/identity/candidates/blocked-veto/clear-veto",
        json={"expected_versions": _versions(env)},
        headers=env.auth,
    )
    assert response.status_code == 200, response.text
    assert (
        env.inv.execute("SELECT state FROM identity_candidates WHERE id='blocked-veto'").fetchone()[
            "state"
        ]
        == "vetoed"
    )

    _run(env)

    assert env.inv.execute(
        "SELECT state FROM identity_candidates WHERE id='blocked-veto'"
    ).fetchone()["state"] == ("vetoed" if active_rule_with_overlap else "suggested")
    resolved = env.get(f"/macs/{ALIAS_MAC}").json()["data"]
    assert resolved["device_id"] == "alias" and resolved["link_source"] == "self"
    assert (
        env.inv.execute(
            "SELECT COUNT(*) FROM rule_attachments WHERE mac=?", (ALIAS_MAC,)
        ).fetchone()[0]
        == 0
    )
