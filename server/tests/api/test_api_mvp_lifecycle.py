"""Exercise an owner's complete identity workflow across the real API and pipeline."""

from __future__ import annotations

from api_helpers import NOW, Env, env, ts  # noqa: F401

from vigie_api import tokens
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once


def _seen(env: Env, device: str, mac: str, start: int, end: int) -> None:
    env.device(device)
    env.inv.execute(
        "UPDATE devices SET first_seen=?, last_seen=? WHERE id=?",
        (ts(start), ts(end), device),
    )
    env.inv.execute(
        "INSERT INTO observations (mac,device_id,is_randomized,dhcp_fingerprint,"
        "vendor_class,hostname,hostname_fold,link_source,first_seen,last_seen)"
        " VALUES (?,?,1,'1,2,3','phone-vendor','owner-phone','owner-phone','self',?,?)",
        (mac, device, ts(start), ts(end)),
    )
    env.inv.execute(
        'INSERT INTO mac_activity (mac,start,"end") VALUES (?,?,?)',
        (mac, int(NOW + start), int(NOW + end)),
    )
    env.inv.execute(
        "INSERT INTO mac_first_received (mac,received) VALUES (?,?)",
        (mac, int(NOW + start)),
    )


def _versions(env: Env, *devices: str) -> dict[str, int]:
    return {
        device: env.get(f"/devices/{device}").json()["data"]["identity_override_version"]
        for device in devices
    }


def test_owner_approval_remember_rotation_and_undo_lifecycle(env: Env) -> None:
    _seen(env, "phone", "ae:10:00:00:00:01", -90000, -80000)
    _seen(env, "rotation", "ae:10:00:00:00:02", -6000, -3000)
    assert (
        env.patch("/devices/phone", {"name": "My phone", "group_id": "iot"}, "0").status_code == 200
    )
    _, human = tokens.create_token(env.ov, "owner", rules_write=True)
    headers = {"Authorization": f"Bearer {human}"}
    config = PipelineConfig(data_dir=env.root)

    run_once(config, now=NOW)

    pending = env.get("/suggestions", state="pending").json()["data"]
    suggestion = next(s for s in pending if s["action"] == "merge_identity")
    assert set(suggestion["device_ids"]) == {"phone", "rotation"}
    # Matching evidence alone never grants the owner's identity or group.
    assert env.get("/macs/ae:10:00:00:00:02").json()["data"]["device_id"] == "rotation"
    body = {"expected_versions": _versions(env, "phone", "rotation"), "remember": True}
    accepted = env.client.post(
        f"/suggestions/{suggestion['id']}/accept",
        json=body,
        headers=headers,
    )
    assert accepted.status_code == 200, accepted.text
    decision = accepted.json()["data"]
    retried = env.client.post(
        f"/suggestions/{suggestion['id']}/accept",
        json=body,
        headers=headers,
    )
    assert retried.json() == accepted.json()
    assert env.ov.execute("SELECT COUNT(*) FROM identity_merges").fetchone()[0] == 1

    run_once(config, now=NOW)
    assert env.get("/macs/ae:10:00:00:00:02").json()["data"]["device_id"] == "phone"
    _seen(env, "next-rotation", "ae:10:00:00:00:03", -2400, -1000)
    run_once(config, now=NOW)
    rotated = env.get("/macs/ae:10:00:00:00:03").json()["data"]
    assert rotated["device_id"] == "phone" and rotated["link_source"] == "rule"
    phone = env.get("/devices/phone").json()["data"]
    assert phone["name"] == "My phone" and phone["group_id"] == "iot"

    undone = env.client.post(
        f"/identity/merges/{decision['merge_id']}/undo",
        # Alias reads expose each participant's own version for a later undo.
        json={"expected_versions": _versions(env, "phone", "rotation")},
        headers=headers,
    )
    assert undone.status_code == 200, undone.text
    run_once(config, now=NOW)
    assert env.get("/macs/ae:10:00:00:00:02").json()["data"]["device_id"] == "rotation"
    rules = env.get("/identity/rules").json()["data"]
    assert next(rule for rule in rules if rule["id"] == decision["rule_id"])["revoked_at"]
    _seen(env, "after-undo", "ae:10:00:00:00:04", -900, 0)
    run_once(config, now=NOW)
    assert env.get("/macs/ae:10:00:00:00:04").json()["data"]["device_id"] == "after-undo"
    assert env.get("/devices/phone").json()["data"]["name"] == "My phone"
