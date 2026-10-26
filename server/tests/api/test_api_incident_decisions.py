"""Incident lifecycle writes: acknowledge / snooze / mark-expected / clear (overrides overlay)."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from incident_helpers import audits, decisions, incident, post, seed_collector, until

from vigie_api import tokens


@pytest.fixture
def e(env: Env) -> Env:  # noqa: F811
    seed_collector(env)
    incident(env, "inc1")
    return env


def test_acknowledge_from_zero_records_decision_audit_and_never_writes_inventory(e):
    before = e.inv.execute("SELECT * FROM monitoring_incidents").fetchall()
    result = post(e, "inc1", "acknowledge")
    assert result.status_code == 200, result.text
    data = result.json()["data"]
    assert data["incident_id"] == "inc1"
    assert (data["status"], data["snooze_until"], data["version"]) == ("acknowledged", None, 1)
    assert data["decided_by"] == "app"  # the token id is never exposed
    assert [d["status"] for d in decisions(e)] == ["acknowledged"]
    row = decisions(e)[0]
    assert (row["collector_id"], row["device_id"], row["lineage"], row["detector"]) == (
        "c1", "d1", "line", "large_upload")  # fmt: skip
    assert row["decided_by"] == "app:test"
    (audit,) = audits(e)
    assert (audit["action"], audit["target"]) == ("monitoring.incident.acknowledge", "inc1")
    detail = json.loads(audit["detail"])
    assert detail["before"]["review"] is None
    assert detail["after"]["review"]["status"] == "acknowledged"
    assert detail["after"]["incident"]["device_id"] == "d1"
    assert e.inv.execute("SELECT * FROM monitoring_incidents").fetchall() == before


def test_cas_increments_and_stale_version_is_409(e):
    assert post(e, "inc1", "acknowledge", {"expected_version": 0}).json()["data"]["version"] == 1
    stale = post(e, "inc1", "mark-expected", {"expected_version": 0})
    assert (stale.status_code, stale.json()["error"]["code"]) == (409, "version_conflict")
    moved = post(e, "inc1", "mark-expected", {"expected_version": 1})
    assert moved.json()["data"]["version"] == 2
    assert moved.json()["data"]["status"] == "expected"
    snooze = post(e, "inc1", "snooze", {"expected_version": 2, "until": until(3600)})
    assert snooze.json()["data"]["version"] == 3
    assert snooze.json()["data"]["snooze_until"] == until(3600)
    assert decisions(e)[0]["snooze_until"] == int(NOW) + 3600
    back = post(e, "inc1", "acknowledge", {"expected_version": 3})
    assert back.json()["data"]["snooze_until"] is None
    assert decisions(e)[0]["snooze_until"] is None


def test_clear_leaves_a_tombstone_and_needs_a_decision(e):
    miss = post(e, "inc1", "clear", {"expected_version": 0})
    assert (miss.status_code, miss.json()["error"]["code"]) == (409, "no_decision")
    post(e, "inc1", "acknowledge")
    assert post(e, "inc1", "clear", {"expected_version": 0}).status_code == 409
    cleared = post(e, "inc1", "clear", {"expected_version": 1})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["data"]["status"] is None
    assert cleared.json()["data"]["version"] == 2
    assert [(d["status"], d["version"]) for d in decisions(e)] == [(None, 2)]
    assert [a["action"] for a in audits(e)][-1] == "monitoring.incident.clear"
    detail = json.loads(audits(e)[-1]["detail"])
    assert detail["before"]["review"]["status"] == "acknowledged"
    assert detail["after"]["review"] is None


def test_two_concurrent_writers_one_wins_one_409(e):
    with ThreadPoolExecutor(2) as pool:
        codes = sorted(
            r.status_code
            for r in pool.map(lambda a: post(e, "inc1", a), ["acknowledge", "mark-expected"])
        )
    assert codes == [200, 409]
    assert len(decisions(e)) == 1


@pytest.mark.parametrize("state", ["resolved", "superseded"])
def test_snooze_on_a_closed_incident_is_409_but_ack_and_expected_work(e, state):
    incident(e, "old", state=state, lineage="l2")
    snooze = post(e, "old", "snooze", {"expected_version": 0, "until": until(3600)})
    assert (snooze.status_code, snooze.json()["error"]["code"]) == (409, "incident_not_open")
    assert decisions(e) == []
    assert post(e, "old", "acknowledge").status_code == 200
    assert post(e, "old", "mark-expected", {"expected_version": 1}).status_code == 200
    assert post(e, "old", "clear", {"expected_version": 2}).status_code == 200


def test_unknown_incident_and_other_collector_are_404_without_leaking(e):
    assert post(e, "nope", "acknowledge").json()["error"]["code"] == "incident_not_found"
    wrong = post(e, "inc1", "acknowledge", collector="c2")
    assert (wrong.status_code, wrong.json()["error"]["code"]) == (404, "incident_not_found")
    assert decisions(e) == []


def test_receipt_target_is_the_incident_so_two_incidents_of_one_device_both_decide(e):
    incident(e, "inc2", lineage="line2")
    first = post(e, "inc1", "acknowledge")
    second = post(e, "inc2", "acknowledge")  # identical body, no X-Request-ID
    assert first.status_code == second.status_code == 200
    assert [d["incident_id"] for d in decisions(e)] == ["inc1", "inc2"]


def test_idempotency_replay_and_conflict(e):
    h = {"X-Request-ID": "req-1"}
    first = post(e, "inc1", "acknowledge", headers=h)
    again = post(e, "inc1", "acknowledge", headers=h)
    assert again.status_code == 200 and again.json() == first.json()
    assert decisions(e)[0]["version"] == 1 and len(audits(e)) == 1
    clash = post(e, "inc1", "acknowledge", {"expected_version": 5}, headers=h)
    assert (clash.status_code, clash.json()["error"]["code"]) == (409, "idempotency_conflict")


@pytest.mark.parametrize("scope", ["read-only", "service", "integration"])
def test_non_writer_scopes_are_forbidden(e, scope):
    _, token = tokens.create_token(e.ov, f"s{scope[:3]}", scope=scope)
    denied = post(e, "inc1", "acknowledge", headers={"Authorization": f"Bearer {token}"})
    assert (denied.status_code, denied.json()["error"]["code"]) == (403, "forbidden")
    assert decisions(e) == []


def test_rules_write_scope_and_anonymous(e):
    _, token = tokens.create_token(e.ov, "rw", rules_write=True)
    ok = post(e, "inc1", "acknowledge", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200
    assert post(e, "inc1", "acknowledge", auth=False).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"expected_version": -1},
        {"expected_version": "0"},
        {"expected_version": True},
        {"expected_version": 1.5},
        {"expected_version": 0, "note": "hi"},
        {"expected_versions": {"inc1": 0}},
        {"expected_version": 0, "until": until(3600)},  # only snooze takes `until`
    ],
)
def test_bad_bodies_are_422_and_write_nothing(e, body):
    for action in ("acknowledge", "mark-expected", "clear"):
        assert post(e, "inc1", action, body).status_code == 422
    assert decisions(e) == [] and audits(e) == []


WEEK = 7 * 24 * 3600


@pytest.mark.parametrize(
    "value",
    [
        until(-10),  # past
        until(30),  # too soon
        until(59),
        until(WEEK + 1),  # over the cap
        "2026-10-21T12:00:00",  # naive
        "2026-10-21T12:00:00+02:00",  # non-UTC offset
        "2026-10-21",
        "2026-02-30T00:00:00Z",
        "not a date",
        "20261021T120000Z",
        "2026-10-21T12:00:00.5Z",
        "",
    ],
)
def test_snooze_until_must_be_a_utc_instant_inside_the_window(e, value):
    r = post(e, "inc1", "snooze", {"expected_version": 0, "until": value})
    assert r.status_code == 422, r.text
    assert decisions(e) == []


def test_snooze_until_boundaries_are_inclusive_and_required(e):
    assert post(e, "inc1", "snooze", {"expected_version": 0}).status_code == 422
    low = post(e, "inc1", "snooze", {"expected_version": 0, "until": until(60)})
    assert low.status_code == 200, low.text
    high = post(e, "inc1", "snooze", {"expected_version": 1, "until": until(WEEK)})
    assert high.status_code == 200, high.text
    offset = post(e, "inc1", "snooze", {"expected_version": 2, "until": until(120)[:-1] + "+00:00"})
    assert offset.status_code == 200, offset.text


def test_snooze_cap_is_configurable(env):
    from fastapi.testclient import TestClient

    from vigie_api.app import create_app
    from vigie_api.config import Settings

    seed_collector(env)
    incident(env, "inc1")
    app = create_app(Settings(data_dir=env.root, incident_snooze_max_s=600), clock=lambda: NOW)
    with TestClient(app) as client:
        body = {"expected_version": 0, "until": until(601)}
        url = "/incidents/inc1/snooze"
        r = client.post(url, params={"collector_id": "c1"}, json=body, headers=env.auth)
        assert r.status_code == 422
        body["until"] = until(600)
        r = client.post(url, params={"collector_id": "c1"}, json=body, headers=env.auth)
        assert r.status_code == 200


def test_settings_reads_snooze_cap_from_env_and_rejects_nonpositive(tmp_path):
    from vigie_api.config import Settings

    s = Settings.from_env({"VIGIE_DATA_DIR": str(tmp_path), "VIGIE_API_INCIDENT_SNOOZE_MAX_S": "5"})
    assert s.incident_snooze_max_s == 5
    with pytest.raises(ValueError):
        Settings(data_dir=tmp_path, incident_snooze_max_s=0)


def test_inventory_is_opened_read_only_and_missing_inventory_is_503(e, monkeypatch):
    import vigie_api.app as app_mod

    opened = []
    real = sqlite3.connect

    def spy(target, *a, **kw):
        opened.append(str(target))
        return real(target, *a, **kw)

    monkeypatch.setattr(app_mod.sqlite3, "connect", spy)
    monkeypatch.setattr("vigie_api.schema.sqlite3.connect", spy)
    assert post(e, "inc1", "acknowledge").status_code == 200
    inventory_opens = [t for t in opened if "inventory.db" in t]
    assert inventory_opens and all("mode=ro" in t for t in inventory_opens)
    (e.root / "inventory.db").rename(e.root / "gone.db")
    assert post(e, "inc1", "clear", {"expected_version": 1}).status_code == 503


def test_rate_limit_and_body_limit_apply(e):
    from fastapi.testclient import TestClient

    from vigie_api.app import create_app
    from vigie_api.config import Settings

    app = create_app(
        Settings(data_dir=e.root, rate_limit_per_window=2, max_body_bytes=64), clock=lambda: NOW
    )
    with TestClient(app) as client:
        url = "/incidents/inc1/acknowledge"
        big = client.post(url, params={"collector_id": "c1"}, json={"expected_version": 0,
                          "pad": "x" * 200}, headers=e.auth)  # fmt: skip
        assert big.status_code == 413
        ok = client.post(url, params={"collector_id": "c1"}, json={"expected_version": 0},
                         headers=e.auth)  # fmt: skip
        assert ok.status_code == 200
        for _ in range(3):
            limited = client.post(url, params={"collector_id": "c1"},
                                  json={"expected_version": 1}, headers=e.auth)  # fmt: skip
        assert limited.status_code == 429


def test_ack_clear_ack_without_request_id_is_not_a_stale_receipt_replay(e):
    """clear must keep versions monotonic, or the third call replays the first receipt."""
    assert post(e, "inc1", "acknowledge", {"expected_version": 0}).json()["data"]["version"] == 1
    cleared = post(e, "inc1", "clear", {"expected_version": 1}).json()["data"]
    assert (cleared["status"], cleared["version"]) == (None, 2)
    third = post(e, "inc1", "acknowledge", {"expected_version": 2})
    assert third.status_code == 200 and third.json()["data"]["version"] == 3
    replay = post(e, "inc1", "acknowledge", {"expected_version": 0})  # a stale retry of call 1
    assert replay.json()["data"]["version"] == 1  # idempotent replay, nothing written
    assert len([a for a in audits(e) if a["action"].endswith("acknowledge")]) == 2
    assert e.get("/incidents/inc1", collector_id="c1").json()["data"]["attention"] is False


def test_cleared_incident_reads_as_unreviewed_and_cannot_be_cleared_twice(e):
    post(e, "inc1", "acknowledge")
    post(e, "inc1", "clear", {"expected_version": 1})
    data = e.get("/incidents/inc1", collector_id="c1").json()["data"]
    assert data["review"] is None and data["attention"] is True
    again = post(e, "inc1", "clear", {"expected_version": 2})
    assert (again.status_code, again.json()["error"]["code"]) == (409, "no_decision")


def test_read_only_token_with_bad_until_gets_403_not_422(e):
    _, token = tokens.create_token(e.ov, "ro", scope="read-only")
    r = post(e, "inc1", "snooze", {"expected_version": 0, "until": "junk"},
             headers={"Authorization": f"Bearer {token}"})  # fmt: skip
    assert r.status_code == 403
