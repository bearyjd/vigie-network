"""Incident lifecycle writes: acknowledge / snooze / mark-expected / clear (overrides overlay)."""

import json
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


def test_clear_deletes_the_row_and_needs_a_decision(e):
    miss = post(e, "inc1", "clear", {"expected_version": 0})
    assert (miss.status_code, miss.json()["error"]["code"]) == (409, "no_decision")
    post(e, "inc1", "acknowledge")
    assert post(e, "inc1", "clear", {"expected_version": 0}).status_code == 409
    cleared = post(e, "inc1", "clear", {"expected_version": 1})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["data"]["status"] is None
    assert cleared.json()["data"]["version"] == 0
    assert decisions(e) == []
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
