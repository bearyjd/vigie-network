"""F6-b: an `essential_absence` incident is served (200) with exactly the fixed evidence shape;
hostile stored evidence is dropped; it is reported apart from the upload pilot numbers."""

from __future__ import annotations

import json

import pytest
from api_helpers import Env, env  # noqa: F401
from incident_helpers import incident, seed_collector
from test_evidence_assemble import section
from test_pilot_report import HOUR0, report, seeded, set_detected  # noqa: F401

GOOD = {"reason_code": "essential_absent", "absent_for_hours": 30, "threshold_hours": 24}
NULLS = {"reason_code": "essential_absent", "absent_for_hours": None, "threshold_hours": None}
HOSTILE = [
    {**GOOD, "mac": "aa:bb:cc:00:00:01", "hostname": "evil\n", "vendor": "x", "ip": "192.0.2.9"},
    {**GOOD, "absent_for_hours": "3; DROP TABLE x"},
    {**GOOD, "absent_for_hours": True},
    {**GOOD, "absent_for_hours": -1},
    {**GOOD, "absent_for_hours": 10**30},
    {**GOOD, "threshold_hours": 3.5},
    {**GOOD, "threshold_hours": 0},
    {**GOOD, "reason_code": "<script>"},
    {**GOOD, "reason_code": ["x" * 5000]},
    {},
    {"unrelated": 1},
    "{",
    "",
    "5",
    "[" * 200_000,
]
ALLOWED = {"reason_code", "absent_for_hours", "threshold_hours"}


def store(env: Env, evidence) -> None:
    seed_collector(env)
    incident(env, "e1", detector="essential_absence")
    env.inv.execute(
        "UPDATE monitoring_incidents SET evidence=?,observed_bytes=0,threshold_bytes=0",
        (evidence if isinstance(evidence, str) else json.dumps(evidence),),
    )


def served(env: Env) -> dict:
    one = env.get("/incidents/e1", collector_id="c1")
    assert one.status_code == 200, one.text
    many = env.get("/incidents", collector_id="c1")
    assert many.status_code == 200, many.text
    assert many.json()["data"][0] == one.json()["data"]
    assert one.json()["data"]["detector"] == "essential_absence"
    return one.json()["data"]["evidence"]


def test_the_incident_is_served_with_exactly_the_design_evidence(env: Env):
    store(env, GOOD)
    assert served(env) == GOOD


@pytest.mark.parametrize("bad", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_evidence_is_neutralised_in_api_and_pack(env: Env, bad):
    store(env, bad)
    evidence = served(env)
    assert set(evidence) == ALLOWED and evidence["reason_code"] == "essential_absent"
    for key in ("absent_for_hours", "threshold_hours"):
        v = evidence[key]
        assert v is None or (type(v) is int and 0 < v < 10**6)
    assert "aa:bb" not in json.dumps(evidence) and "evil" not in json.dumps(evidence)
    pack = section(env, "incidents")
    item = next(i for i in pack["items"] if i["id"] == "e1")
    assert item["detector"] == "essential_absence" and item["evidence"] == evidence


def test_a_bad_value_serves_null_not_a_guess(env: Env):
    store(env, {**GOOD, "absent_for_hours": True})
    assert served(env) == {**GOOD, "absent_for_hours": None}
    env.inv.execute("UPDATE monitoring_incidents SET evidence='{'")
    assert served(env) == NULLS


def test_upload_rows_still_work_beside_it(env: Env):
    store(env, GOOD)
    incident(env, "u1", detector="large_upload", episode=1)
    rows = env.get("/incidents", collector_id="c1").json()["data"]
    assert {r["id"]: r["detector"] for r in rows} == {
        "e1": "essential_absence",
        "u1": "large_upload",
    }


def test_it_is_reported_separately_and_leaves_upload_numbers_alone(seeded, capsys, monkeypatch):
    before = report(seeded, capsys, monkeypatch)
    incident(seeded, "ea1", device="d1", detector="essential_absence", episode=HOUR0 - 3600)
    set_detected(seeded, "ea1", -3600)
    after = report(seeded, capsys, monkeypatch)
    assert after["incidents"]["per_detector"]["essential_absence"] == 1
    assert after["incidents"]["total"] == before["incidents"]["total"]
    assert after["incidents"]["per_day"] == before["incidents"]["per_day"]
    assert after["deliveries"] == before["deliveries"]
    assert after["unwanted_notifications"] == before["unwanted_notifications"]
