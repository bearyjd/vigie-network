"""F5 S2a: a cloned `new_device` incident row is served (200), its evidence is exactly the
design shape and hostile data is dropped; upload evidence bytes are unchanged."""

from __future__ import annotations

import json

import pytest
from api_helpers import Env, env  # noqa: F401
from incident_helpers import EVIDENCE, incident, seed_collector
from test_evidence_assemble import section

GOOD = {"reason_code": "new_device_first_seen", "randomized": False, "dwell_hours": 3}
HOSTILE = [
    {**GOOD, "mac": "aa:bb:cc:00:00:01", "hostname": "evil\n", "vendor": "x", "ip": "10.0.0.9"},
    {**GOOD, "dwell_hours": "3; DROP TABLE x"},
    {**GOOD, "dwell_hours": True},
    {**GOOD, "dwell_hours": -1},
    {**GOOD, "dwell_hours": 10**30},
    {**GOOD, "dwell_hours": 3.5},
    {**GOOD, "randomized": True},
    {**GOOD, "randomized": "no"},
    {**GOOD, "reason_code": "<script>"},
    {**GOOD, "reason_code": ["x" * 5000]},
    {},
    {"unrelated": 1},
]
ALLOWED = {"reason_code", "randomized", "dwell_hours"}


def store(env: Env, evidence) -> None:
    seed_collector(env)
    incident(env, "n1", detector="new_device")
    env.inv.execute(
        "UPDATE monitoring_incidents SET evidence=?,observed_bytes=0,threshold_bytes=0",
        (evidence if isinstance(evidence, str) else json.dumps(evidence),),
    )


def served(env: Env) -> dict:
    one = env.get("/incidents/n1", collector_id="c1")
    assert one.status_code == 200, one.text
    many = env.get("/incidents", collector_id="c1")
    assert many.status_code == 200, many.text
    assert many.json()["data"][0] == one.json()["data"]
    assert one.json()["data"]["detector"] == "new_device"
    return one.json()["data"]["evidence"]


def test_new_device_incident_is_served_with_exactly_the_design_evidence(env: Env):
    store(env, GOOD)
    assert served(env) == GOOD


@pytest.mark.parametrize("bad", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_new_device_evidence_is_neutralised(env: Env, bad):
    store(env, bad)
    evidence = served(env)
    assert set(evidence) <= ALLOWED
    assert evidence["reason_code"] == "new_device_first_seen" and evidence["randomized"] is False
    dwell = evidence.get("dwell_hours")
    assert dwell is None or (type(dwell) is int and 0 <= dwell < 10**6)
    assert "aa:bb" not in json.dumps(evidence) and "evil" not in json.dumps(evidence)


def test_new_device_state_filter_and_upload_rows_still_work(env: Env):
    store(env, GOOD)
    incident(env, "u1", detector="large_upload", episode=1)
    rows = env.get("/incidents", collector_id="c1").json()["data"]
    assert {r["id"]: r["detector"] for r in rows} == {"n1": "new_device", "u1": "large_upload"}
    upload = next(r for r in rows if r["id"] == "u1")["evidence"]
    assert upload["reason_code"] == "large_upload_threshold" and "randomized" not in upload


NULL_DWELL = {"reason_code": "new_device_first_seen", "randomized": False, "dwell_hours": None}
# stored text -> the exact sanitised dict both the API and the pack must serve
EXACT = [
    (GOOD, GOOD),
    (HOSTILE[0], GOOD),
    ({**GOOD, "dwell_hours": True}, NULL_DWELL),
    ({**GOOD, "dwell_hours": 999_999}, {**GOOD, "dwell_hours": 999_999}),
    ({**GOOD, "dwell_hours": 1_000_000}, NULL_DWELL),
    ({**GOOD, "dwell_hours": 0}, {**GOOD, "dwell_hours": 0}),
    ({**GOOD, "dwell_hours": -1}, NULL_DWELL),
    ("{", NULL_DWELL),
    ("", NULL_DWELL),
    ("5", NULL_DWELL),
    ("1" * 5000, NULL_DWELL),
    ("[" * 200_000, NULL_DWELL),
]


@pytest.mark.parametrize(("stored", "want"), EXACT, ids=range(len(EXACT)))
def test_api_and_pack_serve_the_exact_sanitised_evidence(env: Env, stored, want):
    store(env, stored)
    assert served(env) == want
    pack = section(env, "incidents")
    assert pack["status"] == "present"
    item = next(i for i in pack["items"] if i["id"] == "n1")
    assert item["detector"] == "new_device"
    assert item["evidence"] == want
    assert "aa:bb" not in json.dumps(item) and "10.0.0.9" not in json.dumps(item)


def test_upload_evidence_is_unchanged_by_the_widening(env: Env):
    seed_collector(env)
    incident(env, "u1")
    evidence = env.get("/incidents/u1", collector_id="c1").json()["data"]["evidence"]
    nulls = ("baseline_median_upload_bytes", "multiplier", "minimum_bytes")
    nulls += ("sample_hours", "distinct_days")
    assert evidence == {**{k: None for k in nulls}, **EVIDENCE}
