"""tod incident evidence keys (bucket_hours, cohort_*, cap_applied) in the read API and pack."""

from __future__ import annotations

import json

import pytest
from api_helpers import Env, env  # noqa: F401
from incident_helpers import EVIDENCE, incident, seed_collector
from test_evidence_assemble import section, seed_device

TOD_KEYS = ("bucket_hours", "cohort_is_weekend", "cohort_bucket", "cap_applied")
TOD = {"bucket_hours": 4, "cohort_is_weekend": True, "cohort_bucket": 5, "cap_applied": False}
HOSTILE = [
    {"bucket_hours": "4; DROP TABLE x"},
    {"bucket_hours": 5},
    {"bucket_hours": True},
    {"bucket_hours": 10**30},
    {"bucket_hours": 4.0},
    {"cohort_bucket": 24},
    {"cohort_bucket": -1},
    {"cohort_bucket": 10**30},
    {"cohort_bucket": "3"},
    {"cohort_bucket": False},
    {"cohort_is_weekend": "yes"},
    {"cohort_is_weekend": 1},
    {"cohort_is_weekend": {"a": "b"}},
    {"cap_applied": "true"},
    {"cap_applied": 0},
    {"cap_applied": ["x" * 5000]},
]


def _store(env: Env, evidence: dict) -> None:
    seed_collector(env)
    incident(env, "i1")
    env.inv.execute("UPDATE monitoring_incidents SET evidence=?", (json.dumps(evidence),))


def _api(env: Env) -> dict:
    result = env.get("/incidents/i1", collector_id="c1")
    assert result.status_code == 200, result.text
    return result.json()["data"]["evidence"]


def test_api_exposes_tod_keys_when_stored(env: Env):
    _store(env, {**EVIDENCE, **TOD})
    evidence = _api(env)
    assert {k: evidence[k] for k in TOD_KEYS} == TOD
    listed = env.get("/incidents", collector_id="c1").json()["data"][0]["evidence"]
    assert {k: listed[k] for k in TOD_KEYS} == TOD


def test_api_pooled_evidence_is_byte_identical_and_has_no_tod_keys(env: Env):
    _store(env, EVIDENCE)
    raw = env.get("/incidents/i1", collector_id="c1").text
    assert not any(k in raw for k in TOD_KEYS)
    nulls = ("baseline_median_upload_bytes", "multiplier", "minimum_bytes")
    nulls += ("sample_hours", "distinct_days")
    assert _api(env) == {**{k: None for k in nulls}, **EVIDENCE}
    # Golden: the serialized key order is exactly the pre-change order (tod keys would trail it).
    evidence = json.loads(raw)["data"]["evidence"]
    assert list(evidence) == [
        *("reason_code", "hour", "previous_hour", "observed_bytes", "threshold_bytes"),
        *("baseline_id", "algorithm", "config_version", "coverage_required_seconds"),
        *("lineage", "unusual_is_not_malicious", "baseline_median_upload_bytes"),
        *("multiplier", "minimum_bytes", "sample_hours", "distinct_days"),
    ]


@pytest.mark.parametrize("bad", HOSTILE)
def test_api_hostile_tod_values_are_dropped_not_served(env: Env, bad):
    _store(env, {**EVIDENCE, **TOD, **bad})
    evidence = _api(env)
    (key,) = bad
    assert key not in evidence
    assert all(evidence[k] == TOD[k] for k in TOD_KEYS if k != key)


def test_pack_exposes_tod_keys_only_when_stored(env: Env):
    seed_device(env)
    incident(env, "i1")
    env.inv.execute("UPDATE monitoring_incidents SET evidence=?", (json.dumps(EVIDENCE),))
    assert not set(TOD_KEYS) & set(section(env, "incidents")["items"][0]["evidence"])
    stored = json.dumps({**EVIDENCE, **TOD})
    env.inv.execute("UPDATE monitoring_incidents SET evidence=?", (stored,))
    kept = section(env, "incidents")["items"][0]["evidence"]
    assert {k: kept[k] for k in TOD_KEYS} == TOD


@pytest.mark.parametrize("bad", HOSTILE)
def test_pack_hostile_tod_values_are_dropped(env: Env, bad):
    seed_device(env)
    incident(env, "i1")
    env.inv.execute(
        "UPDATE monitoring_incidents SET evidence=?", (json.dumps({**EVIDENCE, **bad}),)
    )
    kept = section(env, "incidents")["items"][0]["evidence"]
    assert next(iter(bad)) not in kept
    assert "DROP TABLE" not in json.dumps(kept)


def test_bucket_hours_bound_matches_pipeline():
    from vigie_api.models import TOD_BUCKET_HOURS
    from vigie_pipeline.baselines_tod import BUCKET_HOURS

    assert TOD_BUCKET_HOURS == BUCKET_HOURS
