"""DNS monitoring reads through the API and evidence pack."""

from __future__ import annotations

import json

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from incident_helpers import HOUR, incident, seed_collector
from test_api_evidence_pack import export
from test_evidence_assemble import section
from test_pilot_report import HOUR0, decide, delivery, report, seeded, set_detected  # noqa: F401

from vigie_api.monitoring import device_macs

MAC = "aa:bb:cc:00:00:01"
ACTIVITY = "/devices/d1/activity"


def test_dns_baseline_absent_for_old_schema_or_missing_profile(env: Env):
    seed_collector(env)
    before = env.get(ACTIVITY, collector_id="c1", from_hour=HOUR, to_hour=HOUR + 3600)
    assert before.status_code == 200
    assert "dns_baseline" not in before.json()["data"]
    for table in (
        "monitoring_dns_profiles",
        "monitoring_dns_baselines",
        "monitoring_dns_suspicious",
    ):
        env.inv.execute(f"DROP TABLE IF EXISTS {table}")  # noqa: S608
    after = env.get(ACTIVITY, collector_id="c1", from_hour=HOUR, to_hour=HOUR + 3600)
    assert after.status_code == 200
    assert after.content == before.content


def test_dns_baseline_status_keeps_upload_reference_independent(env: Env):
    from vigie_pipeline.baselines import BaselineConfig
    from vigie_pipeline.baselines_dns import ALGORITHM_DNS, DnsBaselineConfig
    from vigie_pipeline.monitoring_engine import analyze_monitoring

    seed_collector(env)
    for hour, queries in ((HOUR - 3600, 250), (HOUR, 351)):
        env.inv.execute("INSERT INTO coverage_hourly VALUES ('c1',?,3600,3600,'[]')", (hour,))
        env.inv.execute(
            "INSERT INTO measurements_hourly VALUES ('c1',?,?,350,4,2,?)", (MAC, hour, queries)
        )
    env.inv.execute("INSERT INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, HOUR))

    upload = BaselineConfig(minimum_hours=1, minimum_days=1)
    dns = DnsBaselineConfig(minimum_hours=2, minimum_days=1)
    analyze_monitoring(env.inv, env.ov, upload, NOW)
    previous = env.get(ACTIVITY, collector_id="c1").json()["data"]
    assert "dns_baseline" not in previous
    env.inv.execute("INSERT INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, HOUR))
    analyze_monitoring(env.inv, env.ov, upload, NOW, dns_policy=dns)

    result = env.get(ACTIVITY, collector_id="c1")
    assert result.status_code == 200, result.text
    data = result.json()["data"]
    assert data["baseline"]["median_upload_bytes"] == 350
    status = data.pop("dns_baseline")
    assert data == previous
    assert status["baseline_id"]
    assert status == {
        "state": "mature",
        "baseline_id": status["baseline_id"],
        "algorithm": ALGORITHM_DNS,
        "config_version": dns.version,
        "sample_hours": 2,
        "distinct_days": 1,
        "training_since": HOUR - 3600,
        "trained_until": HOUR,
        "median_queries": 300.5,
    }
    assert "dns_baseline" not in env.get(ACTIVITY, collector_id="c2").json()["data"]

    env.inv.execute("UPDATE monitoring_dns_profiles SET config_version='profile.private.example'")
    malformed = env.get(ACTIVITY, collector_id="c1")
    assert malformed.status_code == 200, malformed.text
    assert "profile.private.example" not in malformed.text
    assert malformed.json()["data"]["dns_baseline"]["config_version"] is None


def dns_evidence(key: str) -> dict:
    return {
        "reason_code": "dns_deviation_threshold",
        "unit": "queries",
        "hour": HOUR,
        "observed_bytes": 1301,
        "threshold_bytes": 1202,
        "baseline_id": "b" * 64,
        "algorithm": "pooled-median-dns-v1",
        "config_version": "c" * 64,
        "coverage_required_seconds": 3420,
        "lineage": key,
        "unusual_is_not_malicious": True,
        "baseline_median_queries": 300.5,
        "multiplier": 4,
        "minimum_queries": 200,
        "sample_hours": 20,
        "distinct_days": 14,
    }


def test_dns_incident_list_detail_and_evidence_pack_use_query_counts(env: Env):
    seed_collector(env)
    key = device_macs(env.inv, env.ov, "d1")[2]
    incident(env, "u1", lineage=key)
    incident(env, "dns1", detector="dns_deviation", lineage=key)
    evidence = dns_evidence(key)
    env.inv.execute(
        "UPDATE monitoring_incidents SET evidence=?, baseline_id=?, observed_bytes=1301, "
        "threshold_bytes=1202 WHERE id='dns1'",
        (
            json.dumps({**evidence, "qname": "private.example", "dns_answers": ["192.0.2.9"]}),
            evidence["baseline_id"],
        ),
    )
    result = env.get("/incidents/dns1", collector_id="c1")
    assert result.status_code == 200, result.text
    detail = result.json()["data"]
    listed = env.get("/incidents", collector_id="c1")
    assert listed.status_code == 200, listed.text
    items = {i["id"]: i for i in listed.json()["data"]}
    assert items["dns1"] == detail
    assert "unit" not in items["u1"]["evidence"]
    assert detail["detector"] == "dns_deviation" and detail["current_lineage"]
    assert (detail["observed_bytes"], detail["threshold_bytes"]) == (1301, 1202)
    assert detail["evidence"] == evidence
    packed = next(i for i in section(env, "incidents")["items"] if i["id"] == "dns1")
    assert packed["detector"] == "dns_deviation"
    assert packed["evidence"] == evidence

    shared = export(env, device="d1")
    assert shared.status_code == 200, shared.text
    shared_dns = next(
        item
        for item in shared.json()["sections"]["incidents"]["items"]
        if item["detector"] == "dns_deviation"
    )
    assert shared_dns["evidence"]["algorithm"] == evidence["algorithm"]
    assert shared_dns["evidence"]["config_version"] == evidence["config_version"]
    assert shared_dns["evidence"]["lineage"] == shared_dns["lineage"]
    assert shared_dns["baseline_id"].startswith("base-")


@pytest.mark.parametrize("surface", ["list", "detail", "shareable", "full"])
def test_dns_incident_rejects_malformed_provenance_without_hiding_query_counts(env: Env, surface):
    seed_collector(env)
    compromised = {
        "algorithm": "algorithm-canary.private.example",
        "config_version": "198.51.100.66",
        "lineage": "lineage-canary.private.example",
        "baseline_id": "baseline-canary.private.example",
    }
    incident(env, "dns1", detector="dns_deviation", lineage=compromised["lineage"])
    env.inv.execute(
        "UPDATE monitoring_incidents SET evidence=?, baseline_id=?, observed_bytes=1301, "
        "threshold_bytes=1202 WHERE id='dns1'",
        (
            json.dumps({**dns_evidence(compromised["lineage"]), **compromised}),
            compromised["baseline_id"],
        ),
    )
    if surface in {"list", "detail"}:
        path = "/incidents" if surface == "list" else "/incidents/dns1"
        response = env.get(path, collector_id="c1")
    else:
        body = {"redaction": "full", "confirm_full": True} if surface == "full" else {}
        response = export(env, body, device="d1")
    assert response.status_code == 200, response.text
    for value in compromised.values():
        assert value not in response.text
    document = response.json()
    if surface == "list":
        (row,) = document["data"]
    elif surface == "detail":
        row = document["data"]
    else:
        (row,) = document["sections"]["incidents"]["items"]
    assert row["detector"] == "dns_deviation" and not row["current_lineage"]
    assert (row["observed_bytes"], row["threshold_bytes"]) == (1301, 1202)
    assert row.get("baseline_id") is None
    assert row["evidence"]["unit"] == "queries"
    assert all(row["evidence"].get(key) is None for key in compromised)


def test_dns_incidents_stay_out_of_upload_pilot_totals(seeded, capsys, monkeypatch):
    before = report(seeded, capsys, monkeypatch)
    incident(seeded, "dns1", detector="dns_deviation", episode=HOUR0 - 3600)
    set_detected(seeded, "dns1", -3600)
    pending = report(seeded, capsys, monkeypatch)
    assert pending["deliveries"] == before["deliveries"]
    assert pending["unwanted_notifications"] == before["unwanted_notifications"]

    delivery(seeded, 10, "sent", NOW - 3600, "dns1")
    decide(seeded, "dns1", "expected", 10, detector="dns_deviation")
    after = report(seeded, capsys, monkeypatch)
    assert after["incidents"]["per_detector"]["dns_deviation"] == 1
    assert after["incidents"]["total"] == before["incidents"]["total"]
    assert after["incidents"]["per_day"] == before["incidents"]["per_day"]
    assert after["deliveries"] == before["deliveries"]
    assert after["unwanted_notifications"] == before["unwanted_notifications"]
    assert after["decisions"] == before["decisions"]
