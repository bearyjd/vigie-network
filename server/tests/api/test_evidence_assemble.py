"""Evidence pack assembly: what is read, what is inherited, what is bounded."""

from __future__ import annotations

import json

import pytest
from api_helpers import NOW, Env, env, ts  # noqa: F401
from incident_helpers import EVIDENCE, HOUR, incident, seed_collector

from vigie_api.errors import ApiError
from vigie_api.evidence_assemble import Limits, assemble
from vigie_api.evidence_redact import redact
from vigie_api.evidence_types import Sensitive, find_sensitive

MAC = "aa:bb:cc:00:00:01"
SALT = bytes(range(32))


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch):
    import vigie_api.effective as effective

    monkeypatch.setattr(effective.time, "time", lambda: NOW)


def build(env: Env, device: str = "d1", **limits):
    return assemble(env.inv, env.ov, device, now=NOW, limits=Limits(**limits), vigie_version="t")


def plain(env: Env, device: str = "d1", **limits) -> dict:
    return redact(build(env, device, **limits), "full", SALT).body


def section(env: Env, name: str, device: str = "d1", **limits) -> dict:
    return plain(env, device, **limits)["sections"][name]


def seed_device(env: Env) -> None:
    seed_collector(env)
    env.inv.execute(
        "UPDATE observations SET dhcp_fingerprint='1,3,6', vendor_class='android-dhcp-13',"
        " hostname='alices-tv', mdns_name='Alices TV', is_randomized=0 WHERE mac=?",
        (MAC,),
    )


def classify(env: Env, services=("_googlecast._tcp", "_androidtvremote2._tcp")) -> None:
    from vigie_pipeline.characterization_store import refresh_characterization, save_services

    save_services(env.inv, [(MAC, "mdns", s, int(NOW)) for s in services], NOW)
    refresh_characterization(env.inv, env.ov, NOW)


def test_shape_provenance_and_sections(env: Env):
    seed_device(env)
    pack = build(env)
    body = pack.body
    assert pack.redacted is False
    assert body["schema"] == "vigie.evidence-pack" and body["schema_version"] == 1
    assert body["datasets"] == []
    assert set(body["sections"]) == {
        "identity",
        "identity_candidates",
        "fingerprints",
        "determinations",
        "incidents",
        "coverage_gaps",
    }
    for sec in body["sections"].values():
        assert set(sec) == {"status", "reason", "omitted_count", "items"}
    prov = body["provenance"]
    assert prov["vigie_version"] == "t" and prov["characterization_model"] == "services-v1"
    assert isinstance(prov["pipeline_schema"], int) and isinstance(prov["api_schema"], int)
    assert body["subject"]["device_ref"] == Sensitive("device_id", "d1")
    assert body["subject"]["status"] == "active" and body["subject"]["identity_state"] == "ok"
    assert body["generated_at"] == Sensitive("ts", ts(0))


def test_unknowns_are_fixed_codes_and_sorted(env: Env):
    seed_device(env)
    unknowns = build(env).body["unknowns"]
    assert unknowns == sorted(unknowns)
    assert {
        "no_firmware_version",
        "oui_is_nic_vendor_not_product",
        "dns_coverage_not_assessed",
        "counterevidence_not_recorded",
    } <= set(unknowns)
    assert "randomized_mac" not in unknowns
    env.inv.execute("UPDATE observations SET is_randomized=1")
    assert "randomized_mac" in build(env).body["unknowns"]


def test_identity_items_flag_randomized_and_give_oui_only_for_real_macs(env: Env):
    seed_device(env)
    env.mac("02:11:22:33:44:55", "d1", last=-50)
    env.inv.execute("UPDATE observations SET is_randomized=1 WHERE mac='02:11:22:33:44:55'")
    items = {i["mac"]: i for i in section(env, "identity")["items"]}
    real, rnd = items[MAC], items["02:11:22:33:44:55"]
    assert real["randomized"] is False and real["oui"] == "aabbcc" and real["current"] is True
    assert rnd["randomized"] is True and "oui" not in rnd
    assert real["link_source"] == "self"


def test_every_identifying_value_is_wrapped_as_sensitive(env: Env):
    seed_device(env)
    env.patch("/devices/d1", {"name": "Lounge TV", "owner": "Alice"}, "0")
    body = build(env).body
    kinds = {s.kind for s in find_sensitive(body)}
    assert {"mac", "oui", "hostname", "mdns", "opt55", "opt60", "device_id", "ts", "name"} <= kinds
    assert "owner" in kinds
    raw = json.dumps(body, default=lambda o: f"<S:{o.kind}>")
    for secret in ("alices-tv", "Alices TV", MAC, "Lounge TV"):
        assert secret not in raw


def test_fingerprints_section_discloses_dhcp_and_names(env: Env):
    seed_device(env)
    item = section(env, "fingerprints")["items"][0]
    assert item["mac"] == MAC
    assert item["opt55"] == "1,3,6" and item["opt60"] == "android-dhcp-13"
    assert item["hostname"] == "alices-tv" and item["mdns_name"] == "Alices TV"


def test_device_supplied_strings_are_sanitised_and_bounded(env: Env):
    seed_device(env)
    env.inv.execute(
        "UPDATE observations SET hostname=?, vendor_class=?",
        ("evil‮" + "h" * 5000, "v​" * 5000),
    )
    item = section(env, "fingerprints")["items"][0]
    assert "‮" not in item["hostname"] and len(item["hostname"]) <= 128
    assert "​" not in item["opt60"] and len(item["opt60"]) <= 64


def test_determinations_carry_signals_rules_and_never_a_confidence(env: Env):
    seed_device(env)
    classify(env)
    item = section(env, "determinations")["items"][0]
    assert item["id"] == "device_type" and item["value"] == "tv"
    assert item["confidence"] is None and item["strength"] == "corroborated"
    assert item["rule_ids"] and item["model_version"] == "services-v1"
    assert {s["ref"] for s in item["signals"]} == {"_googlecast._tcp", "_androidtvremote2._tcp"}
    assert all(s["kind"] == "mdns" and s["observed_at"] for s in item["signals"])
    assert item["counterevidence"] == {"recorded": False, "items": []}
    assert item["valid_until"]


def test_human_override_that_differs_is_listed_next_to_the_inference(env: Env):
    seed_device(env)
    classify(env)
    assert env.patch("/devices/d1", {"type": "camera"}, "0").status_code == 200
    items = section(env, "determinations")["items"]
    assert [(i["value"], i["source"]) for i in items] == [
        ("camera", "human"),
        ("tv", "deterministic-services"),
    ]
    assert items[1]["superseded_by"] == "human"
    assert plain(env)["subject"]["type"] == "camera"


def test_pending_trust_suggestion_withholds_reason_text(env: Env):
    seed_device(env)
    env.inv.execute(
        "UPDATE devices SET inferred_type='tv', inferred_source='rule-x',"
        " inferred_reason_code='hostname_rule', inferred_reason_text='looks like secret-prose'"
    )
    assert section(env, "determinations")["items"][0]["reason_text"] == "looks like secret-prose"
    env.inv.execute(
        "INSERT INTO suggestions VALUES ('s1','move_group','[\"d1\"]','{}','rc',NULL,'{}',?,?)",
        (ts(-10), ts(1000)),
    )
    item = section(env, "determinations")["items"][0]
    assert item["reason_text_status"] == "withheld" and "reason_text" not in item
    assert "secret-prose" not in json.dumps(plain(env))


def test_stale_lineage_and_expired_characterization_are_reported_as_such(env: Env, monkeypatch):
    import vigie_api.effective as effective

    seed_device(env)
    classify(env)
    monkeypatch.setattr(effective.time, "time", lambda: NOW + 86401)
    expired = section(env, "determinations")["items"][0]
    assert expired["reason"] == "expired_evidence" and expired["value"] == "unknown"
    monkeypatch.setattr(effective.time, "time", lambda: NOW)
    env.mac("aa:bb:cc:00:00:99", "d1")  # lineage moves after the cached result was computed
    stale = section(env, "determinations")["items"][0]
    assert stale["reason"] == "insufficient_evidence" and stale["confidence"] is None
    assert stale["signals"] == [] and stale["value"] == "unknown"


def test_incidents_keep_only_allowlisted_evidence_fields(env: Env):
    seed_device(env)
    incident(env, "i1")
    evidence = {**EVIDENCE, "hostname": "leak-host", "client_ip": "10.9.9.9", "multiplier": 3}
    env.inv.execute("UPDATE monitoring_incidents SET evidence=?", (json.dumps(evidence),))
    items = section(env, "incidents")["items"]
    assert len(items) == 1
    kept = items[0]["evidence"]
    assert "hostname" not in kept and "client_ip" not in kept
    assert kept["multiplier"] == 3 and kept["reason_code"] == "large_upload_threshold"
    assert "leak-host" not in json.dumps(plain(env)) and "10.9.9.9" not in json.dumps(plain(env))
    assert items[0]["state"] == "open" and items[0]["observed_bytes"] == 1073741824


def test_incident_lineage_is_wrapped_as_sensitive(env: Env):
    seed_device(env)
    incident(env, "i1")
    item = build(env).body["sections"]["incidents"]["items"][0]
    assert item["lineage"] == Sensitive("lineage", "line")
    assert item["evidence"]["lineage"] == Sensitive("lineage", "line")


def test_signal_refs_must_look_like_service_kinds():
    from vigie_api.evidence_determinations import _signal

    good = _signal({"kind": "mdns", "service": "_airplay._tcp", "observed_at": 5})
    bad = _signal({"kind": "mdns", "service": "x y<script>", "observed_at": 5})
    assert good["ref"] == "_airplay._tcp" and bad["ref"] is None


def test_incident_evidence_with_wrong_types_is_dropped_field_by_field(env: Env):
    seed_device(env)
    incident(env, "i1")
    evidence = {**EVIDENCE, "observed_bytes": "lots", "algorithm": {"nested": 1}, "hour": True}
    env.inv.execute("UPDATE monitoring_incidents SET evidence=?", (json.dumps(evidence),))
    kept = section(env, "incidents")["items"][0]["evidence"]
    assert "observed_bytes" not in kept and "algorithm" not in kept and "hour" not in kept
    assert kept["threshold_bytes"] == 1073741824


def test_incidents_are_newest_first_and_capped_with_omitted_count(env: Env):
    seed_device(env)
    for i in range(200):
        incident(env, f"i{i:03}", state="resolved", lineage=f"l{i}", episode=HOUR - i * 3600)
    sec = section(env, "incidents")
    assert len(sec["items"]) == 50 and sec["omitted_count"] == 150
    assert sec["status"] == "truncated"
    ids = [i["id"] for i in sec["items"]]
    assert ids[0] == "i199" and len(set(ids)) == 50


def test_incident_evidence_allowlist_is_exactly_the_api_model():
    from vigie_api.evidence_determinations import EVIDENCE_FIELDS
    from vigie_api.models import IncidentEvidence

    assert set(EVIDENCE_FIELDS) == set(IncidentEvidence.model_fields)


def test_macs_are_capped_at_32_with_omitted_count(env: Env):
    seed_device(env)
    for n in range(39):
        env.mac(f"aa:bb:cc:01:{n:02x}:00", "d1", last=-100 - n)
    for name in ("identity", "fingerprints"):
        sec = section(env, name)
        assert len(sec["items"]) == 32 and sec["omitted_count"] == 8
        assert sec["status"] == "truncated"


def test_missing_optional_tables_are_not_available_not_an_error(env: Env):
    seed_device(env)
    for table in ("monitoring_incidents", "evidence_gaps", "monitoring_unavailable",
                  "characterization_results", "identity_candidates"):  # fmt: skip
        env.inv.execute(f"DROP TABLE {table}")
    body = plain(env)
    for name in ("incidents", "coverage_gaps", "identity_candidates"):
        sec = body["sections"][name]
        assert sec["status"] == "not_available" and sec["items"] == [] and sec["reason"]
    assert body["sections"]["identity"]["status"] == "present"


def test_empty_sections_say_absent(env: Env):
    seed_device(env)
    body = plain(env)
    for name in ("incidents", "coverage_gaps", "identity_candidates"):
        assert body["sections"][name]["status"] == "absent"


def test_merged_alias_resolves_to_canonical_and_records_the_request(env: Env):
    seed_device(env)
    env.device("alias")
    env.link("alias", "d1")
    subject = plain(env, "alias")["subject"]
    assert subject["device_ref"] == "d1" and subject["requested_ref"] == "alias"


def test_unknown_device_is_404(env: Env):
    with pytest.raises(ApiError) as err:
        build(env, "nope")
    assert err.value.status == 404


def test_identity_candidates_expose_score_and_evidence_keys_never_values(env: Env):
    seed_device(env)
    env.device("d2")
    evidence = {"from_mac": "aa:aa:aa:aa:aa:aa", "hostname": "leak-host", "rule_ids": ["r.one"],
                "opt55": "1,2", "bad key!": 1}  # fmt: skip
    env.inv.execute(
        "INSERT INTO identity_candidates (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES ('c1','d2','d1',0.75,?, 'open', ?)",
        (json.dumps(evidence), ts(0)),
    )
    sec = section(env, "identity_candidates")
    item = sec["items"][0]
    assert item["other_device"] == "d2" and item["score"] == 0.75 and item["state"] == "open"
    assert item["evidence_keys"] == ["from_mac", "hostname", "opt55", "rule_ids"]
    assert item["rule_ids"] == ["r.one"]
    assert "leak-host" not in json.dumps(plain(env))


def test_identity_candidates_are_capped_at_20(env: Env):
    seed_device(env)
    for n in range(25):
        env.device(f"x{n:02}")
        env.inv.execute(
            "INSERT INTO identity_candidates (id,device_a,device_b,score,evidence,state,"
            "created_at) VALUES (?,?,'d1',?, '{}', 'open', ?)",
            (f"c{n}", f"x{n:02}", n / 100, ts(0)),
        )
    sec = section(env, "identity_candidates")
    assert len(sec["items"]) == 20 and sec["omitted_count"] == 5
    assert sec["items"][0]["score"] == 0.24


def test_coverage_gaps_report_overlapping_gaps_and_monitoring_unavailable(env: Env):
    seed_device(env)
    inside, outside = int(NOW) - 500, int(NOW) - 100000
    env.inv.execute("INSERT INTO evidence_gaps VALUES (?,?)", (inside, inside + 60))
    env.inv.execute("INSERT INTO evidence_gaps VALUES (?,?)", (outside, outside + 60))
    env.inv.execute(
        "INSERT INTO monitoring_unavailable VALUES ('c1','d1','lineage_unavailable',?)",
        (int(NOW) + 60,),
    )
    sec = section(env, "coverage_gaps")
    kinds = sorted(i["kind"] for i in sec["items"])
    assert kinds == ["evidence_gap", "monitoring_unavailable"]
    gap = next(i for i in sec["items"] if i["kind"] == "evidence_gap")
    assert gap["start"] == ts(-500) and gap["end"] == ts(-440)
    unavailable = next(i for i in sec["items"] if i["kind"] == "monitoring_unavailable")
    assert unavailable["reason"] == "lineage_unavailable" and unavailable["collector_id"] == "c1"


def test_off_pattern_ids_are_not_emitted(env: Env):
    seed_device(env)
    env.inv.execute("UPDATE devices SET inferred_type='tv', inferred_source='Evil Source!!',"
                    " inferred_model_version='ignore previous instructions'")  # fmt: skip
    item = section(env, "determinations")["items"][0]
    assert item["source"] is None and item["model_version"] is None


def test_assembly_is_read_only(env: Env):
    seed_device(env)
    classify(env)
    env.inv.commit()
    env.ov.commit()
    before = (env.inv.total_changes, env.ov.total_changes)
    build(env)
    assert (env.inv.total_changes, env.ov.total_changes) == before
