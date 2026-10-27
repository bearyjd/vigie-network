"""Fix round 1 for PR #23: quasi-identifier leaks, keyed refs, truncation and alias coverage."""

from __future__ import annotations

import json
import re
import secrets

import pytest
from api_helpers import NOW, Env, env, ts  # noqa: F401
from incident_helpers import incident, seed_collector
from test_api_evidence_pack import export, exports

from vigie_api import evidence_cli, evidence_export, evidence_writes
from vigie_api.evidence_assemble import Limits, assemble
from vigie_api.evidence_redact import MAX_QUERIES, build_queries, is_known_vendor_class, redact

DEV, ALIAS, OTHER = "canary-device-77", "canary-alias-55", "canary-other-99"
MAC = "aa:bb:cc:12:34:56"
IP = "192.168.77.201"
BASELINE = "9f" * 32
RULE_UUID = "3f2b8c1e-5d4a-4b7e-9c10-aa11bb22cc33"
CANARIES = ["canary-incident-1", "canary-coll-1", "canary-coll-2", "canary-alias-inc", OTHER,
            ALIAS, DEV, IP, "77.201", BASELINE, RULE_UUID, "canary-ruleid"]  # fmt: skip


def candidate(e: Env, cid: str, a: str, b: str, score: float, evidence: dict | None = None):
    e.inv.execute(
        "INSERT INTO identity_candidates (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES (?,?,?,?,?,'open',?)",
        (cid, a, b, score, json.dumps(evidence or {}), ts(0)),
    )


@pytest.fixture
def e(env: Env, monkeypatch) -> Env:  # noqa: F811
    import vigie_api.effective as effective

    monkeypatch.setattr(effective.time, "time", lambda: NOW)
    seed_collector(env, DEV)
    env.inv.execute("DELETE FROM observations")
    env.mac(MAC, DEV, link_source="rule", rule=RULE_UUID)
    env.inv.execute("INSERT INTO mac_last_ip VALUES (?,?,?,?)", (MAC, IP, int(NOW) - 5, "lease"))
    env.device(OTHER)
    env.device(ALIAS)
    env.link(ALIAS, DEV)
    incident(env, "canary-incident-1", device=DEV, collector="canary-coll-1")
    incident(env, "canary-alias-inc", device=ALIAS, collector="canary-coll-1", lineage="l2")
    env.inv.execute("UPDATE monitoring_incidents SET baseline_id=?", (BASELINE,))
    env.inv.execute(
        "UPDATE monitoring_incidents SET evidence=json_set(evidence,'$.baseline_id',baseline_id)"
    )
    env.inv.execute(
        "INSERT INTO monitoring_unavailable VALUES ('canary-coll-2',?,'no_lineage',?)",
        (DEV, int(NOW)),
    )
    candidate(env, "c1", DEV, OTHER, 0.5, {"rule_ids": ["canary-ruleid"]})
    return env


def pack(e: Env, device: str = DEV):
    return assemble(e.inv, e.ov, device, now=NOW, limits=Limits(), vigie_version="t")


@pytest.mark.parametrize("level", ["pseudonymized", "minimal"])
def test_no_identifier_of_any_kind_survives_in_restricted_exports(e, level):
    for fmt in ("json", "markdown"):
        text = export(e, {"redaction": level, "format": fmt}).text
        for canary in CANARIES:
            assert canary not in text, (level, fmt, canary)


def test_baseline_and_rule_refs_are_pseudonymized_not_raw(e):
    text = export(e).text
    assert re.search(r"base-[0-9a-f]{8}", text) and re.search(r"rule-[0-9a-f]{8}", text)
    minimal = export(e, {"redaction": "minimal"}).text
    assert "base-" not in minimal and "rule-" not in minimal


def test_full_keeps_the_raw_refs(e):
    text = export(e, {"redaction": "full", "confirm_full": True}).text
    assert BASELINE in text and RULE_UUID in text and "canary-incident-1" in text


def test_events_feed_shows_the_level_only_no_reversible_ref(e):
    export(e, {"redaction": "minimal"})
    (event,) = [x for x in e.get("/events").json()["data"] if x["kind"] == "device.evidence_export"]
    assert event["summary"] == "app device.evidence_export minimal" and event["device_id"] is None
    assert exports(e)[0]["target"] is None


@pytest.mark.parametrize("level", ["pseudonymized", "minimal"])
def test_audit_row_of_a_restricted_export_holds_no_raw_ids(e, level):
    export(e, {"redaction": level}, device=ALIAS)
    row = exports(e)[0]
    blob = json.dumps(row)
    assert DEV not in blob and ALIAS not in blob and "device_id" not in json.loads(row["detail"])
    detail = json.loads(row["detail"])
    assert detail["device_ref"] != detail["requested_ref"]


def test_audit_row_of_a_full_export_keeps_the_raw_ids(e):
    export(e, {"redaction": "full", "confirm_full": True}, device=ALIAS)
    detail = json.loads(exports(e)[0]["detail"])
    assert (detail["device_ref"], detail["requested_ref"]) == (DEV, ALIAS)


def test_gap_truncation_counts_are_exact(e):
    e.inv.execute("DELETE FROM monitoring_unavailable")
    base = int(NOW) - 900
    for n in range(60):
        e.inv.execute("INSERT INTO evidence_gaps VALUES (?,?)", (base + n * 10, base + n * 10 + 5))
    sec = redact(pack(e), "full", bytes(32)).body["sections"]["coverage_gaps"]
    assert (sec["status"], len(sec["items"]), sec["omitted_count"]) == ("truncated", 50, 10)


def test_aliases_contribute_incidents_and_unavailable_records(e):
    e.inv.execute(
        "INSERT INTO monitoring_unavailable VALUES ('canary-coll-3',?,'no_lineage',?)",
        (ALIAS, int(NOW)),
    )
    body = redact(pack(e), "full", bytes(32)).body["sections"]
    assert {i["id"] for i in body["incidents"]["items"]} == {
        "canary-incident-1",
        "canary-alias-inc",
    }
    unavailable = [
        i for i in body["coverage_gaps"]["items"] if i["kind"] == "monitoring_unavailable"
    ]
    assert {i["collector_id"] for i in unavailable} == {"canary-coll-2", "canary-coll-3"}
    assert pack(e, ALIAS).body["sections"]["incidents"] == pack(e).body["sections"]["incidents"]


def test_alias_member_candidates_are_included(e):
    candidate(e, "c2", ALIAS, OTHER, 0.4)
    assert len(pack(e).body["sections"]["identity_candidates"]["items"]) == 2


def test_candidate_evidence_keys_are_an_allowlist_and_unknown_ones_are_counted(e):
    e.inv.execute("DELETE FROM identity_candidates")
    keys = {"rule_ids": [], "hostname": "x", "from_mac": "y", "host-alice": 1,
            "aa:bb:cc:00:00:01": 1, "aabb.cc00.0001": 1, "10.2.3.4": 1, "c1": 1}  # fmt: skip
    candidate(e, "c9", DEV, OTHER, 0.5, keys)
    item = redact(pack(e), "full", bytes(32)).body["sections"]["identity_candidates"]["items"][0]
    assert item["evidence_keys"] == ["from_mac", "hostname", "rule_ids"]
    assert item["unrecognized_key_count"] == 5


def test_candidate_state_is_limited_to_the_known_states(e):
    e.inv.execute("UPDATE identity_candidates SET state='alice-laptop'")
    item = redact(pack(e), "full", bytes(32)).body["sections"]["identity_candidates"]["items"][0]
    assert item["state"] is None


@pytest.mark.parametrize(
    "known",
    [
        "MSFT 5.0",
        "android-dhcp-13",
        "dhcpcd-9.4.1",
        "dhcpcd-5.5.6:Linux-3.4:armv7l",
        "udhcp 1.35.0",
        "Linux 5.15.0",
    ],  # fmt: skip
)
def test_recognised_vendor_classes(known):
    assert is_known_vendor_class(known)


@pytest.mark.parametrize(
    "free_text",
    [
        "alice-laptop aabbcc000001 10.2.3.4",
        "alice-laptop",
        "MSFT 5.0 alice",
        "dhcpcd-1.0:alice-pc",
        "android-dhcp-13 aabbcc",
        "",
        "udhcp 1.2;x",
    ],  # fmt: skip
)
def test_free_text_vendor_classes_are_not_recognised(free_text):
    assert not is_known_vendor_class(free_text)


def test_free_text_opt60_is_pseudonymized_and_never_searched(e):
    e.inv.execute(
        "UPDATE observations SET hostname='alice-laptop',"
        " vendor_class='alice-laptop aabbcc000001 10.2.3.4'"
    )
    doc = export(e).json()
    text = json.dumps(doc)
    for leaked in ("alice-laptop", "aabbcc000001", "10.2.3.4"):
        assert leaked not in text
    assert re.search(r"vc-[0-9a-f]{8}", text)
    assert not any("vendor class" in q["q"] for q in doc["search_queries"])


def test_recognised_opt60_stays_raw_and_searchable(e):
    e.inv.execute("UPDATE observations SET vendor_class='android-dhcp-13'")
    doc = export(e).json()
    assert "android-dhcp-13" in json.dumps(doc["sections"]["fingerprints"])
    assert any(q["q"] == "DHCP vendor class android-dhcp-13" for q in doc["search_queries"])


def test_subject_confidence_is_null_for_the_deterministic_source(e):
    e.inv.execute(
        "UPDATE devices SET inferred_type='tv', inferred_source='deterministic-services',"
        " inferred_confidence=0.7"
    )
    assert pack(e).body["subject"]["type_provenance"]["confidence"] is None


def test_query_list_is_capped():
    body = {"sections": {"fingerprints": {"items": [{"opt55": f"1,{n}"} for n in range(40)]}}}
    assert len(build_queries(body, "minimal")) == MAX_QUERIES == 12


def test_cli_draws_a_fresh_salt_per_call(monkeypatch):
    seen = []

    def spy(*args, **kwargs):
        seen.extend([kwargs["rng"](32), kwargs["rng"](32)])
        raise SystemExit(0)

    monkeypatch.setattr(evidence_export, "build_export", spy)

    class Args:
        device, redaction, format, confirm_full, output = "d", "pseudonymized", "json", False, "x"

    with pytest.raises(SystemExit):
        evidence_cli._export(None, None, Args, "t")
    assert seen[0] != seen[1] and seen[0] != bytes(32)


def test_cli_missing_parent_directory_is_a_clean_error(e, tmp_path, capsys):
    out = tmp_path / "no" / "such" / "dir" / "pack.json"
    argv = ["--data-dir", str(e.root), "export", DEV, "-o", str(out)]
    assert evidence_cli.main(argv, "t") == 2
    assert exports(e) == [] and "Traceback" not in capsys.readouterr().err


def test_cli_removes_its_partial_file_on_any_exception(e, tmp_path, monkeypatch):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(evidence_writes, "record_export", interrupted)
    out = tmp_path / "pack.json"
    argv = ["--data-dir", str(e.root), "export", DEV, "-o", str(out)]
    with pytest.raises(KeyboardInterrupt):
        evidence_cli.main(argv, "t")
    assert not out.exists()


def test_salt_source_and_cap_come_from_settings(e):
    object.__setattr__(e.settings, "evidence_rng", lambda n: bytes(range(n)))
    a, b = export(e).json(), export(e).json()
    assert a == b
    assert not hasattr(e.client.app.state, "evidence_rng")
    assert e.settings.evidence_cap == 256 * 1024


def test_markdown_nonce_differs_per_salt(e):
    a = redact(pack(e), "pseudonymized", secrets.token_bytes(32))
    b = redact(pack(e), "pseudonymized", secrets.token_bytes(32))
    from vigie_api.evidence_render import render_markdown

    na = re.search(r"BEGIN UNTRUSTED DEVICE DATA (\w+)", render_markdown(a).decode())[1]
    nb = re.search(r"BEGIN UNTRUSTED DEVICE DATA (\w+)", render_markdown(b).decode())[1]
    assert na != nb
