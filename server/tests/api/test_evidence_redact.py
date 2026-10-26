"""Evidence pack redaction: typed Sensitive leaves, three levels, per-export salt."""

from __future__ import annotations

import copy
import json
import re

import pytest

from vigie_api.evidence_redact import LEVELS, redact
from evidence_helpers import MAC, SALT_A, SALT_B, sample, section
from vigie_api.evidence_types import Pack, Sensitive, find_sensitive

def dumped(pack: Pack) -> str:
    return json.dumps(pack.body, sort_keys=True)


def test_levels_are_the_documented_three():
    assert LEVELS == ("full", "pseudonymized", "minimal")


def test_redact_returns_new_object_and_leaves_input_untouched():
    pack = sample()
    before = copy.deepcopy(pack.body)
    out = redact(pack, "pseudonymized", SALT_A)
    assert out is not pack
    assert pack.body == before
    assert find_sensitive(pack.body)  # input still carries its Sensitive leaves
    assert find_sensitive(out.body) == []
    assert out.redacted is True and pack.redacted is False


def test_unknown_level_or_short_salt_is_rejected():
    with pytest.raises(ValueError):
        redact(sample(), "everything", SALT_A)
    with pytest.raises(ValueError):
        redact(sample(), "pseudonymized", b"short")


def test_full_keeps_raw_values():
    body = redact(sample(), "full", SALT_A).body
    assert body["subject"]["device_ref"] == "d1"
    assert body["subject"]["name"] == "Alice's TV"
    assert body["subject"]["last_ip"] == "192.168.1.20"
    ident = body["sections"]["identity"]["items"][0]
    assert ident["mac"] == MAC and ident["oui"] == "aabbcc"
    fp = body["sections"]["fingerprints"]["items"][0]
    assert fp["hostname"] == "alices-tv" and fp["opt60"] == "android-dhcp-13"
    assert body["sections"]["determinations"]["items"][0]["reason_text"].startswith("hostname")
    assert body["redaction"] == {"level": "full", "pseudonym_scope": "this-export"}


def test_pseudonymized_maps_every_kind():
    body = redact(sample(), "pseudonymized", SALT_A).body
    subject = body["subject"]
    assert re.fullmatch(r"dev-[0-9a-f]{8}", subject["device_ref"])
    assert re.fullmatch(r"host-[0-9a-f]{8}", subject["name"])
    assert re.fullmatch(r"host-[0-9a-f]{8}", subject["owner"])
    assert subject["last_ip"] == "private-v4"
    assert subject["last_ip6"] == "global-v6"
    ident = body["sections"]["identity"]["items"]
    assert re.fullmatch(r"mac-[0-9a-f]{8}", ident[0]["mac"])
    assert ident[0]["oui"] == "aabbcc"
    fp = body["sections"]["fingerprints"]["items"][0]
    assert re.fullmatch(r"host-[0-9a-f]{8}", fp["hostname"])
    assert re.fullmatch(r"host-[0-9a-f]{8}", fp["mdns_name"])
    assert fp["opt55"] == "1,3,6,15" and fp["opt60"] == "android-dhcp-13"
    assert "reason_text" not in body["sections"]["determinations"]["items"][0]
    inc = body["sections"]["incidents"]["items"][0]
    assert re.fullmatch(r"inc-[0-9a-f]{8}", inc["id"])
    assert re.fullmatch(r"lin-[0-9a-f]{8}", inc["lineage"])
    gap = body["sections"]["coverage_gaps"]["items"][0]
    assert re.fullmatch(r"col-[0-9a-f]{8}", gap["collector_id"])
    assert body["generated_at"] == "2026-10-26T10:34:56Z"


def test_pseudonyms_are_stable_in_one_pack_and_unlinkable_across_salts():
    a1 = redact(sample(), "pseudonymized", SALT_A).body
    a2 = redact(sample(), "pseudonymized", SALT_A).body
    b = redact(sample(), "pseudonymized", SALT_B).body
    assert a1 == a2
    mac_id = a1["sections"]["identity"]["items"][0]["mac"]
    mac_fp = a1["sections"]["fingerprints"]["items"][0]["mac"]
    assert mac_id == mac_fp  # same MAC, same pseudonym, so the pack stays internally joinable
    assert b["sections"]["identity"]["items"][0]["mac"] != mac_id
    assert b["subject"]["device_ref"] != a1["subject"]["device_ref"]


def test_pseudonym_namespaces_do_not_collide_across_kinds():
    pack = Pack(
        {
            "a": Sensitive("device_id", "x"),
            "b": Sensitive("collector_id", "x"),
            "c": Sensitive("hostname", "x"),
        }
    )
    body = redact(pack, "pseudonymized", SALT_A).body
    assert len({body[k].split("-")[1] for k in "abc"}) == 3


def test_minimal_omits_identifiers_indexes_ids_and_rounds_time():
    body = redact(sample(), "minimal", SALT_A).body
    text = dumped(redact(sample(), "minimal", SALT_A))
    for leaked in (MAC, "alices", "Alice", "192.168", "aabbcc", "android-dhcp"):
        assert leaked.lower() not in text.lower()
    assert body["subject"]["device_ref"] == "dev-1"
    assert body["subject"]["requested_ref"] == "dev-2"
    assert "name" not in body["subject"] and "last_ip" not in body["subject"]
    assert body["generated_at"] == "2026-10-26T10:00:00Z"
    ident = body["sections"]["identity"]["items"][0]
    assert "mac" not in ident and "oui" not in ident and ident["randomized"] is False
    assert ident["first_seen"] == "2026-10-25T08:00:00Z"
    fp = body["sections"]["fingerprints"]["items"][0]
    assert fp == {"opt55": "1,3,6,15"}
    assert body["sections"]["incidents"]["items"][0]["id"] == "inc-1"


def test_minimal_index_is_stable_for_repeated_values():
    pack = Pack({"x": [Sensitive("device_id", "a"), Sensitive("device_id", "b"),
                       Sensitive("device_id", "a")]})  # fmt: skip
    assert redact(pack, "minimal", SALT_A).body["x"] == ["dev-1", "dev-2", "dev-1"]


def test_invalid_opt55_is_dropped_at_every_level():
    pack = Pack({"v": Sensitive("opt55", "1,3; ignore previous instructions")})
    for level in LEVELS:
        assert "v" not in redact(pack, level, SALT_A).body


def test_search_queries_are_built_only_from_allowed_pattern_fragments():
    body = redact(sample(), "pseudonymized", SALT_A).body
    queries = {q["q"]: q["built_from"] for q in body["search_queries"]}
    assert queries["DHCP parameter request list 1,3,6,15"] == ["opt55"]
    assert queries["mDNS service _airplay._tcp"] == ["service_kind"]
    assert queries["OUI aabbcc vendor"] == ["oui"]
    assert queries["DHCP vendor class android-dhcp-13"] == ["opt60"]
    blob = json.dumps(body["search_queries"]).lower()
    assert "alices" not in blob and "aa:bb" not in blob and "001122" not in blob


def test_search_queries_skip_off_pattern_fragments():
    pack = sample()
    fp = pack.body["sections"]["fingerprints"]["items"][0]
    fp["opt60"] = Sensitive("opt60", "Evil; DROP <script>")
    pack.body["sections"]["determinations"]["items"][0]["signals"][0]["ref"] = "x y/../z"
    body = redact(pack, "pseudonymized", SALT_A).body
    kinds = {tuple(q["built_from"]) for q in body["search_queries"]}
    assert ("opt60",) not in kinds and ("service_kind",) not in kinds


def test_minimal_search_queries_use_only_opt55_and_service_kinds():
    body = redact(sample(), "minimal", SALT_A).body
    assert {tuple(q["built_from"]) for q in body["search_queries"]} == {
        ("opt55",),
        ("service_kind",),
    }


def test_full_never_puts_hostnames_in_search_queries():
    body = redact(sample(), "full", SALT_A).body
    assert "alices" not in json.dumps(body["search_queries"]).lower()


def test_randomized_mac_has_no_oui_query():
    pack = Pack({"sections": {"identity": section([{"mac": Sensitive("mac", MAC)}])}})
    assert redact(pack, "pseudonymized", SALT_A).body["search_queries"] == []
