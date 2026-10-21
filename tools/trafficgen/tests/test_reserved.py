"""Fixtures only use reserved/documentation identifiers (RFC 5737, RFC 7042, .example)."""

from __future__ import annotations

import ipaddress
import re

import pytest
from conftest import FIXTURES

from trafficgen import PROFILES
from trafficgen.archetypes import DOH_RESOLVERS, ip_for

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
DOC_MAC_PREFIX = "00:00:5e:00:53:"  # RFC 7042 documentation range
REAL_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4", "1.0.0.1")


def _in_doc(ip: str) -> bool:
    return any(ipaddress.ip_address(ip) in n for n in DOC_NETS)


def _is_laa(mac: str) -> bool:
    return bool(int(mac.split(":")[0], 16) & 0x02)


@pytest.mark.parametrize("profile", PROFILES)
def test_all_public_addresses_and_names_are_reserved(gen, profile):
    sc = gen(profile, 3, 12)
    dsts, answers, names, macs = set(), set(), set(), set()
    for e in sc.emissions:
        b = e.batch
        dsts |= {c["dst_ip"] for c in b["conntrack"] if c["dst_ip"]}
        answers |= {q["answer_ip"] for q in b["dns"] if q["answer_ip"]}
        names |= {q["qname"] for q in b["dns"]}
        macs |= {x["mac"] for k in ("leases", "neigh", "dns", "conntrack") for x in b[k]}
    assert dsts and all(_in_doc(ip) for ip in dsts), sorted(ip for ip in dsts if not _in_doc(ip))
    assert all(_in_doc(ip) for ip in answers)
    assert all(n.endswith(".example") for n in names)
    stable = {m for m in macs if not _is_laa(m)}
    assert stable and all(m.startswith(DOC_MAC_PREFIX) for m in stable)


def test_ip_for_is_deterministic_and_documentation_only():
    assert ip_for("a.example") == ip_for("a.example")
    assert all(_in_doc(ip_for(f"h{i}.example")) for i in range(200))


def test_doh_resolvers_are_documentation_addresses_named_in_manifest(gen):
    assert all(_in_doc(ip) for ip in DOH_RESOLVERS)
    sc = gen("doh_user", 3, 12)
    (doh,) = [d for d in sc.manifest["devices"] if d["doh"]]
    assert sc.manifest["doh_resolvers"] == list(DOH_RESOLVERS)
    mac = doh["macs"][0]["mac"]
    seen = {c["dst_ip"] for e in sc.emissions for c in e.batch["conntrack"] if c["mac"] == mac}
    assert seen & set(DOH_RESOLVERS)


def test_no_real_resolver_ip_in_any_fixture():
    text = "".join(p.read_text() for p in FIXTURES.glob("*.jsonl"))
    for ip in REAL_RESOLVERS:
        assert not re.search(rf'"{re.escape(ip)}"', text), ip
