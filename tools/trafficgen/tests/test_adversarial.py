"""Each adversarial profile must really contain its intended anomaly."""

from __future__ import annotations

import json

from trafficgen import PRP_BATCH_CAP_BYTES


def _role(sc, role):
    return [d for d in sc.manifest["devices"] if d["role"] == role]


def _by_id(sc, dev_id):
    return next(d for d in sc.manifest["devices"] if d["device_id"] == dev_id)


def _leases(sc, mac):
    return [x for e in sc.emissions for x in e.batch["leases"] if x["mac"] == mac]


def test_hostname_spoof_copies_hostname_and_mdns_not_fingerprint(gen):
    sc = gen("hostname_spoof", 2, 12)
    (atk,) = _role(sc, "attacker")
    victim = _by_id(sc, atk["impersonates"])
    assert atk["hostname"] == victim["hostname"] and atk["mdns_name"] == victim["mdns_name"]
    assert atk["macs"][0]["mac"] != victim["macs"][0]["mac"]
    assert (atk["opt55"], atk["opt60"]) != (victim["opt55"], victim["opt60"])
    names = {
        s["name"]
        for e in sc.emissions
        for s in e.batch["sightings"]
        if s["mac"] == atk["macs"][0]["mac"]
    }
    assert victim["mdns_name"] in names
    assert _leases(sc, atk["macs"][0]["mac"])[0]["hostname"] == victim["hostname"]


def test_mac_clone_same_mac_different_dhcp_fingerprint(gen):
    sc = gen("mac_clone", 2, 12)
    (atk,) = _role(sc, "attacker")
    victim = _by_id(sc, atk["impersonates"])
    mac = victim["macs"][0]["mac"]
    assert atk["macs"][0]["mac"] == mac
    fps = {(tuple(x["opt55"]), x["opt60"]) for x in _leases(sc, mac)}
    assert len(fps) == 2
    assert atk["macs"][0]["from_ts"] > sc.manifest["start"]  # clone appears mid-run
    assert {a["kind"] for a in sc.manifest["anomalies"]} == {"mac_clone"}


def test_ip_flap_one_ip_alternates_between_two_macs(gen):
    sc = gen("ip_flap", 2, 14)
    (atk,) = _role(sc, "attacker")
    victim = _by_id(sc, atk["impersonates"])
    vip = victim["macs"][0]["ip"]
    seq = []
    for e in sc.emissions:
        macs = {n["mac"] for n in e.batch["neigh"] if n["ip"] == vip}
        seq.append(macs)
    flat = [m for s in seq for m in s]
    assert {victim["macs"][0]["mac"], atk["macs"][0]["mac"]} <= set(flat)
    owner = [next(iter(s)) for s in seq if len(s) == 1]
    changes = sum(1 for a, b in zip(owner, owner[1:], strict=False) if a != b)
    assert changes >= 3


def test_doh_user_zero_queries_large_443(gen):
    sc = gen("doh_user", 2, 12)
    (doh,) = [d for d in sc.manifest["devices"] if d.get("doh")]
    mac = doh["macs"][0]["mac"]
    assert not [q for e in sc.emissions for q in e.batch["dns"] if q["mac"] == mac]
    flows = [c for e in sc.emissions for c in e.batch["conntrack"] if c["mac"] == mac]
    assert sum(c["bytes_down"] for c in flows if c["dst_port"] == 443) > 5_000_000
    others_dns = [q for e in sc.emissions for q in e.batch["dns"] if q["mac"] != mac]
    assert others_dns  # the rest of the LAN still queries the router


def test_replay_stream(gen):
    sc = gen("replay", 2, 8)
    ems = sc.emissions
    dup = [e for e in ems if e.label == "replay_identical"]
    tamper = [e for e in ems if e.label == "replay_resigned_ts"]
    assert len(dup) == 1 and len(tamper) == 1
    orig = next(
        e
        for e in ems
        if e.batch["batch_id"] == dup[0].batch["batch_id"] and e.label != "replay_identical"
    )
    assert json.dumps(orig.batch) == json.dumps(dup[0].batch)
    assert (dup[0].expect_status, dup[0].expect_duplicate) == (200, True)
    assert tamper[0].expect_status == 401 and tamper[0].header_overrides


def test_out_of_order_seq(gen):
    sc = gen("out_of_order", 2, 8)
    seqs = [e.batch["seq"] for e in sc.emissions]
    assert seqs != sorted(seqs)
    assert [e.expect_status for e in sc.emissions].count(409) == 1
    late = next(e for e in sc.emissions if e.expect_status == 409)
    assert late.batch["seq"] < max(seqs[: seqs.index(late.batch["seq"])])
    arrivals = [e.arrival_ts for e in sc.emissions]
    assert arrivals == sorted(arrivals)


def test_stale_sent_ts(gen):
    sc = gen("stale_ts", 2, 8)
    stale = [e for e in sc.emissions if e.expect_status == 400]
    assert len(stale) == 1
    assert stale[0].arrival_ts - stale[0].batch["sent_ts"] >= 3600


def test_flood_follows_prp_truncation_order(gen):
    sc = gen("flood", 2, 6)
    flood = max(sc.emissions, key=lambda e: len(e.batch["truncated"]))
    b = flood.batch
    assert len(json.dumps(b, separators=(",", ":")).encode()) <= PRP_BATCH_CAP_BYTES
    t = b["truncated"]
    # Order: leases/neigh/mDNS first, then DNS, then conntrack (top-N + per-MAC "other").
    assert {"leases", "neigh", "sightings", "dns", "conntrack"} <= t.keys()
    assert not b["leases"] and not b["neigh"] and not b["sightings"]
    others = [c for c in b["conntrack"] if c["proto"] == "other" and c["dst_ip"] is None]
    assert others and len({c["mac"] for c in others}) == len(others)
    ranked = [c for c in b["conntrack"] if c not in others]
    assert len(ranked) < 5000 and sc.manifest["anomalies"][0]["kind"] == "flow_flood"
    raw = sc.manifest["anomalies"][0]["raw_flows"]
    assert raw > 5000 and len(ranked) + t["conntrack"] == raw
    # Byte/flow totals survive folding.
    tot = sc.manifest["anomalies"][0]["totals"]
    assert sum(c["bytes_down"] for c in b["conntrack"]) == tot["bytes_down"]
    assert sum(c["flows"] for c in b["conntrack"]) == tot["flows"]
    # Top-N by bytes: the big legit flows survive, the tiny flood flows are what got folded.
    assert max(c["bytes_down"] for c in ranked) > 100_000


def test_flood_with_small_cap_still_orders(gen):
    sc = gen("flood", 2, 6, batch_cap_bytes=60_000)
    flood = max(sc.emissions, key=lambda e: len(e.batch["truncated"]))
    assert len(json.dumps(flood.batch, separators=(",", ":")).encode()) <= 60_000
