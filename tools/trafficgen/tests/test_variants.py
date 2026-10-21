"""Variants and overlap modelling: the emitted traffic must match the manifest's ground truth."""

from __future__ import annotations

import pytest

from trafficgen import generate
from trafficgen.model import GRACE_S, WINDOW_S

KINDS = ("leases", "neigh", "dns", "conntrack", "sightings")


def _dev(sc, dev_id):
    return next(d for d in sc.manifest["devices"] if d["device_id"] == dev_id)


def _presence(sc):
    """mac -> sorted window_start values in which it appears anywhere in the batch."""
    out: dict[str, set[int]] = {}
    for e in sc.emissions:
        for kind in KINDS:
            for x in e.batch[kind]:
                out.setdefault(x["mac"], set()).add(e.batch["window_start"])
    return {m: sorted(v) for m, v in out.items()}


def _both_s(pres, a, b):
    return len(set(pres[a]) & set(pres[b])) * WINDOW_S


def _leases(sc, mac):
    return [x for e in sc.emissions for x in e.batch["leases"] if x["mac"] == mac]


def _fp(lease):
    return (tuple(lease["opt55"]), lease["opt60"], lease["hostname"])


# ---- variant plumbing -------------------------------------------------------------------------


def test_unknown_variant_rejected():
    with pytest.raises(ValueError, match="variant"):
        generate("hostname_spoof", variant="nope")


def test_variant_on_profile_without_variants_rejected():
    with pytest.raises(ValueError, match="variant"):
        generate("baseline", variant="full_fingerprint")


def test_default_variant_recorded_in_manifest(gen):
    assert gen("hostname_spoof", 1, 8).manifest["variant"] == "hostname_only"
    assert gen("baseline", 1, 8).manifest["variant"] is None


# ---- hostname_spoof ---------------------------------------------------------------------------


def test_hostname_spoof_full_fingerprint_copies_everything_observable(gen):
    sc = gen("hostname_spoof", 2, 12, variant="full_fingerprint")
    (an,) = sc.manifest["anomalies"]
    atk, victim = _dev(sc, an["attacker"]), _dev(sc, an["victim"])
    assert (atk["opt55"], atk["opt60"], atk["hostname"], atk["mdns_name"]) == (
        victim["opt55"],
        victim["opt60"],
        victim["hostname"],
        victim["mdns_name"],
    )
    assert atk["macs"][0]["mac"] != victim["macs"][0]["mac"]
    lease = _leases(sc, atk["macs"][0]["mac"])[0]
    assert _fp(lease) == _fp(_leases(sc, victim["macs"][0]["mac"])[0])
    names = {
        s["name"]
        for e in sc.emissions
        for s in e.batch["sightings"]
        if s["mac"] == atk["macs"][0]["mac"]
    }
    assert victim["mdns_name"] in names
    assert an["variant"] == "full_fingerprint"
    assert set(an["copied"]) == {"opt55", "opt60", "hostname", "mdns_name"}


def test_hostname_spoof_default_still_hostname_only(gen):
    sc = gen("hostname_spoof", 2, 12)
    (an,) = sc.manifest["anomalies"]
    atk, victim = _dev(sc, an["attacker"]), _dev(sc, an["victim"])
    assert atk["hostname"] == victim["hostname"]
    assert (atk["opt55"], atk["opt60"]) != (victim["opt55"], victim["opt60"])
    assert an["variant"] == "hostname_only" and "opt55" not in an["copied"]


# ---- mac_clone --------------------------------------------------------------------------------


def _flows(sc, mac, before):
    start = sc.manifest["anomalies"][0]["from_ts"]
    return [
        c
        for e in sc.emissions
        for c in e.batch["conntrack"]
        if c["mac"] == mac and (e.batch["window_start"] < start) == before
    ]


def test_mac_clone_same_fingerprint_differs_only_in_behavior(gen):
    sc = gen("mac_clone", 2, 20, variant="same_fingerprint")
    (an,) = sc.manifest["anomalies"]
    mac = an["mac"]
    assert {_fp(x) for x in _leases(sc, mac)} == {_fp(_leases(sc, mac)[0])}  # no fingerprint change
    victim, atk = _dev(sc, an["victim"]), _dev(sc, an["attacker"])
    assert (atk["opt55"], atk["opt60"], atk["hostname"], atk["mdns_name"]) == (
        victim["opt55"],
        victim["opt60"],
        victim["hostname"],
        victim["mdns_name"],
    )
    assert {c["dst_port"] for c in _flows(sc, mac, before=True)} == {8000}
    assert 443 in {c["dst_port"] for c in _flows(sc, mac, before=False)}
    assert an["variant"] == "same_fingerprint"
    assert an["detectable_only_by"] == "behavioral_demotion"
    assert "only behavioral demotion" in an["note"]


def test_mac_clone_naive_is_labelled_naive(gen):
    sc = gen("mac_clone", 2, 12)
    (an,) = sc.manifest["anomalies"]
    assert an["variant"] == "naive" and "naive" in an["note"]
    mac = an["mac"]
    assert len({_fp(x) for x in _leases(sc, mac)}) == 2


# ---- rolling_overlap_veto ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def veto():
    return generate("rolling_overlap_veto", seed=3, windows=26)


def test_overlap_span_semantics():
    from trafficgen.devices import MacSpan

    s = MacSpan("m", "ip", 100, 200, overlap_s=60)
    assert s.active_at(199) and s.active_at(259) and not s.active_at(260)
    assert not MacSpan("m", "ip", 100, 200).active_at(200)


def test_veto_manifest_marks_both_cases(veto):
    cases = {a["case"]: a for a in veto.manifest["anomalies"] if a["kind"] == "overlap"}
    assert set(cases) == {"legit_rolling", "sustained_two_devices"}
    legit, two = cases["legit_rolling"], cases["sustained_two_devices"]
    assert veto.manifest["grace_s"] == GRACE_S == 600
    assert legit["expected_verdict"] == "same_device" and legit["overlap_s"] < GRACE_S
    assert two["expected_verdict"] == "two_devices" and two["overlap_s"] > GRACE_S
    assert legit["within_grace"] is True and two["within_grace"] is False


def test_veto_legit_rolling_overlap_is_short_in_the_traffic(veto):
    legit = next(a for a in veto.manifest["anomalies"] if a["case"] == "legit_rolling")
    pres = _presence(veto)
    assert len(legit["transitions"]) >= 3
    for t in legit["transitions"]:
        both = _both_s(pres, t["old_mac"], t["new_mac"])
        assert both == t["overlap_s"] and 0 < both <= legit["overlap_s"] <= GRACE_S
        assert max(pres[t["old_mac"]]) + WINDOW_S == t["old_active_until"]
        assert min(pres[t["new_mac"]]) == t["new_from_ts"]
    dev = _dev(veto, legit["device"])
    assert dev["rolling"] and len({m["mac"] for m in dev["macs"]}) >= 4


def test_veto_sustained_overlap_exceeds_grace_in_the_traffic(veto):
    two = next(a for a in veto.manifest["anomalies"] if a["case"] == "sustained_two_devices")
    pres = _presence(veto)
    both = _both_s(pres, two["old_mac"], two["new_mac"])
    assert both == two["overlap_s"] > GRACE_S
    d1, d2 = (_dev(veto, i) for i in two["devices"])
    assert d1["device_id"] != d2["device_id"]
    assert (d1["opt55"], d1["opt60"], d1["hostname"]) == (d2["opt55"], d2["opt60"], d2["hostname"])
    assert max(pres[two["old_mac"]]) + WINDOW_S == two["old_active_until"]


def test_veto_old_mac_silent_after_active_until(veto):
    for a in veto.manifest["anomalies"]:
        pairs = a.get("transitions") or [a]
        pres = _presence(veto)
        for t in pairs:
            assert all(ws < t["old_active_until"] for ws in pres[t["old_mac"]])


# ---- rolling_fingerprint_copy -----------------------------------------------------------------


@pytest.mark.parametrize("variant", ["victim_away", "victim_present"])
def test_fingerprint_copy_copies_opt55_opt60_hostname(variant):
    sc = generate("rolling_fingerprint_copy", seed=4, windows=24, variant=variant)
    (an,) = sc.manifest["anomalies"]
    atk, victim = _dev(sc, an["attacker"]), _dev(sc, an["victim"])
    assert (atk["opt55"], atk["opt60"], atk["hostname"]) == (
        victim["opt55"],
        victim["opt60"],
        victim["hostname"],
    )
    assert atk["mdns_name"] != victim["mdns_name"]  # §8 scenario copies exactly these three
    assert set(an["copied"]) == {"opt55", "opt60", "hostname"} and an["variant"] == variant
    assert victim["rolling"] and atk["role"] == "attacker"
    amac = atk["macs"][0]["mac"]
    assert _fp(_leases(sc, amac)[0]) == _fp(_leases(sc, victim["macs"][0]["mac"])[0])
    assert len({m["mac"] for m in victim["macs"]}) >= 3


def test_fingerprint_copy_victim_away_has_no_overlap():
    sc = generate("rolling_fingerprint_copy", seed=4, windows=24, variant="victim_away")
    (an,) = sc.manifest["anomalies"]
    pres = _presence(sc)
    vmacs = {m["mac"] for m in _dev(sc, an["victim"])["macs"]}
    amac = _dev(sc, an["attacker"])["macs"][0]["mac"]
    last_victim = max(max(pres[m]) for m in vmacs if m in pres)
    assert last_victim + WINDOW_S <= min(pres[amac])
    assert an["victim_present"] is False and an["victim_last_active_ts"] == last_victim + WINDOW_S


def test_fingerprint_copy_victim_present_overlaps_beyond_grace():
    sc = generate("rolling_fingerprint_copy", seed=4, windows=24, variant="victim_present")
    (an,) = sc.manifest["anomalies"]
    pres = _presence(sc)
    vmacs = {m["mac"] for m in _dev(sc, an["victim"])["macs"]}
    amac = _dev(sc, an["attacker"])["macs"][0]["mac"]
    victim_ws = {ws for m in vmacs if m in pres for ws in pres[m]}
    overlap = len(victim_ws & set(pres[amac])) * WINDOW_S
    assert an["victim_present"] is True and overlap == an["overlap_s"] > GRACE_S
