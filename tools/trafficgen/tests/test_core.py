"""Determinism, schema validity, archetype behavior, rolling-MAC manifest."""

from __future__ import annotations

import json

import pytest
from conftest import macs_of

from trafficgen import PROFILES, generate, validate_batch
from trafficgen.generator import emissions_to_jsonl


def _device(sc, true_type):
    return [
        d for d in sc.manifest["devices"] if d["true_type"] == true_type and d["role"] == "benign"
    ]


def _flows(sc, mac):
    return [c for e in sc.emissions for c in e.batch["conntrack"] if c["mac"] == mac]


def _dns(sc, mac):
    return [(i, q) for i, e in enumerate(sc.emissions) for q in e.batch["dns"] if q["mac"] == mac]


@pytest.mark.parametrize("profile", PROFILES)
def test_deterministic_by_seed(gen, profile):
    a = emissions_to_jsonl(gen(profile, 7, 8).emissions)
    b = emissions_to_jsonl(generate(profile, seed=7, windows=8).emissions)  # uncached
    c = emissions_to_jsonl(gen(profile, 8, 8).emissions)
    assert a == b
    assert a != c


@pytest.mark.parametrize("profile", PROFILES)
def test_every_batch_validates_and_manifest_covers_all_macs(gen, profile):
    sc = gen(profile, 3, 12)
    for em in sc.emissions:
        validate_batch(em.batch)  # JSON Schema + strict pydantic model
    known = {m["mac"] for d in sc.manifest["devices"] for m in d["macs"]}
    assert macs_of(sc) <= known


def test_manifest_shape(gen):
    m = gen("baseline", 1, 6).manifest
    assert {"seed", "profile", "start", "windows", "devices"} <= m.keys()
    assert {d["true_type"] for d in m["devices"]} == {
        "phone_ios",
        "phone_android",
        "smart_tv",
        "ip_camera",
        "thermostat",
        "laptop",
        "game_console",
    }
    json.dumps(m)  # serialisable


def test_seq_monotonic_and_windows_contiguous(gen):
    ems = gen("baseline", 1, 10).emissions
    assert [e.batch["seq"] for e in ems] == list(range(1, 11))
    for prev, cur in zip(ems, ems[1:], strict=False):
        assert cur.batch["window_start"] == prev.batch["window_end"]


def test_phones_use_private_macs_and_distinct_fingerprints(gen):
    sc = gen("baseline", 1, 6)
    (ios,) = _device(sc, "phone_ios")
    (droid,) = _device(sc, "phone_android")
    for d in (ios, droid):
        first = int(d["macs"][0]["mac"][:2], 16)
        assert first & 0x02 and not first & 0x01  # locally administered unicast
    assert droid["opt60"] == "android-dhcp-14" and ios["opt60"] is None
    assert ios["opt55"] != droid["opt55"]


def test_tv_is_download_heavy_and_steady(gen):
    sc = gen("baseline", 1, 20)
    (tv,) = _device(sc, "smart_tv")
    mac = tv["macs"][0]["mac"]
    up = sum(c["bytes_up"] for c in _flows(sc, mac))
    down = sum(c["bytes_down"] for c in _flows(sc, mac))
    assert down / up > 20
    active = [any(c["mac"] == mac for c in e.batch["conntrack"]) for e in sc.emissions]
    assert all(active)  # steady: every window
    assert any(
        s["kind"] == "ssdp" for e in sc.emissions for s in e.batch["sightings"] if s["mac"] == mac
    )


def test_camera_constant_upstream_fixed_ports_periodic_beacon(gen):
    sc = gen("baseline", 1, 30)
    (cam,) = _device(sc, "ip_camera")
    mac = cam["macs"][0]["mac"]
    flows = _flows(sc, mac)
    assert len({c["dst_port"] for c in flows if c["bytes_up"] > 100_000}) == 1
    ups = [
        sum(c["bytes_up"] for c in e.batch["conntrack"] if c["mac"] == mac) for e in sc.emissions
    ]
    assert min(ups) > 100_000 and max(ups) / min(ups) < 1.5
    assert sum(c["bytes_up"] for c in flows) > 5 * sum(c["bytes_down"] for c in flows)
    beacon_windows = [i for i, _ in _dns(sc, mac)]
    assert beacon_windows and all(i % 5 == 0 for i in beacon_windows)


def test_thermostat_tiny_periodic_few_domains(gen):
    sc = gen("baseline", 1, 30)
    (t,) = _device(sc, "thermostat")
    mac = t["macs"][0]["mac"]
    assert len({q["qname"] for _, q in _dns(sc, mac)}) <= 2
    assert max(c["bytes_up"] + c["bytes_down"] for c in _flows(sc, mac)) < 10_000
    idx = [
        i for i, e in enumerate(sc.emissions) if any(c["mac"] == mac for c in e.batch["conntrack"])
    ]
    assert 3 <= len(idx) <= 8 and len({b - a for a, b in zip(idx, idx[1:], strict=False)}) == 1


def test_phone_is_bursty_with_mdns(gen):
    sc = gen("baseline", 1, 40)
    (p,) = _device(sc, "phone_ios")
    mac = p["macs"][0]["mac"]
    per_window = [
        sum(c["bytes_down"] for c in e.batch["conntrack"] if c["mac"] == mac) for e in sc.emissions
    ]
    assert (
        any(v == 0 for v in per_window)
        and max(per_window) > 10 * (sum(per_window) / len(per_window)) * 0.3
    )
    assert any(
        s["kind"] == "mdns" and s["mac"] == mac for e in sc.emissions for s in e.batch["sightings"]
    )


def test_rolling_mac_manifest_correctness(gen):
    sc = gen("rolling_mac", 5, 30, roll_interval_s=300)
    rollers = [d for d in sc.manifest["devices"] if d.get("rolling")]
    assert len(rollers) == 1
    d = rollers[0]
    spans = d["macs"]
    assert len(spans) >= 5 and len({s["mac"] for s in spans}) == len(spans)
    for a, b in zip(spans, spans[1:], strict=False):
        assert a["to_ts"] == b["from_ts"]  # contiguous, no overlap
        assert b["from_ts"] - a["from_ts"] == 300
    assert all(int(s["mac"][:2], 16) & 0x02 for s in spans)
    # Same fingerprint on every MAC, and traffic only under the MAC valid at that time.
    fps = set()
    for e in sc.emissions:
        for lease in e.batch["leases"]:
            if lease["mac"] in {s["mac"] for s in spans}:
                fps.add((lease["hostname"], tuple(lease["opt55"]), lease["opt60"]))
        for c in e.batch["conntrack"]:
            for s in spans:
                if c["mac"] == s["mac"]:
                    assert s["from_ts"] <= e.batch["window_start"] < s["to_ts"]
    assert fps == {(d["hostname"], tuple(d["opt55"]), d["opt60"])}
    seen = {x["mac"] for e in sc.emissions for x in e.batch["leases"]}
    assert {s["mac"] for s in spans} <= seen  # every roll produced a lease (urgent-push signal)
