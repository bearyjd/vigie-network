"""Scenario generation: windows of collector batches plus the ground-truth manifest."""

from __future__ import annotations

import json
import random
import uuid
from pathlib import Path
from typing import Any

from .archetypes import Ctx, ip_for
from .model import (
    DEFAULT_START,
    PRP_BATCH_CAP_BYTES,
    WINDOW_S,
    Emission,
    Scenario,
    emissions_to_jsonl,
    shift_batch,
)
from .roster import PROFILES, Device, build_roster
from .truncate import apply_cap

__all__ = ["emissions_to_jsonl", "generate", "load_emissions"]

_MIN_WINDOWS = 4
_LEASE_RENEW_WINDOWS = 15


def _uuid7(rng: random.Random, ms: int) -> str:
    raw = bytearray(ms.to_bytes(6, "big") + rng.randbytes(10))
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _link_local(mac: str) -> str:
    o = [int(x, 16) for x in mac.split(":")]
    o[0] ^= 0x02
    return f"fe80::{o[0]:02x}{o[1]:02x}:{o[2]:02x}ff:fe{o[3]:02x}:{o[4]:02x}{o[5]:02x}"


def _window(
    devices: list[Device], rngs: dict[str, random.Random], widx: int, ws: int, window_s: int
) -> dict[str, Any]:
    """Raw (untruncated) per-window content for every device holding a MAC."""
    leases: list[dict[str, Any]] = []
    neigh: list[dict[str, Any]] = []
    dns: list[dict[str, Any]] = []
    sightings: list[dict[str, Any]] = []
    conntrack: dict[tuple[str, str, int, str], list[int]] = {}
    for dev in devices:
        span = dev.span_at(ws)
        if span is None:
            continue
        new_span = span.from_ts == ws
        act = dev.behavior(
            Ctx(rngs[dev.device_id], widx, (ws // 3600) % 24, new_span, dev.mdns_name)
        )
        if new_span or widx % _LEASE_RENEW_WINDOWS == 0:
            leases.append(
                {
                    "mac": span.mac,
                    "ip": span.ip,
                    "hostname": dev.hostname,
                    "opt55": list(dev.opt55),
                    "opt60": dev.opt60,
                }
            )
            neigh.append({"ip": span.ip, "mac": span.mac, "family": "inet"})
            neigh.append({"ip": _link_local(span.mac), "mac": span.mac, "family": "inet6"})
        for off, qname, qtype in act.dns:
            dns.append(
                {
                    "ts": ws + off,
                    "mac": span.mac,
                    "qname": qname,
                    "qtype": qtype,
                    "answer_ip": ip_for(qname) if qtype == "A" else None,
                }
            )
        for ip, port, proto, up, down, flows in act.flows:
            agg = conntrack.setdefault((span.mac, ip, port, proto), [0, 0, 0])
            agg[0] += up
            agg[1] += down
            agg[2] += flows
        for kind, name, service, ua in act.sightings:
            sightings.append(
                {"mac": span.mac, "kind": kind, "name": name, "service": service, "ua": ua}
            )
    dns.sort(key=lambda q: q["ts"])
    return {
        "leases": leases,
        "neigh": neigh,
        "dns": dns,
        "sightings": sightings,
        "conntrack": [
            {
                "mac": m,
                "dst_ip": ip,
                "dst_port": port,
                "proto": proto,
                "bytes_up": v[0],
                "bytes_down": v[1],
                "flows": v[2],
            }
            for (m, ip, port, proto), v in conntrack.items()
        ],
    }


def _apply_ip_flap(
    content: dict[str, Any], devices: list[Device], anomaly: dict[str, Any], ws: int, window_s: int
) -> dict[str, Any]:
    """From the anomaly start on, the neighbor table's owner of the victim IP alternates."""
    if ws < anomaly["from_ts"]:
        return content
    by_id = {d.device_id: d for d in devices}
    victim_mac = by_id[anomaly["victim"]].spans[0].mac
    attacker_mac = by_id[anomaly["attacker"]].spans[0].mac
    owner = attacker_mac if ((ws - anomaly["from_ts"]) // window_s) % 2 == 0 else victim_mac
    kept = [n for n in content["neigh"] if n["ip"] != anomaly["ip"]]
    return {**content, "neigh": kept + [{"ip": anomaly["ip"], "mac": owner, "family": "inet"}]}


def _flood_summary(raw: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "raw_flows": len(raw),
        "totals": {k: sum(c[k] for c in raw) for k in ("bytes_up", "bytes_down", "flows")},
    }


def _stream(profile: str, emissions: list[Emission], rng: random.Random) -> list[Emission]:
    """Delivery-level anomalies layered over a clean in-order stream."""
    last = emissions[-1]
    mid = len(emissions) // 2
    if profile == "replay":
        src = emissions[mid]
        return [
            *emissions,
            Emission("replay_identical", src.batch, last.arrival_ts + 30, 200, True),
            Emission(
                "replay_resigned_ts",
                src.batch,
                last.arrival_ts + 60,
                401,
                None,
                {"X-Vigie-Sent-Ts": str(last.arrival_ts + 60)},
            ),
        ]
    if profile == "out_of_order":
        # Swap two adjacent batches but keep arrival time monotonic: seq mid+1 shows up late.
        a, b = emissions[mid], emissions[mid + 1]
        first = Emission(b.label, b.batch, a.arrival_ts)
        second = Emission(a.label, a.batch, b.arrival_ts, 409)
        return [*emissions[:mid], first, second, *emissions[mid + 2 :]]
    if profile == "stale_ts":
        shifted = shift_batch(last.batch, -3600)
        batch = {
            **shifted,
            "seq": last.batch["seq"] + 1,
            "batch_id": _uuid7(rng, shifted["sent_ts"] * 1000),
        }
        return [*emissions, Emission("stale_sent_ts", batch, last.arrival_ts + 60, 400)]
    return emissions


def generate(
    profile: str = "baseline",
    *,
    seed: int = 0,
    windows: int = 10,
    start: int = DEFAULT_START,
    window_s: int = WINDOW_S,
    collector_id: str = "rtr-1",
    key_id: str = "k1",
    boot_id: str = "boot-a",
    roll_interval_s: int | None = None,
    batch_cap_bytes: int = PRP_BATCH_CAP_BYTES,
    variant: str | None = None,
) -> Scenario:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose from {', '.join(PROFILES)}")
    if windows < _MIN_WINDOWS:
        raise ValueError(f"windows must be >= {_MIN_WINDOWS}")
    if roll_interval_s is None and profile == "rolling_mac":
        roll_interval_s = 180
    end = start + windows * window_s
    devices, anomalies = build_roster(profile, seed, start, end, window_s, roll_interval_s)
    rngs = {d.device_id: random.Random(f"{seed}:{d.device_id}") for d in devices}
    crng = random.Random(f"{seed}:{profile}:collector")
    flap = next((a for a in anomalies if a["kind"] == "ip_flap"), None)
    flood = next((a for a in anomalies if a["kind"] == "flow_flood"), None)

    emissions: list[Emission] = []
    for widx in range(windows):
        ws = start + widx * window_s
        content = _window(devices, rngs, widx, ws, window_s)
        if flap:
            content = _apply_ip_flap(content, devices, flap, ws, window_s)
        if flood and flood["window"] == widx:
            flood.update(_flood_summary(content["conntrack"]), cap_bytes=batch_cap_bytes)
        we = ws + window_s
        batch = {
            "collector_id": collector_id,
            "key_id": key_id,
            "boot_id": boot_id,
            "seq": widx + 1,
            "batch_id": _uuid7(crng, we * 1000 + crng.randrange(1000)),
            "window_start": ws,
            "window_end": we,
            "sent_ts": we,
            "truncated": {},
            "dropped_batches": 0,
            **content,
            "health": {
                "dns_log_quiet": False,
                "rss_kb": 6000 + crng.randrange(500),
                "spool_batches": 0,
                "uptime_s": 3600 + (widx + 1) * window_s,
            },
        }
        emissions.append(Emission(f"batch_{widx + 1}", apply_cap(batch, batch_cap_bytes), we))

    manifest = {
        "seed": seed,
        "profile": profile,
        "start": start,
        "window_s": window_s,
        "windows": windows,
        "collector_id": collector_id,
        "key_id": key_id,
        "boot_id": boot_id,
        "roll_interval_s": roll_interval_s,
        "devices": [d.to_manifest() for d in devices],
        "anomalies": anomalies,
    }
    return Scenario(_stream(profile, emissions, crng), manifest)


def load_emissions(path: Path) -> list[Emission]:
    return [Emission.from_dict(json.loads(line)) for line in path.read_text().splitlines() if line]
