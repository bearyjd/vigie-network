"""Ground-truth device roster: who exists, which MAC they hold when, and attacker add-ons."""

from __future__ import annotations

import random
from collections.abc import Iterator
from dataclasses import dataclass, replace
from itertools import count
from typing import Any

from .archetypes import ARCHETYPES, Activity, Behavior, Ctx, DnsEvent, FlowEvent, doh_laptop

PROFILES = (
    "baseline",
    "rolling_mac",
    "hostname_spoof",
    "mac_clone",
    "ip_flap",
    "doh_user",
    "replay",
    "out_of_order",
    "stale_ts",
    "flood",
)
BASELINE_KINDS = (
    "phone_ios",
    "phone_android",
    "smart_tv",
    "ip_camera",
    "thermostat",
    "laptop",
    "game_console",
)
FLOOD_FLOWS, FLOOD_DNS = 12_000, 3_000
_OWNERS = ("Alice", "Bob", "Carol", "Dave")


@dataclass(frozen=True)
class MacSpan:
    mac: str
    ip: str
    from_ts: int
    to_ts: int  # exclusive


@dataclass(frozen=True)
class Device:
    device_id: str
    true_type: str
    behavior: Behavior
    hostname: str
    mdns_name: str | None
    opt55: tuple[int, ...]
    opt60: str | None
    spans: tuple[MacSpan, ...]
    role: str = "benign"
    impersonates: str | None = None
    doh: bool = False
    rolling: bool = False

    def span_at(self, ts: int) -> MacSpan | None:
        return next((s for s in self.spans if s.from_ts <= ts < s.to_ts), None)

    def to_manifest(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "true_type": self.true_type,
            "role": self.role,
            "hostname": self.hostname,
            "mdns_name": self.mdns_name,
            "opt55": list(self.opt55),
            "opt60": self.opt60,
            "impersonates": self.impersonates,
            "doh": self.doh,
            "rolling": self.rolling,
            "macs": [
                {"mac": s.mac, "ip": s.ip, "from_ts": s.from_ts, "to_ts": s.to_ts}
                for s in self.spans
            ],
        }


def random_mac(rng: random.Random, private: bool) -> str:
    """Private: locally administered unicast. Otherwise a fake globally-unique unicast MAC."""
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] & 0xFC) | 0x02 if private else octets[0] & 0xFC
    return ":".join(f"{o:02x}" for o in octets)


def _ips() -> Iterator[str]:
    return (f"192.168.8.{n}" for n in count(100))


def _device(
    idx: int, kind: str, rng: random.Random, ips: Iterator[str], start: int, end: int
) -> Device:
    a = ARCHETYPES[kind]
    tag = rng.choice(_OWNERS) if a.true_type.startswith("phone") else f"{rng.randrange(16**4):04X}"
    if kind == "phone_android":
        tag = str(rng.randint(6, 9))
    span = MacSpan(random_mac(rng, a.private_mac), next(ips), start, end)
    return Device(
        f"dev-{idx:02d}",
        a.true_type,
        a.behavior,
        a.hostname.format(tag=tag),
        a.mdns_name.format(tag=tag) if a.mdns_name else None,
        a.opt55,
        a.opt60,
        (span,),
    )


def _rolling_phone(
    idx: int, rng: random.Random, ips: Iterator[str], start: int, end: int, roll_s: int
) -> Device:
    base = _device(idx, "phone_ios", rng, ips, start, end)
    spans = tuple(
        MacSpan(random_mac(rng, True), next(ips), t, min(t + roll_s, end))
        for t in range(start, end, roll_s)
    )
    return replace(
        base,
        spans=spans,
        rolling=True,
        hostname=f"{base.hostname}-roller",
        mdns_name=f"{base.mdns_name} roller",
    )


def _attacker(idx: int, rng: random.Random, ips: Iterator[str], start: int, end: int) -> Device:
    return replace(_device(idx, "laptop", rng, ips, start, end), role="attacker")


def _flood_behavior(flood_widx: int) -> Behavior:
    def behave(ctx: Ctx) -> Activity:
        act = Activity()
        if ctx.widx != flood_widx:
            return act
        rng = ctx.rng
        flows: list[FlowEvent] = [
            (
                ".".join(map(str, (rng.randint(23, 126), *rng.randbytes(2), rng.randint(1, 254)))),
                rng.randint(1, 65535),
                rng.choice(("tcp", "udp")),
                rng.randint(40, 1_500),
                rng.randint(40, 1_500),
                1,
            )
            for _ in range(FLOOD_FLOWS)
        ]
        dns: list[DnsEvent] = [
            (rng.randrange(60), f"{rng.getrandbits(40):010x}.scan.example", "A")
            for _ in range(FLOOD_DNS)
        ]
        return Activity(dns=dns, flows=flows, sightings=[("mdns", "flood-box", "_scan._tcp", None)])

    return behave


def build_roster(
    profile: str, seed: int, start: int, end: int, window_s: int, roll_interval_s: int | None
) -> tuple[list[Device], list[dict[str, Any]]]:
    """Baseline home LAN plus whatever the profile adds. Returns (devices, anomalies)."""
    rng = random.Random(f"{seed}:roster")
    ips = _ips()
    devices = [_device(i + 1, k, rng, ips, start, end) for i, k in enumerate(BASELINE_KINDS)]
    by_type = {d.true_type: d for d in devices}
    anomalies: list[dict[str, Any]] = []
    windows = (end - start) // window_s
    mid = start + (windows // 2) * window_s
    nxt = len(devices) + 1
    arng = random.Random(f"{seed}:attackers")

    if roll_interval_s is not None:
        step = max(1, roll_interval_s // window_s) * window_s
        devices.append(_rolling_phone(nxt, arng, ips, start, end, step))
    elif profile == "doh_user":
        base = _attacker(nxt, arng, ips, start, end)
        devices.append(
            replace(
                base,
                role="benign",
                behavior=doh_laptop,
                doh=True,
                hostname=f"DOH-{base.hostname}",
                mdns_name=None,
            )
        )
    elif profile == "hostname_spoof":
        victim = by_type["phone_ios"]
        devices.append(
            replace(
                _attacker(nxt, arng, ips, start, end),
                impersonates=victim.device_id,
                hostname=victim.hostname,
                mdns_name=victim.mdns_name,
            )
        )
        anomalies.append(
            {
                "kind": "hostname_spoof",
                "attacker": devices[-1].device_id,
                "victim": victim.device_id,
            }
        )
    elif profile == "mac_clone":
        victim = by_type["ip_camera"]
        atk = _attacker(nxt, arng, ips, start, end)
        span = MacSpan(victim.spans[0].mac, next(ips), mid, end)
        devices.append(replace(atk, spans=(span,), impersonates=victim.device_id))
        anomalies.append(
            {
                "kind": "mac_clone",
                "mac": span.mac,
                "attacker": atk.device_id,
                "victim": victim.device_id,
                "from_ts": mid,
            }
        )
    elif profile == "ip_flap":
        victim = by_type["smart_tv"]
        atk = replace(_attacker(nxt, arng, ips, start, end), impersonates=victim.device_id)
        devices.append(atk)
        anomalies.append(
            {
                "kind": "ip_flap",
                "ip": victim.spans[0].ip,
                "attacker": atk.device_id,
                "victim": victim.device_id,
                "from_ts": mid,
            }
        )
    elif profile == "flood":
        fw = max(1, windows - 2)
        atk = _attacker(nxt, arng, ips, start, end)
        # The flooder joins the LAN in the flood window, so its lease/neigh/mDNS are in that batch.
        span = replace(atk.spans[0], from_ts=start + fw * window_s)
        devices.append(replace(atk, role="flooder", spans=(span,), behavior=_flood_behavior(fw)))
        anomalies.append({"kind": "flow_flood", "window": fw, "attacker": atk.device_id})
    return devices, anomalies
