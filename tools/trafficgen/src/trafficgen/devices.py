"""Device model and constructors: who exists and which MAC they hold when."""

from __future__ import annotations

import random
from collections.abc import Iterator
from dataclasses import dataclass, replace
from itertools import count
from typing import Any

from .archetypes import (
    ARCHETYPES,
    DOC_NETS,
    Activity,
    Behavior,
    Ctx,
    DnsEvent,
    FlowEvent,
)

FLOOD_FLOWS, FLOOD_DNS = 12_000, 3_000
_OWNERS = ("Alice", "Bob", "Carol", "Dave")


@dataclass(frozen=True)
class MacSpan:
    mac: str
    ip: str
    from_ts: int
    to_ts: int  # exclusive: a successor MAC may take over at to_ts
    overlap_s: int = 0  # this MAC stays active this long after to_ts (reconnect / second device)

    @property
    def active_until(self) -> int:
        return self.to_ts + self.overlap_s

    def active_at(self, ts: int) -> bool:
        return self.from_ts <= ts < self.active_until


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
    heartbeat: bool = False  # emit an ARP/neigh entry every window while any MAC is active

    def spans_at(self, ts: int) -> list[MacSpan]:
        return [s for s in self.spans if s.active_at(ts)]

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
                {
                    "mac": s.mac,
                    "ip": s.ip,
                    "from_ts": s.from_ts,
                    "to_ts": s.to_ts,
                    "overlap_s": s.overlap_s,
                    "active_until": s.active_until,
                }
                for s in self.spans
            ],
        }


def random_mac(rng: random.Random) -> str:
    """Randomised (private) MAC: locally administered unicast."""
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] & 0xFC) | 0x02
    return ":".join(f"{o:02x}" for o in octets)


def doc_mac(host: int) -> str:
    """Stable (non-randomised) MAC in the RFC 7042 documentation range 00:00:5e:00:53:xx."""
    return f"00:00:5e:00:53:{host & 0xFF:02x}"


def new_ips() -> Iterator[str]:
    return (f"192.168.8.{n}" for n in count(100))


def make_device(
    idx: int, kind: str, rng: random.Random, ips: Iterator[str], start: int, end: int
) -> Device:
    a = ARCHETYPES[kind]
    tag = rng.choice(_OWNERS) if a.true_type.startswith("phone") else f"{rng.randrange(16**4):04X}"
    if kind == "phone_android":
        tag = str(rng.randint(6, 9))
    ip = next(ips)
    mac = random_mac(rng) if a.private_mac else doc_mac(int(ip.rsplit(".", 1)[1]))
    span = MacSpan(mac, ip, start, end)
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


def rolling_phone(
    idx: int,
    rng: random.Random,
    ips: Iterator[str],
    start: int,
    end: int,
    roll_s: int,
    overlap_s: int = 0,
) -> Device:
    """A phone that takes a fresh private MAC every roll_s; the old MAC lingers overlap_s."""
    base = make_device(idx, "phone_ios", rng, ips, start, end)
    spans = tuple(
        MacSpan(
            random_mac(rng),
            next(ips),
            t,
            min(t + roll_s, end),
            overlap_s if t + roll_s < end else 0,
        )
        for t in range(start, end, roll_s)
    )
    return replace(
        base,
        spans=spans,
        rolling=True,
        hostname=f"{base.hostname}-roller",
        mdns_name=f"{base.mdns_name} roller",
    )


def make_attacker(idx: int, rng: random.Random, ips: Iterator[str], start: int, end: int) -> Device:
    return replace(make_device(idx, "laptop", rng, ips, start, end), role="attacker")


def flood_behavior(flood_widx: int) -> Behavior:
    def behave(ctx: Ctx) -> Activity:
        act = Activity()
        if ctx.widx != flood_widx:
            return act
        rng = ctx.rng
        flows: list[FlowEvent] = [
            (
                f"{rng.choice(DOC_NETS)}.{rng.randint(1, 254)}",
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
