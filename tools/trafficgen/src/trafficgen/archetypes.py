"""Device archetypes: static fingerprint plus a per-window traffic behavior.

All names, addresses and MACs are reserved/documentation values: .example domains,
RFC 5737 IPv4 ranges and the RFC 7042 documentation MAC range.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable
from dataclasses import dataclass, field

# (offset_s, qname, qtype)
DnsEvent = tuple[int, str, str]
# (dst_ip, dst_port, proto, bytes_up, bytes_down, flows)
FlowEvent = tuple[str, int, str, int, int, int]
# (kind, name, service, ua)
SightingEvent = tuple[str, str | None, str | None, str | None]

# RFC 5737 documentation networks: the only "public" destinations the generator ever emits.
DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")
# Stand-ins for public DoH resolvers (documentation addresses); named in the doh_user manifest.
DOH_RESOLVERS = ("192.0.2.53", "198.51.100.53", "203.0.113.53")


def ip_for(name: str) -> str:
    """Stable fake public IPv4 (RFC 5737 documentation range) for a hostname."""
    h = hashlib.sha256(name.encode()).digest()
    return f"{DOC_NETS[h[0] % len(DOC_NETS)]}.{1 + h[1] % 254}"


@dataclass(frozen=True)
class Ctx:
    rng: random.Random
    widx: int  # window index within the run
    hour: int  # UTC hour of the window start
    new_span: bool  # this window is the first one under the current MAC
    mdns_name: str | None


@dataclass
class Activity:
    dns: list[DnsEvent] = field(default_factory=list)
    flows: list[FlowEvent] = field(default_factory=list)
    sightings: list[SightingEvent] = field(default_factory=list)


Behavior = Callable[[Ctx], Activity]

WEB = tuple(
    f"{s}.{d}.example" for s in ("www", "api", "cdn") for d in ("news", "shop", "social", "video")
)
APPLE = ("gateway.icloud.example", "push.apple.example", "mesu.apple.example", "cdn.apple.example")
GOOGLE = ("play.google.example", "mtalk.google.example", "clients.google.example")
CDN = ("cdn.streamco.example", "edge1.streamco.example", "edge2.streamco.example")
CONSOLE = ("live.console-net.example", "dl.console-net.example", "party.console-net.example")
CAMERA_CLOUD = "cloud.ipcam-vendor.example"
THERMO = ("api.thermo-cloud.example", "fw.thermo-cloud.example")


def _lognorm(rng: random.Random, mu: float, sigma: float) -> int:
    return max(1, int(rng.lognormvariate(mu, sigma)))


def _dns(rng: random.Random, name: str, qtype: str = "A") -> DnsEvent:
    return rng.randrange(0, 60), name, qtype


def _web_activity(ctx: Ctx, pool: tuple[str, ...], p_active: float, mu: float) -> Activity:
    rng, act = ctx.rng, Activity()
    if rng.random() > p_active:
        return act
    for name in rng.sample(pool, rng.randint(2, 4)):
        act.dns.append(_dns(rng, name))
        down = _lognorm(rng, mu, 1.5)
        act.flows.append(
            (ip_for(name), 443, "tcp", int(down * rng.uniform(0.02, 0.2)) + 1, down, 1)
        )
    if rng.random() < 0.3:
        name = rng.choice(pool)
        act.flows.append(
            (ip_for(name), 443, "udp", rng.randint(1_000, 20_000), _lognorm(rng, 11, 1), 1)
        )
    return act


def phone(pool: tuple[str, ...], service: str) -> Behavior:
    def behave(ctx: Ctx) -> Activity:
        act = _web_activity(ctx, pool, 0.6 if 7 <= ctx.hour < 23 else 0.05, 11.5)
        if ctx.new_span or ctx.widx % 5 == 0:
            act.sightings.append(("mdns", ctx.mdns_name, service, None))
        return act

    return behave


def laptop(ctx: Ctx) -> Activity:
    act = _web_activity(ctx, WEB, 0.7 if 7 <= ctx.hour < 23 else 0.1, 11.0)
    for name in ctx.rng.sample(WEB, ctx.rng.randint(1, 4)):
        act.dns.append(_dns(ctx.rng, name))
    if ctx.widx % 7 == 0:
        act.sightings.append(("mdns", ctx.mdns_name, "_smb._tcp", None))
    return act


def smart_tv(ctx: Ctx) -> Activity:
    rng, act = ctx.rng, Activity()
    for name in rng.sample(CDN, rng.randint(1, 2)):
        down = rng.randint(2_000_000, 6_000_000)
        act.flows.append((ip_for(name), 443, "tcp", int(down * rng.uniform(0.01, 0.03)), down, 1))
    for name in rng.sample(CDN, rng.randint(0, 2)):
        act.dns.append(_dns(rng, name))
    if ctx.widx % 6 == 0:
        act.sightings.append(
            (
                "ssdp",
                None,
                "urn:schemas-upnp-org:device:MediaRenderer:1",
                "Linux/4.14 UPnP/1.0 SmartTV/2.0",
            )
        )
    if ctx.widx % 10 == 0:
        act.sightings.append(("mdns", ctx.mdns_name, "_airplay._tcp", None))
    return act


def ip_camera(ctx: Ctx) -> Activity:
    rng, act = ctx.rng, Activity()
    act.flows.append(
        (
            ip_for(CAMERA_CLOUD),
            8000,
            "tcp",
            rng.randint(650_000, 700_000),
            rng.randint(5_000, 15_000),
            1,
        )
    )
    if ctx.widx % 5 == 0:  # beacon: periodic re-resolve of the vendor cloud
        act.dns.append(_dns(rng, CAMERA_CLOUD))
    if ctx.widx % 10 == 0:
        act.sightings.append(
            ("ssdp", None, "urn:schemas-upnp-org:device:camera:1", "ipcam/1.0 UPnP/1.0")
        )
    return act


def thermostat(ctx: Ctx) -> Activity:
    rng, act = ctx.rng, Activity()
    if ctx.widx % 5 == 2:  # poll every five minutes
        name = THERMO[1] if ctx.widx % 20 == 2 else THERMO[0]
        act.dns.append(_dns(rng, name))
        act.flows.append(
            (ip_for(name), 443, "tcp", rng.randint(400, 800), rng.randint(1_000, 3_000), 1)
        )
    return act


def game_console(ctx: Ctx) -> Activity:
    rng, act = ctx.rng, Activity()
    if ctx.widx % 3 == 0:
        act.dns.append(_dns(rng, CONSOLE[0]))
        act.flows.append((ip_for(CONSOLE[0]), 443, "tcp", 2_000, 5_000, 1))
    roll = rng.random()
    if roll < 0.12:  # download burst
        down = rng.randint(20_000_000, 80_000_000)
        act.dns.append(_dns(rng, CONSOLE[1]))
        act.flows.append((ip_for(CONSOLE[1]), 443, "tcp", int(down * 0.015), down, 1))
    elif roll < 0.37:  # multiplayer session
        for port in (3074, 3478):
            act.flows.append(
                (
                    ip_for(CONSOLE[2]),
                    port,
                    "udp",
                    rng.randint(200_000, 800_000),
                    rng.randint(400_000, 1_500_000),
                    2,
                )
            )
        act.dns.append(_dns(rng, CONSOLE[2]))
    return act


def doh_laptop(ctx: Ctx) -> Activity:
    """Large 443 traffic, DNS-over-HTTPS to public resolvers: zero queries reach the router."""
    rng, act = ctx.rng, Activity()
    for ip in rng.sample(DOH_RESOLVERS, 2):
        act.flows.append(
            (ip, 443, "tcp", rng.randint(20_000, 60_000), rng.randint(400_000, 1_200_000), 3)
        )
    for name in rng.sample(WEB, 2):
        down = rng.randint(400_000, 1_200_000)
        act.flows.append((ip_for(name), 443, "tcp", int(down * 0.1), down, 1))
    return act


def quiet(_: Ctx) -> Activity:
    return Activity()


@dataclass(frozen=True)
class Archetype:
    true_type: str
    behavior: Behavior
    opt55: tuple[int, ...]
    opt60: str | None
    private_mac: bool
    hostname: str  # str.format(tag=...)
    mdns_name: str | None = None


ARCHETYPES: dict[str, Archetype] = {
    "phone_ios": Archetype(
        "phone_ios",
        phone(APPLE + WEB, "_companion-link._tcp"),
        (1, 121, 3, 6, 15, 119, 252),
        None,
        True,
        "{tag}s-iPhone",
        "{tag}s iPhone",
    ),
    "phone_android": Archetype(
        "phone_android",
        phone(GOOGLE + WEB, "_googlecast._tcp"),
        (1, 3, 6, 15, 26, 28, 51, 58, 59, 43),
        "android-dhcp-14",
        True,
        "Pixel-{tag}",
        "Pixel {tag}",
    ),
    "smart_tv": Archetype(
        "smart_tv",
        smart_tv,
        (1, 3, 6, 12, 15, 28, 42),
        "udhcp 1.30.1",
        False,
        "LivingRoom-TV-{tag}",
        "Living Room TV",
    ),
    "ip_camera": Archetype(
        "ip_camera", ip_camera, (1, 3, 6, 12, 15, 28), "udhcp 1.19.4", False, "ipcam-{tag}"
    ),
    "thermostat": Archetype(
        "thermostat", thermostat, (1, 3, 6, 15), "udhcpc 1.22.1", False, "thermostat-{tag}"
    ),
    "laptop": Archetype(
        "laptop",
        laptop,
        (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252),
        "MSFT 5.0",
        False,
        "DESKTOP-{tag}",
        "desktop-{tag}",
    ),
    "game_console": Archetype(
        "game_console", game_console, (1, 3, 6, 15, 28, 33), "dhcpcd-5.5.6", False, "PS5-{tag}"
    ),
}
