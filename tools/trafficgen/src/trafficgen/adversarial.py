"""Profile builders: each returns the devices a profile adds to the baseline LAN, plus anomalies."""

from __future__ import annotations

import random
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from typing import Any

from .archetypes import doh_laptop
from .devices import (
    Device,
    MacSpan,
    flood_behavior,
    make_attacker,
    make_device,
    random_mac,
    rolling_phone,
)
from .model import GRACE_S

Anomalies = list[dict[str, Any]]

# Overlap lengths in windows, chosen relative to the 10 min grace (10 windows of 60 s).
SHORT_OVERLAP_WINDOWS = 3  # well inside the grace window
SUSTAINED_OVERLAP_WINDOWS = 14  # well beyond it
ROLL_WINDOWS = 5


@dataclass(frozen=True)
class Build:
    by_type: dict[str, Device]
    rng: random.Random
    ips: Iterator[str]
    start: int
    end: int
    window_s: int
    nxt: int
    roll_interval_s: int | None
    variant: str | None

    @property
    def mid(self) -> int:
        return self.start + (((self.end - self.start) // self.window_s) // 2) * self.window_s

    def attacker(self) -> Device:
        return make_attacker(self.nxt, self.rng, self.ips, self.start, self.end)


def _copy_fp(atk: Device, victim: Device, fields: tuple[str, ...]) -> Device:
    return replace(atk, impersonates=victim.device_id, **{f: getattr(victim, f) for f in fields})


def rolling_mac(b: Build) -> tuple[list[Device], Anomalies]:
    step = max(1, (b.roll_interval_s or 180) // b.window_s) * b.window_s
    return [rolling_phone(b.nxt, b.rng, b.ips, b.start, b.end, step)], []


def doh_user(b: Build) -> tuple[list[Device], Anomalies]:
    base = b.attacker()
    dev = replace(
        base,
        role="benign",
        behavior=doh_laptop,
        doh=True,
        hostname=f"DOH-{base.hostname}",
        mdns_name=None,
    )
    return [dev], []


_SPOOF_FIELDS = {
    "hostname_only": ("hostname", "mdns_name"),
    "full_fingerprint": ("hostname", "mdns_name", "opt55", "opt60"),
}


def hostname_spoof(b: Build) -> tuple[list[Device], Anomalies]:
    victim = b.by_type["phone_ios"]
    variant = b.variant or "hostname_only"
    fields = _SPOOF_FIELDS[variant]
    atk = _copy_fp(b.attacker(), victim, fields)
    an = {
        "kind": "hostname_spoof",
        "variant": variant,
        "attacker": atk.device_id,
        "victim": victim.device_id,
        "copied": list(fields),
    }
    return [atk], [an]


def mac_clone(b: Build) -> tuple[list[Device], Anomalies]:
    victim = b.by_type["ip_camera"]
    variant = b.variant or "naive"
    atk = b.attacker()
    span = MacSpan(victim.spans[0].mac, next(b.ips), b.mid, b.end)
    atk = replace(atk, spans=(span,), impersonates=victim.device_id)
    an: dict[str, Any] = {
        "kind": "mac_clone",
        "variant": variant,
        "mac": span.mac,
        "attacker": atk.device_id,
        "victim": victim.device_id,
        "from_ts": b.mid,
    }
    if variant == "same_fingerprint":
        fields = ("hostname", "mdns_name", "opt55", "opt60")
        atk = _copy_fp(atk, victim, fields)
        an |= {
            "copied": list(fields),
            "detectable_only_by": "behavioral_demotion",
            "note": "same MAC and same fingerprint; only behavioral demotion can detect it",
        }
    else:
        an["note"] = "naive clone: same MAC, attacker keeps its own DHCP fingerprint"
    return [atk], [an]


def ip_flap(b: Build) -> tuple[list[Device], Anomalies]:
    victim = b.by_type["smart_tv"]
    atk = replace(b.attacker(), impersonates=victim.device_id)
    an = {
        "kind": "ip_flap",
        "ip": victim.spans[0].ip,
        "attacker": atk.device_id,
        "victim": victim.device_id,
        "from_ts": b.mid,
    }
    return [atk], [an]


def flood(b: Build) -> tuple[list[Device], Anomalies]:
    windows = (b.end - b.start) // b.window_s
    fw = max(1, windows - 2)
    atk = b.attacker()
    # The flooder joins the LAN in the flood window, so its lease/neigh/mDNS are in that batch.
    span = replace(atk.spans[0], from_ts=b.start + fw * b.window_s)
    dev = replace(atk, role="flooder", spans=(span,), behavior=flood_behavior(fw))
    return [dev], [{"kind": "flow_flood", "window": fw, "attacker": atk.device_id}]


def _transitions(dev: Device, end: int) -> list[dict[str, Any]]:
    """MAC hand-overs with the overlap actually observable before the run ends."""
    return [
        {
            "old_mac": old.mac,
            "new_mac": new.mac,
            "new_from_ts": new.from_ts,
            "old_active_until": min(old.active_until, end),
            "overlap_s": min(old.overlap_s, end - new.from_ts),
        }
        for old, new in zip(dev.spans, dev.spans[1:], strict=False)
    ]


def rolling_overlap_veto(b: Build) -> tuple[list[Device], Anomalies]:
    w = b.window_s
    roller = replace(
        rolling_phone(
            b.nxt, b.rng, b.ips, b.start, b.end, ROLL_WINDOWS * w, SHORT_OVERLAP_WINDOWS * w
        ),
        heartbeat=True,
    )
    # Two devices, one signature: the first never left when the second showed up.
    t_second = b.start + 8 * w
    first = make_device(b.nxt + 1, "phone_ios", b.rng, b.ips, b.start, b.end)
    old = replace(first.spans[0], to_ts=t_second, overlap_s=SUSTAINED_OVERLAP_WINDOWS * w)
    first = replace(first, spans=(old,), heartbeat=True)
    new = MacSpan(random_mac(b.rng), next(b.ips), t_second, b.end)
    second = replace(
        first, device_id=f"dev-{b.nxt + 2:02d}", spans=(new,), impersonates=first.device_id
    )
    legit = {
        "kind": "overlap",
        "case": "legit_rolling",
        "device": roller.device_id,
        "overlap_s": SHORT_OVERLAP_WINDOWS * w,
        "grace_s": GRACE_S,
        "within_grace": SHORT_OVERLAP_WINDOWS * w <= GRACE_S,
        "expected_verdict": "same_device",
        "transitions": _transitions(roller, b.end),
    }
    sustained = {
        "kind": "overlap",
        "case": "sustained_two_devices",
        "devices": [first.device_id, second.device_id],
        "old_mac": old.mac,
        "new_mac": new.mac,
        "new_from_ts": t_second,
        "old_active_until": old.active_until,
        "overlap_s": SUSTAINED_OVERLAP_WINDOWS * w,
        "grace_s": GRACE_S,
        "within_grace": SUSTAINED_OVERLAP_WINDOWS * w <= GRACE_S,
        "expected_verdict": "two_devices",
    }
    return [roller, first, replace(second, impersonates=None)], [legit, sustained]


def rolling_fingerprint_copy(b: Build) -> tuple[list[Device], Anomalies]:
    """PRP section 8 accepted risk: copy opt55, opt60 and hostname of a rolling device."""
    w, variant = b.window_s, b.variant or "victim_away"
    victim = replace(
        rolling_phone(b.nxt, b.rng, b.ips, b.start, b.end, ROLL_WINDOWS * w), heartbeat=True
    )
    away = variant == "victim_away"
    if away:  # the victim leaves the LAN at mid
        spans = tuple(
            replace(s, to_ts=min(s.to_ts, b.mid)) for s in victim.spans if s.from_ts < b.mid
        )
        victim = replace(victim, spans=spans)
    atk_start = b.mid + 2 * w if away else b.mid
    base = make_attacker(b.nxt + 1, b.rng, b.ips, b.start, b.end)
    span = MacSpan(random_mac(b.rng), next(b.ips), atk_start, b.end)
    fields = ("opt55", "opt60", "hostname")
    atk = replace(_copy_fp(base, victim, fields), spans=(span,), heartbeat=True)
    an = {
        "kind": "rolling_fingerprint_copy",
        "variant": variant,
        "attacker": atk.device_id,
        "victim": victim.device_id,
        "copied": list(fields),
        "not_copied": ["mdns_name"],
        "attacker_mac": span.mac,
        "from_ts": atk_start,
        "victim_present": not away,
        "victim_last_active_ts": victim.spans[-1].active_until if away else None,
        "overlap_s": 0 if away else b.end - atk_start,
        "grace_s": GRACE_S,
    }
    return [victim, atk], [an]


BUILDERS: dict[str, Callable[[Build], tuple[list[Device], Anomalies]]] = {
    "doh_user": doh_user,
    "hostname_spoof": hostname_spoof,
    "mac_clone": mac_clone,
    "ip_flap": ip_flap,
    "flood": flood,
    "rolling_overlap_veto": rolling_overlap_veto,
    "rolling_fingerprint_copy": rolling_fingerprint_copy,
}
