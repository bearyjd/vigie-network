"""Ground-truth device roster: the baseline home LAN plus whatever the profile adds."""

from __future__ import annotations

import random
from typing import Any

from .adversarial import BUILDERS, Build, rolling_mac
from .devices import Device, make_device, new_ips

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
    "rolling_overlap_veto",
    "rolling_fingerprint_copy",
)
# First entry is the default.
VARIANTS: dict[str, tuple[str, ...]] = {
    "hostname_spoof": ("hostname_only", "full_fingerprint"),
    "mac_clone": ("naive", "same_fingerprint"),
    "rolling_fingerprint_copy": ("victim_away", "victim_present"),
}
BASELINE_KINDS = (
    "phone_ios",
    "phone_android",
    "smart_tv",
    "ip_camera",
    "thermostat",
    "laptop",
    "game_console",
)


def resolve_variant(profile: str, variant: str | None) -> str | None:
    """Default variant when none given; ValueError for an unknown one."""
    options = VARIANTS.get(profile)
    if variant is None:
        return options[0] if options else None
    if not options or variant not in options:
        have = ", ".join(options) if options else "none"
        raise ValueError(f"unknown variant {variant!r} for {profile}; choose from: {have}")
    return variant


def build_roster(
    profile: str,
    seed: int,
    start: int,
    end: int,
    window_s: int,
    roll_interval_s: int | None,
    variant: str | None = None,
) -> tuple[list[Device], list[dict[str, Any]]]:
    """Baseline home LAN plus whatever the profile adds. Returns (devices, anomalies)."""
    rng = random.Random(f"{seed}:roster")
    ips = new_ips()
    devices = [make_device(i + 1, k, rng, ips, start, end) for i, k in enumerate(BASELINE_KINDS)]
    build = Build(
        by_type={d.true_type: d for d in devices},
        rng=random.Random(f"{seed}:attackers"),
        ips=ips,
        start=start,
        end=end,
        window_s=window_s,
        nxt=len(devices) + 1,
        roll_interval_s=roll_interval_s,
        variant=resolve_variant(profile, variant),
    )
    builder = BUILDERS.get(profile) or (rolling_mac if roll_interval_s is not None else None)
    if builder is None:
        return devices, []
    added, anomalies = builder(build)
    return [*devices, *added], anomalies
