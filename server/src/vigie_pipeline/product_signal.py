"""M2b-I product-signal coverage over effective devices; evidence only, never authorization.

Pure and deterministic: the clock is the inventory's `now`, output is canonical JSON and never
echoes raw vendor, model, service, user-agent or hostname strings. See
docs/product-signal-inventory.md for the rule contract and class precedence.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from fractions import Fraction
from typing import Any

from vigie_api.effective import resolve
from vigie_pipeline.characterization import Observation, classify
from vigie_pipeline.product_signal_input import Device, Inventory, Obs
from vigie_pipeline.sources import is_randomized

REPORT_FORMAT = "vigie-product-signal-coverage"
RULES_VERSION = "product-signal-v1"
NOTICE = (
    "evidence only: this coverage report does not authorize known-issue notes, trust, groups,"
    " merges or enforcement"
)
# Precedence is the order of this table: the first class whose condition holds wins.
CLASS_REASONS: dict[str, tuple[str, ...]] = {
    "conflicting": ("product_claims_disagree",),
    "product_level": ("fresh_product_claim",),
    "expired": ("product_claim_expired",),
    "generic": ("type_level_service_match", "vendor_without_model", "generic_hint"),
    "oui_only": ("oui_vendor_only", "oui_vendors_differ"),
    "unknown": ("random_mac_oui_ignored", "expired_generic_only", "no_signal"),
}
CLASSES = tuple(CLASS_REASONS)
REASONS = tuple(r for reasons in CLASS_REASONS.values() for r in reasons)
_THRESHOLD = re.compile(r"0\.[0-9]{1,6}|1(?:\.0{1,6})?", re.ASCII)


def parse_threshold(text: str) -> Fraction:
    """Owner usefulness threshold as an exact fraction, 0 < t <= 1, at most 6 decimals."""
    if not isinstance(text, str) or not _THRESHOLD.fullmatch(text) or Fraction(text) == 0:
        raise ValueError("invalid threshold")
    return Fraction(text)


def _norm(value: str) -> str:
    return " ".join(value.split()).casefold()


def _tokens(obs: Obs) -> list[str]:
    """Canonical source tokens for one observation; hostname is never evidence."""
    out = []
    if obs.manufacturer and obs.model:
        out.append(f"{obs.kind}_model")
    elif obs.manufacturer:
        out.append(f"{obs.kind}_vendor")
    if obs.service:
        out.append("mdns_service")
    if obs.ua:
        out.append("ssdp_ua")
    out += [f"dhcp_{f}" for f in ("opt55", "opt60") if getattr(obs, f)]
    return out


def _type_level(macs: Iterable[str], obs: list[Obs], inv: Inventory) -> bool:
    """Reuse services-v1 per MAC: a matched rule is a type hint, never product evidence."""
    for mac in macs:
        services = [
            Observation(mac, o.observed_at, "mdns", o.service)
            for o in obs
            if o.mac == mac and o.kind == "mdns" and o.service
        ]
        if services and classify(services, inv.now, ttl_seconds=inv.ttl_seconds).reason == (
            "matched_rule"
        ):
            return True
    return False


def _classify(members: list[Device], obs: list[Obs], inv: Inventory) -> dict[str, Any]:
    macs = [m for d in members for m in d.macs]
    fresh = [o for o in obs if inv.now < o.observed_at + inv.ttl_seconds]
    expired = [o for o in obs if inv.now >= o.observed_at + inv.ttl_seconds]
    latest: dict[tuple[str, str], float] = {}
    for o in fresh:
        if o.manufacturer and o.model:
            key = (_norm(o.manufacturer), _norm(o.model))
            latest[key] = max(o.observed_at, latest.get(key, o.observed_at))
    expired_claim = any(o.manufacturer and o.model for o in expired)
    generic = [t for o in fresh for t in _tokens(o)]  # model claims already took precedence
    ouis = {_norm(m.oui_vendor) for m in macs if m.oui_vendor and not is_randomized(m.mac)}
    random_oui = any(m.oui_vendor and is_randomized(m.mac) for m in macs)
    sources = sorted({t for o in fresh for t in _tokens(o)} | ({"oui"} if ouis else set()))
    valid_until = min(latest.values()) + inv.ttl_seconds if latest else None
    if len(latest) > 1:
        verdict = ("conflicting", "product_claims_disagree")
    elif latest:
        verdict = ("product_level", "fresh_product_claim")
    elif expired_claim:
        verdict = ("expired", "product_claim_expired")
    elif generic:
        if _type_level([m.mac for m in macs], obs, inv):
            verdict = ("generic", "type_level_service_match")
        elif any(t.endswith("_vendor") for t in generic):
            verdict = ("generic", "vendor_without_model")
        else:
            verdict = ("generic", "generic_hint")
    elif ouis:
        verdict = ("oui_only", "oui_vendors_differ" if len(ouis) > 1 else "oui_vendor_only")
    elif random_oui:
        verdict = ("unknown", "random_mac_oui_ignored")
    elif any(_tokens(o) for o in expired):
        verdict = ("unknown", "expired_generic_only")
    else:
        verdict = ("unknown", "no_signal")
    return {
        "device_id": members[0].id,
        "class": verdict[0],
        "reason": verdict[1],
        "members": sorted(d.id for d in members),
        "mac_count": len(macs),
        "random_mac_count": sum(is_randomized(m.mac) for m in macs),
        "sources": sources,
        "valid_until": valid_until,
    }


def _coverage(numerator: int, denominator: int) -> dict[str, Any]:
    if denominator == 0:
        return {"numerator": 0, "denominator": 0, "ratio": None, "reason": "empty_scope"}
    ratio = round(numerator / denominator, 6)
    return {"numerator": numerator, "denominator": denominator, "ratio": ratio, "reason": None}


def build_report(inv: Inventory, threshold: str | None) -> dict[str, Any]:
    """Coverage report; `threshold` is the owner's value or None (then not evaluated)."""
    limit = None if threshold is None else parse_threshold(threshold)
    by_id = {d.id: d for d in inv.devices}
    groups: dict[str, list[Device]] = {}
    for device in sorted(inv.devices, key=lambda d: d.id):
        groups.setdefault(resolve(dict(inv.active_links), device.id), []).append(device)
    mac_owner = {m.mac: canonical for canonical, ds in groups.items() for d in ds for m in d.macs}
    obs_by_group: dict[str, list[Obs]] = {}
    for o in sorted(inv.observations, key=lambda o: (o.mac, o.observed_at, repr(o))):
        if o.mac in mac_owner:
            obs_by_group.setdefault(mac_owner[o.mac], []).append(o)
    status = {c: by_id[c].status for c in groups}
    devices = []
    for canonical, members in groups.items():
        if status[canonical] == "active":
            ordered = [by_id[canonical], *(d for d in members if d.id != canonical)]
            devices.append(_classify(ordered, obs_by_group.get(canonical, []), inv))
    devices.sort(key=lambda d: d["device_id"])
    by_class = {c: sum(d["class"] == c for d in devices) for c in sorted(CLASSES)}
    coverage = _coverage(by_class["product_level"], len(devices))
    met = None
    if limit is not None and coverage["denominator"]:
        met = coverage["numerator"] * limit.denominator >= limit.numerator * len(devices)
    return {
        "format": REPORT_FORMAT,
        "rules_version": RULES_VERSION,
        "now": inv.now,
        "ttl_seconds": inv.ttl_seconds,
        "authorizes_known_issue_notes": False,
        "notice": NOTICE,
        "coverage": coverage,
        "threshold": {"value": threshold, "met": met},
        "scope": {
            "input_devices": len(inv.devices),
            "in_scope": len(devices),
            "aliases_folded": len(inv.devices) - len(groups),
            "excluded_retired": sum(s == "retired" for s in status.values()),
            "excluded_transient": sum(s == "transient" for s in status.values()),
            "unattributed_observations": sum(o.mac not in mac_owner for o in inv.observations),
        },
        "counts_by_class": by_class,
        "counts_by_reason": {r: sum(d["reason"] == r for d in devices) for r in sorted(REASONS)},
        "devices": devices,
    }


def render(report: dict[str, Any]) -> bytes:
    """Canonical, byte-stable JSON: sorted keys, compact separators, ASCII, trailing newline."""
    text = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return (text + "\n").encode("ascii")
