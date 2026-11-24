"""Fixed explanation texts for the E0 report. Codes are stable; texts never carry event values."""

from __future__ import annotations

from .model import Scope

TEXTS = {
    "key_level_match": "Matching is per (device, dst IP, proto, port, window) key, not per "
    "connection: router `flows` is a max of live flows and the router has no source port.",
    "degraded_coverage": "Some batch windows were degraded (truncation, dropped batches, missing "
    "health, cross-hour or probe); their keys are excluded from the match denominators and their "
    "bytes are still counted in the share (`degraded_bytes`).",
    "legacy_windows": "Some batches have no window bounds (legacy). Their keys cannot be placed "
    "in time and are excluded; their bytes stay in the share.",
    "warm_up": "Keys whose 24 h carryover lookback starts before the export began are reported "
    "under `warm_up`, apart from the gated denominator, and must also reach the 90% ratio.",
    "attribution_changed": "The device's attribution changed in the period (several scoped MACs, "
    "rows from a scoped MAC outside its validity span, or several endpoint source IPs).",
    "zero_denominator": "A gate denominator is zero, so the gate gives no result, never a pass.",
    "skew_assumed_zero": "No endpoint clock skew was supplied; endpoint times are used as is. "
    "Skew beyond the 120 s tolerance moves keys from direct to carryover or to unmatched.",
    "skew_supplied": "Endpoint times were corrected by the supplied skew_s.",
    "events_rejected": "Some endpoint events were rejected; see `events.rejected` by reason.",
    "duplicate_events": "Duplicate endpoint events (same host, time, proto, addresses and ports) "
    "were collapsed.",
    "nat_or_off_lan_sources": "Some events had a source address off the declared LAN (container "
    "or VM NAT, VPN); they are excluded. NAT'd traffic seen by the router stays unmatched.",
    "shared_destinations": "Some destination IPs carried several hostnames (shared or CDN "
    "hosting); a key match does not identify the program or the site.",
    "tls_without_app_identity": "Some events had no destination hostname (for example TLS "
    "without a name); they still count as reported.",
    "ipv6_keys": "IPv6 keys are included; addresses are compared in canonical form.",
    "orphan_flow_rows": "Some raw_flow rows had no accepted batch with the same collector and "
    "batch ID; their bytes count in the share (`orphan_bytes`), but they give no match keys.",
    "duplicate_flow_rows": "Exact duplicate raw_flow rows were collapsed before counting bytes.",
    "raw_shard_missing": "One or more raw shard days were missing. A missing day inside the "
    "period gives no result; only the day after a midnight-aligned period end is exempt.",
    "export_ends_before_period_end": "The last accepted endpoint event is before the period "
    "end, so the export may not cover the end of the period and late keys can stay unmatched. "
    "This is an explanation, not a gate.",
    "clean_window_scope": "A window counts as clean from its own batch row only. The pipeline's "
    "raw_missing check, its collector-wide ct_lan_unmapped_bytes share and overlapping windows "
    "are not re-derived here; missing shard days are reported instead.",
}


def explanations(sc: Scope, out: dict) -> list[dict[str, str]]:
    match, events, flows = out["match"], out["events"], out["flows"]
    reasons = out["batches"]["by_reason"]
    rejected = events["rejected"]
    on = {
        "key_level_match": True,
        "clean_window_scope": True,
        "export_ends_before_period_end": events["last_accepted_t"] is None
        or events["last_accepted_t"] < sc.period_end,
        "degraded_coverage": any(r != "legacy_window" for r in reasons),
        "legacy_windows": "legacy_window" in reasons,
        "warm_up": match["warm_up"]["combined"]["denominator"] > 0,
        "attribution_changed": out["attribution"]["distinct_macs"] > 1
        or flows["out_of_span_rows"] > 0
        or events["distinct_src_ips"] > 1,
        "zero_denominator": any(r.startswith("zero_") for r in out["gate"]["reasons"]),
        "skew_assumed_zero": not sc.skew_supplied,
        "skew_supplied": sc.skew_supplied,
        "events_rejected": bool(rejected),
        "duplicate_events": events["duplicates"] > 0,
        "nat_or_off_lan_sources": rejected.get("src_off_lan", 0) > 0,
        "shared_destinations": events["shared_destinations"] > 0,
        "tls_without_app_identity": events["no_app_identity"] > 0,
        "ipv6_keys": match["ipv6_keys"] > 0,
        "orphan_flow_rows": flows["orphan_rows"] > 0,
        "duplicate_flow_rows": flows["duplicate_rows"] > 0,
        "raw_shard_missing": bool(flows["missing_shards"]),
    }
    return [{"code": code, "text": TEXTS[code]} for code in sorted(c for c, v in on.items() if v)]
