"""E0 report: `other` byte share, key match ratio (direct and 24 h carryover) and the gate.

Gate (PRP-003 section 10): `other` bytes < 10% of mapped bytes and matched keys >= 90%,
in integer arithmetic. A zero denominator never passes. Output holds counts and class labels
only: no process path, hostname, user id or rule leaves this module.
"""

from __future__ import annotations

import bisect
import json
from collections import Counter
from datetime import UTC, datetime

from . import explain, netutil
from .model import Batch, EventLog, Flow, RouterData, Scope

SCHEMA = "vigie-e0-feasibility/1"
DIRECT_TOLERANCE_S = 120
CARRYOVER_S = 86400
_Key = tuple[str, str, int, int, int]  # dst_ip, proto, dst_port, window_start, window_end


def _attributed(sc: Scope, flow: Flow) -> bool:
    return any(span.covers(flow.mac, flow.ts) for span in sc.macs)


def _row_exclusion(sc: Scope, flow: Flow) -> str | None:
    if flow.dst_ip is None:
        return "other_row"
    if flow.proto not in netutil.ELIGIBLE_PROTOS:
        return "proto_excluded"
    if flow.dst_port is None or flow.dst_port in netutil.EXCLUDED_PORTS:
        return "port_excluded"
    return netutil.dst_exclusion(flow.dst_ip, sc.lan_prefixes, sc.router_ips)


def _join(sc: Scope, router: RouterData) -> tuple[list[tuple[Flow, Batch]], dict[str, int]]:
    seen: set[Flow] = set()
    joined, counts = [], Counter()
    macs = {span.mac for span in sc.macs}
    for flow in router.flows:
        if flow in seen:
            counts["duplicate_rows"] += 1
            continue
        seen.add(flow)
        batch = router.batches.get((flow.collector_id, flow.batch_id))
        if batch is None:
            counts["orphan_rows"] += 1
        elif not _attributed(sc, flow):
            counts["unattributed_rows"] += 1
            counts["out_of_span_rows"] += flow.mac in macs
        else:
            joined.append((flow, batch))
    names = ("duplicate_rows", "orphan_rows", "unattributed_rows", "out_of_span_rows")
    return joined, {"rows": len(router.flows), **{n: counts[n] for n in names}}


def _other_share(joined: list[tuple[Flow, Batch]]) -> dict:
    total = other = flows = other_flows = degraded = 0
    for flow, batch in joined:
        size = flow.bytes_up + flow.bytes_down
        total += size
        flows += flow.flows
        if flow.dst_ip is None:
            other += size
            other_flows += flow.flows
        if batch.reasons:
            degraded += size
    return {
        "other_bytes": other,
        "mapped_bytes": total,
        "other_flows": other_flows,
        "mapped_flows": flows,
        "degraded_bytes": degraded,
        "share_ppm": other * 1_000_000 // total if total else None,
    }


def _keys(sc: Scope, joined: list[tuple[Flow, Batch]]) -> tuple[set[_Key], dict[str, int]]:
    eligible: set[_Key] = set()
    excluded: dict[str, set] = {}
    for flow, batch in joined:
        key = (flow.dst_ip, flow.proto, flow.dst_port, batch.start, batch.end)
        reason = _row_exclusion(sc, flow) or (batch.reasons[0] if batch.reasons else None)
        if reason is None:
            eligible.add(key)  # type: ignore[arg-type]
        else:
            excluded.setdefault(reason, set()).add(key)
    return eligible, {reason: len(keys) for reason, keys in sorted(excluded.items())}


def _index(log: EventLog) -> dict[tuple[str, str, int], list[int]]:
    out: dict[tuple[str, str, int], list[int]] = {}
    for ev in log.events:  # already sorted by time
        out.setdefault((ev.dst_ip, ev.proto, ev.dst_port), []).append(ev.t)
    return out


def _any_in(times: list[int], low: int, high: int) -> bool:
    """True when some time t satisfies low <= t <= high."""
    i = bisect.bisect_left(times, low)
    return i < len(times) and times[i] <= high


def _bucket() -> dict[str, dict[str, int]]:
    names = ("direct", "carryover_only", "combined")
    return {n: {"matched": 0, "denominator": 0} for n in names}


def _match(sc: Scope, keys: set[_Key], log: EventLog) -> dict:
    index = _index(log)
    if sc.export_start is not None:
        export_start = sc.export_start
    else:
        export_start = log.events[0].t if log.events else sc.period_start
    buckets = {"gated": _bucket(), "warm_up": _bucket()}
    unmatched: Counter[str] = Counter()
    for dst, proto, port, start, end in sorted(keys):
        times = index.get((dst, proto, port), [])
        direct = _any_in(times, start - DIRECT_TOLERANCE_S, end + DIRECT_TOLERANCE_S)
        carry = not direct and _any_in(times, start - CARRYOVER_S, start - DIRECT_TOLERANCE_S - 1)
        name = "warm_up" if start - CARRYOVER_S < export_start else "gated"
        for part, hit in (
            ("direct", direct),
            ("carryover_only", carry),
            ("combined", direct or carry),
        ):
            buckets[name][part]["denominator"] += 1
            buckets[name][part]["matched"] += hit
        if name == "gated" and not (direct or carry):
            unmatched[f"ipv{netutil.parse_ip(dst).version}_{proto}"] += 1  # type: ignore[union-attr]
    return {
        **buckets,
        "eligible_keys": len(keys),
        "export_start": export_start,
        "unmatched_by_class": dict(sorted(unmatched.items())),
        "ipv6_keys": sum(1 for k in keys if ":" in k[0]),
    }


def _events(log: EventLog, mapped_bytes: int) -> dict:
    hosts: dict[str, set[str]] = {}
    for ev in log.events:
        if ev.dst_host:
            hosts.setdefault(ev.dst_ip, set()).add(ev.dst_host)
    per_day = Counter(f"{datetime.fromtimestamp(ev.t, UTC):%Y-%m-%d}" for ev in log.events)
    return {
        "read": log.read,
        "accepted": log.accepted,
        "duplicates": log.duplicates,
        "rejected": dict(log.rejected),
        "no_app_identity": log.no_app_identity,
        "shared_destinations": sum(1 for names in hosts.values() if len(names) > 1),
        "distinct_src_ips": len({ev.src_ip for ev in log.events}),
        "per_day": dict(sorted(per_day.items())),
        "bytes_per_event": mapped_bytes // log.accepted if log.accepted else None,
    }


def _batches(router: RouterData) -> dict:
    by_reason: Counter[str] = Counter()
    for batch in router.batches.values():
        by_reason.update(batch.reasons)
    clean = sum(1 for b in router.batches.values() if not b.reasons)
    return {
        "total": len(router.batches),
        "clean": clean,
        "by_reason": dict(sorted(by_reason.items())),
    }


def _gate(share: dict, gated: dict) -> dict:
    reasons = []
    other, mapped = share["other_bytes"], share["mapped_bytes"]
    if mapped == 0:
        reasons.append("zero_mapped_bytes")
    elif other * 10 >= mapped:
        reasons.append("other_share_at_or_above_10pct")
    matched, keys = gated["combined"]["matched"], gated["combined"]["denominator"]
    if keys == 0:
        reasons.append("zero_gated_keys")
    elif matched * 10 < 9 * keys:
        reasons.append("match_ratio_below_90pct")
    if any(r.startswith("zero_") for r in reasons):
        verdict = "no_result"
    else:
        verdict = "no_go" if reasons else "go"
    return {
        "verdict": verdict,
        "reasons": reasons,
        "match_rule": "direct_or_carryover_post_warm_up",
    }


def build_report(sc: Scope, router: RouterData, log: EventLog) -> dict:
    joined, flow_counts = _join(sc, router)
    share = _other_share(joined)
    keys, excluded = _keys(sc, joined)
    match = {**_match(sc, keys, log), "excluded_keys": excluded}
    out = {
        "schema": SCHEMA,
        "device_id": sc.device_id,
        "period": {"start": sc.period_start, "end": sc.period_end},
        "assumptions": {
            "direct_tolerance_s": DIRECT_TOLERANCE_S,
            "carryover_s": CARRYOVER_S,
            "skew_s": sc.skew_s,
            "time_basis": "endpoint time minus skew_s against router window bounds",
        },
        "other_share": share,
        "match": match,
        "flows": {**flow_counts, "missing_shards": list(router.missing_shards)},
        "events": _events(log, share["mapped_bytes"]),
        "batches": _batches(router),
        "attribution": {"mac_spans": len(sc.macs), "distinct_macs": len({m.mac for m in sc.macs})},
        "gate": _gate(share, match["gated"]),
    }
    return {**out, "explanations": explain.explanations(sc, out)}


def render(report: dict) -> str:
    return json.dumps(report, sort_keys=True, indent=2) + "\n"
