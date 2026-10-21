"""Collector-side batch cap, following the PRP section 4 truncation order.

leases/neigh/mDNS first; then DNS; then conntrack top-N by bytes with the remainder
folded into one `other` bucket per MAC (byte and flow totals are preserved).
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from typing import Any

Batch = dict[str, Any]


def encoded_size(batch: Batch) -> int:
    return len(json.dumps(batch, separators=(",", ":")).encode())


def _largest_fitting(count: int, fits: Callable[[int], bool]) -> int:
    """Largest n in [0, count] with fits(n); assumes fits is monotone (True then False)."""
    lo, hi = 0, count
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fits(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


def _fold(entries: list[dict[str, Any]], keep: int) -> list[dict[str, Any]]:
    ranked = sorted(
        range(len(entries)),
        key=lambda i: (-(entries[i]["bytes_up"] + entries[i]["bytes_down"]), i),
    )
    kept_idx = set(ranked[:keep])
    kept = [entries[i] for i in sorted(kept_idx)]
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for i, entry in enumerate(entries):
        if i not in kept_idx:
            t = totals[entry["mac"]]
            t[0] += entry["bytes_up"]
            t[1] += entry["bytes_down"]
            t[2] += entry["flows"]
    others = [
        {
            "mac": mac,
            "dst_ip": None,
            "dst_port": None,
            "proto": "other",
            "bytes_up": up,
            "bytes_down": down,
            "flows": flows,
        }
        for mac, (up, down, flows) in sorted(totals.items())
    ]
    return kept + others


def apply_cap(batch: Batch, cap_bytes: int) -> Batch:
    """Return a copy of batch that encodes to <= cap_bytes (or as close as the order allows)."""
    out: Batch = {**batch, "truncated": dict(batch.get("truncated", {}))}
    if encoded_size(out) <= cap_bytes:
        return out
    for key in ("sightings", "neigh", "leases"):
        if out[key]:
            out["truncated"][key] = len(out[key])
            out[key] = []
            if encoded_size(out) <= cap_bytes:
                return out
    if out["dns"]:
        newest = sorted(out["dns"], key=lambda q: q["ts"])
        keep = _largest_fitting(
            len(newest),
            lambda n: encoded_size({**out, "dns": newest[len(newest) - n :]}) <= cap_bytes,
        )
        out["truncated"]["dns"] = len(newest) - keep
        out["dns"] = newest[len(newest) - keep :]
        if encoded_size(out) <= cap_bytes:
            return out
    flows = out["conntrack"]

    def with_keep(n: int) -> Batch:
        # Include the truncated counter: it is part of the encoded size.
        counters = {**out["truncated"], "conntrack": len(flows) - n}
        return {**out, "truncated": counters, "conntrack": _fold(flows, n)}

    keep = _largest_fitting(len(flows), lambda n: encoded_size(with_keep(n)) <= cap_bytes)
    # Size is not strictly monotone in keep (digit counts of the folded totals change).
    while keep > 0 and encoded_size(with_keep(keep)) > cap_bytes:
        keep -= 1
    return with_keep(keep)
