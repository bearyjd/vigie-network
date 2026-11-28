"""The unattributed-LAN-bytes rule, shared by coverage and essential-absence evidence.

It lives in ingest because ingest must not import the pipeline; the pipeline imports it from here.
"""

from __future__ import annotations

# ct_lan_unmapped_flows counts LAN-prefix sources without a MAC: informational, never a defect.
LAN_UNMAPPED_FLOWS_KEY = "ct_lan_unmapped_flows"
# ct_lan_unmapped_bytes (LAN-prefix sources with no MAC: a genuine attribution failure) is governed
# by a threshold instead of presence. It is handled separately and must not hit the generic rule.
LAN_UNMAPPED_BYTES_KEY = "ct_lan_unmapped_bytes"
# Distinct reason for the threshold trip (attribution trouble), not a collector fault.
LAN_UNMAPPED_REASON = "lan_unmapped_share"
# The hour is disqualified (`lan_unmapped_share`) only when BOTH hold; at or below either bound
# it qualifies. Both numbers are PER WINDOW and the share is collector-wide: see docs/monitoring.md.
# Floor per window: a quiet hour must not be disqualified by a few KB of unattributed traffic.
LAN_UNMAPPED_MIN_BYTES = 262144  # 256 KiB
# Share of all conntrack bytes (mapped + LAN-unmapped). A read-only router snapshot showed
# unmapped-but-LAN traffic at ~0.02% of bytes, so 5% leaves a ~250x margin. Policy number, to be
# tuned on real data.
LAN_UNMAPPED_MAX_SHARE_PCT = 5
MAX_VALUE = (2**63 - 1) // 64  # at most64 canonical MACs can be summed safely


def lan_unmapped_reason(value: object, counters: dict, overflowed: bool) -> str | None:
    """Reason ct_lan_unmapped_bytes degrades the hour, or None. Fails closed on any doubt.

    `counters` maps each MAC to its (bytes_up, bytes_down, ...) totals for the window, and
    `overflowed` says a per-MAC total passed MAX_VALUE. A malformed value or uncomputable totals
    is a data fault (`flow_degraded`); only the policy threshold itself reports the distinct
    `lan_unmapped_share`, so operators can tell attribution trouble from a collector fault.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or overflowed:
        return "flow_degraded"
    if value <= LAN_UNMAPPED_MIN_BYTES:
        return None
    mapped = sum(v[0] + v[1] for v in counters.values())
    if value * 100 > LAN_UNMAPPED_MAX_SHARE_PCT * (mapped + value):
        return LAN_UNMAPPED_REASON
    return None
