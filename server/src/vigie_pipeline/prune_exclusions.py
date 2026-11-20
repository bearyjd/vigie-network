"""Inventory-side rows that name a retired device or MAC: while any exists, its MAC rows are not
pruned. Deleting the observation would change what the other table's key resolves to (a
monitoring lineage key reads only the device's current MACs), so the pruner must leave it alone.

Every probe is a point or index-prefix seek, never a scan: the collector set is tiny and each
collector-keyed table leads its key with collector_id (the `_MEASURED` pattern of
new_device_notice.py). The fragment is spliced into the candidate SELECT of the DELETE itself, so
it is evaluated at delete time inside the same transaction. Collector rows are never deleted;
a monitoring row naming an unknown collector would not be seen (accepted, nothing writes one)."""

from __future__ import annotations

# (table, column) pairs keyed collector_id first, then the device id / the MAC.
_DEVICE_BY_COLLECTOR = (
    ("monitoring_profiles", "device_id"),
    ("monitoring_incidents", "device_id"),
    ("monitoring_suspicious", "device_id"),
    ("monitoring_unavailable", "device_id"),
)
_MAC_BY_COLLECTOR = (("measurements_hourly", "mac"), ("monitoring_dirty", "mac"))
# suggestions.action is CHECK-constrained to exactly these; the id indexes lead with action.
_SUGGESTION_ACTIONS = "('label','move_group','quarantine','merge_identity')"


def _by_collector(table: str, column: str, key: str) -> str:
    return (
        "EXISTS (SELECT 1 FROM collectors c WHERE EXISTS"  # noqa: S608
        f" (SELECT 1 FROM {table} x WHERE x.collector_id=c.id AND x.{column}={key}))"
    )


def _clauses() -> tuple[str, ...]:
    return (
        "EXISTS (SELECT 1 FROM identity_candidates WHERE device_a=d.id)",
        "EXISTS (SELECT 1 FROM identity_candidates WHERE device_b=d.id)",
        # the unary + drops d.id's column affinity, which would otherwise hide the index expression
        f"EXISTS (SELECT 1 FROM suggestions WHERE action IN {_SUGGESTION_ACTIONS}"  # noqa: S608
        " AND json_extract(device_ids, '$[0]')=+d.id)",
        f"EXISTS (SELECT 1 FROM suggestions WHERE action IN {_SUGGESTION_ACTIONS}"  # noqa: S608
        " AND json_extract(device_ids, '$[1]')=+d.id)",
        *(_by_collector(t, c, "d.id") for t, c in _DEVICE_BY_COLLECTOR),
        *(_by_collector(t, c, "o.mac") for t, c in _MAC_BY_COLLECTOR),
        "EXISTS (SELECT 1 FROM rule_attachments r WHERE r.mac=o.mac)",
    )


# " AND NOT (..) AND NOT (..)" over aliases d (devices) and o (observations).
PRUNE_EXCLUSIONS_SQL = "".join(f" AND NOT {clause}" for clause in _clauses())
