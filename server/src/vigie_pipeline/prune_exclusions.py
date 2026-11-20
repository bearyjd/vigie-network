"""Inventory-side rows that name a retired device or MAC: while any exists, its MAC rows are not
pruned. Deleting the observation would change what the other table's key resolves to (a
monitoring lineage key reads only the device's current MACs), so the pruner must leave it alone.

Decided history does not pin forever, because neither table is ever deleted from. A candidate
blocks in every state but `dismissed` (open, suggested, vetoed, cleared, or one this build does not
know: a state that cannot be shown safe stays excluding). A dismissed row is the pipeline's
memory of a closed pair; what the owner decided about the pair lives in overrides.db
(`candidate_decisions`, `identity_merges`, both ends in `PROTECTED_READS`), so a device with such a
decision is protected there whatever this table says. A suggestion blocks only while unexpired
(`expires_at` is the only state it has: decisions are keyed by suggestion id in overrides.db, and
the suggestion row itself is never deleted, so an expired one's decision stays attached to it; an
accepted merge is protected through `identity_merges`).

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
LIVE_SUGGESTION_PARAMS = 2  # the one bound `expires_at>=?` per suggestion direction
# suggestions.action is CHECK-constrained to exactly these; the id indexes lead with action.
_SUGGESTION_ACTIONS = "('label','move_group','quarantine','merge_identity')"


def _by_collector(table: str, column: str, key: str) -> str:
    return (
        "EXISTS (SELECT 1 FROM collectors c WHERE EXISTS"  # noqa: S608
        f" (SELECT 1 FROM {table} x WHERE x.collector_id=c.id AND x.{column}={key}))"
    )


def _clauses() -> tuple[str, ...]:
    return (
        "EXISTS (SELECT 1 FROM identity_candidates WHERE device_a=d.id AND state<>'dismissed')",
        "EXISTS (SELECT 1 FROM identity_candidates WHERE device_b=d.id AND state<>'dismissed')",
        # the unary + drops d.id's column affinity, which would otherwise hide the index expression
        # naming expires_at lets the planner walk idx_suggestions_pair instead: pin the seek
        "EXISTS (SELECT 1 FROM suggestions INDEXED BY idx_suggestions_from_id"  # noqa: S608
        f" WHERE action IN {_SUGGESTION_ACTIONS}"
        " AND json_extract(device_ids, '$[0]')=+d.id AND expires_at>=?)",
        f"EXISTS (SELECT 1 FROM suggestions WHERE action IN {_SUGGESTION_ACTIONS}"  # noqa: S608
        " AND json_extract(device_ids, '$[1]')=+d.id AND expires_at>=?)",
        *(_by_collector(t, c, "d.id") for t, c in _DEVICE_BY_COLLECTOR),
        *(_by_collector(t, c, "o.mac") for t, c in _MAC_BY_COLLECTOR),
        "EXISTS (SELECT 1 FROM rule_attachments r WHERE r.mac=o.mac)",
    )


# " AND NOT (..) AND NOT (..)" over aliases d (devices) and o (observations); binds
# LIVE_SUGGESTION_PARAMS times the ISO instant a suggestion must still be live at.
PRUNE_EXCLUSIONS_SQL = "".join(f" AND NOT {clause}" for clause in _clauses())
