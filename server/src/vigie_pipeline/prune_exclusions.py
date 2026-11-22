"""Inventory-side rows that name a retired device or MAC: while any exists, its MAC rows are not
pruned. Deleting the observation would change what the other table's key resolves to (a
monitoring lineage key reads only the device's current MACs), so the pruner must leave it alone.

Decided history does not pin forever, because neither table is ever deleted from. A candidate
blocks while it is `open` or `suggested`, or in a state this build does not know (one that cannot be
shown safe stays excluding). `dismissed`, `vetoed` and `cleared` do not: a veto is keyed by device
id (`vetoed_between`) and the row survives the MAC rows, and what the owner decided about a pair
lives in overrides.db (`candidate_decisions`, `identity_merges`, both ends in `PROTECTED_READS`), so
a device with such a decision is protected there whatever this table says. An `open` or `suggested`
candidate on a retired device settles when a rule settles one of its MACs
(`dismiss_open_candidates`) or fresh evidence rewrites it; one that neither happens to keeps the
device's MAC rows for good (accepted: the cost is a few rows, never a wrong deletion).

A suggestion blocks while it is unexpired (`expires_at`), whatever its action, and for good once
the owner decided it: that decision lives in overrides.db keyed by suggestion id
(`suggestion_decisions`), so `suggestion_devices` turns the decided ids into the devices their
inventory rows name, and the prune protects those like any other decision (accepted merges are
also protected through `identity_merges`).

Every probe is a point or index-prefix seek, never a scan: the collector set is tiny and each
collector-keyed table leads its key with collector_id (the `_MEASURED` pattern of
new_device_notice.py). The fragment is spliced into the candidate SELECT of the DELETE itself, so
it is evaluated at delete time inside the same transaction. Collector rows are never deleted;
a monitoring row naming an unknown collector would not be seen (accepted, nothing writes one)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Collection

from vigie_pipeline.overrides import OverridesNotUsable

# (table, column) pairs keyed collector_id first, then the device id / the MAC.
_DEVICE_BY_COLLECTOR = (
    ("monitoring_profiles", "device_id"),
    ("monitoring_incidents", "device_id"),
    ("monitoring_suspicious", "device_id"),
    ("monitoring_unavailable", "device_id"),
)
_MAC_BY_COLLECTOR = (
    ("measurements_hourly", "mac"),
    ("monitoring_dirty", "mac"),
    ("essential_activity", "mac"),
)
LIVE_SUGGESTION_PARAMS = 2  # the one bound `expires_at>=?` per suggestion direction
# suggestions.action is CHECK-constrained to exactly these; the id indexes lead with action.
_SUGGESTION_ACTIONS = "('label','move_group','quarantine','merge_identity')"


# candidate states that no longer pin a device (see above); every other state does
_SETTLED = "('dismissed','vetoed','cleared')"
SUGGESTION_ID_CHUNK = 500  # ids per IN list, under SQLite's bound-variable limit


def _devices_of(raw: object) -> set[str]:
    try:
        parsed = json.loads(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise OverridesNotUsable("a decided suggestion's device list cannot be read") from exc
    if not isinstance(parsed, list) or not all(isinstance(d, str) and d for d in parsed):
        raise OverridesNotUsable("a decided suggestion's device list is not a list of ids")
    return set(parsed)


def suggestion_devices(inv: sqlite3.Connection, suggestion_ids: Collection[str]) -> set[str]:
    """The devices named by the inventory rows of these decided suggestions, whatever their
    action and whether or not they expired (a primary-key lookup per id). A decided id with no
    row names nothing; a row whose device list cannot be read fails the prune closed."""
    ids = sorted(suggestion_ids)
    devices: set[str] = set()
    for start in range(0, len(ids), SUGGESTION_ID_CHUNK):
        chunk = ids[start : start + SUGGESTION_ID_CHUNK]
        marks = ",".join("?" * len(chunk))
        for (raw,) in inv.execute(
            f"SELECT device_ids FROM suggestions WHERE id IN ({marks})",  # noqa: S608
            chunk,
        ):
            devices |= _devices_of(raw)
    return devices


def _by_collector(table: str, column: str, key: str) -> str:
    return (
        "EXISTS (SELECT 1 FROM collectors c WHERE EXISTS"  # noqa: S608
        f" (SELECT 1 FROM {table} x WHERE x.collector_id=c.id AND x.{column}={key}))"
    )


def _clauses() -> tuple[str, ...]:
    return (
        "EXISTS (SELECT 1 FROM identity_candidates"  # noqa: S608
        f" WHERE device_a=d.id AND state NOT IN {_SETTLED})",
        "EXISTS (SELECT 1 FROM identity_candidates"  # noqa: S608
        f" WHERE device_b=d.id AND state NOT IN {_SETTLED})",
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
