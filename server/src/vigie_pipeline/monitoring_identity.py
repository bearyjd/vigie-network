"""Read-only bounded identity lineage for monitoring; contains no trust/override mutations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from vigie_pipeline.overrides import link_sources, link_target

MAX_MACS = 64
MAX_ALIASES = 256


class LineageUnavailable(ValueError):
    pass


@dataclass(frozen=True)
class Lineage:
    device_id: str
    macs: tuple[str, ...]
    key: str
    versioned: bool
    rule_attached: bool


def has_table(db, name):
    return (
        db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
        is not None
    )


def lineage(inv, ov, device):
    if ov is not None and not has_table(ov, "monitoring_lineage_versions"):
        raise LineageUnavailable("monitoring identity migration missing")
    seen = set()
    canonical = device
    while ov is not None:
        if canonical in seen or len(seen) >= MAX_ALIASES:
            raise LineageUnavailable("identity graph is invalid or too large")
        seen.add(canonical)
        target = link_target(ov, canonical)
        if target is None:
            break
        canonical = target
    members = {canonical}
    queue = [canonical]
    while queue and ov is not None:
        current = queue.pop()
        for source in link_sources(ov, current):
            if source not in members:
                members.add(source)
                queue.append(source)
                if len(members) > MAX_ALIASES:
                    raise LineageUnavailable("identity component is too large")
    marks = ",".join("?" for _ in members)
    rows = inv.execute(
        f"SELECT mac,device_id,link_source,link_rule_id FROM observations "  # noqa: S608
        f"WHERE device_id IN ({marks}) "  # noqa: S608
        "ORDER BY mac LIMIT 65",
        tuple(sorted(members)),
    ).fetchall()  # noqa: S608
    if len(rows) > MAX_MACS:
        raise LineageUnavailable("device has too many MACs for monitoring")
    versioned = has_table(inv, "monitoring_assignment_versions") and (
        ov is None or has_table(ov, "monitoring_lineage_versions")
    )
    link_versions = []
    assignments = []
    if versioned:
        if ov is not None:
            link_versions = [
                tuple(row)
                for row in ov.execute(
                    f"SELECT device_id,version FROM monitoring_lineage_versions "  # noqa: S608
                    f"WHERE device_id IN ({marks}) ORDER BY device_id",  # noqa: S608
                    tuple(sorted(members)),
                )
            ]  # noqa: S608
        for row in rows:
            version = inv.execute(
                "SELECT version FROM monitoring_assignment_versions WHERE mac=?", (row["mac"],)
            ).fetchone()
            assignments.append((*tuple(row), version[0] if version else 0))
    else:
        assignments = [tuple(row) for row in rows]
    key = hashlib.sha256(
        json.dumps(
            [canonical, sorted(members), link_versions, assignments], separators=(",", ":")
        ).encode()
    ).hexdigest()
    return Lineage(
        canonical,
        tuple(row["mac"] for row in rows),
        key,
        versioned,
        any(row["link_source"] == "rule" for row in rows),
    )
