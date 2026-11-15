"""Read side of probes: turn pipeline_meta['probe_status'] into the /probes view.

The stored value is written by the pipeline from an untrusted file, so it is read as hostile data:
bounded size, strict types, bad values dropped (a target with a bad id is dropped whole), nothing
reflected unvalidated. Read-only. Freshness comes from the stored `valid_until` and `written_at`,
never from the pipeline still running.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from vigie_api.models import ProbeTargetOut, probe_number
from vigie_ingest.db import iso_utc

STATUS_KEY = "probe_status"
MAX_STATUS_BYTES = 64 * 1024  # the pipeline writes at most 32 KiB
MAX_TARGETS = 10
FUTURE_SKEW_S = 10.0  # same bound the pipeline applies to the runner's written_at
COLLECTOR_FRESH_S = 900  # the latest observation batch must be this recent for "Vigie sees"
ID_RE = re.compile(r"[a-z0-9_-]{1,32}")


def _clean_targets(raw: Any) -> list[ProbeTargetOut]:
    """At most MAX_TARGETS targets with a valid, unique id; the model drops bad field values."""
    if not isinstance(raw, list):
        return []
    out: list[ProbeTargetOut] = []
    seen: set[str] = set()
    for item in raw:
        ident = item.get("id") if isinstance(item, dict) else None
        if not isinstance(ident, str) or not ID_RE.fullmatch(ident) or ident in seen:
            continue
        seen.add(ident)
        out.append(ProbeTargetOut.model_validate(item, strict=False))
        if len(out) == MAX_TARGETS:
            break
    return out


def _load(inv: sqlite3.Connection) -> Any:
    """The stored status object, None when absent, or {} when present but unusable."""
    row = inv.execute(
        "SELECT length(value), value FROM pipeline_meta WHERE key=?", (STATUS_KEY,)
    ).fetchone()
    if row is None:
        return None
    if row[0] > MAX_STATUS_BYTES:
        return {}
    try:
        doc = json.loads(row[1])
    except (ValueError, RecursionError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _collector_fresh(inv: sqlite3.Connection, now: float) -> bool:
    try:
        row = inv.execute(
            "SELECT MAX(received_at) FROM batches WHERE observation_kind='observation'"
        ).fetchone()
    except sqlite3.Error:
        return False
    return row is not None and row[0] is not None and row[0] >= iso_utc(now - COLLECTOR_FRESH_S)


def verdict(targets: list[ProbeTargetOut], stale: bool, collector_fresh: bool) -> str:
    """The spec's table. Unknown whenever the probe data cannot be trusted or has no dns_local."""
    if stale:
        return "unknown"
    local = [t.state for t in targets if t.kind == "dns_local"]
    if "outage" in local:
        return "router_resolver_down"
    if not local or "unknown" in local:
        return "unknown"
    if not collector_fresh:
        return "vigie_blind"
    if any(t.kind == "dns_upstream" and t.state == "outage" for t in targets):
        return "upstream_unreachable"
    return "normal"


def probes_view(inv: sqlite3.Connection, now: float) -> dict[str, Any]:
    doc = _load(inv)
    if doc is None or doc.get("reason") == "disabled":
        return {
            "enabled": False, "written_at": None, "stale": False, "targets": [],
            "verdict": "unknown",
        }  # fmt: skip
    written_at = probe_number(doc.get("written_at"), integer=True)
    valid_until = probe_number(doc.get("valid_until"))
    stale = (
        doc.get("stale") is not False
        or written_at is None
        or valid_until is None
        or now > valid_until
        or written_at > now + FUTURE_SKEW_S
    )
    targets = _clean_targets(doc.get("targets")) if not doc.get("stale") else []
    if stale:  # an expired "ok" must not be shown as ok
        targets = [t.model_copy(update={"state": "unknown"}) for t in targets]
    return {
        "enabled": True,
        "written_at": written_at,
        "stale": stale,
        "targets": targets,
        "verdict": verdict(targets, stale, not stale and _collector_fresh(inv, now)),
    }
