"""Read-only feeds: the event union (inventory events + audit_log) and suggestions."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from vigie_api.effective import decode_cursor, encode_cursor, rows
from vigie_api.errors import ApiError

# LLM/ML prose is never shown for actions that change trust (PRP section 7).
PROSE_SUPPRESSED = frozenset({"move_group", "quarantine", "merge_identity"})
SUGGESTION_STATES = ("pending", "accepted", "rejected", "expired")


def _split_cursor(cursor: str | None) -> tuple[str, str]:
    if not cursor:
        return "", ""
    ts, sep, event_id = decode_cursor(cursor).partition("|")
    if not sep:
        raise ApiError(422, "invalid_cursor", "malformed cursor")
    return ts, event_id


def _inventory_events(inv, ts, eid, kind, severity, limit) -> list[dict[str, Any]]:
    sql = (
        "SELECT id, device_id, ts, kind, severity, summary FROM events"
        " WHERE (ts > ? OR (ts = ? AND id > ?))"
    )
    params: list[Any] = [ts, ts, eid]
    if kind:
        sql, params = sql + " AND kind = ?", [*params, kind]
    if severity:
        sql, params = sql + " AND severity = ?", [*params, severity]
    found = rows(inv, sql + " ORDER BY ts, id LIMIT ?", (*params, limit))
    return [{**dict(r), "source": "inventory"} for r in found]


def _audit_events(ov, ts, eid, kind, severity, limit) -> list[dict[str, Any]]:
    if severity not in (None, "info"):  # human actions are always informational
        return []
    sql = (
        "SELECT id, target, ts, principal, action FROM audit_log"
        " WHERE (ts > ? OR (ts = ? AND id > ?))"
    )
    params: list[Any] = [ts, ts, eid]
    if kind:
        sql, params = sql + " AND action = ?", [*params, kind]
    found = rows(ov, sql + " ORDER BY ts, id LIMIT ?", (*params, limit))
    return [
        {
            "id": r["id"],
            "device_id": r["target"],
            "ts": r["ts"],
            "kind": r["action"],
            "severity": "info",
            "summary": f"{r['principal']} {r['action']} {r['target'] or ''}".strip(),
            "source": "audit",
        }
        for r in found
    ]


def list_events(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    *,
    since: str | None,
    kind: str | None,
    severity: str | None,
    limit: int,
) -> tuple[list[dict[str, Any]], str | None]:
    """Oldest-first; `next_cursor` is the resume point (last item), echoing `since` if empty."""
    ts, eid = _split_cursor(since)
    merged = _inventory_events(inv, ts, eid, kind, severity, limit)
    merged += _audit_events(ov, ts, eid, kind, severity, limit)
    merged.sort(key=lambda e: (e["ts"], e["id"]))
    page = merged[:limit]
    if not page:
        return [], since
    last = page[-1]
    return page, encode_cursor(f"{last['ts']}|{last['id']}")


def _suggestion(row: sqlite3.Row, decision: sqlite3.Row | None, now_iso: str) -> dict[str, Any]:
    if decision is not None:
        state = decision["state"]
    elif now_iso > row["expires_at"]:
        state = "expired"
    else:
        state = "pending"
    return {
        "id": row["id"],
        "action": row["action"],
        "device_ids": json.loads(row["device_ids"]),
        "payload": json.loads(row["payload"]),
        "reason_code": row["reason_code"],
        "reason_text": None if row["action"] in PROSE_SUPPRESSED else row["reason_text"],
        "basis": json.loads(row["basis"]),
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "state": state,
        "decided_by": decision["decided_by"] if decision else None,
        "decided_at": decision["decided_at"] if decision else None,
    }


def list_suggestions(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    *,
    now_iso: str,
    state: str | None,
    cursor: str | None,
    limit: int,
) -> tuple[list[dict[str, Any]], str | None]:
    after = decode_cursor(cursor) if cursor else ""
    decisions = {r["suggestion_id"]: r for r in rows(ov, "SELECT * FROM suggestion_decisions")}
    out: list[dict[str, Any]] = []
    more = False
    for row in rows(inv, "SELECT * FROM suggestions WHERE id > ? ORDER BY id", (after,)):
        item = _suggestion(row, decisions.get(row["id"]), now_iso)
        if state is not None and item["state"] != state:
            continue
        if len(out) == limit:
            more = True
            break
        out.append(item)
    return out, (encode_cursor(out[-1]["id"]) if more else None)
