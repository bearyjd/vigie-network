"""Read-only feeds: the event union (inventory events + audit_log) and suggestions."""

from __future__ import annotations

import heapq
import json
import sqlite3
from itertools import islice
from typing import Any

from vigie_api.effective import PROSE_ALLOWED_ACTIONS, decode_cursor, encode_cursor, rows
from vigie_api.errors import ApiError

SUGGESTION_STATES = ("pending", "accepted", "rejected", "expired")


_CURSOR_KEYS = ("inv", "audit")
_MAX_ROWID = 2**63 - 1


def _decode_event_cursor(cursor: str | None) -> dict[str, int]:
    """Opaque `{"inv": <events.rowid>, "audit": <audit_log.rowid>}`; anything else is a 400."""
    if not cursor:
        return dict.fromkeys(_CURSOR_KEYS, 0)
    try:
        raw = json.loads(decode_cursor(cursor))
    except ValueError as exc:
        raise ApiError(400, "invalid_cursor", "malformed cursor") from exc
    valid = isinstance(raw, dict) and set(raw) <= set(_CURSOR_KEYS)
    valid = valid and all(
        type(v) is int and 0 <= v <= _MAX_ROWID  # noqa: E721 - bool is not a rowid
        for v in raw.values()
    )
    if not valid:
        raise ApiError(400, "invalid_cursor", "malformed cursor")
    return {key: raw.get(key, 0) for key in _CURSOR_KEYS}


def _inventory_events(inv, after, kind, severity, limit) -> list[dict[str, Any]]:
    sql = (
        "SELECT rowid AS rid, id, device_id, ts, kind, severity, summary FROM events"
        " WHERE rowid > ?"
    )
    params: list[Any] = [after]
    if kind:
        sql, params = sql + " AND kind = ?", [*params, kind]
    if severity:
        sql, params = sql + " AND severity = ?", [*params, severity]
    found = rows(inv, sql + " ORDER BY rowid LIMIT ?", (*params, limit))
    return [{**dict(r), "source": "inventory"} for r in found]


def _audit_events(ov, after, kind, severity, limit) -> list[dict[str, Any]]:
    if severity not in (None, "info"):  # human actions are always informational
        return []
    sql = "SELECT rowid AS rid, id, target, ts, principal, action FROM audit_log WHERE rowid > ?"
    params: list[Any] = [after]
    if kind:
        sql, params = sql + " AND action = ?", [*params, kind]
    found = rows(ov, sql + " ORDER BY rowid LIMIT ?", (*params, limit))
    return [
        {
            "rid": r["rid"],
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
    """Paginate on insertion order (rowid per source); `ts` is for display only.

    A late-arriving row can carry an older `ts` than rows already served, so a (ts, id) cursor
    would skip it. The page is the merge of both sources' rowid-ordered streams (so it is always
    a rowid prefix per source), re-sorted by ts for display. `next_cursor` is the resume point
    (the last included rowid per source); an empty page echoes `since`.
    """
    cursor = _decode_event_cursor(since)
    streams = [
        _inventory_events(inv, cursor["inv"], kind, severity, limit),
        _audit_events(ov, cursor["audit"], kind, severity, limit),
    ]
    page = list(islice(heapq.merge(*streams, key=lambda e: (e["ts"], e["id"])), limit))
    if not page:
        return [], since
    resume = dict(cursor)
    for event in page:
        key = "inv" if event["source"] == "inventory" else "audit"
        resume[key] = max(resume[key], event["rid"])
    page.sort(key=lambda e: (e["ts"], e["id"]))
    token = encode_cursor(json.dumps(resume, sort_keys=True, separators=(",", ":")))
    return [{k: v for k, v in e.items() if k != "rid"} for e in page], token


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
        # LLM/ML prose is shown for allowlisted actions only (PRP section 7)
        "reason_text": row["reason_text"] if row["action"] in PROSE_ALLOWED_ACTIONS else None,
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
