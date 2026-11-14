"""Read-only feeds: the event union (inventory events + audit_log) and suggestions."""

from __future__ import annotations

import heapq
import json
import sqlite3
from itertools import islice
from typing import Any

from vigie_api.effective import PROSE_ALLOWED_ACTIONS, decode_cursor, encode_cursor, rows
from vigie_api.errors import ApiError
from vigie_api.evidence_redact import LEVELS
from vigie_api.evidence_writes import AUDIT_ACTION
from vigie_api.textsafe import PROSE_MAX, display_json, display_text

SUGGESTION_STATES = ("pending", "accepted", "rejected", "expired")


_CURSOR_KEYS = ("inv", "audit")
_MAX_ROWID = 2**63 - 1


def _decode_event_cursor(cursor: str | None, newest_first: bool = False) -> dict[str, Any]:
    """Opaque `{"inv": <events.rowid>, "audit": <audit_log.rowid>}`; anything else is a 400.

    Ascending cursors are the resume points (rowid > value, absent = 0). Newest-first cursors
    carry `"dir": "desc"` and are the lowest rowid served per source (rowid < value, absent =
    unbounded), so a cursor can never be replayed in the other order.
    """
    if not cursor:
        return {} if newest_first else dict.fromkeys(_CURSOR_KEYS, 0)
    try:
        raw = json.loads(decode_cursor(cursor))
    except ValueError as exc:
        raise ApiError(400, "invalid_cursor", "malformed cursor") from exc
    allowed = {*_CURSOR_KEYS, "dir"} if newest_first else set(_CURSOR_KEYS)
    valid = isinstance(raw, dict) and set(raw) <= allowed
    valid = valid and (raw.get("dir") == "desc" if newest_first else True)
    valid = valid and all(
        type(v) is int and 0 <= v <= _MAX_ROWID  # noqa: E721 - bool is not a rowid
        for k, v in (raw.items() if isinstance(raw, dict) else ())
        if k != "dir"
    )
    if not valid:
        raise ApiError(400, "invalid_cursor", "malformed cursor")
    if newest_first:
        return {k: raw[k] for k in _CURSOR_KEYS if k in raw}
    return {key: raw.get(key, 0) for key in _CURSOR_KEYS}


def _rowid_window(after: int | None, newest_first: bool) -> tuple[str, list[Any], str]:
    """The rowid clause, its params and the ORDER BY for one source's stream."""
    if newest_first:
        return (
            ("" if after is None else " AND rowid < ?"),
            ([] if after is None else [after]),
            "DESC",
        )
    return " AND rowid > ?", [after], "ASC"


def _inventory_events(
    inv, after, kind, severity, limit, device_id=None, newest_first=False
) -> list[dict[str, Any]]:
    window, params, order = _rowid_window(after, newest_first)
    sql = (
        "SELECT rowid AS rid, id, device_id, ts, kind, severity, summary FROM events"  # noqa: S608 - fixed fragments, values bound
        " WHERE 1 = 1" + window
    )
    if kind:
        sql, params = sql + " AND kind = ?", [*params, kind]
    if severity:
        sql, params = sql + " AND severity = ?", [*params, severity]
    if device_id:
        sql, params = sql + " AND device_id = ?", [*params, device_id]
    found = rows(inv, sql + f" ORDER BY rowid {order} LIMIT ?", (*params, limit))
    return [
        {**dict(r), "summary": display_text(r["summary"]), "kind": display_text(r["kind"]),
         "source": "inventory"}
        for r in found
    ]  # fmt: skip


def _actor(principal: str) -> str:
    """The app principal is shown as `app`; its token id is never exposed."""
    return "app" if principal.startswith("app:") else principal


def _audit_events(
    ov, after, kind, severity, limit, device_id=None, newest_first=False
) -> list[dict[str, Any]]:
    if severity not in (None, "info"):  # human actions are always informational
        return []
    window, params, order = _rowid_window(after, newest_first)
    sql = (
        "SELECT rowid AS rid, id, target, ts, principal, action, detail FROM audit_log"  # noqa: S608 - fixed fragments, values bound
        " WHERE action NOT LIKE 'token.%'" + window
    )
    if kind:
        sql, params = sql + " AND action = ?", [*params, kind]
    if device_id:  # only rows that `_audit_event` shows with a device id
        sql += " AND action != ? AND action NOT LIKE 'monitoring.incident.%' AND target = ?"
        params = [*params, AUDIT_ACTION, device_id]
    found = rows(ov, sql + f" ORDER BY rowid {order} LIMIT ?", (*params, limit))
    return [_audit_event(r) for r in found]


def _export_level(detail: str | None) -> str:
    try:
        level = json.loads(detail or "")["level"]
    except (ValueError, TypeError, KeyError):
        return "unknown"
    return level if level in LEVELS else "unknown"


def _audit_event(r: sqlite3.Row) -> dict[str, Any]:
    """Incident and evidence-export events carry no device id; an export shows level and ref."""
    shown = f"{_actor(r['principal'])} {r['action']} {r['target'] or ''}".strip()
    exported = r["action"] == AUDIT_ACTION
    if exported:
        shown = f"{_actor(r['principal'])} {r['action']} {_export_level(r['detail'])}"
    return {
        "rid": r["rid"],
        "id": r["id"],
        "device_id": None
        if exported or r["action"].startswith("monitoring.incident.")
        else r["target"],
        "ts": r["ts"],
        "kind": display_text(r["action"]),
        "severity": "info",
        "summary": display_text(shown),
        "source": "audit",
    }


def list_events(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    *,
    since: str | None,
    kind: str | None,
    severity: str | None,
    limit: int,
    device_id: str | None = None,
    newest_first: bool = False,
) -> tuple[list[dict[str, Any]], str | None]:
    """Paginate on insertion order (rowid per source); `ts` is for display only.

    A late-arriving row can carry an older `ts` than rows already served, so a (ts, id) cursor
    would skip it. The page is the merge of both sources' rowid-ordered streams (so it is always
    a rowid prefix per source), re-sorted by ts for display. `next_cursor` is the resume point
    (the last included rowid per source); an empty page echoes `since`. `newest_first` walks the
    same streams from the highest rowid down; its cursor is the lowest rowid served per source.
    """
    cursor = _decode_event_cursor(since, newest_first)
    streams = [
        _inventory_events(inv, cursor.get("inv"), kind, severity, limit, device_id, newest_first),
        _audit_events(ov, cursor.get("audit"), kind, severity, limit, device_id, newest_first),
    ]
    page = list(
        islice(heapq.merge(*streams, key=lambda e: (e["ts"], e["id"]), reverse=newest_first), limit)
    )
    if not page:
        return [], since
    resume = dict(cursor)
    pick = min if newest_first else max
    for event in page:
        key = "inv" if event["source"] == "inventory" else "audit"
        resume[key] = pick(resume[key], event["rid"]) if key in resume else event["rid"]
    if newest_first:
        resume["dir"] = "desc"
    page.sort(key=lambda e: (e["ts"], e["id"]), reverse=newest_first)
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
        "payload": display_json(json.loads(row["payload"])),
        "reason_code": display_text(row["reason_code"]),
        # LLM/ML prose is shown for allowlisted actions only (PRP section 7)
        "reason_text": (
            display_text(row["reason_text"], PROSE_MAX)
            if row["action"] in PROSE_ALLOWED_ACTIONS
            else None
        ),
        "basis": display_json(json.loads(row["basis"])),
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
