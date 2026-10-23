"""inventory.db writes for identity stitching: events, candidate rows, immutable suggestions.

Every function here is idempotent in the sense stitching needs: events are guarded by a token
look-up, candidates are one row per (from, into) pair, suggestions are one open row per pair.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Collection, Mapping
from dataclasses import dataclass

from vigie_ingest.db import iso_utc
from vigie_pipeline.snapshot import Snapshot


def emit_once(
    inv: sqlite3.Connection, device_id: str | None, kind: str, severity: str, summary: str,
    token: str, now: float,
) -> bool:  # fmt: skip
    """Insert an event unless one of this kind already carries `token` (unique index lookup)."""
    return bool(
        inv.execute(
            "INSERT OR IGNORE INTO events (id, device_id, ts, kind, severity, summary, dedup)"
            " VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), device_id, iso_utc(now), kind, severity, summary, token),
        ).rowcount
    )


def event_exists(inv: sqlite3.Connection, kind: str, token: str) -> bool:
    return (
        inv.execute("SELECT 1 FROM events WHERE kind=? AND dedup=?", (kind, token)).fetchone()
        is not None
    )


def emit_event(
    inv: sqlite3.Connection, device_id: str, kind: str, severity: str, summary: str, now: float
) -> None:
    inv.execute(
        "INSERT INTO events (id, device_id, ts, kind, severity, summary) VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), device_id, iso_utc(now), kind, severity, summary),
    )


def _candidate_row(inv: sqlite3.Connection, a: str, b: str) -> sqlite3.Row | None:
    return inv.execute(
        "SELECT id, score, evidence, state FROM identity_candidates"
        " WHERE device_a=? AND device_b=?",
        (a, b),
    ).fetchone()


def _row_write_needed(row: sqlite3.Row | None, score: float, text: str, state: str) -> bool:
    if row is None:
        return True
    if row["state"] == "dismissed" or (row["state"] == "vetoed" and state != "vetoed"):
        return False  # dismissed and vetoed are sticky
    return (row["score"], row["evidence"], row["state"]) != (score, text, state)


def candidate_state(inv: sqlite3.Connection, a: str, b: str) -> str | None:
    row = _candidate_row(inv, a, b)
    return row["state"] if row else None


def candidate_write_needed(
    inv: sqlite3.Connection, a: str, b: str, score: float, evidence: dict, state: str
) -> bool:
    """Would upsert_candidate write this row? (An identical or sticky row is not written.)"""
    text = json.dumps(evidence, sort_keys=True)
    return _row_write_needed(_candidate_row(inv, a, b), score, text, state)


def upsert_candidate(
    inv: sqlite3.Connection, a: str, b: str, score: float, evidence: dict, state: str, now: float
) -> tuple[str, bool]:
    """One row per (from, into). Returns (id, row_written). 'dismissed' and 'vetoed' are sticky
    (no later evidence, stitcher view or capped window rewrites them) and an identical row is not
    rewritten, so the write is the unit the per-pass cap charges."""
    text = json.dumps(evidence, sort_keys=True)
    row = _candidate_row(inv, a, b)
    if row is None:
        cid = str(uuid.uuid4())
        inv.execute(
            "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
            " created_at) VALUES (?,?,?,?,?,?,?)",
            (cid, a, b, score, text, state, iso_utc(now)),
        )
        return cid, True
    if not _row_write_needed(row, score, text, state):
        return row["id"], False
    inv.execute(
        "UPDATE identity_candidates SET score=?, evidence=?, state=? WHERE id=?",
        (score, text, state, row["id"]),
    )
    return row["id"], True


def withdraw_open_suggestions(
    inv: sqlite3.Connection, snap: Snapshot, frm: str, into: str, now: float
) -> int:
    """Expire the undecided, unexpired merge suggestion(s) for (frm -> into) right now: the pair
    became vetoed or ambiguous. Inventory side only; a decided suggestion is never touched."""
    pair = json.dumps([frm, into])
    now_iso = iso_utc(now)
    ids = [
        r["id"]
        for r in inv.execute(
            "SELECT id FROM suggestions WHERE action='merge_identity' AND device_ids=?"
            " AND expires_at>=?",
            (pair, now_iso),
        )
        if r["id"] not in snap.decisions
    ]
    for sid in ids:
        inv.execute("UPDATE suggestions SET expires_at=? WHERE id=?", (iso_utc(now - 1), sid))
    return len(ids)


@dataclass(frozen=True)
class SuggestionOutcome:
    status: str  # open | rejected | accepted (a decision or an open suggestion already exists)
    suggestion_id: str | None = None


def find_merge_suggestion(
    inv: sqlite3.Connection, snap: Snapshot, frm: str, into: str, now: float
) -> SuggestionOutcome | None:
    """The human decision on, or the still-open (unexpired) suggestion of, the pair; None when a
    new one may be created. One indexed look-up (idx_suggestions_pair)."""
    open_id = None
    now_iso = iso_utc(now)
    for row in inv.execute(
        "SELECT id, expires_at FROM suggestions WHERE action='merge_identity' AND device_ids=?",
        (json.dumps([frm, into]),),
    ):
        if row["id"] in snap.decisions:
            return SuggestionOutcome(snap.decisions[row["id"]], row["id"])
        if row["expires_at"] > now_iso:
            open_id = row["id"]
    return SuggestionOutcome("open", open_id) if open_id else None


def create_merge_suggestion(
    inv: sqlite3.Connection, snap: Snapshot, frm: str, into: str, *, score: float,
    reason_code: str, evidence_summary: dict, now: float, ttl_s: int,
) -> str:  # fmt: skip
    sid = str(uuid.uuid4())
    payload = {"from_device": frm, "into_device": into, "score": score,
               "evidence_summary": evidence_summary}  # fmt: skip
    basis = {frm: snap.version(frm), into: snap.version(into)}
    inv.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, reason_text,"
        " basis, created_at, expires_at) VALUES (?,?,?,?,?,NULL,?,?,?)",
        (sid, "merge_identity", json.dumps([frm, into]), json.dumps(payload, sort_keys=True),
         reason_code, json.dumps(basis, sort_keys=True), iso_utc(now), iso_utc(now + ttl_s)),
    )  # fmt: skip
    return sid


def state_get(inv: sqlite3.Connection, key: str) -> str | None:
    row = inv.execute("SELECT value FROM stitch_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def state_set(inv: sqlite3.Connection, key: str, value: str | None) -> None:
    if value is None:
        inv.execute("DELETE FROM stitch_state WHERE key=?", (key,))
    else:
        inv.execute("INSERT OR REPLACE INTO stitch_state (key, value) VALUES (?,?)", (key, value))


def _marks(ids: Collection[str]) -> str:
    return ",".join("?" * len(ids))


CHUNK = 400  # ids per IN (...) list: far below SQLite's variable limit


def _chunks(ids: Collection[str]) -> list[list[str]]:
    items = sorted(ids)
    return [items[i : i + CHUNK] for i in range(0, len(items), CHUNK)]


def vetoed_between(inv: sqlite3.Connection, a_ids: Collection[str], b_ids: Collection[str]) -> bool:
    """Is any (a, b) pair of the two alias sets recorded as vetoed? A permanent veto keyed by a
    device id must survive that device being merged into another. The vetoes are looked up by the
    ids of the SMALLER side (chunked, through the index of that side) and checked by set membership
    against the larger one, so a huge merge component never becomes an IN list."""
    if len(a_ids) <= len(b_ids):
        column, other, small, large = "device_a", "device_b", a_ids, set(b_ids)
    else:
        column, other, small, large = "device_b", "device_a", b_ids, set(a_ids)
    for chunk in _chunks(small):
        rows = inv.execute(
            f"SELECT {other} FROM identity_candidates WHERE state='vetoed'"  # noqa: S608
            f" AND {column} IN ({_marks(chunk)})",
            chunk,
        )
        if any(r[0] in large for r in rows):
            return True
    return False


def widen_linked_devices(inv: sqlite3.Connection, links: Mapping[str, str]) -> None:
    """Catch-up for the first/last seen widening of merged devices that a run with unreadable
    overrides.db could not do: every linked-into device covers its sources' ranges. Idempotent;
    writes only where the range is actually too narrow."""
    for src, dst in links.items():
        inv.execute(
            "UPDATE devices SET"
            " first_seen=MIN(first_seen, (SELECT first_seen FROM devices WHERE id=?)),"
            " last_seen=MAX(last_seen, (SELECT last_seen FROM devices WHERE id=?))"
            " WHERE id=? AND EXISTS (SELECT 1 FROM devices s WHERE s.id=? AND"
            " (s.first_seen < devices.first_seen OR s.last_seen > devices.last_seen))",
            (src, src, dst, src),
        )


@dataclass(frozen=True)
class Attachment:
    rule_id: str
    target: str
    hostname: str | None
    mdns_name: str | None
    opt55: str | None = None  # None: attached before the fingerprints were recorded
    opt60: str | None = None
    views: tuple[tuple[bool, bool], ...] | None = None  # each matched rule's (hostname, mdns)


def _views(text: str | None) -> tuple[tuple[bool, bool], ...] | None:
    if text is None:
        return None
    return tuple((bool(h), bool(m)) for h, m in json.loads(text))


def load_attachments(inv: sqlite3.Connection) -> dict[str, Attachment]:
    return {
        r["mac"]: Attachment(
            r["rule_id"],
            r["target"],
            r["hostname"],
            r["mdns_name"],
            r["opt55"],
            r["opt60"],
            _views(r["views"]),
        )
        for r in inv.execute(
            "SELECT mac, rule_id, target, hostname, mdns_name, opt55, opt60, views"
            " FROM rule_attachments"
        )
    }


def save_attachment(inv: sqlite3.Connection, mac: str, att: Attachment, now: float) -> None:
    inv.execute(
        "INSERT OR REPLACE INTO rule_attachments (mac, rule_id, target, hostname, mdns_name,"
        " attached_at, opt55, opt60, views) VALUES (?,?,?,?,?,?,?,?,?)",
        (mac, att.rule_id, att.target, att.hostname, att.mdns_name, iso_utc(now), att.opt55,
         att.opt60, None if att.views is None else json.dumps(att.views)),
    )  # fmt: skip


def withdraw_orphan_suggestions(
    inv: sqlite3.Connection, snap: Snapshot, device_id: str, now: float
) -> int:
    """Expire (expires_at only) EVERY undecided merge suggestion that starts at, or points into, the
    orphaned device `device_id`, in one go. The 'from' direction is an index range; the 'into'
    direction goes through the candidate rows that name the orphan (idx_candidates_b) and exact pair
    look-ups. Deliberately not limited by the row allowance: an orphan's suggestion must never stay
    actionable. Returns the rows expired."""
    prefix = json.dumps([device_id, ""])[:-2]  # '["<id>", "'
    now_iso = iso_utc(now)
    ids = {
        r["id"]
        for r in inv.execute(
            "SELECT id FROM suggestions WHERE action='merge_identity' AND device_ids >= ?"
            " AND device_ids < ? AND expires_at >= ?",
            (prefix, prefix + "\uffff", now_iso),
        )
    }
    froms = [r[0] for r in inv.execute(
        "SELECT DISTINCT device_a FROM identity_candidates WHERE device_b=?", (device_id,)
    )]  # fmt: skip
    for chunk in _chunks(froms):
        pairs = [json.dumps([a, device_id]) for a in chunk]
        ids.update(
            r["id"]
            for r in inv.execute(
                "SELECT id FROM suggestions WHERE action='merge_identity'"  # noqa: S608
                f" AND device_ids IN ({_marks(pairs)}) AND expires_at >= ?",
                [*pairs, now_iso],
            )
        )
    todo = sorted(i for i in ids if i not in snap.decisions)
    inv.executemany(
        "UPDATE suggestions SET expires_at=? WHERE id=?", [(iso_utc(now - 1), i) for i in todo]
    )
    return len(todo)
