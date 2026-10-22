"""inventory.db writes for identity stitching: events, candidate rows, immutable suggestions.

Every function here is idempotent in the sense stitching needs: events are guarded by a token
look-up, candidates are one row per (from, into) pair, suggestions are one open row per pair.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
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


def emit_event(
    inv: sqlite3.Connection, device_id: str, kind: str, severity: str, summary: str, now: float
) -> None:
    inv.execute(
        "INSERT INTO events (id, device_id, ts, kind, severity, summary) VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), device_id, iso_utc(now), kind, severity, summary),
    )


def upsert_candidate(
    inv: sqlite3.Connection, a: str, b: str, score: float, evidence: dict, state: str, now: float
) -> tuple[str, bool]:
    """One row per (from, into). Returns (id, state_changed_or_new). 'dismissed' is sticky."""
    text = json.dumps(evidence, sort_keys=True)
    row = inv.execute(
        "SELECT id, state FROM identity_candidates WHERE device_a=? AND device_b=?", (a, b)
    ).fetchone()
    if row is None:
        cid = str(uuid.uuid4())
        inv.execute(
            "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
            " created_at) VALUES (?,?,?,?,?,?,?)",
            (cid, a, b, score, text, state, iso_utc(now)),
        )
        return cid, True
    if row["state"] == "dismissed":
        return row["id"], False
    inv.execute(
        "UPDATE identity_candidates SET score=?, evidence=?, state=? WHERE id=?",
        (score, text, state, row["id"]),
    )
    return row["id"], row["state"] != state


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
    status: str  # created | open | rejected | accepted
    suggestion_id: str | None = None


def ensure_merge_suggestion(
    inv: sqlite3.Connection, snap: Snapshot, frm: str, into: str, *, score: float,
    reason_code: str, evidence_summary: dict, now: float, ttl_s: int,
) -> SuggestionOutcome:  # fmt: skip
    """Create the immutable merge_identity suggestion for (frm -> into) unless a human decision
    exists for the pair or one is still open (not expired). basis = current override versions."""
    pair = json.dumps([frm, into])
    now_iso = iso_utc(now)
    open_id = None
    for row in inv.execute(
        "SELECT id, expires_at FROM suggestions WHERE action='merge_identity' AND device_ids=?",
        (pair,),
    ):
        if row["id"] in snap.decisions:
            return SuggestionOutcome(snap.decisions[row["id"]], row["id"])
        if row["expires_at"] > now_iso:
            open_id = row["id"]
    if open_id:
        return SuggestionOutcome("open", open_id)
    sid = str(uuid.uuid4())
    payload = {"from_device": frm, "into_device": into, "score": score,
               "evidence_summary": evidence_summary}  # fmt: skip
    basis = {frm: snap.version(frm), into: snap.version(into)}
    inv.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, reason_text,"
        " basis, created_at, expires_at) VALUES (?,?,?,?,?,NULL,?,?,?)",
        (sid, "merge_identity", pair, json.dumps(payload, sort_keys=True), reason_code,
         json.dumps(basis, sort_keys=True), now_iso, iso_utc(now + ttl_s)),
    )  # fmt: skip
    return SuggestionOutcome("created", sid)
