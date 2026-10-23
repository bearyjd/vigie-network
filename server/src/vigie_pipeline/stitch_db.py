"""inventory.db reads and writes for identity stitching: events, candidate rows, immutable
suggestions, attach evidence, vetoes. Every statement is an indexed point or range lookup.

Idempotent in the sense stitching needs: events are guarded by a (kind, dedup) unique index,
candidates are one row per (from, into) pair, suggestions one open row per pair.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Collection, Mapping
from dataclasses import dataclass

from vigie_ingest.db import iso_utc
from vigie_pipeline.snapshot import Snapshot

CHUNK = 400  # ids per IN (...) list: far below SQLite's variable limit


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


# ---- candidates ----------------------------------------------------------------------------


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
    (no later evidence or capped window rewrites them) and an identical row is not rewritten, so
    the write is the unit the per-pass cap charges."""
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


def dismiss_open_candidates(inv: sqlite3.Connection, device_id: str, limit: int) -> int:
    """A rule settled the device's MAC: up to `limit` of the undecided candidate rows naming it on
    either side are dismissed (one indexed statement). Returns the rows written."""
    if limit <= 0:
        return 0
    return inv.execute(
        "UPDATE identity_candidates SET state='dismissed' WHERE id IN (SELECT id FROM"
        " identity_candidates WHERE (device_a=? OR device_b=?) AND state IN ('open','suggested')"
        " LIMIT ?)",
        (device_id, device_id, limit),
    ).rowcount


def open_candidates_left(inv: sqlite3.Connection, device_id: str) -> bool:
    return (
        inv.execute(
            "SELECT 1 FROM identity_candidates WHERE (device_a=? OR device_b=?)"
            " AND state IN ('open','suggested') LIMIT 1",
            (device_id, device_id),
        ).fetchone()
        is not None
    )


def _chunks(ids: Collection[str]) -> list[list[str]]:
    items = sorted(ids)
    return [items[i : i + CHUNK] for i in range(0, len(items), CHUNK)]


def vetoed_between(inv: sqlite3.Connection, a_ids: Collection[str], b_ids: Collection[str]) -> bool:
    """Is any (a, b) pair of the two alias sets recorded as vetoed? A permanent veto keyed by a
    device id must survive that device being merged into another. The vetoes are looked up by the
    ids of the SMALLER side (chunked, through that side's index) and checked by set membership
    against the larger one, so a huge merge component never becomes an IN list."""
    if len(a_ids) <= len(b_ids):
        column, other, small, large = "device_a", "device_b", a_ids, set(b_ids)
    else:
        column, other, small, large = "device_b", "device_a", b_ids, set(a_ids)
    for chunk in _chunks(small):
        rows = inv.execute(
            f"SELECT {other} FROM identity_candidates WHERE state='vetoed'"  # noqa: S608
            f" AND {column} IN ({','.join('?' * len(chunk))})",
            chunk,
        )
        if any(r[0] in large for r in rows):
            return True
    return False


# ---- suggestions ---------------------------------------------------------------------------


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


def open_suggestions_into(inv: sqlite3.Connection, into: str, now: float) -> int:
    """Unexpired merge suggestions pointing into `into` (idx_suggestions_into)."""
    return inv.execute(
        "SELECT COUNT(*) FROM suggestions WHERE action='merge_identity'"
        " AND json_extract(device_ids, '$[1]')=? AND expires_at>?",
        (into, iso_utc(now)),
    ).fetchone()[0]


def create_merge_suggestion(
    inv: sqlite3.Connection, snap: Snapshot, frm: str, into: str, *, score: float,
    reason_code: str, reason_text: str | None, evidence_summary: dict, now: float, ttl_s: int,
) -> str:  # fmt: skip
    sid = str(uuid.uuid4())
    payload = {"from_device": frm, "into_device": into, "score": score,
               "evidence_summary": evidence_summary}  # fmt: skip
    basis = {frm: snap.version(frm), into: snap.version(into)}
    inv.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, reason_text,"
        " basis, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (sid, "merge_identity", json.dumps([frm, into]), json.dumps(payload, sort_keys=True),
         reason_code, reason_text, json.dumps(basis, sort_keys=True), iso_utc(now),
         iso_utc(now + ttl_s)),
    )  # fmt: skip
    return sid


def _expire(inv: sqlite3.Connection, snap: Snapshot, rows: list[sqlite3.Row], now: float) -> int:
    """Set expires_at to just before now on every undecided suggestion of `rows`."""
    todo = sorted({r["id"] for r in rows if r["id"] not in snap.decisions})
    inv.executemany(
        "UPDATE suggestions SET expires_at=? WHERE id=?", [(iso_utc(now - 1), i) for i in todo]
    )
    return len(todo)


def withdraw_open_suggestions(
    inv: sqlite3.Connection, snap: Snapshot, frm: str, into: str, now: float
) -> int:
    """Expire the undecided, unexpired merge suggestion(s) for (frm -> into) right now: the pair
    became vetoed or ambiguous. Inventory side only; a decided suggestion is never touched."""
    rows = inv.execute(
        "SELECT id FROM suggestions WHERE action='merge_identity' AND device_ids=?"
        " AND expires_at>=?",
        (json.dumps([frm, into]), iso_utc(now)),
    ).fetchall()
    return _expire(inv, snap, rows, now)


def withdraw_orphan_suggestions(
    inv: sqlite3.Connection, snap: Snapshot, device_id: str, now: float, limit: int,
    cursor: Mapping[str, str],
) -> tuple[int, bool, dict[str, str]]:  # fmt: skip
    """Expire up to `limit` undecided merge suggestions that start at, or point into, the orphaned
    `device_id` (an attach settled it). Each direction is read by keyset (`id > cursor`,
    `LIMIT remaining write allowance + 1`, through idx_suggestions_from_id /
    idx_suggestions_into_id).
    Each call reads at most 2 * (limit + 1) rows. Expired rows and decided ids are skipped in
    Python against the snapshot's set (never serialised into SQL), and the cursor advances past
    every row examined. History takes additional passes; decided suggestions are never touched.
    Returns (rows written, more left, cursor)."""
    if limit <= 0:
        return 0, True, dict(cursor)
    now_iso = iso_utc(now)
    queries = {
        "from": (
            "SELECT id, expires_at FROM suggestions WHERE action='merge_identity'"
            " AND json_extract(device_ids, '$[0]')=? AND id > ? ORDER BY id LIMIT ?",
            (device_id,),
        ),
        "into": (
            "SELECT id, expires_at FROM suggestions WHERE action='merge_identity'"
            " AND json_extract(device_ids, '$[1]')=? AND id > ? ORDER BY id"
            " LIMIT ?",
            (device_id,),
        ),
    }
    out, written, more = dict(cursor), 0, False
    for direction, (sql, params) in queries.items():
        room = limit - written
        if room <= 0:
            more = True
            break
        rows = inv.execute(sql, (*params, out.get(direction, ""), room + 1)).fetchall()
        if len(rows) > room:
            more = True
        examined = rows[:room]
        todo = [
            r["id"]
            for r in examined
            if r["id"] not in snap.decisions and r["expires_at"] >= now_iso
        ]
        written += _expire_ids(inv, todo, now)
        if examined:
            out[direction] = examined[-1]["id"]
    return written, more, out


def _expire_ids(inv: sqlite3.Connection, ids: list[str], now: float) -> int:
    inv.executemany(
        "UPDATE suggestions SET expires_at=? WHERE id=?", [(iso_utc(now - 1), i) for i in ids]
    )
    return len(ids)


# ---- state and attach evidence --------------------------------------------------------------


def state_get(inv: sqlite3.Connection, key: str) -> str | None:
    row = inv.execute("SELECT value FROM stitch_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def state_set(inv: sqlite3.Connection, key: str, value: str | None) -> None:
    if value is None:
        inv.execute("DELETE FROM stitch_state WHERE key=?", (key,))
    else:
        inv.execute("INSERT OR REPLACE INTO stitch_state (key, value) VALUES (?,?)", (key, value))


@dataclass(frozen=True)
class Attachment:
    """What justified a rule attach, at attach time: the name fields any matched rule required
    with the MAC's values then, its fingerprints then, and each matched rule's own field mask."""

    rule_id: str
    target: str
    hostname: str | None
    mdns_name: str | None
    opt55: str | None
    opt60: str | None
    views: tuple[tuple[bool, bool], ...]  # each matched rule's (hostname required, mdns required)


def load_attachment(inv: sqlite3.Connection, mac: str) -> Attachment | None:
    r = inv.execute(
        "SELECT rule_id, target, hostname, mdns_name, opt55, opt60, views FROM rule_attachments"
        " WHERE mac=?",
        (mac,),
    ).fetchone()
    if r is None:
        return None
    views = tuple((bool(h), bool(m)) for h, m in json.loads(r["views"]))
    return Attachment(
        r["rule_id"], r["target"], r["hostname"], r["mdns_name"], r["opt55"], r["opt60"], views
    )


def save_attachment(inv: sqlite3.Connection, mac: str, att: Attachment, now: float) -> None:
    inv.execute(
        "INSERT OR REPLACE INTO rule_attachments (mac, rule_id, target, hostname, mdns_name,"
        " opt55, opt60, views, attached_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (mac, att.rule_id, att.target, att.hostname, att.mdns_name, att.opt55, att.opt60,
         json.dumps(att.views), iso_utc(now)),
    )  # fmt: skip
