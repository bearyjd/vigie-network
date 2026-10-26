"""Human review decisions on monitoring incidents (an overrides.db overlay; inventory stays ro).

Two independent axes: the pipeline owns the incident `state`; humans own the review status.
Nothing here writes inventory.db, and the pipeline never reads this table.
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Any

from vigie_api.config import MIN_SNOOZE_S
from vigie_api.errors import ApiError
from vigie_api.feeds import _actor
from vigie_api.identity_writes import atomic
from vigie_ingest.db import iso_utc

STATUSES = ("acknowledged", "snoozed", "expected")
QUIET_STATUSES = frozenset({"acknowledged", "expected"})
ACTION_STATUS = {"acknowledge": "acknowledged", "snooze": "snoozed", "mark-expected": "expected"}
RETENTION_DAYS = 120
PRUNE_BATCH = 100
PRUNE_SCAN = 500
AUDIT_PREFIX = "monitoring.incident."
DESCRIPTION = (
    "Human review of one monitoring incident (overrides-side overlay; the pipeline's incident "
    "state is untouched). `expected_version` is the incident's decision version (0 when it "
    "has none); a stale value is a 409 `version_conflict`. Errors: 404 `incident_not_found`, "
    "409 `incident_not_open` (snooze on a resolved/superseded incident), 409 `no_decision` "
    "(clear with nothing to clear), 409 `idempotency_conflict`."
)
_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|\+00:00)")


def attention(state: str, review: dict[str, Any] | None, now: float) -> bool:
    """An incident needs a human only while the pipeline holds it open and no decision covers it.

    A snooze covers it strictly before `snooze_until`; at or after that instant it is back.
    """
    if state != "open":
        return False
    if review is None:
        return True
    if review["status"] in QUIET_STATUSES:
        return False
    return not (review["status"] == "snoozed" and now < review["snooze_until"])


def parse_until(value: str) -> int:
    """Syntax only: a whole-second RFC 3339 UTC instant. The window is checked at write time."""
    if not _RFC3339_UTC.fullmatch(value):
        raise ApiError(
            422, "invalid_until", "until must be RFC 3339 UTC, e.g. 2026-01-01T00:00:00Z"
        )
    try:
        return int(datetime.fromisoformat(value).timestamp())
    except (ValueError, OverflowError):
        raise ApiError(422, "invalid_until", "until is not a valid instant") from None


def check_window(instant: int, now: float, max_s: int) -> None:
    """Relative window; evaluated inside the write so a receipt replay never re-checks it."""
    if not now + MIN_SNOOZE_S <= instant <= now + max_s:
        raise ApiError(
            422,
            "invalid_until",
            f"until must be between {MIN_SNOOZE_S} seconds and {max_s} seconds from now",
        )


def review_view(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """Public shape of a decision row (the stored principal is shown as its actor)."""
    if row is None or row["status"] is None:  # a cleared tombstone is "no review"
        return None
    until = row["snooze_until"]
    return {
        "status": row["status"],
        "snooze_until": None if until is None else iso_utc(until),
        "version": row["version"],
        "decided_by": _actor(row["decided_by"]),
        "decided_at": row["decided_at"],
    }


def reviews_for(ov: sqlite3.Connection, incident_ids: list[str]) -> dict[str, sqlite3.Row]:
    """One indexed query for a page of incidents; orphan rows are never reached."""
    if not incident_ids:
        return {}
    marks = ",".join("?" * len(incident_ids))
    found = ov.execute(
        f"SELECT * FROM incident_decisions WHERE incident_id IN ({marks})",  # noqa: S608
        incident_ids,
    ).fetchall()
    return {row["incident_id"]: row for row in found}


def _prune_orphans(inv: sqlite3.Connection, ov: sqlite3.Connection, now: float) -> None:
    """Scan stale rows from a persisted (decided_at, id) cursor, wrapping at the end."""
    cutoff = iso_utc(now - timedelta(days=RETENTION_DAYS).total_seconds())
    saved = ov.execute("SELECT decided_at,incident_id FROM incident_decision_prune").fetchone()
    after = (saved[0], saved[1]) if saved else ("", "")
    stale = ov.execute(
        "SELECT decided_at,incident_id FROM incident_decisions WHERE decided_at<? AND"
        " (decided_at,incident_id)>(?,?) ORDER BY decided_at,incident_id LIMIT ?",
        (cutoff, *after, PRUNE_SCAN),
    ).fetchall()
    deleted, last = 0, after
    for decided_at, incident_id in stale:
        if inv.execute("SELECT 1 FROM monitoring_incidents WHERE id=?", (incident_id,)).fetchone():
            last = (decided_at, incident_id)
            continue
        if deleted == PRUNE_BATCH:
            break
        ov.execute("DELETE FROM incident_decisions WHERE incident_id=?", (incident_id,))
        deleted, last = deleted + 1, (decided_at, incident_id)
    if len(stale) < PRUNE_SCAN:
        last = ("", "")  # reached the end: start over next time
    ov.execute("DELETE FROM incident_decision_prune")
    ov.execute("INSERT INTO incident_decision_prune VALUES (?,?)", last)


def _write_decision(ov, incident, action, until, version, principal, now_iso):  # noqa: ANN001
    ov.execute(
        "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,detector,"
        "episode_start,status,snooze_until,version,decided_by,decided_at,id)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET"
        " status=excluded.status,snooze_until=excluded.snooze_until,version=excluded.version,"
        "decided_by=excluded.decided_by,decided_at=excluded.decided_at,id=excluded.id",
        (incident["id"], incident["collector_id"], incident["device_id"], incident["lineage"],
         incident["detector"], incident["episode_start"], ACTION_STATUS.get(action), until, version,
         principal, now_iso, str(uuid.uuid4())),
    )  # fmt: skip


def _find(inv, incident_id, collector_id):  # noqa: ANN001
    return inv.execute(
        "SELECT id,collector_id,device_id,lineage,detector,state,episode_start"
        " FROM monitoring_incidents WHERE id=? AND collector_id=?",
        (incident_id, collector_id),
    ).fetchone()


def decide(
    inv,
    ov,
    *,
    incident_id,
    collector_id,
    action,
    body,
    until,
    principal,
    clock,
    request_id,
    snooze_max_s=None,
):  # noqa: ANN001
    """Apply one review action under per-incident CAS, a receipt and an audit row.

    Receipts replay only for an explicit X-Request-ID; without one every call gets a fresh key,
    so a stale expected_version is always a 409 and never a replay of an older success.
    """
    principal.require_write()
    if _find(inv, incident_id, collector_id) is None:  # before any receipt can answer
        raise ApiError(404, "incident_not_found", "incident not found")

    sampled: dict[str, float] = {}

    def operation():
        # sampled only now: after the write lock and the receipt lookup, so a long lock wait
        # cannot make a snooze lead look longer than it is
        now = sampled["now"] = clock()
        now_iso = iso_utc(now)
        incident = _find(inv, incident_id, collector_id)
        if incident is None:
            raise ApiError(404, "incident_not_found", "incident not found")
        if action == "snooze":
            check_window(until, now, snooze_max_s)
            if incident["state"] != "open":
                raise ApiError(409, "incident_not_open", "only an open incident can be snoozed")
        old = ov.execute(
            "SELECT * FROM incident_decisions WHERE incident_id=?", (incident_id,)
        ).fetchone()
        current = old["version"] if old else 0
        if current != body.expected_version:
            raise ApiError(
                409, "version_conflict", "decision version no longer matches",
                extra={"current_version": current},
            )  # fmt: skip
        if action == "clear" and (old is None or old["status"] is None):
            raise ApiError(409, "no_decision", "incident has no decision to clear")
        _write_decision(ov, incident, action, until, current + 1, principal.name, now_iso)
        _prune_orphans(inv, ov, now)
        new = ov.execute(
            "SELECT * FROM incident_decisions WHERE incident_id=?", (incident_id,)
        ).fetchone()
        return _outcome(incident, old, new, principal, now_iso)

    return atomic(
        ov,
        principal=principal.name,
        action=AUDIT_PREFIX + action.replace("-", "_"),
        target=incident_id,
        body=body,
        request_id=request_id or str(uuid.uuid4()),
        now=lambda: iso_utc(sampled["now"]),
        operation=operation,
    )


def _outcome(incident, old, new, principal, now_iso):  # noqa: ANN001
    identity = {k: incident[k] for k in incident.keys()}
    before = {"incident": identity, "review": review_view(old)}
    after = {"incident": identity, "review": review_view(new)}
    shown = after["review"]
    result = {
        "incident_id": incident["id"],
        "status": shown["status"] if shown else None,
        "snooze_until": shown["snooze_until"] if shown else None,
        "version": new["version"],
        "decided_by": _actor(principal.name),
        "decided_at": now_iso,
    }
    return result, before, after
