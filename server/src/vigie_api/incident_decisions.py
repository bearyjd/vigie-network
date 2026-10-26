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

from vigie_api.errors import ApiError
from vigie_api.feeds import _actor
from vigie_api.identity_writes import atomic
from vigie_ingest.db import iso_utc

STATUSES = ("acknowledged", "snoozed", "expected")
QUIET_STATUSES = frozenset({"acknowledged", "expected"})
ACTION_STATUS = {"acknowledge": "acknowledged", "snooze": "snoozed", "mark-expected": "expected"}
MIN_SNOOZE_S = 60
RETENTION_DAYS = 120
PRUNE_BATCH = 100
AUDIT_PREFIX = "monitoring.incident."
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


def parse_until(value: str, now: float, max_s: int) -> int:
    """Whole-second RFC 3339 UTC instant within [now + MIN_SNOOZE_S, now + max_s]."""
    if not _RFC3339_UTC.fullmatch(value):
        raise ApiError(
            422, "invalid_until", "until must be RFC 3339 UTC, e.g. 2026-01-01T00:00:00Z"
        )
    try:
        instant = int(datetime.fromisoformat(value).timestamp())
    except (ValueError, OverflowError):
        raise ApiError(422, "invalid_until", "until is not a valid instant") from None
    if not now + MIN_SNOOZE_S <= instant <= now + max_s:
        raise ApiError(
            422,
            "invalid_until",
            f"until must be between {MIN_SNOOZE_S} seconds and {max_s} seconds from now",
        )
    return instant


def review_view(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """Public shape of a decision row (the stored principal is shown as its actor)."""
    if row is None:
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
    cutoff = iso_utc(now - timedelta(days=RETENTION_DAYS).total_seconds())
    stale = ov.execute(
        "SELECT incident_id FROM incident_decisions WHERE decided_at<? ORDER BY decided_at LIMIT ?",
        (cutoff, PRUNE_BATCH),
    ).fetchall()
    for row in stale:
        if inv.execute("SELECT 1 FROM monitoring_incidents WHERE id=?", (row[0],)).fetchone():
            continue
        ov.execute("DELETE FROM incident_decisions WHERE incident_id=?", (row[0],))


def _write_decision(ov, incident, action, until, version, principal, now_iso):  # noqa: ANN001
    ov.execute(
        "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,detector,"
        "episode_start,status,snooze_until,version,decided_by,decided_at,id)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET"
        " status=excluded.status,snooze_until=excluded.snooze_until,version=excluded.version,"
        "decided_by=excluded.decided_by,decided_at=excluded.decided_at,id=excluded.id",
        (incident["id"], incident["collector_id"], incident["device_id"], incident["lineage"],
         incident["detector"], incident["episode_start"], ACTION_STATUS[action], until, version,
         principal, now_iso, str(uuid.uuid4())),
    )  # fmt: skip


def decide(
    inv, ov, *, incident_id, collector_id, action, body, until, principal, now, now_iso, request_id
):  # noqa: ANN001
    """Apply one review action under per-incident CAS, a receipt and an audit row."""
    principal.require_write()

    def operation():
        incident = inv.execute(
            "SELECT id,collector_id,device_id,lineage,detector,state,episode_start"
            " FROM monitoring_incidents WHERE id=? AND collector_id=?",
            (incident_id, collector_id),
        ).fetchone()
        if incident is None:
            raise ApiError(404, "incident_not_found", "incident not found")
        if action == "snooze" and incident["state"] != "open":
            raise ApiError(409, "incident_not_open", "only an open incident can be snoozed")
        old = ov.execute(
            "SELECT * FROM incident_decisions WHERE incident_id=?", (incident_id,)
        ).fetchone()
        current = old["version"] if old else 0
        if current != body.expected_version:
            raise ApiError(409, "version_conflict", "decision version no longer matches")
        if action == "clear" and old is None:
            raise ApiError(409, "no_decision", "incident has no decision to clear")
        if action == "clear":
            ov.execute("DELETE FROM incident_decisions WHERE incident_id=?", (incident_id,))
        else:
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
        request_id=request_id,
        now=now_iso,
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
        "version": shown["version"] if shown else 0,
        "decided_by": _actor(principal.name),
        "decided_at": now_iso,
    }
    return result, before, after
