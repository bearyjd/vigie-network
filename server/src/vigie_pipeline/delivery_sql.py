"""SQL that applies delivery actions to `incident_deliveries`.

Unit 4b executes these statements verbatim and the tests run them against a real SQLite table
built by the production migration, so the SQL cannot drift from the schema CHECKs.
docs/monitoring.md quotes every constant (a test keeps them identical). Every UPDATE sets
`updated_at=:now` and `version=version+1`. Within a pass each statement must affect exactly one
row: anything else is a planner bug, so roll the whole pass back (one `BEGIN IMMEDIATE`).

SENDER PROTOCOL (a lease). CLAIM, in a short `BEGIN IMMEDIATE` transaction, is the only way to
transmit: it moves one `pending` row to `sending`, counts the attempt and sets the lease end in
`next_attempt_at`, so the database allows at most one live claim per delivery_id. The transmission
happens outside any transaction. The completion statements, again short transactions, are always
version-checked against the claimed version; the planner never touches a live `sending` row, so a
completion always matches unless the lease lapsed first. A crash after a successful send leaves the
row `sending`; the planner then Reclaims it (at-least-once: one retransmission per reclaim,
bounded by `max_attempts` overall).
"""

from __future__ import annotations

import math

from vigie_pipeline.delivery_plan import (
    Action,
    DeliveryConfig,
    DeliveryView,
    Enqueue,
    Expire,
    Fail,
    Forget,
    Reclaim,
    Requeue,
    Reschedule,
    Revive,
    Suppress,
    Withdraw,
    backoff,
    delivery_id,
)

ENQUEUE_INSERT = """\
INSERT OR IGNORE INTO incident_deliveries
  (delivery_id, incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at,
   version)
VALUES (:id, :incident_id, :kind, 'pending', 0, :not_before, :now, :now, :now)"""

SUPPRESS_INSERT = """\
INSERT OR IGNORE INTO incident_deliveries
  (delivery_id, incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at,
   version)
VALUES (:id, :incident_id, :kind, 'suppressed', 0, NULL, :now, :now, :now)"""

SUPPRESS_UPDATE = """\
UPDATE incident_deliveries SET state='suppressed', updated_at=:now, version=version+1
WHERE delivery_id=:id AND state='pending' AND attempts=:attempts AND version=:version"""

RESCHEDULE_UPDATE = """\
UPDATE incident_deliveries SET next_attempt_at=:next_attempt_at, updated_at=:now, version=version+1
WHERE delivery_id=:id AND state='pending' AND attempts=:attempts AND version=:version"""

REQUEUE_UPDATE = """\
UPDATE incident_deliveries SET state='pending', next_attempt_at=:not_before, updated_at=:now,
  version=version+1
WHERE delivery_id=:id AND state='suppressed' AND attempts=:attempts AND version=:version"""

REVIVE_UPDATE = """\
UPDATE incident_deliveries SET state='pending', next_attempt_at=:not_before, updated_at=:now,
  version=version+1
WHERE delivery_id=:id AND state='withdrawn' AND attempts=:attempts AND version=:version"""

EXPIRE_UPDATE = """\
UPDATE incident_deliveries SET state='expired', updated_at=:now, version=version+1
WHERE delivery_id=:id AND state=:state AND attempts=:attempts AND version=:version"""

FAIL_UPDATE = """\
UPDATE incident_deliveries SET state='failed', updated_at=:now, version=version+1
WHERE delivery_id=:id AND state=:state AND attempts=:attempts AND version=:version"""

WITHDRAW_UPDATE = """\
UPDATE incident_deliveries SET state='withdrawn', updated_at=:now, version=version+1
WHERE delivery_id=:id AND state=:state AND attempts=:attempts AND version=:version"""

FORGET_DELETE = """\
DELETE FROM incident_deliveries
WHERE delivery_id=:id AND state=:state AND attempts=:attempts AND version=:version"""

FORGET_OPEN_DELETE = """\
DELETE FROM incident_deliveries
WHERE delivery_id=:id AND state=:state AND attempts=:attempts AND version=:version
  AND NOT EXISTS (SELECT 1 FROM incident_deliveries r
                  WHERE r.incident_id=:incident_id AND r.kind='recover'
                    AND r.state IN ('pending', 'sending'))"""

RECLAIM_UPDATE = """\
UPDATE incident_deliveries SET state='pending', next_attempt_at=:next_attempt_at, updated_at=:now,
  version=version+1
WHERE delivery_id=:id AND state='sending' AND attempts=:attempts AND version=:version"""

CLAIM = """\
UPDATE incident_deliveries SET state='sending', attempts=attempts+1,
  next_attempt_at=:now+:lease_seconds, updated_at=:now, version=version+1
WHERE delivery_id=:id AND state='pending' AND next_attempt_at<=:now
  AND attempts<:max_attempts AND version=:version"""

COMPLETE_SENT = """\
UPDATE incident_deliveries SET state='sent', updated_at=:now, version=version+1
WHERE delivery_id=:id AND state='sending' AND version=:version"""

COMPLETE_RETRY = """\
UPDATE incident_deliveries SET state='pending', next_attempt_at=:next_attempt_at,
  updated_at=:now, version=version+1
WHERE delivery_id=:id AND state='sending' AND version=:version"""

COMPLETE_FAILED = """\
UPDATE incident_deliveries SET state='failed', updated_at=:now, version=version+1
WHERE delivery_id=:id AND state='sending' AND version=:version"""

ALL_SQL = (
    ENQUEUE_INSERT, SUPPRESS_INSERT, SUPPRESS_UPDATE, RESCHEDULE_UPDATE, REQUEUE_UPDATE,
    REVIVE_UPDATE, EXPIRE_UPDATE, FAIL_UPDATE, WITHDRAW_UPDATE, FORGET_DELETE,
    FORGET_OPEN_DELETE, RECLAIM_UPDATE, CLAIM, COMPLETE_SENT, COMPLETE_RETRY, COMPLETE_FAILED,
)  # fmt: skip


def statement(a: Action, now: float) -> tuple[str, dict]:
    """The SQL and named parameters that apply one planned action."""
    p: dict = {"id": delivery_id(a.incident_id, a.kind), "incident_id": a.incident_id}
    p |= {"kind": a.kind, "now": int(now)}
    if a.expected is not None:
        p |= {"state": a.expected.state, "attempts": a.expected.attempts}
        p["version"] = a.expected.version
    if isinstance(a, Enqueue):
        return ENQUEUE_INSERT, p | {"not_before": a.not_before}
    if isinstance(a, Suppress):
        return (SUPPRESS_INSERT if a.expected is None else SUPPRESS_UPDATE), p
    if isinstance(a, Requeue):
        return REQUEUE_UPDATE, p | {"not_before": a.not_before}
    if isinstance(a, Revive):
        return REVIVE_UPDATE, p | {"not_before": a.not_before}
    if isinstance(a, Reschedule):
        return RESCHEDULE_UPDATE, p | {"next_attempt_at": a.next_attempt_at}
    if isinstance(a, Reclaim):
        return RECLAIM_UPDATE, p | {"next_attempt_at": a.next_attempt_at}
    if isinstance(a, Forget):
        return (FORGET_OPEN_DELETE if a.sibling_recover else FORGET_DELETE), p
    table = {Expire: EXPIRE_UPDATE, Fail: FAIL_UPDATE, Withdraw: WITHDRAW_UPDATE}
    return table[type(a)], p


def claim_params(row: DeliveryView, now: float, config: DeliveryConfig) -> dict:
    """Parameters of CLAIM for a pending row the sender just read."""
    return {
        "id": delivery_id(row.incident_id, row.kind),
        "version": row.version,
        "now": int(now),
        "lease_seconds": config.lease_seconds,
        "max_attempts": config.max_attempts,
    }


def completion_params(claimed: DeliveryView, now: float) -> dict:
    """Parameters of the COMPLETE_* statements: `claimed` is the row as CLAIM left it."""
    return {
        "id": delivery_id(claimed.incident_id, claimed.kind),
        "version": claimed.version,
        "now": int(now),
    }


def failure_statement(
    claimed: DeliveryView, now: float, config: DeliveryConfig
) -> tuple[str, dict]:
    """The sender's completion for a failed send: retry later, or give up past the budget.
    `claimed.attempts` already counts the attempt that just failed."""
    params = completion_params(claimed, now)
    if claimed.attempts >= config.max_attempts:
        return COMPLETE_FAILED, params
    due = math.ceil(now) + backoff(claimed.attempts, config)
    return COMPLETE_RETRY, params | {"next_attempt_at": due}
