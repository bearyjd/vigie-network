"""SQL that applies delivery actions to `incident_deliveries`.

Unit 4b executes these statements verbatim and the tests run them against a real SQLite table
built by the production migration, so the SQL cannot drift from the schema CHECKs.
docs/monitoring.md quotes every constant (a test keeps them identical). Every UPDATE sets
`updated_at=:now` and `version=version+1`. Within a pass each statement must affect exactly one
row: anything else is a planner bug, so roll the whole pass back (one `BEGIN IMMEDIATE`).

The sender's three statements are separate short transactions. Its completion is version-checked
only for `recover` rows (Withdraw/Revive create new incarnations); an `open` row is never
withdrawn or revived, so its completion matches on `attempts` alone and also records a send that
an acknowledgement overtook (`suppressed`), which keeps one open from being sent twice.
"""

from __future__ import annotations

from vigie_pipeline.delivery_plan import (
    Action,
    DeliveryView,
    Enqueue,
    Expire,
    Fail,
    Forget,
    Requeue,
    Reschedule,
    Revive,
    Suppress,
    Withdraw,
    delivery_id,
)

ENQUEUE_INSERT = """\
INSERT OR IGNORE INTO incident_deliveries
  (delivery_id, incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at,
   version)
VALUES (:id, :incident_id, :kind, 'pending', 0, :not_before, :now, :now, 0)"""

SUPPRESS_INSERT = """\
INSERT OR IGNORE INTO incident_deliveries
  (delivery_id, incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at,
   version)
VALUES (:id, :incident_id, :kind, 'suppressed', 0, NULL, :now, :now, 0)"""

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
WHERE delivery_id=:id AND state='pending' AND attempts=:attempts AND version=:version"""

FORGET_DELETE = """\
DELETE FROM incident_deliveries
WHERE delivery_id=:id AND state=:state AND attempts=:attempts AND version=:version"""

FORGET_OPEN_DELETE = """\
DELETE FROM incident_deliveries
WHERE delivery_id=:id AND state=:state AND attempts=:attempts AND version=:version
  AND NOT EXISTS (SELECT 1 FROM incident_deliveries r
                  WHERE r.incident_id=:incident_id AND r.kind='recover' AND r.state='pending')"""

SENDER_SENT = """\
UPDATE incident_deliveries SET state='sent', attempts=attempts+1, updated_at=:now,
  version=version+1
WHERE delivery_id=:id AND attempts=:attempts
  AND (state='pending' OR (state='suppressed' AND kind='open'))
  AND (:version IS NULL OR version=:version)"""

SENDER_RETRY = """\
UPDATE incident_deliveries SET attempts=attempts+1, next_attempt_at=:next_attempt_at,
  updated_at=:now, version=version+1
WHERE delivery_id=:id AND state='pending' AND attempts=:attempts
  AND (:version IS NULL OR version=:version)"""

SENDER_GIVE_UP = """\
UPDATE incident_deliveries SET state='failed', attempts=attempts+1, updated_at=:now,
  version=version+1
WHERE delivery_id=:id AND state='pending' AND attempts=:attempts
  AND (:version IS NULL OR version=:version)"""

ALL_SQL = (
    ENQUEUE_INSERT, SUPPRESS_INSERT, SUPPRESS_UPDATE, RESCHEDULE_UPDATE, REQUEUE_UPDATE,
    REVIVE_UPDATE, EXPIRE_UPDATE, FAIL_UPDATE, WITHDRAW_UPDATE, FORGET_DELETE,
    FORGET_OPEN_DELETE, SENDER_SENT, SENDER_RETRY, SENDER_GIVE_UP,
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
    if isinstance(a, Forget):
        return (FORGET_OPEN_DELETE if a.sibling_recover else FORGET_DELETE), p
    table = {Expire: EXPIRE_UPDATE, Fail: FAIL_UPDATE, Withdraw: WITHDRAW_UPDATE}
    return table[type(a)], p


def sender_params(captured: DeliveryView, now: float) -> dict:
    """Parameters for the sender statements: only a recover completion checks the version."""
    version = captured.version if captured.kind == "recover" else None
    return {
        "id": delivery_id(captured.incident_id, captured.kind),
        "attempts": captured.attempts,
        "version": version,
        "now": int(now),
    }
