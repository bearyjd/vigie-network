"""Pure planner for incident notification deliveries.

No database, I/O, clock or environment: callers pass the current state and `now` (epoch seconds,
like `vigie_api.incident_decisions.attention`) and get back the actions to apply. Applying them
and feeding the result back yields no further actions (idempotent). The review mirror below
intentionally duplicates `attention()` instead of importing vigie_api; keep the two in step.

Rules: one `open` delivery per incident (dedup by incident+kind); acknowledged/expected incidents
are suppressed, and a suppressed row is re-evaluated every pass (a cleared decision Requeues it);
a snooze defers the delivery to `snooze_until` (strictly-before is quiet, so until == now is
loud) and a pending row without attempts tracks the current verdict exactly, while a retrying
row keeps its backoff unless a later snooze pushes it out; an incident that closes before its
open delivery went out expires it and never gets a `recover`; only a `resolved` incident whose
open delivery was `sent` gets exactly one `recover`; unknown states or statuses and non-finite or
non-numeric data fail closed (`unrecognised_state`, never raise); a bad `now` is a programmer
error (ValueError). Incidents detected before `eligible_since` are ignored entirely: no action
of any kind for them or their rows, so changing the watermark never deletes or re-announces
anything. Terminal rows of closed or missing incidents are Forgotten after `retention_seconds`
since `updated_at`, but never while a `recover` is still owed (a `sent` open of a resolved
incident without a terminal recover row). A Requeue keeps `attempts` and `created_at`; past the
attempt budget it becomes Fail, past the original ttl it becomes Expire. A pending `recover` of an
incident that is open again expires as `reopened`. Times in actions are integer epoch seconds.

`incidents` MUST be the complete current set: a pending row whose incident is absent from it is
expired as `incident_missing`.

Applying actions MUST be conditional so that a plan made before an in-flight send cannot overwrite
the sender's outcome: Expire/Fail/Reschedule/Suppress `WHERE state='pending'` (Fail, Expire and
Requeue may also name `state='suppressed'`), Requeue `WHERE state='suppressed'`, and Forget as
`DELETE ... WHERE state != 'pending'` for the row's planned state.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

KINDS = ("open", "recover")
STATES = frozenset({"pending", "sent", "failed", "suppressed", "expired"})
TERMINAL = frozenset({"sent", "failed", "suppressed", "expired"})
QUIET_STATUSES = frozenset({"acknowledged", "expected"})
CLOSED_STATES = frozenset({"resolved", "superseded"})
UNRECOGNISED = "unrecognised_state"


def _num(value: object) -> bool:
    """A real finite number: not a bool, not NaN/inf, not too large for a float."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


@dataclass(frozen=True)
class IncidentView:
    id: str
    state: str
    detected_at: int


@dataclass(frozen=True)
class ReviewView:
    """`status` None with no `snooze_until` is a cleared decision, i.e. no decision."""

    status: str | None
    snooze_until: float | None


@dataclass(frozen=True)
class DeliveryView:
    incident_id: str
    kind: str
    state: str
    attempts: int
    next_attempt_at: float | None
    created_at: float
    updated_at: float


@dataclass(frozen=True)
class DeliveryConfig:
    max_attempts: int = 6
    backoff_base_seconds: int = 60
    backoff_cap_seconds: int = 3600
    pending_ttl_seconds: int = 86400
    retention_seconds: int = 30 * 86400
    eligible_since: float | None = None

    def __post_init__(self) -> None:
        durations = (
            self.backoff_base_seconds,
            self.backoff_cap_seconds,
            self.pending_ttl_seconds,
            self.retention_seconds,
        )
        if not all(_num(v) and v > 0 for v in durations):
            raise ValueError("durations must be finite numbers > 0")
        if not _num(self.max_attempts) or self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.backoff_cap_seconds < self.backoff_base_seconds:
            raise ValueError("backoff cap must be >= base")
        if self.eligible_since is not None and not _num(self.eligible_since):
            raise ValueError("eligible_since must be a finite number or None")


@dataclass(frozen=True)
class Enqueue:
    incident_id: str
    kind: str
    not_before: float


@dataclass(frozen=True)
class Requeue:
    """Move a suppressed row back to pending (attempts reset to 0) at `not_before`."""

    incident_id: str
    kind: str
    not_before: float


@dataclass(frozen=True)
class Suppress:
    incident_id: str
    kind: str
    reason: str


@dataclass(frozen=True)
class Expire:
    incident_id: str
    kind: str
    reason: str


@dataclass(frozen=True)
class Reschedule:
    incident_id: str
    kind: str
    next_attempt_at: float


@dataclass(frozen=True)
class Fail:
    incident_id: str
    kind: str
    reason: str


@dataclass(frozen=True)
class Forget:
    incident_id: str
    kind: str


Action = Enqueue | Requeue | Suppress | Expire | Reschedule | Fail | Forget


def _ceil(value: float) -> int:
    return math.ceil(value)


def delivery_id(incident_id: str, kind: str) -> str:
    """Stable id: first 32 hex chars of sha256 over `incident_id`, a newline, then `kind`."""
    return hashlib.sha256(f"{incident_id}\n{kind}".encode()).hexdigest()[:32]


def backoff(attempts: int, config: DeliveryConfig) -> int:
    """Seconds to wait after the `attempts`-th failure: base, 2*base, 4*base ... capped."""
    doubling = 2 ** min(max(attempts - 1, 0), 32)
    return min(config.backoff_base_seconds * doubling, config.backoff_cap_seconds)


def after_failure(delivery: DeliveryView, now: float, config: DeliveryConfig) -> Action:
    """`delivery.attempts` already counts the attempt that just failed."""
    if delivery.attempts >= config.max_attempts:
        return Fail(delivery.incident_id, delivery.kind, "max_attempts")
    return Reschedule(
        delivery.incident_id, delivery.kind, _ceil(now) + backoff(delivery.attempts, config)
    )


def _verdict(review: ReviewView | None, now: float) -> tuple[str, float | str | None]:
    """Mirror of `attention()` for an open incident: loud, quiet(reason), until(t) or unknown."""
    if review is None or (review.status is None and review.snooze_until is None):
        return "loud", None
    if review.status in QUIET_STATUSES:
        return "quiet", review.status
    if review.status != "snoozed" or not _num(review.snooze_until):
        return "unknown", None
    if now < review.snooze_until:
        return "until", review.snooze_until
    return "loud", None


def _retarget(d: DeliveryView, target: int, later_only: bool) -> Action | None:
    """Pending row vs the verdict's time. A retrying row (attempts > 0) only moves later."""
    if d.next_attempt_at == target:
        return None
    if later_only or d.attempts > 0:
        return Reschedule(d.incident_id, "open", target) if d.next_attempt_at < target else None
    return Reschedule(d.incident_id, "open", target)


def _revive(d: DeliveryView, kind: str, target: int, now: float, config: DeliveryConfig):
    """A suppressed row whose verdict turned loud: requeue, within the original budget."""
    nxt_ok = d.next_attempt_at is None or _num(d.next_attempt_at)
    if not (
        nxt_ok
        and _num(d.attempts)
        and d.attempts >= 0
        and _num(d.created_at)
        and _num(d.updated_at)
    ):
        return None  # malformed row: cannot prove the budget, stay suppressed
    if d.attempts >= config.max_attempts:
        return Fail(d.incident_id, "open", "max_attempts")
    if kind == "loud" and now - d.created_at >= config.pending_ttl_seconds:
        return Expire(d.incident_id, "open", "ttl")
    return Requeue(d.incident_id, "open", target)


def _open_action(
    iid: str,
    state: object,
    review: ReviewView | None,
    d: DeliveryView | None,
    now: float,
    config: DeliveryConfig,
) -> Action | None:
    pending = d is not None and d.state == "pending"
    if d is not None and not pending and d.state != "suppressed":
        return None
    if state in CLOSED_STATES:
        return Expire(iid, "open", "resolved_before_send") if pending else None
    kind, detail = _verdict(review, now) if state == "open" else ("unknown", None)
    target = _ceil(detail) if kind == "until" else _ceil(now)
    if d is not None and d.state == "suppressed":
        return _revive(d, kind, target, now, config) if kind in ("loud", "until") else None
    if kind in ("unknown", "quiet"):
        return Suppress(iid, "open", UNRECOGNISED if kind == "unknown" else str(detail))
    if d is None:
        return Enqueue(iid, "open", target)
    if kind == "loud":
        early = d.attempts == 0 and d.next_attempt_at > target
        return Reschedule(iid, "open", target) if early else None
    return _retarget(d, target, False)


def _row_ok(d: DeliveryView) -> bool:
    numbers = (d.next_attempt_at, d.created_at, d.updated_at)
    return _num(d.attempts) and d.attempts >= 0 and all(_num(v) for v in numbers)


def _aged(d: DeliveryView, now: float, config: DeliveryConfig) -> bool:
    return _num(d.updated_at) and now - d.updated_at > config.retention_seconds


def _may_forget(d: DeliveryView, state: object, ds: Mapping[str, DeliveryView], now, config):
    """Aged terminal rows of a closed incident, unless a recover is still owed."""
    if state not in CLOSED_STATES or not _aged(d, now, config):
        return False
    opened, recover = ds.get("open"), ds.get("recover")
    if state == "resolved" and opened is not None and opened.state == "sent":
        if d.kind == "open":
            return recover is not None and recover.state in TERMINAL
        return _aged(opened, now, config)  # the recover goes together with its open row
    return True


def _row_action(
    iid: str, d: DeliveryView, state: object, ds: Mapping[str, DeliveryView], now, config
) -> Action | None:
    if d.state == "pending":
        if not _row_ok(d):
            return Expire(iid, d.kind, UNRECOGNISED)
        if d.kind == "recover" and state == "open":
            return Expire(iid, d.kind, "reopened")
        if now - max(d.created_at, d.next_attempt_at) >= config.pending_ttl_seconds:
            return Expire(iid, d.kind, "ttl")
        return None
    return Forget(iid, d.kind) if _may_forget(d, state, ds, now, config) else None


def _orphan_action(iid: str, d: DeliveryView, now: float, config: DeliveryConfig) -> Action | None:
    if d.state == "pending":
        return Expire(iid, d.kind, "incident_missing")
    return Forget(iid, d.kind) if _aged(d, now, config) else None


def _plan_incident(
    iid: str,
    incident: IncidentView | None,
    review: ReviewView | None,
    ds: Mapping[str, DeliveryView],
    now: float,
    config: DeliveryConfig,
) -> list[Action]:
    if incident is None:  # pruned: nothing left to announce
        orphans = (_orphan_action(iid, d, now, config) for _, d in sorted(ds.items()))
        return [a for a in orphans if a]
    state = incident.state if _num(incident.detected_at) else None
    actions: list[Action] = []
    for _, d in sorted(ds.items()):
        row = _row_action(iid, d, state, ds, now, config)
        if row:
            actions.append(row)
    if "open" not in {a.kind for a in actions}:
        opened = _open_action(iid, state, review, ds.get("open"), now, config)
        actions.extend([opened] if opened else [])
    announced = ds.get("open") is not None and ds["open"].state == "sent"
    if state == "resolved" and announced and "recover" not in ds:
        actions.append(Enqueue(iid, "recover", _ceil(now)))
    return actions


def _eligible(incident: IncidentView, config: DeliveryConfig) -> bool:
    since = config.eligible_since
    return since is None or not _num(incident.detected_at) or incident.detected_at >= since


def plan(
    incidents: Iterable[IncidentView],
    reviews: Mapping[str, ReviewView],
    deliveries: Iterable[DeliveryView],
    now: float,
    config: DeliveryConfig,
) -> tuple[Action, ...]:
    """Actions reconciling deliveries with incidents and reviews, sorted by (incident, kind)."""
    if not _num(now):
        raise ValueError("now must be a finite number of epoch seconds")
    by_incident: dict[str, IncidentView] = {}
    ignored: set[str] = set()
    for incident in incidents:
        if _eligible(incident, config):
            by_incident.setdefault(incident.id, incident)
        else:
            ignored.add(incident.id)
    grouped: dict[str, dict[str, DeliveryView]] = {}
    for d in deliveries:
        if d.kind in KINDS and d.state in STATES:
            grouped.setdefault(d.incident_id, {})[d.kind] = d
    actions: list[Action] = []
    for iid in sorted((by_incident.keys() | grouped.keys()) - ignored):
        actions.extend(
            _plan_incident(
                iid, by_incident.get(iid), reviews.get(iid), grouped.get(iid, {}), now, config
            )
        )
    return tuple(sorted(actions, key=lambda a: (a.incident_id, a.kind)))
