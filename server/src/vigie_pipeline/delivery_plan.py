"""Pure planner for incident notification deliveries.

No database, I/O, clock or environment: callers pass the current state and `now` (epoch seconds,
like `vigie_api.incident_decisions.attention`) and get back the actions to apply. The review
mirror below duplicates `attention()` instead of importing vigie_api; keep the two in step.
The rules are listed in docs/monitoring.md ("Incident delivery"); in short:

* one `open` delivery per incident; ack/expected suppress it, a cleared decision Requeues it
  (attempts and created_at kept), a snooze defers it to `snooze_until` (strictly-before is quiet);
* a pending TTL counts from `max(created_at, next_attempt_at)`; a Requeue sets `next_attempt_at`
  to its target, so a long ack never expires a still-open loud incident. Spam is bounded by the
  attempt budget (past it: Fail) and by a hard lifetime: a row older than `retention_seconds`
  from `created_at` is Expired as `lifetime` and never revived;
* an incident that closes before its open delivery went out expires it; only a `resolved` incident
  whose open was `sent` gets exactly one `recover`; a pending recover of an incident that is no
  longer resolved is Withdrawn (deleted);
* an incident behind `eligible_since` that has NO rows is ignored; one with rows is managed;
* terminal rows of closed or missing incidents are Forgotten after `retention_seconds` since
  `updated_at`, never while a recover is owed or pending;
* unknown states or statuses and non-finite or non-numeric data fail closed
  (`unrecognised_state`, never raise); a bad `now` raises ValueError.

CONCURRENCY CONTRACT (the primary defence). Unit 4b reads the incident set (the COMPLETE current
set; skip the pass if that read fails) AND the delivery rows, runs `plan()` and applies every
action inside ONE `BEGIN IMMEDIATE` transaction on the pipeline database. The sender records its
results with its own conditional `UPDATE ... WHERE delivery_id=? AND state='pending' AND
version=?` (bumping `version`) and never changes rows outside that lock. A plan can then only be
stale relative to the sender's in-flight send, never relative to another planner.

`expected` is an assertion on top of the contract: None means the row must not exist (INSERT OR
IGNORE), otherwise Expected(state, attempts, version) of the row planned against. Each action is
one conditional statement that also bumps `version`; 0 affected rows is a bug: log it and abort
the pass (the transaction rolls back). A Forget of an `open` row carries
`sibling_recover='absent_or_terminal'`: its DELETE adds `AND NOT EXISTS (SELECT 1 FROM
incident_deliveries r WHERE r.incident_id=? AND r.kind='recover' AND r.state='pending')`.
Times in actions are integer epoch seconds. `expected`/`sibling_recover` are excluded from
dataclass equality so tests compare actions by meaning and assert them separately.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

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
    version: int = 0


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
class Expected:
    """Precondition of a conditional update: the row's state, attempts and version when planned."""

    state: str
    attempts: int
    version: int


def _exp(d: DeliveryView) -> Expected:
    return Expected(d.state, d.attempts, d.version)


@dataclass(frozen=True)
class Enqueue:
    incident_id: str
    kind: str
    not_before: int
    expected: Expected | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Requeue:
    """Move a suppressed row back to pending at `not_before`, keeping attempts and created_at."""

    incident_id: str
    kind: str
    not_before: int
    expected: Expected | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Suppress:
    incident_id: str
    kind: str
    reason: str
    expected: Expected | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Expire:
    incident_id: str
    kind: str
    reason: str
    expected: Expected | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Reschedule:
    incident_id: str
    kind: str
    next_attempt_at: int
    expected: Expected | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Fail:
    incident_id: str
    kind: str
    reason: str
    expected: Expected | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Forget:
    incident_id: str
    kind: str
    expected: Expected | None = field(default=None, compare=False)
    sibling_recover: str | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Withdraw:
    """Delete a pending `recover` whose incident is open again."""

    incident_id: str
    kind: str
    expected: Expected | None = field(default=None, compare=False)


Action = Enqueue | Requeue | Suppress | Expire | Reschedule | Fail | Forget | Withdraw


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
        return Fail(delivery.incident_id, delivery.kind, "max_attempts", _exp(delivery))
    due = math.ceil(now) + backoff(delivery.attempts, config)
    return Reschedule(delivery.incident_id, delivery.kind, due, _exp(delivery))


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


def _retarget(d: DeliveryView, target: int) -> Action | None:
    """Pending row vs the verdict's time. A retrying row (attempts > 0) only moves later."""
    if d.next_attempt_at == target or (d.attempts > 0 and d.next_attempt_at > target):
        return None
    return Reschedule(d.incident_id, "open", target, _exp(d))


def _lifetime_over(d: DeliveryView, now: float, config: DeliveryConfig) -> bool:
    return now - d.created_at > config.retention_seconds


def _revive(d: DeliveryView, target: int, now: float, config: DeliveryConfig):
    """A suppressed row whose verdict turned loud: requeue, within the attempt budget/lifetime."""
    nxt_ok = d.next_attempt_at is None or _num(d.next_attempt_at)
    numbers = (d.attempts, d.created_at, d.updated_at, d.version)
    if not (nxt_ok and all(_num(v) for v in numbers) and d.attempts >= 0):
        return None  # malformed row: cannot prove the budget, stay suppressed
    if d.attempts >= config.max_attempts:
        return Fail(d.incident_id, "open", "max_attempts", _exp(d))
    if _lifetime_over(d, now, config):
        return Expire(d.incident_id, "open", "lifetime", _exp(d))
    if d.attempts > 0 and d.next_attempt_at is not None:  # wait out an earlier backoff
        target = max(target, math.ceil(d.next_attempt_at))
    return Requeue(d.incident_id, "open", target, _exp(d))


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
        return Expire(iid, "open", "resolved_before_send", _exp(d)) if pending else None
    kind, detail = _verdict(review, now) if state == "open" else ("unknown", None)
    target = math.ceil(detail) if kind == "until" else math.ceil(now)
    if d is not None and d.state == "suppressed":
        return _revive(d, target, now, config) if kind in ("loud", "until") else None
    if kind in ("unknown", "quiet"):
        reason = UNRECOGNISED if kind == "unknown" else str(detail)
        return Suppress(iid, "open", reason, _exp(d) if d else None)
    if d is None:
        return Enqueue(iid, "open", target)
    if kind == "loud":
        early = d.attempts == 0 and d.next_attempt_at > target
        return Reschedule(iid, "open", target, _exp(d)) if early else None
    return _retarget(d, target)


def _row_ok(d: DeliveryView) -> bool:
    numbers = (d.next_attempt_at, d.created_at, d.updated_at, d.version)
    return _num(d.attempts) and d.attempts >= 0 and all(_num(v) for v in numbers)


def _aged(d: DeliveryView, now: float, config: DeliveryConfig) -> bool:
    return _num(d.updated_at) and now - d.updated_at > config.retention_seconds


def _may_forget(d: DeliveryView, state: object, ds: Mapping[str, DeliveryView], now, config):
    """Aged terminal rows of a closed incident, unless a recover is still owed."""
    if state not in CLOSED_STATES or not _aged(d, now, config):
        return False
    opened, recover = ds.get("open"), ds.get("recover")
    if d.kind == "open" and recover is not None and recover.state == "pending":
        return False
    if state == "resolved" and opened is not None and opened.state == "sent":
        if d.kind == "open":
            return recover is not None and recover.state in TERMINAL
        return _aged(opened, now, config)  # the recover goes together with its open row
    return True


def _forget(iid: str, d: DeliveryView) -> Forget:
    return Forget(iid, d.kind, _exp(d), "absent_or_terminal" if d.kind == "open" else None)


def _row_action(
    iid: str, d: DeliveryView, state: object, ds: Mapping[str, DeliveryView], now, config
) -> Action | None:
    if d.state == "pending":
        if not _row_ok(d):
            return Expire(iid, d.kind, UNRECOGNISED, _exp(d))
        if d.kind == "recover" and state != "resolved":
            return Withdraw(iid, d.kind, _exp(d))
        if _lifetime_over(d, now, config):
            return Expire(iid, d.kind, "lifetime", _exp(d))
        if now - max(d.created_at, d.next_attempt_at) >= config.pending_ttl_seconds:
            return Expire(iid, d.kind, "ttl", _exp(d))
        return None
    return _forget(iid, d) if _may_forget(d, state, ds, now, config) else None


def _orphan_action(
    iid: str, d: DeliveryView, ds: Mapping[str, DeliveryView], now: float, config: DeliveryConfig
) -> Action | None:
    if d.state == "pending":
        return Expire(iid, d.kind, "incident_missing", _exp(d))
    recover = ds.get("recover")
    blocked = d.kind == "open" and recover is not None and recover.state == "pending"
    return _forget(iid, d) if _aged(d, now, config) and not blocked else None


def _plan_incident(
    iid: str,
    incident: IncidentView | None,
    review: ReviewView | None,
    ds: Mapping[str, DeliveryView],
    now: float,
    config: DeliveryConfig,
) -> list[Action]:
    if incident is None:  # pruned: nothing left to announce
        orphans = (_orphan_action(iid, d, ds, now, config) for _, d in sorted(ds.items()))
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
        actions.append(Enqueue(iid, "recover", math.ceil(now)))
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
    grouped: dict[str, dict[str, DeliveryView]] = {}
    for d in deliveries:
        if d.kind in KINDS and d.state in STATES:
            grouped.setdefault(d.incident_id, {})[d.kind] = d
    by_incident: dict[str, IncidentView] = {}
    for incident in incidents:  # the watermark only hides incidents that have no rows yet
        if incident.id in grouped or _eligible(incident, config):
            by_incident.setdefault(incident.id, incident)
    actions: list[Action] = []
    for iid in sorted(by_incident.keys() | grouped.keys()):
        actions.extend(
            _plan_incident(
                iid, by_incident.get(iid), reviews.get(iid), grouped.get(iid, {}), now, config
            )
        )
    return tuple(sorted(actions, key=lambda a: (a.incident_id, a.kind)))
