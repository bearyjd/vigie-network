"""Pure planner for incident notification deliveries.

No database, I/O, clock or environment: callers pass the current state and `now` (epoch seconds,
like `vigie_api.incident_decisions.attention`) and get back the actions to apply. Applying them
and feeding the result back yields no further actions (idempotent). The review mirror below
intentionally duplicates `attention()` instead of importing vigie_api; keep the two in step.

Rules: one `open` delivery per incident (dedup by incident+kind); acknowledged/expected incidents
are suppressed; a snooze defers the delivery to `snooze_until` (strictly-before is quiet, so
until == now is loud); an incident that closes before its open delivery went out expires it and
never gets a `recover`; only an incident whose open delivery was `sent` gets exactly one
`recover`; unknown states or statuses fail closed (Suppress `unrecognised_state`, never raise).
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

KINDS = ("open", "recover")
QUIET_STATUSES = frozenset({"acknowledged", "expected"})
CLOSED_STATES = frozenset({"resolved", "superseded"})
UNRECOGNISED = "unrecognised_state"


@dataclass(frozen=True)
class IncidentView:
    id: str
    state: str
    detected_at: float
    last_hour: int


@dataclass(frozen=True)
class ReviewView:
    status: str
    snooze_until: float | None


@dataclass(frozen=True)
class DeliveryView:
    incident_id: str
    kind: str
    state: str
    attempts: int
    next_attempt_at: float | None
    created_at: float


@dataclass(frozen=True)
class DeliveryConfig:
    max_attempts: int = 6
    backoff_base_seconds: int = 60
    backoff_cap_seconds: int = 3600
    pending_ttl_seconds: int = 86400


@dataclass(frozen=True)
class Enqueue:
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


Action = Enqueue | Suppress | Expire | Reschedule | Fail


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
    return Reschedule(delivery.incident_id, delivery.kind, now + backoff(delivery.attempts, config))


def _is_time(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _verdict(review: ReviewView | None, now: float) -> tuple[str, float | str | None]:
    """Mirror of `attention()` for an open incident: loud, quiet(reason), until(t) or unknown."""
    if review is None:
        return "loud", None
    if review.status in QUIET_STATUSES:
        return "quiet", review.status
    if review.status != "snoozed" or not _is_time(review.snooze_until):
        return "unknown", None
    if now < review.snooze_until:
        return "until", review.snooze_until
    return "loud", None


def _open_action(
    iid: str, state: str, review: ReviewView | None, d: DeliveryView | None, now: float
) -> Action | None:
    pending = d is not None and d.state == "pending"
    if d is not None and not pending:
        return None
    if state in CLOSED_STATES:
        return Expire(iid, "open", "resolved_before_send") if pending else None
    kind, detail = _verdict(review, now) if state == "open" else ("unknown", None)
    if kind == "unknown":
        return Suppress(iid, "open", UNRECOGNISED)
    if kind == "quiet":
        return Suppress(iid, "open", str(detail))
    if kind == "until":
        if d is None:
            return Enqueue(iid, "open", float(detail))
        if d.next_attempt_at is None or d.next_attempt_at < detail:
            return Reschedule(iid, "open", float(detail))
        return None
    return Enqueue(iid, "open", now) if d is None else None


def _ttl_expired(d: DeliveryView, now: float, config: DeliveryConfig) -> bool:
    reference = max(d.created_at, d.next_attempt_at or d.created_at)
    return d.state == "pending" and now - reference >= config.pending_ttl_seconds


def _plan_incident(
    iid: str,
    incident: IncidentView | None,
    review: ReviewView | None,
    ds: Mapping[str, DeliveryView],
    now: float,
    config: DeliveryConfig,
) -> list[Action]:
    if incident is None:
        return [
            Expire(iid, k, "incident_missing")
            for k, d in sorted(ds.items())
            if d.state == "pending"
        ]
    actions: list[Action] = []
    expired = {k for k, d in ds.items() if _ttl_expired(d, now, config)}
    actions.extend(Expire(iid, k, "ttl") for k in sorted(expired))
    if "open" not in expired:
        opened = _open_action(iid, incident.state, review, ds.get("open"), now)
        actions.extend([opened] if opened else [])
    announced = ds.get("open") is not None and ds["open"].state == "sent"
    if incident.state == "resolved" and announced and "recover" not in ds:
        actions.append(Enqueue(iid, "recover", now))
    return actions


def plan(
    incidents: Iterable[IncidentView],
    reviews: Mapping[str, ReviewView],
    deliveries: Iterable[DeliveryView],
    now: float,
    config: DeliveryConfig,
) -> tuple[Action, ...]:
    """Actions reconciling deliveries with incidents and reviews, sorted by (incident, kind)."""
    by_incident: dict[str, IncidentView] = {}
    for incident in incidents:
        by_incident.setdefault(incident.id, incident)
    grouped: dict[str, dict[str, DeliveryView]] = {}
    for d in deliveries:
        grouped.setdefault(d.incident_id, {})[d.kind] = d
    actions: list[Action] = []
    for iid in sorted(by_incident.keys() | grouped.keys()):
        actions.extend(
            _plan_incident(
                iid, by_incident.get(iid), reviews.get(iid), grouped.get(iid, {}), now, config
            )
        )
    return tuple(sorted(actions, key=lambda a: (a.incident_id, a.kind)))
