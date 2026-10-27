"""Plain data for the delivery planner: states, views of the inputs, config and the actions.

See `vigie_pipeline.delivery_plan` for the rules and the concurrency contract.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

KINDS = ("open", "recover")
STATES = frozenset({"pending", "sending", "sent", "failed", "suppressed", "expired", "withdrawn"})
TERMINAL = frozenset({"sent", "failed", "suppressed", "expired", "withdrawn"})
QUIET_STATUSES = frozenset({"acknowledged", "expected"})
CLOSED_STATES = frozenset({"resolved", "superseded"})
UNRECOGNISED = "unrecognised_state"


def is_number(value: object) -> bool:
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
    lease_seconds: int = 300
    transmit_deadline_seconds: int = 30
    eligible_since: float | None = None

    def __post_init__(self) -> None:
        durations = (
            self.backoff_base_seconds,
            self.backoff_cap_seconds,
            self.pending_ttl_seconds,
            self.retention_seconds,
            self.lease_seconds,
            self.transmit_deadline_seconds,
        )
        if not all(is_number(v) and v > 0 for v in durations):
            raise ValueError("durations must be finite numbers > 0")
        for name in ("lease_seconds", "transmit_deadline_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
        if self.lease_seconds < 60:
            raise ValueError("lease_seconds must be at least 60")
        if self.transmit_deadline_seconds * 2 > self.lease_seconds:
            raise ValueError("a lease must cover twice the transmit deadline")
        if not is_number(self.max_attempts) or self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.backoff_cap_seconds < self.backoff_base_seconds:
            raise ValueError("backoff cap must be >= base")
        if self.eligible_since is not None and not is_number(self.eligible_since):
            raise ValueError("eligible_since must be a finite number or None")


@dataclass(frozen=True)
class Expected:
    """Precondition of a conditional update: the row's state, attempts and version when planned."""

    state: str
    attempts: int
    version: int


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
    """Mark a pending `recover` whose incident is no longer resolved as `withdrawn`."""

    incident_id: str
    kind: str
    expected: Expected | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Revive:
    """Bring a `withdrawn` recover back to pending. `attempts` and `created_at` are kept (the retry
    budget and the lifetime are cumulative for the whole life of the row) and `not_before` is not
    earlier than the row's own backoff; `version` only grows."""

    incident_id: str
    kind: str
    not_before: int
    expected: Expected | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Reclaim:
    """A `sending` row whose lease lapsed (the sender crashed): back to pending after a backoff.
    The claim already counted the attempt, so `attempts` is not incremented again."""

    incident_id: str
    kind: str
    next_attempt_at: int
    expected: Expected | None = field(default=None, compare=False)


Action = (
    Enqueue | Requeue | Suppress | Expire | Reschedule | Fail | Forget | Withdraw | Revive | Reclaim
)
