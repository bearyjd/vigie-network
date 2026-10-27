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
  whose open was `sent` gets exactly one `recover` row per delivery life; a pending recover of an
  incident that is no longer resolved is Withdrawn (state `withdrawn`, never deleted: versions
  only grow), and a later resolution Revives that row; the attempt budget (`attempts`) and the
  lifetime (`created_at`) are cumulative for the whole life of a delivery_id, so a flapping
  detector cannot raise the number of sends past `max_attempts`;
* an incident behind `eligible_since` that has NO rows is ignored; one with rows is managed;
* an incident's rows are Forgotten ALL TOGETHER, in one pass, only when the incident is closed or
  missing, no recover is owed, and every row is terminal and older than `retention_seconds`
  (by `updated_at`); a half-forgotten incident would re-announce when it reopens;
* unknown states or statuses and non-finite or non-numeric data fail closed
  (`unrecognised_state`, never raise); a bad `now` raises ValueError.

CONCURRENCY CONTRACT. Unit 4b reads the incident set (the COMPLETE current set; skip the pass if
that read fails) AND the delivery rows, runs `plan()` and applies every action inside ONE
`BEGIN IMMEDIATE` transaction, using the statements in `vigie_pipeline.delivery_sql`.

SENDER LEASE. The sender CLAIMs a due `pending` row (the only way to transmit: it moves the row to
`sending`, counts the attempt and puts the lease end in `next_attempt_at`; the lease is half-open,
at `next_attempt_at == now` it has lapsed), transmits outside any transaction, then COMPLETEs with
the claimed version. The database allows one live claim per delivery_id and fences every write by
version, but only the SENDER CONTRACT keeps two transmissions from overlapping: a hard network
timeout no longer than `transmit_deadline_seconds`, a call to `may_transmit()` right before the
network call (abort without transmitting if it is false); recording the result before the lease
lapses is what avoids a duplicate (a late completion is harmless to the table, being fenced by
`(row_id, version)`); `lease_seconds >= 2 * transmit_deadline_seconds` then guarantees a
contract-abiding sender is done before any Reclaim. Sender and planner must share one clock. A
sender that violates its timeout can cause a duplicate (the receiver cannot detect it). The
planner NEVER touches a live `sending` row and an announcement in flight counts as not yet sent
(no recover until `sent`; no Forget while any row of the incident is `sending` or `pending`). A
lapsed lease means we cannot know whether the send happened, so the normal cancellation rules run
first (lifetime, missing incident, a resolved or superseded incident for an open, a non-resolved
incident for a recover); only otherwise Reclaim (back to `pending` after a backoff; `attempts`
already counted) or Fail past the budget. Delivery is at least once, and a cancelled announcement
is never retransmitted. Rows are fenced by `row_id`, an AUTOINCREMENT incarnation token, and
`version`, a plain counter (see delivery_sql).

`expected` is an assertion: None means the row must not exist (INSERT OR IGNORE), otherwise
Expected(state, attempts, version, row_id) of the row planned against. Each action is one
conditional statement that bumps `version` and sets `updated_at`; anything but exactly one
affected row is a bug: log it and roll the whole pass back. A Forget of an `open` row carries
`sibling_recover='absent_or_terminal'`: its DELETE refuses while a recover row is pending or
sending. Times in actions are integer epoch seconds. `expected`/`sibling_recover` are excluded
from dataclass equality so tests compare actions by meaning and assert them separately.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping

from vigie_pipeline.delivery_types import (  # noqa: F401 - re-exported
    CLOSED_STATES,
    KINDS,
    QUIET_STATUSES,
    STATES,
    TERMINAL,
    UNRECOGNISED,
    Action,
    DeliveryConfig,
    DeliveryView,
    Enqueue,
    Expected,
    Expire,
    Fail,
    Forget,
    IncidentView,
    Reclaim,
    Requeue,
    Reschedule,
    ReviewView,
    Revive,
    Suppress,
    Withdraw,
    tick_ceil,
    tick_floor,
)
from vigie_pipeline.delivery_types import is_number as _num


def _exp(d: DeliveryView) -> Expected:
    return Expected(d.state, d.attempts, d.version, d.row_id)


def delivery_id(incident_id: str, kind: str) -> str:
    """Stable id: first 32 hex chars of sha256 over `incident_id`, a newline, then `kind`."""
    return hashlib.sha256(f"{incident_id}\n{kind}".encode()).hexdigest()[:32]


def backoff(attempts: int, config: DeliveryConfig) -> int:
    """Seconds to wait after the `attempts`-th failure: base, 2*base, 4*base ... capped."""
    doubling = 2 ** min(max(attempts - 1, 0), 32)
    return min(config.backoff_base_seconds * doubling, config.backoff_cap_seconds)


def may_transmit(claimed_at: float, now: float, config: DeliveryConfig) -> bool:
    """The sender asks this right before the network call. Past the deadline it must abort without
    transmitting (and record a failed attempt): the lease then still covers a send that started in
    time and lasted at most `transmit_deadline_seconds` (the sender's hard timeout)."""
    if not (_num(claimed_at) and _num(now)):
        return False
    return tick_floor(now) - claimed_at < config.transmit_deadline_seconds


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


def _retarget(
    d: DeliveryView, target: int, snoozed: bool, now: float, config: DeliveryConfig
) -> Action | None:
    """A pending open against the verdict's time `target` (`now` when loud). The row is due at the
    verdict, but never before its cumulative backoff, and never later than that: a cleared or
    shortened snooze pulls it in. A snooze that ends later pushes it out."""
    floor = tick_ceil(now)
    if d.attempts > 0:
        floor = max(floor, math.ceil(d.updated_at) + backoff(d.attempts, config))
    want = max(target, floor)
    if d.next_attempt_at > want or (snoozed and d.next_attempt_at < target):
        return Reschedule(d.incident_id, "open", want, _exp(d))
    return None


def _lifetime_over(d: DeliveryView, now: float, config: DeliveryConfig) -> bool:
    return now - d.created_at > config.retention_seconds


def _revive(d: DeliveryView, target: int, now: float, config: DeliveryConfig, make: type):
    """Bring a suppressed (Requeue) or withdrawn (Revive) row back, within its cumulative attempt
    budget and its lifetime; an earlier backoff is waited out."""
    nxt_ok = d.next_attempt_at is None or _num(d.next_attempt_at)
    numbers = (d.attempts, d.created_at, d.updated_at, d.version)
    if not (nxt_ok and all(_num(v) for v in numbers) and d.attempts >= 0):
        return None  # malformed row: cannot prove the budget, stay as it is
    if d.attempts >= config.max_attempts:
        return Fail(d.incident_id, d.kind, "max_attempts", _exp(d))
    if _lifetime_over(d, now, config):
        return Expire(d.incident_id, d.kind, "lifetime", _exp(d))
    if d.next_attempt_at is not None and (d.attempts > 0 or make is Revive):
        target = max(target, math.ceil(d.next_attempt_at))
    return make(d.incident_id, d.kind, target, _exp(d))


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
    target = math.ceil(detail) if kind == "until" else tick_ceil(now)
    if d is not None and d.state == "suppressed":
        return _revive(d, target, now, config, Requeue) if kind in ("loud", "until") else None
    if kind in ("unknown", "quiet"):
        reason = UNRECOGNISED if kind == "unknown" else str(detail)
        return Suppress(iid, "open", reason, expected=_exp(d) if d else None)
    if d is None:
        return Enqueue(iid, "open", target)
    return _retarget(d, target, kind == "until", now, config)


def _row_ok(d: DeliveryView) -> bool:
    numbers = (d.next_attempt_at, d.created_at, d.updated_at, d.version)
    return _num(d.attempts) and d.attempts >= 0 and all(_num(v) for v in numbers)


def _aged(d: DeliveryView, now: float, config: DeliveryConfig) -> bool:
    return _num(d.updated_at) and now - d.updated_at > config.retention_seconds


def _forget_all(
    iid: str, ds: Mapping[str, DeliveryView], now: float, config: DeliveryConfig
) -> list[Action]:
    """All-or-nothing: an incident's rows go together, and only when every one is terminal and
    older than retention (the dedup memory of a half-forgotten incident would re-announce it)."""
    rows = [d for _, d in sorted(ds.items())]
    if not rows or any(d.state not in TERMINAL or not _aged(d, now, config) for d in rows):
        return []
    sibling = "absent_or_terminal"
    return [Forget(iid, d.kind, _exp(d), sibling if d.kind == "open" else None) for d in rows]


def _lease_action(
    iid: str,
    d: DeliveryView,
    state: object,
    review: ReviewView | None,
    now: float,
    config: DeliveryConfig,
    missing: bool = False,
) -> Action | None:
    """A `sending` row belongs to its sender: hands off while the lease is live ([claim, claim +
    lease): at `next_attempt_at == now` it has lapsed). Once it lapsed we cannot know whether the
    send happened, so the normal cancellation rules run first (a lapsed claim counts as unsent:
    it is never retransmitted for a cancelled announcement); an open then meets the current
    decision exactly as a pending row would (ack/expected: Suppress; a snooze: back to pending no
    earlier than its end); only otherwise is it reclaimed."""
    if not _row_ok(d):
        return Expire(iid, d.kind, UNRECOGNISED, _exp(d))
    if d.next_attempt_at > tick_floor(now):  # a lease lapses at its end, never before
        return None
    if _lifetime_over(d, now, config):
        return Expire(iid, d.kind, "lifetime", _exp(d))
    if missing:
        return Expire(iid, d.kind, "incident_missing", _exp(d))
    if d.kind == "open" and state in CLOSED_STATES:
        return Expire(iid, d.kind, "resolved_before_send", _exp(d))
    if d.kind == "recover" and state != "resolved":
        return Withdraw(iid, d.kind, _exp(d))
    if d.attempts >= config.max_attempts:
        return Fail(iid, d.kind, "max_attempts", _exp(d))
    due = tick_ceil(now) + backoff(d.attempts, config)
    if d.kind == "open":
        verdict, detail = _verdict(review, now) if state == "open" else ("unknown", None)
        if verdict in ("quiet", "unknown"):
            reason = UNRECOGNISED if verdict == "unknown" else str(detail)
            return Suppress(iid, "open", reason, due, _exp(d))
        if verdict == "until":
            due = max(due, math.ceil(detail))
    return Reclaim(iid, d.kind, due, _exp(d))


def _row_action(
    iid: str,
    d: DeliveryView,
    state: object,
    review: ReviewView | None,
    now: float,
    config: DeliveryConfig,
) -> Action | None:
    """Pending and sending rows; the others are inert until a verdict or a Forget touches them."""
    if d.state == "sending":
        return _lease_action(iid, d, state, review, now, config)
    if d.state != "pending":
        return None
    if not _row_ok(d):
        return Expire(iid, d.kind, UNRECOGNISED, _exp(d))
    if d.kind == "recover" and state != "resolved":
        return Withdraw(iid, d.kind, _exp(d))
    if d.attempts >= config.max_attempts:  # CLAIM refuses it, so do not wait for the ttl
        return Fail(iid, d.kind, "max_attempts", _exp(d))
    if _lifetime_over(d, now, config):
        return Expire(iid, d.kind, "lifetime", _exp(d))
    if now - max(d.created_at, d.next_attempt_at) >= config.pending_ttl_seconds:
        return Expire(iid, d.kind, "ttl", _exp(d))
    return None


def _recover_action(
    iid: str, ds: Mapping[str, DeliveryView], now: float, config: DeliveryConfig
) -> Action | None:
    """The recover a resolved incident with a sent open is owed, if its row is missing/withdrawn."""
    opened, recover = ds.get("open"), ds.get("recover")
    if opened is None or opened.state != "sent":
        return None
    if recover is None:
        return Enqueue(iid, "recover", tick_ceil(now))
    if recover.state == "withdrawn":
        return _revive(recover, tick_ceil(now), now, config, Revive)
    return None


def _plan_incident(
    iid: str,
    incident: IncidentView | None,
    review: ReviewView | None,
    ds: Mapping[str, DeliveryView],
    now: float,
    config: DeliveryConfig,
) -> list[Action]:
    if incident is None:  # pruned: nothing left to announce
        rows = sorted(ds.items())
        live = [
            Expire(iid, k, "incident_missing", _exp(d))
            if d.state == "pending"
            else _lease_action(iid, d, None, None, now, config, missing=True)
            for k, d in rows
            if d.state in ("pending", "sending")
        ]
        live = [a for a in live if a]
        return live or _forget_all(iid, ds, now, config)
    state = incident.state if _num(incident.detected_at) else None
    rows = (_row_action(iid, d, state, review, now, config) for _, d in sorted(ds.items()))
    actions = [a for a in rows if a]
    if "open" not in {a.kind for a in actions}:
        opened = _open_action(iid, state, review, ds.get("open"), now, config)
        actions.extend([opened] if opened else [])
    recover = _recover_action(iid, ds, now, config) if state == "resolved" else None
    actions.extend([recover] if recover else [])
    if state in CLOSED_STATES and not actions:  # nothing pending, nothing owed
        return _forget_all(iid, ds, now, config)
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
