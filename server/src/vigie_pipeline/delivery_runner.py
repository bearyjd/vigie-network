"""Incident delivery runner (unit 4b): one planner pass, then a bounded sender drain.

It follows the SENDER CHECKLIST in docs/monitoring.md exactly:

* planner pass: ONE `BEGIN IMMEDIATE` on the pipeline DB; `now` is read after it; the COMPLETE
  incident set, every delivery row and the decisions (overrides.db, read-only) are read, `plan()`
  runs and each action is applied through `delivery_sql`; a statement that does not affect exactly
  one row rolls the whole pass back (`PassError`, raised to the caller). Without a readable
  decision store the whole run is skipped: nothing is planned and nothing is sent.
* drain: per due row a CLAIM in its own short transaction, `may_transmit` right before the
  publisher, the publish OUTSIDE any transaction under a hard wall timeout enforced here (a
  daemon worker thread that is abandoned at the deadline), then a COMPLETE in a short transaction
  fenced by the claim token. A hung publisher ends the drain for this run.

Each clock read is one call to `clock()`: plan pass, then per row claim, may_transmit, complete.
"""

from __future__ import annotations

import logging
import math
import sqlite3
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime

from vigie_ingest.db import immediate
from vigie_pipeline.delivery_plan import (
    DeliveryConfig,
    DeliveryView,
    IncidentView,
    ReviewView,
    delivery_id,
    may_transmit,
    plan,
)
from vigie_pipeline.delivery_publish import Message, Publisher, build_message
from vigie_pipeline.delivery_sql import (
    CLAIM,
    COMPLETE_SENT,
    apply_actions,
    claim_params,
    completion_params,
    failure_statement,
)
from vigie_pipeline.delivery_types import tick_ceil, tick_floor
from vigie_pipeline.logs import log

logger = logging.getLogger("vigie_pipeline")
DEFAULT_MAX_PER_RUN = 20
DEFAULT_MAX_ABANDONED = 2
DEFAULT_DRAIN_BUDGET = 60
LOG_WEDGED_EVERY = 20  # a wedged transport is logged on the first run and every 20th after
# Publish workers abandoned at their deadline and still running. Process-wide: it is the bound
# on stranded threads across runs. A worker that finishes late has its result discarded; only the
# claim that spawned it (already completed as a failure) could have used it.
_ABANDONED: dict[threading.Thread, str] = {}  # worker -> the delivery_id it is publishing
_ABANDONED_LOCK = threading.Lock()
_IN_FLIGHT = 0  # reserved publishes (claimed or about to be) that are not abandoned yet
_wedged_runs = 0
_ROW = "row_id,incident_id,kind,state,attempts,next_attempt_at,created_at,updated_at,version"


@dataclass(frozen=True)
class RunReport:
    planned: int = 0
    claimed: int = 0
    sent: int = 0
    failed: int = 0  # a failed attempt (retried or out of budget), including a timeout
    aborted: int = 0  # past the transmit deadline at the last moment: nothing was transmitted
    lost: int = 0  # the lease lapsed before the completion could be recorded
    skipped: str | None = None


class DecisionsUnavailable(Exception):
    pass


def _epoch(text: object) -> float:
    try:
        return int(datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp())
    except (ValueError, OverflowError):
        return math.nan  # the planner fails closed on a non-finite time


def _delivery(row: tuple) -> DeliveryView:
    return DeliveryView(
        incident_id=row[1], kind=row[2], state=row[3], attempts=row[4],
        next_attempt_at=row[5], created_at=row[6], updated_at=row[7], version=row[8], row_id=row[0],
    )  # fmt: skip


def _read_reviews(ro: sqlite3.Connection | None) -> dict[str, ReviewView]:
    if ro is None:
        raise DecisionsUnavailable("no decision store")
    try:
        rows = ro.execute("SELECT incident_id,status,snooze_until FROM incident_decisions")
        return {r[0]: ReviewView(r[1], r[2]) for r in rows.fetchall()}
    except sqlite3.Error as exc:
        raise DecisionsUnavailable(str(exc)) from exc


def _plan_pass(inv, ro, config: DeliveryConfig, clock: Callable[[], float]) -> tuple[int, float]:
    """Returns (actions applied, the pass's `now`); raises DecisionsUnavailable or PassError."""
    with immediate(inv):
        now = clock()  # after BEGIN IMMEDIATE: never older than the state it plans against
        incidents = [
            IncidentView(r[0], r[1], _epoch(r[2]))
            for r in inv.execute("SELECT id,state,detected_at FROM monitoring_incidents")
        ]
        every = inv.execute(f"SELECT {_ROW} FROM incident_deliveries")  # noqa: S608
        deliveries = [_delivery(r) for r in every]
        reviews = _read_reviews(ro)
        actions = plan(incidents, reviews, deliveries, now, config)
        apply_actions(inv, actions, now)
    return len(actions), now


def _claim(inv, row: DeliveryView, config, clock) -> tuple[DeliveryView, int] | None:
    with immediate(inv):
        now = clock()
        if inv.execute(CLAIM, claim_params(row, now, config)).rowcount != 1:
            return None
    stamp = tick_ceil(now)
    claimed = replace(row, state="sending", attempts=row.attempts + 1, version=row.version + 1)
    return replace(claimed, next_attempt_at=stamp + config.lease_seconds), stamp


def _message(inv, ro, claimed: DeliveryView) -> Message | None:
    row = inv.execute(
        "SELECT device_id FROM monitoring_incidents WHERE id=?", (claimed.incident_id,)
    ).fetchone()
    if row is None:
        return None
    device = row[0]
    label = None  # only a name from device_overrides may be offered; never the raw device id
    try:
        named = ro.execute("SELECT name FROM device_overrides WHERE device_id=?", (device,))
        found = named.fetchone() if ro is not None else None
        label = found[0] if found and found[0] else None
    except sqlite3.Error:
        pass  # the label is a nicety: without it the message carries the alias
    did = delivery_id(claimed.incident_id, claimed.kind)
    return build_message(did, claimed.kind, claimed.incident_id, label, device)


def _prune() -> None:
    for worker in [t for t in _ABANDONED if not t.is_alive()]:
        del _ABANDONED[worker]


def busy_deliveries() -> frozenset[str]:
    """delivery_ids that still have a live abandoned worker."""
    with _ABANDONED_LOCK:
        _prune()
        return frozenset(_ABANDONED.values())


def abandoned_count() -> int:
    """Abandoned publish workers still running (finished ones are dropped here)."""
    with _ABANDONED_LOCK:
        _prune()
        return len(_ABANDONED)


class _Slot:
    """One unit of publish capacity. Held until released, or converted into an abandoned worker."""

    held = True

    def __init__(self, delivery: str = "") -> None:
        self.delivery = delivery


_BUSY = _Slot()  # sentinel: this delivery already has a live abandoned worker
_BUSY.held = False


def _reserve(limit: int, delivery: str = "") -> _Slot | None:
    """Atomically take capacity BEFORE the CLAIM: in-flight plus still-running abandoned publishes
    never exceed `limit` (so it also bounds concurrent publishes across the process). None when
    full: the caller ends its drain without claiming anything. `_BUSY` when `delivery` still has a
    live abandoned worker: that row is skipped, never published twice concurrently."""
    global _IN_FLIGHT, _wedged_runs
    with _ABANDONED_LOCK:
        _prune()
        if delivery and delivery in _ABANDONED.values():
            return _BUSY
        running, active = len(_ABANDONED), _IN_FLIGHT
        if running + active < limit:
            _IN_FLIGHT += 1
            return _Slot(delivery)
        noisy = _wedged_runs % LOG_WEDGED_EVERY == 0
        _wedged_runs += 1
    if noisy:
        detail = (
            f"delivery transport wedged: {running} abandoned publishes still running, "
            f"{active} in flight"
        )
        log(logger, logging.ERROR, "delivery_transport_wedged", abandoned=running, detail=detail)
    return None


def _release(slot: _Slot) -> None:
    global _IN_FLIGHT
    with _ABANDONED_LOCK:
        if slot.held:
            slot.held = False
            _IN_FLIGHT -= 1


def _abandon(slot: _Slot, worker: threading.Thread) -> None:
    """The deadline expired: the reservation becomes an abandoned entry in one locked step."""
    global _IN_FLIGHT
    with _ABANDONED_LOCK:
        _ABANDONED[worker] = slot.delivery
        if slot.held:
            slot.held = False
            _IN_FLIGHT -= 1


def _publish(publisher: Publisher, message: Message, seconds: float, slot: _Slot) -> str:
    """'sent', 'failed' or 'timeout'. The publisher runs in a daemon thread that is abandoned at
    the deadline: a hard wall timeout that does not depend on the transport honouring one."""
    outcome: list[BaseException | None] = []

    def work() -> None:
        try:
            publisher.publish(message, timeout_seconds=seconds)
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - any failure is a failed attempt
            outcome.append(exc)

    worker = threading.Thread(target=work, name="vigie-delivery-publish", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive() or not outcome:
        _abandon(slot, worker)
        log(logger, logging.ERROR, "delivery_publish_timeout", delivery_id=message.delivery_id)
        return "timeout"
    if outcome[0] is not None:
        log(logger, logging.WARNING, "delivery_publish_failed", delivery_id=message.delivery_id,
            error=type(outcome[0]).__name__)  # fmt: skip
        return "failed"
    return "sent"


def _complete(inv, claimed: DeliveryView, ok: bool, config, clock) -> bool:
    with immediate(inv):
        now = clock()
        if ok:
            sql, params = COMPLETE_SENT, completion_params(claimed, now)
        else:
            sql, params = failure_statement(claimed, now, config)
        return inv.execute(sql, params).rowcount == 1


def _send_one(inv, ro, publisher, row: DeliveryView, config, clock, slot: _Slot) -> str:
    taken = _claim(inv, row, config, clock)
    if taken is None:
        return "skipped"
    claimed, stamp = taken
    message = _message(inv, ro, claimed)
    outcome = "failed"
    if message is None:
        log(logger, logging.WARNING, "delivery_incident_missing", row_id=claimed.row_id)
    elif not may_transmit(stamp, clock(), config):
        outcome = "aborted"
    else:
        outcome = _publish(publisher, message, config.transmit_deadline_seconds, slot)
    if not _complete(inv, claimed, outcome == "sent", config, clock):
        log(logger, logging.WARNING, "delivery_completion_lost", row_id=claimed.row_id)
        return "lost"
    return outcome


def _due(
    inv, now: float, config: DeliveryConfig, limit: int, busy: frozenset[str] = frozenset()
) -> list[DeliveryView]:
    """Due pending rows, oldest first. Busy deliveries are excluded BEFORE the LIMIT, so a row
    that owns a hung worker can never starve the others (the list is bounded by max_abandoned)."""
    skip = ",".join("?" * len(busy))
    rows = inv.execute(
        f"SELECT {_ROW} FROM incident_deliveries WHERE state='pending' AND next_attempt_at<=?"  # noqa: S608
        f" AND attempts<?{f' AND delivery_id NOT IN ({skip})' if busy else ''}"
        " ORDER BY next_attempt_at,row_id LIMIT ?",
        (tick_floor(now), config.max_attempts, *sorted(busy), limit),
    )
    return [_delivery(r) for r in rows.fetchall()]


def _drain(inv, ro, publisher, rows, config, clock, monotonic, max_abandoned, budget) -> Counter:
    counts: Counter[str] = Counter()
    started = monotonic()
    for row in rows:
        if monotonic() - started >= budget:  # before EVERY claim attempt, skipped ones included
            log(logger, logging.WARNING, "delivery_drain_budget_spent", budget=budget)
            break  # nothing more is claimed: the pipeline pass must stay short
        slot = _reserve(max_abandoned, delivery_id(row.incident_id, row.kind))
        if slot is None:
            break  # reserved BEFORE the claim, so a dead transport burns no attempts
        if slot is _BUSY:
            continue  # a worker started since the SELECT still holds this very delivery
        try:
            outcome = _send_one(inv, ro, publisher, row, config, clock, slot)
        finally:
            _release(slot)
        counts[outcome] += 1
        if outcome == "timeout":
            break  # the transport is wedged: do not strand more worker threads this run
    return counts


def run_delivery(
    inv: sqlite3.Connection,
    overrides: sqlite3.Connection | None,
    publisher: Publisher,
    config: DeliveryConfig,
    clock: Callable[[], float],
    *,
    max_per_run: int = DEFAULT_MAX_PER_RUN,
    max_abandoned: int = DEFAULT_MAX_ABANDONED,
    drain_budget_seconds: float = DEFAULT_DRAIN_BUDGET,
    monotonic: Callable[[], float] = time.monotonic,
) -> RunReport:
    """`overrides` is the READ-ONLY decision store connection (None: unavailable). `clock` stamps
    the database; `monotonic` (never steps back) measures the drain budget."""
    if drain_budget_seconds < config.transmit_deadline_seconds:
        raise ValueError("drain_budget must be at least the transmit deadline")
    try:
        planned, now = _plan_pass(inv, overrides, config, clock)
    except DecisionsUnavailable as exc:
        log(logger, logging.WARNING, "delivery_decisions_unavailable", error=str(exc))
        return RunReport(skipped="decisions_unavailable")
    rows = _due(inv, now, config, max_per_run, busy_deliveries())
    counts = _drain(
        inv,
        overrides,
        publisher,
        rows,
        config,
        clock,
        monotonic,
        max_abandoned,
        drain_budget_seconds,
    )
    return RunReport(
        planned=planned,
        claimed=sum(counts.values()) - counts["skipped"],
        sent=counts["sent"],
        failed=counts["failed"] + counts["timeout"],
        aborted=counts["aborted"],
        lost=counts["lost"],
    )
