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

import json
import logging
import math
import sqlite3
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import datetime

from vigie_ingest.db import immediate
from vigie_pipeline.baselines_dns import DnsBaselineConfig
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
from vigie_pipeline.delivery_types import (
    DEFAULT_DETECTORS,
    OPEN_ONLY_DETECTORS,
    tick_ceil,
    tick_floor,
)
from vigie_pipeline.detectors import DNS_DEVIATION
from vigie_pipeline.logs import log
from vigie_pipeline.monitoring_dns import dns_notice_deliverable
from vigie_pipeline.overrides import read_decisions

logger = logging.getLogger("vigie_pipeline")
DEFAULT_MAX_PER_RUN = 20
DEFAULT_MAX_ABANDONED = 2
DEFAULT_DRAIN_BUDGET = 60
DNS_DUE_SCAN_ROWS = 128
_DNS_DUE_CURSOR = "dns_delivery_scan_cursor"
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
        return {r[0]: ReviewView(r[1], r[2]) for r in read_decisions(ro)}
    except sqlite3.Error as exc:
        raise DecisionsUnavailable(str(exc)) from exc


def _plan_pass(
    inv,
    ro,
    config: DeliveryConfig,
    clock: Callable[[], float],
    detectors: frozenset[str],
    held: frozenset[str],
    held_incidents: frozenset[str],
) -> tuple[int, float]:
    """Returns (actions applied, the pass's `now`); raises DecisionsUnavailable or PassError.

    Every incident is read, but one whose detector is not allowlisted is planned as FROZEN: no
    open/recover row is ever created for it, its pending and lapsed rows expire
    (`incident_missing`), and its rows are deleted only once it is closed (retention rule) or gone.
    A sent open is therefore not followed by a recover while its detector stays off the list.
    Held incidents and their existing deliveries are skipped."""
    with immediate(inv):
        now = clock()  # after BEGIN IMMEDIATE: never older than the state it plans against
        rows = inv.execute(
            "SELECT id,state,detected_at,detector FROM monitoring_incidents"
        ).fetchall()
        incidents = [IncidentView(r[0], r[1], _epoch(r[2])) for r in rows]
        frozen = frozenset(r[0] for r in rows if r[3] not in detectors)
        open_only = frozenset(r[0] for r in rows if r[3] in OPEN_ONLY_DETECTORS)
        held_ids = frozenset(r[0] for r in rows if r[3] in held or r[0] in held_incidents) - frozen
        every = inv.execute(f"SELECT {_ROW} FROM incident_deliveries")  # noqa: S608
        deliveries = [_delivery(r) for r in every]
        reviews = _read_reviews(ro)
        actions = plan(
            incidents, reviews, deliveries, now, config, frozen, open_only, held=held_ids
        )
        apply_actions(inv, actions, now)
    return len(actions), now


def _claim(
    inv, row: DeliveryView, config, clock, *, ro=None, dns_policy=None
) -> tuple[DeliveryView, int] | None:
    with immediate(inv):
        now = clock()
        if dns_policy is not None and not dns_notice_deliverable(
            inv, ro, dns_policy, row.incident_id, row.kind, now
        ):
            return None
        if inv.execute(CLAIM, claim_params(row, now, config)).rowcount != 1:
            return None
    stamp = tick_ceil(now)
    claimed = replace(row, state="sending", attempts=row.attempts + 1, version=row.version + 1)
    return replace(claimed, next_attempt_at=stamp + config.lease_seconds), stamp


def _message(inv, ro, claimed: DeliveryView, include_label: bool) -> Message | None:
    row = inv.execute(
        "SELECT device_id,detector FROM monitoring_incidents WHERE id=?", (claimed.incident_id,)
    ).fetchone()
    if row is None:
        return None
    device = row[0]
    if claimed.kind != "open" and row[1] in OPEN_ONLY_DETECTORS:
        return None  # defence in depth: the planner never claims one, and none is ever built
    label = None  # only a name from device_overrides may be offered; never the raw device id
    if include_label and ro is not None:  # default: the label is not even read
        try:
            found = ro.execute(
                "SELECT name FROM device_overrides WHERE device_id=?", (device,)
            ).fetchone()
            label = found[0] if found and found[0] else None
        except sqlite3.Error:
            pass  # the label is a nicety: without it the message carries the alias
    did = delivery_id(claimed.incident_id, claimed.kind)
    return build_message(did, claimed.kind, claimed.incident_id, label, device, row[1])


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


def _send_one(
    inv, ro, publisher, row: DeliveryView, config, clock, slot, labels, dns_policy
) -> str:
    taken = _claim(
        inv, row, config, clock, **({"ro": ro, "dns_policy": dns_policy} if dns_policy else {})
    )
    if taken is None:
        return "skipped"
    claimed, stamp = taken
    message = _message(inv, ro, claimed, labels)
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
    inv,
    now: float,
    config: DeliveryConfig,
    limit: int,
    busy: frozenset[str],
    held: frozenset[str],
    held_incidents: frozenset[str],
    *,
    dns_range: tuple[int, int] | None = None,
) -> list[DeliveryView]:
    """Due pending rows with held and busy deliveries removed before applying the limit."""
    skip = ",".join("?" * len(busy))
    hold_filter = ""
    if held:
        placeholders = ",".join("?" * len(held))
        hold_filter = (
            " AND EXISTS (SELECT 1 FROM monitoring_incidents AS i"  # noqa: S608
            f" WHERE i.id=incident_deliveries.incident_id AND i.detector NOT IN ({placeholders}))"
        )
    incident_params = ()
    if held_incidents:
        hold_filter += " AND incident_id NOT IN (SELECT value FROM json_each(?))"
        incident_params = (json.dumps(sorted(held_incidents)),)
    dns_params = ()
    order = "next_attempt_at,row_id"
    if dns_range is not None:
        hold_filter += (
            " AND row_id>? AND row_id<=? AND EXISTS (SELECT 1 FROM monitoring_incidents i "
            "WHERE i.id=incident_deliveries.incident_id AND i.detector=?)"
        )
        dns_params = (*dns_range, DNS_DEVIATION)
        order = "row_id"
    rows = inv.execute(
        f"SELECT {_ROW} FROM incident_deliveries WHERE state='pending' AND next_attempt_at<=?"  # noqa: S608
        f" AND attempts<?{f' AND delivery_id NOT IN ({skip})' if busy else ''}{hold_filter}"
        f" ORDER BY {order} LIMIT ?",
        (
            tick_floor(now),
            config.max_attempts,
            *sorted(busy),
            *sorted(held),
            *incident_params,
            *dns_params,
            limit,
        ),
    )
    return [_delivery(r) for r in rows.fetchall()]


@dataclass(frozen=True)
class _DnsDuePage:
    rows: list[DeliveryView]
    end: int
    previous_cursor: str | None


def _due_dns(inv, now, config, busy, held_incidents) -> _DnsDuePage:
    """Page through real due rows so one set of unclaimable DNS notices cannot block the rest."""
    with immediate(inv):
        saved = inv.execute(
            "SELECT value FROM pipeline_meta WHERE key=?", (_DNS_DUE_CURSOR,)
        ).fetchone()
        after, end = 0, 0
        if saved is not None:
            try:
                after, end = map(int, saved[0].split(":"))
            except (ValueError, AttributeError):
                pass
        if not 0 < after < end <= 2**63 - 1:
            after = 0
            end = inv.execute("SELECT COALESCE(MAX(row_id),0) FROM incident_deliveries").fetchone()[
                0
            ]
        rows = _due(
            inv,
            now,
            config,
            DNS_DUE_SCAN_ROWS,
            busy,
            frozenset(),
            held_incidents,
            dns_range=(after, end),
        )
    return _DnsDuePage(rows, end, saved[0] if saved is not None else None)


def _advance_dns_page(inv, page: _DnsDuePage, examined: int) -> None:
    if page.rows and examined == 0:
        return
    last = page.rows[examined - 1].row_id if examined else 0
    more = examined < len(page.rows) or (len(page.rows) == DNS_DUE_SCAN_ROWS and last < page.end)
    updated = f"{last}:{page.end}" if more else None
    if updated == page.previous_cursor:
        return
    with immediate(inv):
        current = inv.execute(
            "SELECT value FROM pipeline_meta WHERE key=?", (_DNS_DUE_CURSOR,)
        ).fetchone()
        if (current[0] if current is not None else None) != page.previous_cursor:
            return
        if updated is None:
            inv.execute("DELETE FROM pipeline_meta WHERE key=?", (_DNS_DUE_CURSOR,))
        else:
            inv.execute(
                "INSERT INTO pipeline_meta VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (_DNS_DUE_CURSOR, updated),
            )


def _merge_due_rows(normal, dns_rows):
    """Preserve each stream's order and let its oldest available head go first."""
    pending = deque(normal)
    for row in dns_rows:
        while pending and (pending[0].next_attempt_at, pending[0].row_id) <= (
            row.next_attempt_at,
            row.row_id,
        ):
            yield pending.popleft()
        yield row
    yield from pending


def _drain(
    inv, ro, publisher, rows, config, clock, limits, labels, max_per_run, dns_rows, dns_policy
) -> tuple[Counter, int]:
    monotonic, max_abandoned, budget, should_stop = limits
    counts: Counter[str] = Counter()
    dns_examined = 0
    started = monotonic()
    for row in rows:
        if counts.total() - counts["skipped"] >= max_per_run:
            break
        if should_stop():  # a stop request: only the in-flight claim (already finished) completes
            log(logger, logging.INFO, "delivery_drain_stopped")
            break
        if monotonic() - started >= budget:  # before EVERY claim attempt, skipped ones included
            log(logger, logging.WARNING, "delivery_drain_budget_spent", budget=budget)
            break  # nothing more is claimed: the pipeline pass must stay short
        slot = _reserve(max_abandoned, delivery_id(row.incident_id, row.kind))
        if slot is None:
            break  # reserved BEFORE the claim, so a dead transport burns no attempts
        is_dns = row.row_id in dns_rows
        dns_examined += is_dns
        if slot is _BUSY:
            continue  # a worker started since the SELECT still holds this very delivery
        try:
            policy = dns_policy if is_dns else None
            outcome = _send_one(inv, ro, publisher, row, config, clock, slot, labels, policy)
        finally:
            _release(slot)
        counts[outcome] += 1
        if outcome == "timeout":
            break  # the transport is wedged: do not strand more worker threads this run
    return counts, dns_examined


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
    include_label: bool = False,
    should_stop: Callable[[], bool] = lambda: False,
    detectors: Iterable[str] = DEFAULT_DETECTORS,
    held: frozenset[str] = frozenset(),
    held_incidents: frozenset[str] = frozenset(),
    dns_policy: DnsBaselineConfig | None = None,
) -> RunReport:
    """`overrides` is the READ-ONLY decision store connection (None: unavailable). `clock` stamps
    the database; `monotonic` (never steps back) measures the drain budget.
    `held` and `held_incidents` pause delivery for allowlisted detectors and incidents this run."""
    if isinstance(detectors, str) or not (detectors := frozenset(detectors)):
        raise ValueError("detectors must be a non-empty collection of detector ids")
    if drain_budget_seconds < config.transmit_deadline_seconds:
        raise ValueError("drain_budget must be at least the transmit deadline")
    held = detectors.intersection(held)
    dns_dispatch = dns_policy is not None and DNS_DEVIATION in detectors - held
    if DNS_DEVIATION in detectors and dns_policy is None:
        held |= {DNS_DEVIATION}
    try:
        planned, now = _plan_pass(inv, overrides, config, clock, detectors, held, held_incidents)
    except DecisionsUnavailable as exc:
        log(logger, logging.WARNING, "delivery_decisions_unavailable", error=str(exc))
        return RunReport(skipped="decisions_unavailable")
    busy = busy_deliveries()
    normal_held = held | {DNS_DEVIATION} if dns_dispatch else held
    rows = _due(inv, now, config, max_per_run, busy, normal_held, held_incidents)
    dns_rows = set()
    page = None
    if dns_dispatch:
        try:
            page = _due_dns(inv, now, config, busy, held_incidents)
        except sqlite3.DatabaseError as exc:
            log(logger, logging.WARNING, "dns_delivery_scan_failed", error=type(exc).__name__)
        else:
            dns_rows = {row.row_id for row in page.rows}
            rows = _merge_due_rows(rows, page.rows)
    counts, dns_examined = _drain(
        inv,
        overrides,
        publisher,
        rows,
        config,
        clock,
        (monotonic, max_abandoned, drain_budget_seconds, should_stop),
        include_label,
        max_per_run,
        dns_rows,
        dns_policy,
    )
    if page is not None:
        try:
            _advance_dns_page(inv, page, dns_examined)
        except sqlite3.DatabaseError as exc:
            log(logger, logging.WARNING, "dns_delivery_cursor_failed", error=type(exc).__name__)
    return RunReport(
        planned=planned,
        claimed=sum(counts.values()) - counts["skipped"],
        sent=counts["sent"],
        failed=counts["failed"] + counts["timeout"],
        aborted=counts["aborted"],
        lost=counts["lost"],
    )
