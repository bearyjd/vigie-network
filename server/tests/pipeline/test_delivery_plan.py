from __future__ import annotations

import dataclasses
import itertools
import math

import pytest
from delivery_sim import PassAborted, Store, apply_cas

from vigie_pipeline import delivery_sql as sql
from vigie_pipeline.delivery_plan import (
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
    backoff,
    delivery_id,
    may_transmit,
    plan,
)

NOW = 1_000_000
CFG = DeliveryConfig()
DAY = 86400


def inc(iid="i1", state="open", detected=NOW - 10):
    return IncidentView(id=iid, state=state, detected_at=detected)


def dv(
    kind="open",
    state="pending",
    iid="i1",
    attempts=0,
    nxt=NOW - 5,
    created=NOW - 5,
    upd=None,
    ver=0,
):
    upd = created if upd is None else upd
    return DeliveryView(iid, kind, state, attempts, nxt, created, upd, ver)


def run(incidents, reviews=None, deliveries=(), now=NOW, cfg=CFG):
    return plan(tuple(incidents), reviews or {}, tuple(deliveries), now, cfg)


def snooze(delta):
    return {"i1": ReviewView("snoozed", NOW + delta)}


# (a) loud open incident -> exactly one Enqueue, never a second
def test_new_open_incident_gets_one_open_enqueue():
    assert run([inc()]) == (Enqueue("i1", "open", NOW),)


@pytest.mark.parametrize("state", ["pending", "sent", "failed", "expired"])
def test_an_existing_open_delivery_blocks_a_second_enqueue(state):
    assert run([inc()], deliveries=[dv(state=state)]) == ()


def test_duplicate_incident_rows_still_enqueue_once():
    assert run([inc(), inc()]) == (Enqueue("i1", "open", NOW),)


# (b) quiet decisions suppress, recorded once
@pytest.mark.parametrize("status", ["acknowledged", "expected"])
def test_quiet_decisions_suppress_once(status):
    reviews = {"i1": ReviewView(status, None)}
    assert run([inc()], reviews) == (Suppress("i1", "open", status),)
    assert run([inc()], reviews, [dv(state="suppressed")]) == ()


def test_a_decision_made_while_pending_suppresses_the_pending_open():
    reviews = {"i1": ReviewView("acknowledged", None)}
    assert run([inc()], reviews, [dv()]) == (Suppress("i1", "open", "acknowledged"),)


def test_a_sent_open_is_not_touched_by_a_later_ack():
    reviews = {"i1": ReviewView("acknowledged", None)}
    assert run([inc()], reviews, [dv(state="sent")]) == ()


# (1) suppressed rows are re-evaluated: a cleared decision notifies
def test_ack_then_clear_requeues():
    assert run([inc()], deliveries=[dv(state="suppressed")]) == (Requeue("i1", "open", NOW),)


def test_ack_replaced_by_a_future_snooze_requeues_for_then():
    got = run([inc()], snooze(100), [dv(state="suppressed")])
    assert got == (Requeue("i1", "open", NOW + 100),)


def test_unrecognised_then_recognised_requeues():
    suppressed = [dv(state="suppressed")]
    assert run([inc(state="weird")], deliveries=suppressed) == ()
    assert run([inc()], deliveries=suppressed) == (Requeue("i1", "open", NOW),)
    bogus = {"i1": ReviewView("bogus", None)}
    assert run([inc()], bogus, suppressed) == ()
    assert run([inc()], {"i1": ReviewView("snoozed", None)}, suppressed) == ()


@pytest.mark.parametrize("status", ["acknowledged", "expected"])
def test_quiet_stays_quiet_without_duplicate_suppress(status):
    assert run([inc()], {"i1": ReviewView(status, None)}, [dv(state="suppressed")]) == ()


@pytest.mark.parametrize("state", ["resolved", "superseded"])
def test_closed_incident_with_suppressed_open_is_not_requeued(state):
    assert run([inc(state=state)], deliveries=[dv(state="suppressed")]) == ()


# (2) a cleared decision row (status None) is no decision, not garbage
def test_cleared_decision_row_is_loud():
    assert run([inc()], {"i1": ReviewView(None, None)}) == (Enqueue("i1", "open", NOW),)


def test_status_none_with_a_snooze_time_is_still_garbage():
    got = run([inc()], {"i1": ReviewView(None, NOW + 5)})
    assert got == (Suppress("i1", "open", "unrecognised_state"),)


# (c) snooze boundaries mirror attention(): strictly before snooze_until is quiet
@pytest.mark.parametrize(
    "delta,expected",
    [
        (1, Enqueue("i1", "open", NOW + 1)),
        (0, Enqueue("i1", "open", NOW)),  # until == now: expired, loud immediately
        (-1, Enqueue("i1", "open", NOW)),
    ],
)
def test_snooze_boundary(delta, expected):
    assert run([inc()], snooze(delta)) == (expected,)


def test_snoozed_incident_that_resolved_is_never_enqueued():
    assert run([inc(state="resolved")], snooze(100)) == ()


# (3) a pending open's not_before tracks the current verdict, both directions
@pytest.mark.parametrize(
    "review,attempts,nxt,expected",
    [
        (snooze(100), 0, NOW, Reschedule("i1", "open", NOW + 100)),  # later snooze
        (snooze(100), 0, NOW + 500, Reschedule("i1", "open", NOW + 100)),  # shorter snooze
        (snooze(100), 0, NOW + 100, None),
        ({}, 0, NOW + 100, Reschedule("i1", "open", NOW)),  # snooze cleared
        (snooze(0), 0, NOW + 100, Reschedule("i1", "open", NOW)),  # snooze just expired
        ({}, 0, NOW - 50, None),  # already due
        ({}, 2, NOW + 500, None),  # backoff after failures is kept
        (snooze(100), 2, NOW + 50, Reschedule("i1", "open", NOW + 100)),
        (snooze(100), 2, NOW + 500, None),
    ],
)
def test_pending_open_tracks_the_current_verdict(review, attempts, nxt, expected):
    got = run([inc()], review, [dv(attempts=attempts, nxt=nxt)])
    assert got == ((expected,) if expected else ())


# (d) resolved before send
@pytest.mark.parametrize("state", ["resolved", "superseded"])
def test_pending_open_expires_when_the_incident_closes(state):
    assert run([inc(state=state)], deliveries=[dv()]) == (
        Expire("i1", "open", "resolved_before_send"),
    )


@pytest.mark.parametrize("deliveries", [[], [dv(state="suppressed")], [dv(state="expired")]])
def test_never_announced_incident_gets_no_recover(deliveries):
    assert run([inc(state="resolved")], deliveries=deliveries) == ()


# (e)/(4) recover only for a resolved incident whose open was sent, exactly once
def test_sent_open_then_resolved_enqueues_one_recover():
    assert run([inc(state="resolved")], deliveries=[dv(state="sent")]) == (
        Enqueue("i1", "recover", NOW),
    )


@pytest.mark.parametrize("state", ["pending", "sent", "failed", "expired", "suppressed"])
def test_recover_is_not_enqueued_twice(state):
    ds = [dv(state="sent"), dv(kind="recover", state=state)]
    assert run([inc(state="resolved")], deliveries=ds) == ()


def test_superseded_incident_gets_no_recover():
    assert run([inc(state="superseded")], deliveries=[dv(state="sent")]) == ()


def test_still_open_incident_gets_no_recover_even_if_the_device_went_silent():
    assert run([inc()], deliveries=[dv(state="sent")]) == ()


@pytest.mark.parametrize("state", ["failed", "expired"])
def test_unsent_open_never_triggers_recover(state):
    assert run([inc(state="resolved")], deliveries=[dv(state=state)]) == ()


# (f) ttl
@pytest.mark.parametrize(
    "age,expected",
    [
        (DAY - 1, ()),
        (DAY, (Expire("i1", "open", "ttl"),)),
        (DAY + 1, (Expire("i1", "open", "ttl"),)),
    ],
)
def test_pending_ttl_boundary(age, expected):
    assert run([inc()], deliveries=[dv(created=NOW - age, nxt=NOW - age)]) == expected


def test_ttl_applies_to_recover_too():
    ds = [dv(state="sent"), dv(kind="recover", created=NOW - DAY, nxt=NOW - DAY)]
    assert run([inc(state="resolved")], deliveries=ds) == (Expire("i1", "recover", "ttl"),)


def test_ttl_counts_from_the_scheduled_time_for_a_snoozed_delivery():
    d = dv(created=NOW - 200000, nxt=NOW - 10)
    assert run([inc()], deliveries=[d]) == ()
    d = dv(created=NOW - 200000, nxt=NOW - DAY)
    assert run([inc()], deliveries=[d]) == (Expire("i1", "open", "ttl"),)


def test_non_pending_deliveries_never_expire_by_ttl():
    assert run([inc()], deliveries=[dv(state="sent", created=NOW - 10**5)]) == ()


def test_ttl_is_configurable():
    cfg = DeliveryConfig(pending_ttl_seconds=10)
    assert run([inc()], deliveries=[dv(created=NOW - 10, nxt=NOW - 10)], cfg=cfg) == (
        Expire("i1", "open", "ttl"),
    )
    assert run([inc()], deliveries=[dv(created=NOW - 9, nxt=NOW - 9)], cfg=cfg) == ()


# (6) retention
RET = CFG.retention_seconds


@pytest.mark.parametrize("state", ["sent", "failed", "suppressed", "expired"])
@pytest.mark.parametrize("kind", ["open", "recover"])
def test_terminal_rows_of_a_closed_incident_are_forgotten_past_retention(state, kind):
    old = dv(kind, state, created=NOW - RET - 1)
    edge = dv(kind, state, created=NOW - RET)
    assert run([inc(state="superseded")], deliveries=[old]) == (Forget("i1", kind),)
    assert run([inc(state="superseded")], deliveries=[edge]) == ()
    if (kind, state) != ("open", "sent"):  # a sent open of a resolved incident owes a recover
        assert run([inc(state="resolved")], deliveries=[old]) == (Forget("i1", kind),)
        assert run([inc(state="resolved")], deliveries=[edge]) == ()


@pytest.mark.parametrize("state", ["sent", "failed", "expired"])
def test_rows_of_a_still_open_incident_are_kept_so_it_never_re_announces(state):
    assert run([inc()], deliveries=[dv(state=state, created=NOW - 10 * RET)]) == ()


def test_retention_counts_from_updated_at():
    d = dv(state="sent", created=NOW - 10 * RET, upd=NOW - RET)
    assert run([inc(state="resolved")], deliveries=[d]) == (Enqueue("i1", "recover", NOW),)


def test_an_old_sent_open_of_a_just_resolved_incident_still_gets_its_recover():
    d = dv(state="sent", created=NOW - 31 * DAY)
    assert run([inc(state="resolved")], deliveries=[d]) == (Enqueue("i1", "recover", NOW),)


@pytest.mark.parametrize("state", ["pending"])
def test_open_row_is_kept_while_the_recover_is_not_terminal(state):
    old = NOW - 10 * RET
    ds = [dv(state="sent", created=old), dv("recover", state, created=NOW - 5)]
    assert run([inc(state="resolved")], deliveries=ds) == ()


@pytest.mark.parametrize("state", ["sent", "failed", "suppressed", "expired"])
def test_open_and_recover_rows_go_together_once_the_recover_is_terminal(state):
    old = NOW - RET - 1
    ds = [dv(state="sent", created=old), dv("recover", state, created=old)]
    assert run([inc(state="resolved")], deliveries=ds) == (
        Forget("i1", "open"),
        Forget("i1", "recover"),
    )
    young = [dv(state="sent", created=old), dv("recover", state, created=NOW - 5)]
    assert run([inc(state="resolved")], deliveries=young) == ()  # all or nothing


def test_an_old_recover_is_kept_while_its_open_row_is_still_young():
    ds = [dv(state="sent", created=NOW - 5), dv("recover", "sent", created=NOW - RET - 1)]
    assert run([inc(state="resolved")], deliveries=ds) == ()


def test_orphans_expire_when_pending_and_age_out_when_terminal():
    assert run([], deliveries=[dv()]) == (Expire("i1", "open", "incident_missing"),)
    for state in ("sent", "failed", "suppressed", "expired"):
        assert run([], deliveries=[dv(state=state)]) == ()
        assert run([], deliveries=[dv(state=state, created=NOW - RET)]) == ()
        old = dv(state=state, created=NOW - RET - 1)
        assert run([], deliveries=[old]) == (Forget("i1", "open"),)


def test_retention_is_configurable():
    cfg = DeliveryConfig(retention_seconds=100)
    old = dv(state="sent", created=NOW - 101)
    assert run([inc(state="superseded")], deliveries=[old], cfg=cfg) == (Forget("i1", "open"),)


# (7) enable watermark
def test_incidents_older_than_the_watermark_are_ignored():
    cfg = DeliveryConfig(eligible_since=NOW - 5)
    assert run([inc(detected=NOW - 6)], cfg=cfg) == ()
    assert run([inc(detected=NOW - 6, state="resolved")], cfg=cfg) == ()
    assert run([inc(detected=NOW - 5)], cfg=cfg) == (Enqueue("i1", "open", NOW),)
    assert run([inc(detected=NOW - 6)], cfg=DeliveryConfig()) == (Enqueue("i1", "open", NOW),)


def test_an_incident_with_rows_is_managed_normally_whatever_the_watermark():
    hidden = DeliveryConfig(eligible_since=NOW)
    old = NOW - 2 * RET
    owed = [dv(state="sent", created=old)]
    assert run([inc(state="resolved", detected=old)], deliveries=owed, cfg=hidden) == (
        Enqueue("i1", "recover", NOW),
    )
    stale = [dv(created=NOW - DAY, nxt=NOW - DAY)]
    assert run([inc(detected=old)], deliveries=stale, cfg=hidden) == (Expire("i1", "open", "ttl"),)
    quiet = {"i1": ReviewView("acknowledged", None)}
    assert run([inc(detected=old)], quiet, [dv()], cfg=hidden) == (
        Suppress("i1", "open", "acknowledged"),
    )
    assert run([inc(detected=old)], deliveries=[dv(state="suppressed")], cfg=hidden) == (
        Requeue("i1", "open", NOW),
    )


def test_disable_enable_raise_and_lower_the_watermark():
    old, new = inc("old", detected=NOW - 1000), inc("new", detected=NOW - 10)
    on = DeliveryConfig(eligible_since=NOW - 500)
    first = run([old, new], cfg=on)
    assert first == (Enqueue("new", "open", NOW),)
    ds = apply((), first, NOW)
    sent = tuple(dataclasses.replace(d, state="sent") for d in ds)
    assert run([old, new], deliveries=sent, cfg=on) == ()
    raised = DeliveryConfig(eligible_since=NOW)  # nothing without rows is admitted
    assert run([old, new], deliveries=ds, cfg=raised) == ()
    done = [old, inc("new", "resolved", NOW - 10)]  # but an owed recover is never dropped
    assert run(done, deliveries=sent, cfg=raised) == (Enqueue("new", "recover", NOW),)
    lowered = DeliveryConfig(eligible_since=NOW - 5000)  # nothing already sent re-announces
    assert run([old, new], deliveries=sent, cfg=lowered) == (Enqueue("old", "open", NOW),)


def test_a_partial_incident_list_expires_pending_rows():
    assert run([inc("other")], deliveries=[dv()]) == (
        Expire("i1", "open", "incident_missing"),
        Enqueue("other", "open", NOW),
    )


# (g) backoff
@pytest.mark.parametrize(
    "attempts,seconds",
    [(0, 60), (1, 60), (2, 120), (3, 240), (6, 1920), (7, 3600), (50, 3600), (10**6, 3600)],
)
def test_backoff_doubles_from_base_and_caps(attempts, seconds):
    assert backoff(attempts, CFG) == seconds


def test_backoff_respects_config():
    cfg = DeliveryConfig(backoff_base_seconds=10, backoff_cap_seconds=25)
    assert [backoff(n, cfg) for n in (1, 2, 3, 4)] == [10, 20, 25, 25]


def _failed(attempts, now=NOW, cfg=CFG):
    return sql.failure_statement(dv(attempts=attempts, ver=3), now, cfg)


def test_a_failed_send_retries_with_backoff_until_the_budget_then_fails():
    retry, params = _failed(1)
    assert (retry, params["next_attempt_at"]) == (sql.COMPLETE_RETRY, NOW + 60)
    assert _failed(5)[1]["next_attempt_at"] == NOW + 960
    for attempts in (6, 9):
        statement, params = _failed(attempts)
        assert statement == sql.COMPLETE_FAILED and "next_attempt_at" not in params
    assert _failed(1, NOW + 0.5)[1]["next_attempt_at"] == NOW + 61


def test_a_failure_statement_applies_to_the_claimed_row_in_real_sqlite():
    for attempts, state in ((1, "pending"), (CFG.max_attempts, "failed")):
        store = Store([dv(nxt=NOW - 1, attempts=attempts - 1)])
        claimed = _claim(store, ("i1", "open"), NOW)
        assert claimed.attempts == attempts
        statement, params = sql.failure_statement(claimed, NOW + 1, CFG)
        assert store.run(statement, params) == 1
        assert store.rows()[("i1", "open")].state == state


def test_delivery_id_is_stable_distinct_and_hex():
    a = delivery_id("i1", "open")
    assert a == delivery_id("i1", "open") and len(a) == 32
    int(a, 16)
    assert len({a, delivery_id("i1", "recover"), delivery_id("i2", "open")}) == 3
    assert delivery_id("a", "bopen") != delivery_id("ab", "open")  # no concatenation collision


# (8) config validation
@pytest.mark.parametrize(
    "kwargs",
    [
        {"backoff_base_seconds": 0},
        {"backoff_base_seconds": -1},
        {"backoff_base_seconds": float("nan")},
        {"backoff_cap_seconds": float("inf")},
        {"backoff_base_seconds": 100, "backoff_cap_seconds": 99},
        {"pending_ttl_seconds": 0},
        {"retention_seconds": 0},
        {"retention_seconds": "30d"},
        {"max_attempts": 0},
        {"eligible_since": float("nan")},
        {"eligible_since": "2026-01-01"},
    ],
)
def test_invalid_config_is_refused(kwargs):
    with pytest.raises(ValueError):
        DeliveryConfig(**kwargs)


def test_boundary_config_is_accepted():
    DeliveryConfig(max_attempts=1, backoff_base_seconds=5, backoff_cap_seconds=5)


# (i) fail closed
@pytest.mark.parametrize("state", ["", "OPEN", "weird", "reopened"])
def test_unknown_incident_state_is_suppressed(state):
    assert run([inc(state=state)]) == (Suppress("i1", "open", "unrecognised_state"),)
    assert run([inc(state=state)], deliveries=[dv(state="suppressed")]) == ()
    assert run([inc(state=state)], deliveries=[dv()]) == (
        Suppress("i1", "open", "unrecognised_state"),
    )


@pytest.mark.parametrize(
    "review",
    [ReviewView("weird", None), ReviewView("", None), ReviewView("snoozed", None)],
)
def test_unknown_or_malformed_review_is_suppressed(review):
    assert run([inc()], {"i1": review}) == (Suppress("i1", "open", "unrecognised_state"),)


BAD = [
    "2026-01-01T00:00:00Z",
    None,
    math.nan,
    math.inf,
    -math.inf,
    1e400,
    10**400,
    -(10**400),
    True,
    "5",
]
U = "unrecognised_state"


@pytest.mark.parametrize("bad", BAD)
def test_bad_incident_time_fails_closed(bad):
    assert run([inc(detected=bad)]) == (Suppress("i1", "open", U),)
    cfg = DeliveryConfig(eligible_since=NOW)
    run([inc(detected=bad)], cfg=cfg)  # the watermark never raises on it either


@pytest.mark.parametrize("bad", BAD)
def test_bad_snooze_time_fails_closed(bad):
    got = run([inc()], {"i1": ReviewView("snoozed", bad)})
    assert got == (Suppress("i1", "open", U),)


@pytest.mark.parametrize(
    "field", ["attempts", "next_attempt_at", "created_at", "updated_at", "version"]
)
@pytest.mark.parametrize("bad", BAD + [-1])
def test_pending_row_with_a_bad_number_is_expired_not_stuck(field, bad):
    if field != "attempts" and bad == -1:
        return
    d = dataclasses.replace(dv(), **{field: bad})
    for incident in ([inc()], [inc(state="resolved")], []):
        assert run(incident, deliveries=[d]) in (
            (Expire("i1", "open", U),),
            (Expire("i1", "open", "incident_missing"),),
        )


def _expected_for_bad_terminal_row(state, incident_state, field, bad):
    if incident_state == "resolved" and state == "sent":
        return (Enqueue("i1", "recover", NOW),)  # the open row did go out
    if (incident_state, state, field, bad) == ("open", "suppressed", "next_attempt_at", None):
        return (Requeue("i1", "open", NOW),)  # a suppressed row legitimately has no next time
    return ()


@pytest.mark.parametrize(
    "field", ["attempts", "next_attempt_at", "created_at", "updated_at", "version"]
)
@pytest.mark.parametrize("bad", BAD)
@pytest.mark.parametrize("state", ["sent", "failed", "suppressed", "expired"])
@pytest.mark.parametrize("incident_state", ["open", "resolved", "superseded"])
def test_terminal_rows_with_bad_numbers_produce_exactly_the_safe_actions(
    field, bad, state, incident_state
):
    d = dataclasses.replace(dv(state=state), **{field: bad})
    got = run([inc(state=incident_state)], deliveries=[d])
    assert got == _expected_for_bad_terminal_row(state, incident_state, field, bad)


def test_still_open_incident_hidden_by_the_watermark_keeps_its_sent_row():
    sent = dv(state="sent", created=NOW - 10 * RET)
    hidden = DeliveryConfig(eligible_since=NOW)
    assert run([inc(detected=NOW - 2 * RET)], deliveries=[sent], cfg=hidden) == ()
    assert run([inc(detected=NOW - 2 * RET)], deliveries=[sent], cfg=DeliveryConfig()) == ()


def test_garbage_review_with_a_valid_incident_is_reachable_and_suppressed():
    got = run([inc()], {"i1": ReviewView("snoozed", "soon")})  # type: ignore[arg-type]
    assert got == (Suppress("i1", "open", U),)
    got = run([inc()], {"i1": ReviewView(7, None)})  # type: ignore[arg-type]
    assert got == (Suppress("i1", "open", U),)


# (h) determinism and idempotence
def test_actions_are_sorted_by_incident_then_kind_whatever_the_input_order():
    incidents = [inc("b"), inc("a"), inc("c", "resolved")]
    ds = [dv(iid="c", state="sent")]
    got = run(incidents, deliveries=ds)
    assert got == (
        Enqueue("a", "open", NOW),
        Enqueue("b", "open", NOW),
        Enqueue("c", "recover", NOW),
    )
    assert run(reversed(incidents), deliveries=ds) == got


def apply(deliveries, actions, now):
    rows, skipped = apply_cas({(d.incident_id, d.kind): d for d in deliveries}, actions, now)
    assert not skipped, skipped  # every fresh plan applies in full
    return tuple(rows.values())


STATES = ["open", "resolved", "superseded", "bogus"]
REVIEWS = [
    None,
    "acknowledged",
    "expected",
    ("snoozed", 100),
    ("snoozed", -100),
    "cleared",
    "bogus",
]
OPEN_D = [None, "pending", "sending", "sent", "failed", "suppressed", "expired"]
REC_D = [None, "pending", "sending", "sent", "withdrawn"]
AGES = [5, 90000, 3_000_000]


def _scenarios():
    for state, rv, od, rd, age, nxt, att in itertools.product(
        STATES, REVIEWS, OPEN_D, REC_D, AGES, (-100, 400), (0, 2)
    ):
        if rv == "cleared":
            review = ReviewView(None, None)
        elif isinstance(rv, tuple):
            review = ReviewView(rv[0], NOW + rv[1])
        else:
            review = ReviewView(rv, None) if rv else None
        rows = [(k, s) for k, s in (("open", od), ("recover", rd)) if s]
        ds = [dv(k, s, attempts=att, nxt=NOW + nxt, created=NOW - age) for k, s in rows]
        yield [inc(state=state)], ({"i1": review} if review else {}), ds


def test_plan_settles_within_three_passes_over_every_generated_state():
    count = 0
    for incidents, reviews, ds in _scenarios():
        rows = tuple(ds)
        for _ in range(4):
            actions = plan(tuple(incidents), reviews, rows, NOW, CFG)
            keys = [(a.incident_id, a.kind) for a in actions]
            assert keys == sorted(set(keys))
            if not actions:
                break
            rows = apply(rows, actions, NOW)
        assert actions == (), (incidents, reviews, ds)
        count += 1
    assert count > 4000


def test_orphans_settle_then_age_out():
    for state in ("pending", "sent", "failed", "suppressed", "expired"):
        ds = apply((dv(state=state),), plan((), {}, (dv(state=state),), NOW, CFG), NOW)
        assert plan((), {}, ds, NOW, CFG) == ()
        later = NOW + RET + 1
        assert ds and apply(ds, plan((), {}, ds, later, CFG), later) == ()


def test_plan_does_not_mutate_its_inputs():
    incidents, reviews, ds = (inc(),), {"i1": ReviewView("snoozed", NOW + 5)}, (dv(),)
    plan(incidents, reviews, ds, NOW, CFG)
    assert incidents == (inc(),) and reviews == {"i1": ReviewView("snoozed", NOW + 5)}
    assert ds == (dv(),)
    with pytest.raises(dataclasses.FrozenInstanceError):
        incidents[0].state = "x"  # type: ignore[misc]


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, 10**400, True, None, "5"])
def test_a_bad_now_is_a_programmer_error(bad):
    with pytest.raises(ValueError, match="now"):
        run([inc()], now=bad)


def test_huge_but_finite_snooze_is_rejected_not_raised():
    got = run([inc()], {"i1": ReviewView("snoozed", 10**400)})
    assert got == (Suppress("i1", "open", U),)


def test_snooze_cleared_after_a_failure_keeps_the_backoff_but_a_later_snooze_wins():
    retrying = dv(attempts=1, nxt=NOW + 60)
    assert run([inc()], deliveries=[retrying]) == ()  # cleared: backoff kept
    assert run([inc()], snooze(30), [retrying]) == ()  # shorter than the backoff: kept
    assert run([inc()], snooze(500), [retrying]) == (Reschedule("i1", "open", NOW + 500),)


def test_snooze_cleared_before_any_attempt_goes_earlier():
    long_snooze = dv(attempts=0, nxt=NOW + 5000)
    assert run([inc()], deliveries=[long_snooze]) == (Reschedule("i1", "open", NOW),)


def test_rows_with_an_unknown_kind_or_state_are_ignored_not_fatal():
    odd = [dv(kind="page"), dv(state="queued")]
    assert run([inc()], deliveries=odd) == (Enqueue("i1", "open", NOW),)
    assert run([], deliveries=odd) == ()


def test_a_pending_recover_for_an_open_incident_is_withdrawn():
    ds = [dv(state="sent"), dv("recover")]
    assert run([inc()], deliveries=ds) == (Withdraw("i1", "recover"),)
    assert run([inc(state="superseded")], deliveries=ds) == (Withdraw("i1", "recover"),)
    assert run([inc(state="weird")], deliveries=ds) == (Withdraw("i1", "recover"),)
    assert run([inc(state="resolved")], deliveries=ds) == ()


def test_resolve_reopen_resolve_and_a_double_flap_each_end_with_one_recover():
    ds = apply((), run([inc()]), NOW)
    ds = tuple(dataclasses.replace(d, state="sent") for d in ds)
    for _ in range(2):  # flap twice
        ds = apply(ds, run([inc(state="resolved")], deliveries=ds), NOW)
        assert [d.kind for d in ds if d.state == "pending"] == ["recover"]
        ds = apply(ds, run([inc()], deliveries=ds), NOW)  # reopens: the recover is withdrawn
        assert sorted((d.kind, d.state) for d in ds) == [("open", "sent"), ("recover", "withdrawn")]
    ds = apply(ds, run([inc(state="resolved")], deliveries=ds), NOW)
    assert sorted((d.kind, d.state) for d in ds) == [("open", "sent"), ("recover", "pending")]
    assert run([inc(state="resolved")], deliveries=ds) == ()


def test_a_stale_plan_is_skipped_not_applied_over_a_sender_outcome():
    pending = dv(nxt=NOW + 500)
    stale = run([inc()], {"i1": ReviewView("acknowledged", None)}, [pending])
    assert stale == (Suppress("i1", "open", "acknowledged"),)
    sent = dataclasses.replace(pending, state="sent", attempts=1)
    rows, skipped = apply_cas({("i1", "open"): sent}, stale, NOW)
    assert rows[("i1", "open")] == sent and skipped == list(stale)
    again = dataclasses.replace(pending, attempts=1)  # the sender retried: attempts moved
    assert apply_cas({("i1", "open"): again}, stale, NOW)[1] == list(stale)
    assert apply_cas({}, stale, NOW)[1] == list(stale)
    assert apply_cas({("i1", "open"): pending}, stale, NOW)[1] == []
    inserted = run([inc()], {"i1": ReviewView("acknowledged", None)})
    assert inserted[0].expected is None
    assert apply_cas({("i1", "open"): pending}, inserted, NOW)[1] == list(inserted)


@pytest.mark.parametrize(
    "incidents,review,rows,expected",
    [
        ([inc()], None, [], {"Enqueue": None}),
        ([inc()], ReviewView("acknowledged", None), [], {"Suppress": None}),
        ([inc()], ReviewView("acknowledged", None), [dv(attempts=2)], {"Suppress": ("pending", 2)}),
        ([inc()], snooze(100)["i1"], [dv(nxt=NOW)], {"Reschedule": ("pending", 0)}),
        ([inc()], None, [dv("open", "suppressed", attempts=3)], {"Requeue": ("suppressed", 3)}),
        ([inc()], None, [dv("open", "suppressed", attempts=6)], {"Fail": ("suppressed", 6)}),
        (
            [inc()],
            None,
            [dv("open", "suppressed", created=NOW - RET - 1)],
            {"Expire": ("suppressed", 0)},
        ),
        ([inc(state="resolved")], None, [dv(attempts=1)], {"Expire": ("pending", 1)}),
        ([inc(state="resolved")], None, [dv(state="sent")], {"Enqueue": None}),
        (
            [inc()],
            None,
            [dv(state="sent"), dv("recover", attempts=1)],
            {"Withdraw": ("pending", 1)},
        ),
        (
            [inc(state="superseded")],
            None,
            [dv(state="sent", created=NOW - RET - 1)],
            {"Forget": ("sent", 0)},
        ),
    ],
)
def test_every_action_carries_the_row_state_it_was_planned_against(
    incidents, review, rows, expected
):
    got = run(incidents, {"i1": review} if review else {}, rows)
    assert {type(a).__name__ for a in got} == set(expected)
    for a in got:
        want = expected[type(a).__name__]
        assert a.expected == (Expected(*want, 0) if want else None)
        assert a.expected is None or (a.expected.state, a.expected.attempts) == want


def test_expected_carries_the_row_version():
    got = run([inc()], {"i1": ReviewView("acknowledged", None)}, [dv(attempts=2, ver=7)])
    assert got[0].expected == Expected("pending", 2, 7)


# requeue target respects an existing backoff; every revival path honours the original ttl
def test_requeue_waits_out_a_pending_backoff_only_for_rows_that_were_attempted():
    retried = dv("open", "suppressed", attempts=2, nxt=NOW + 300)
    assert run([inc()], deliveries=[retried]) == (Requeue("i1", "open", NOW + 300),)
    passed = dv("open", "suppressed", attempts=2, nxt=NOW - 300)
    assert run([inc()], deliveries=[passed]) == (Requeue("i1", "open", NOW),)
    fresh = dv("open", "suppressed", attempts=0, nxt=NOW + 300)
    assert run([inc()], deliveries=[fresh]) == (Requeue("i1", "open", NOW),)
    later = {"i1": ReviewView("snoozed", NOW + 900)}
    assert run([inc()], later, [retried]) == (Requeue("i1", "open", NOW + 900),)
    never = dv("open", "suppressed", attempts=2, nxt=None)
    assert run([inc()], deliveries=[never]) == (Requeue("i1", "open", NOW),)


def test_immediate_ack_clear_after_a_failure_keeps_the_backoff():
    ds = (dv(attempts=1, nxt=NOW + 60),)
    ds = apply(ds, run([inc()], {"i1": ReviewView("acknowledged", None)}, ds), NOW)
    ds = apply(ds, run([inc()], deliveries=ds), NOW)
    assert (ds[0].state, ds[0].next_attempt_at, ds[0].attempts) == ("pending", NOW + 60, 1)


def test_a_long_ack_never_expires_a_still_open_loud_incident():
    acked = dv("open", "suppressed", created=NOW - 25 * 3600, nxt=NOW - 25 * 3600)
    assert run([inc()], deliveries=[acked]) == (Requeue("i1", "open", NOW),)  # ttl is 24h
    assert run([inc()], snooze(100), [acked]) == (Requeue("i1", "open", NOW + 100),)
    after_snooze = dv("open", "suppressed", created=NOW - 3 * DAY, nxt=NOW + 40 - 3 * DAY)
    assert run([inc()], deliveries=[after_snooze]) == (Requeue("i1", "open", NOW),)
    # ... and the revived row then has a fresh ttl clock (from its next_attempt_at)
    revived = apply([acked], run([inc()], deliveries=[acked]), NOW)
    assert run([inc()], deliveries=revived) == ()


@pytest.mark.parametrize("state", ["pending", "suppressed"])
def test_the_hard_lifetime_caps_every_open_row(state):
    old = dv("open", state, created=NOW - RET - 1, nxt=NOW + 10)
    edge = dv("open", state, created=NOW - RET, nxt=NOW + 10)
    assert run([inc()], deliveries=[old]) == (Expire("i1", "open", "lifetime"),)
    assert run([inc()], snooze(100), [old]) == (Expire("i1", "open", "lifetime"),)
    assert run([inc()], deliveries=[edge]) != (Expire("i1", "open", "lifetime"),)


# item 4: integer times
def test_action_times_are_integers():
    got = run([inc()], {"i1": ReviewView("snoozed", NOW + 100.5)})
    assert got == (Enqueue("i1", "open", NOW + 101),)
    assert type(got[0].not_before) is int
    assert run([inc()], now=NOW + 0.5) == (Enqueue("i1", "open", NOW + 1),)
    moved = run([inc()], {"i1": ReviewView("snoozed", NOW + 100.5)}, [dv(nxt=NOW)])
    assert moved == (Reschedule("i1", "open", NOW + 101),)
    again = run([inc()], {"i1": ReviewView("snoozed", NOW + 100.5)}, [dv(nxt=NOW + 101)])
    assert again == ()
    requeue = run([inc()], snooze(0.5), [dv(state="suppressed")])
    assert requeue == (Requeue("i1", "open", NOW + 1),)
    assert _failed(1, NOW + 0.5)[1]["next_attempt_at"] == NOW + 61
    assert run([inc()], now=NOW + 0.5, deliveries=[dv(nxt=NOW + 1)]) == ()
    owed = run([inc(state="resolved")], deliveries=[dv(state="sent")], now=NOW + 0.5)
    assert owed == (Enqueue("i1", "recover", NOW + 1),)


# item 3: a requeue never refreshes the retry budget or the ttl clock
def test_requeue_past_the_attempt_budget_fails_instead():
    spent = dv(state="suppressed", attempts=CFG.max_attempts)
    assert run([inc()], deliveries=[spent]) == (Fail("i1", "open", "max_attempts"),)
    left = dv(state="suppressed", attempts=CFG.max_attempts - 1)
    assert run([inc()], deliveries=[left]) == (Requeue("i1", "open", NOW),)


def _cycle(fail_each_time, step, rounds):
    """ack/clear alternately; optionally every delivery attempt fails. Returns (rows, trace)."""
    ds, t, ack, clear = (), NOW, {"i1": ReviewView("acknowledged", None)}, {}
    seen = []
    for _ in range(rounds):
        t += step
        ds = apply(ds, plan((inc(),), clear, ds, t, CFG), t)
        row = ds[0]
        if fail_each_time and row.state == "pending":
            due = t + backoff(row.attempts + 1, CFG)  # a failed attempt, retry scheduled
            failed = dataclasses.replace(
                row, attempts=row.attempts + 1, next_attempt_at=due, version=row.version + 1
            )
            ds = (
                (failed,)
                if failed.attempts < CFG.max_attempts
                else (dataclasses.replace(failed, state="failed"),)
            )
        seen.append(ds[0])
        t += step
        ds = apply(ds, plan((inc(),), ack, ds, t, CFG), t)
        seen.append(ds[0])
    return ds, seen, t


def test_ack_clear_cycles_never_exceed_the_attempt_budget():
    ds, seen, _ = _cycle(True, 600, 30)
    assert max(r.attempts for r in seen) <= CFG.max_attempts
    assert ds[0].state == "failed" and ds[0].attempts == CFG.max_attempts


def test_ack_clear_cycles_end_at_the_lifetime_cap_not_before():
    step = 20 * 3600  # shorter than the ttl, so only the lifetime cap can end the cycle
    ds, seen, _ = _cycle(False, step, 40)
    assert ds[0].state == "expired" and ds[0].created_at == NOW + step
    life = ds[0].updated_at - ds[0].created_at
    assert RET < life <= RET + 2 * step  # never early, and on the first revival after the cap
    assert {r.created_at for r in seen} == {ds[0].created_at}


# item 3: a Forget of an open row never deletes it from under a pending recover
def test_forget_of_an_open_row_carries_the_sibling_recover_precondition():
    old = NOW - RET - 1
    got = run([inc(state="superseded")], deliveries=[dv(state="sent", created=old)])
    assert got == (Forget("i1", "open"),) and got[0].sibling_recover == "absent_or_terminal"
    got = run([inc(state="superseded")], deliveries=[dv("recover", "sent", created=old)])
    assert got == (Forget("i1", "recover"),) and got[0].sibling_recover is None
    orphan = run([], deliveries=[dv(state="sent", created=old)])
    assert orphan[0].sibling_recover == "absent_or_terminal"


@pytest.mark.parametrize("incident", [[], [inc(state="superseded")]])
def test_a_pending_recover_holds_back_the_forget_of_its_open_row(incident):
    old = NOW - RET - 1
    ds = [dv(state="sent", created=old), dv("recover", created=NOW - 5, nxt=NOW)]
    got = run(incident, deliveries=ds)
    assert not [a for a in got if isinstance(a, Forget)]


def test_the_apply_model_refuses_a_forget_when_a_recover_is_pending_meanwhile():
    old = NOW - RET - 1
    plan_ = run([inc(state="superseded")], deliveries=[dv(state="sent", created=old)])
    pending_recover = dv("recover", created=NOW - 5, nxt=NOW)
    rows = {("i1", "open"): dv(state="sent", created=old), ("i1", "recover"): pending_recover}
    out, skipped = apply_cas(rows, plan_, NOW)
    assert skipped == list(plan_) and ("i1", "open") in out
    assert apply_cas({("i1", "open"): rows[("i1", "open")]}, plan_, NOW)[0] == {}


# item 2: versions make a stale action miss a different incarnation of the row
def test_a_stale_action_cannot_hit_a_different_incarnation_of_a_row():
    ack = {"i1": ReviewView("acknowledged", None)}
    stale = run([inc()], ack, [dv(attempts=1, ver=3)])
    reborn = dv(attempts=1, ver=5)  # same state and attempts, different incarnation
    out, skipped = apply_cas({("i1", "open"): reborn}, stale, NOW)
    assert skipped == list(stale) and out[("i1", "open")] == reborn
    out, skipped = apply_cas({("i1", "open"): dv(attempts=1, ver=3)}, stale, NOW)
    assert not skipped and out[("i1", "open")].version == 4  # every change bumps the version
    inserted = apply_cas({}, run([inc()]), NOW)[0]
    assert inserted[("i1", "open")].version == NOW  # created at the epoch second, see below


def test_bad_version_fails_closed():
    d = dataclasses.replace(dv(), version="x")  # type: ignore[arg-type]
    assert run([inc()], deliveries=[d]) == (Expire("i1", "open", "unrecognised_state"),)
    s = dataclasses.replace(dv(state="suppressed"), version=None)  # type: ignore[arg-type]
    assert run([inc()], deliveries=[s]) == ()


# round 5: an incident's rows are forgotten all together, never half
def test_a_half_forgotten_incident_cannot_announce_twice():
    t0, d = NOW, DAY
    rows = [dv("open", "sent", created=t0), dv("recover", "sent", created=t0 + 10 * d)]
    resolved, at = (
        inc(state="resolved"),
        lambda day, incident: run(  # noqa: E731
            [incident], deliveries=rows, now=t0 + day * d
        ),
    )
    assert at(35, resolved) == ()  # the open row is old but the recover row is not: keep both
    assert at(36, inc()) == ()  # reopened: no second announcement
    assert at(37, resolved) == ()  # and no second recover (one per delivery life)
    assert at(40, resolved) == ()  # exactly retention since the recover: still kept
    both = run([resolved], deliveries=rows, now=t0 + 40 * d + 1)
    assert both == (Forget("i1", "open"), Forget("i1", "recover"))


# round 5: a withdrawn recover is revived, never deleted and recreated
def test_a_withdrawn_recover_is_revived_with_its_budget_and_clock_kept():
    ds = [
        dv(state="sent"),
        dv("recover", "withdrawn", attempts=2, nxt=NOW + 300, created=NOW - 500, ver=3),
    ]
    got = run([inc(state="resolved")], deliveries=ds)
    assert got == (Revive("i1", "recover", NOW + 300),)  # waits out its own backoff
    assert got[0].expected == Expected("withdrawn", 2, 3)
    revived = apply(ds, got, NOW)[1]
    assert (revived.state, revived.attempts, revived.version) == ("pending", 2, 4)
    assert (revived.created_at, revived.next_attempt_at) == (NOW - 500, NOW + 300)
    assert run([inc(state="resolved")], deliveries=[ds[0], revived]) == ()


def test_a_revive_past_the_budget_or_the_lifetime_fails_or_expires_instead():
    spent = dv("recover", "withdrawn", attempts=CFG.max_attempts)
    got = run([inc(state="resolved")], deliveries=[dv(state="sent"), spent])
    assert got == (Fail("i1", "recover", "max_attempts"),)
    assert got[0].expected == Expected("withdrawn", CFG.max_attempts, 0)
    old = dv("recover", "withdrawn", created=NOW - RET - 1, upd=NOW - 5)
    got = run([inc(state="resolved")], deliveries=[dv(state="sent"), old])
    assert got == (Expire("i1", "recover", "lifetime"),)


def test_twenty_flaps_never_exceed_the_attempt_budget_and_keep_the_backoff_spacing():
    rows = {("i1", "open"): dv(state="sent", created=NOW)}
    t, sends, last = NOW, [], None
    for cycle in range(20):
        t += 10
        actions = run([inc(state="resolved")], deliveries=list(rows.values()), now=t)
        rows, skipped = apply_cas(rows, actions, t)
        row = rows.get(("i1", "recover"))
        if row is not None and row.state == "pending" and row.next_attempt_at <= t:
            if last is not None:
                assert t - last >= backoff(len(sends), CFG), (cycle, t, last)
            sends.append(t)  # a transmission that fails
            last = t
            tried = dataclasses.replace(
                row,
                attempts=row.attempts + 1,
                next_attempt_at=t + backoff(row.attempts + 1, CFG),
                version=row.version + 1,
            )
            rows = {**rows, ("i1", "recover"): tried}
        actions = run([inc()], deliveries=list(rows.values()), now=t + 1)  # reopens
        rows, skipped = apply_cas(rows, actions, t + 1)
    assert len(sends) <= CFG.max_attempts
    assert rows[("i1", "recover")].attempts <= CFG.max_attempts


@pytest.mark.parametrize("state", ["open", "superseded"])
def test_a_withdrawn_recover_stays_withdrawn_while_nothing_is_owed(state):
    ds = [dv(state="sent"), dv("recover", "withdrawn")]
    assert run([inc(state=state)], deliveries=ds) == ()
    assert run([inc(state="resolved")], deliveries=[dv(state="failed"), ds[1]]) == ()


def test_withdraw_marks_the_row_and_the_next_resolution_revives_it_with_a_higher_version():
    ds = [dv(state="sent"), dv("recover")]
    withdrawn = apply(ds, run([inc()], deliveries=ds), NOW)
    assert [(d.kind, d.state, d.version) for d in withdrawn] == [
        ("open", "sent", 0),
        ("recover", "withdrawn", 1),
    ]
    again = apply(withdrawn, run([inc(state="resolved")], deliveries=withdrawn), NOW)
    assert [(d.kind, d.state, d.version) for d in again][1] == ("recover", "pending", 2)


def test_a_withdrawn_row_is_terminal_for_the_all_or_nothing_forget():
    old = NOW - RET - 1
    ds = [dv(state="sent", created=old), dv("recover", "withdrawn", created=old)]
    both = (Forget("i1", "open"), Forget("i1", "recover"))
    assert run([inc(state="superseded")], deliveries=ds) == both
    assert run([], deliveries=ds) == both
    assert run([inc(state="resolved")], deliveries=ds) == (Expire("i1", "recover", "lifetime"),)


def test_orphan_rows_are_forgotten_all_or_nothing():
    old, young = NOW - RET - 1, NOW - 5
    assert (
        run([], deliveries=[dv(state="sent", created=old), dv("recover", "sent", created=young)])
        == ()
    )
    both = run([], deliveries=[dv(state="sent", created=old), dv("recover", "sent", created=old)])
    assert both == (Forget("i1", "open"), Forget("i1", "recover"))
    live = run([], deliveries=[dv(state="sent", created=old), dv("recover", created=old, nxt=NOW)])
    assert live == (Expire("i1", "recover", "incident_missing"),)


def test_an_open_incident_never_loses_any_row_whatever_their_age():
    old = NOW - 10 * RET
    ds = [dv(state="sent", created=old), dv("recover", "sent", created=old)]
    assert run([inc()], deliveries=ds) == ()


def test_a_forget_pass_with_one_missed_precondition_rolls_back_entirely():
    old = NOW - RET - 1
    ds = [dv(state="sent", created=old), dv("recover", "sent", created=old)]
    both = run([inc(state="superseded")], deliveries=ds)
    assert both == (Forget("i1", "open"), Forget("i1", "recover"))
    missed = (both[0], dataclasses.replace(both[1], expected=Expected("sent", 0, 99)))
    with pytest.raises(PassAborted):
        apply_cas(ds, missed, NOW, strict=True)
    rows, skipped = apply_cas(ds, both, NOW, strict=True)
    assert rows == {} and skipped == []
    store = Store(ds)  # the failed pass must leave both rows in place: all or nothing
    with pytest.raises(PassAborted):
        store.apply_pass(missed, NOW)
    assert set(store.rows()) == {("i1", "open"), ("i1", "recover")}


def test_a_revive_never_schedules_before_the_rows_own_backoff_even_without_attempts():
    ds = [
        dv(state="sent"),
        dv("recover", "withdrawn", attempts=0, nxt=NOW + 300),
    ]  # clock stepped back
    assert run([inc(state="resolved")], deliveries=ds) == (Revive("i1", "recover", NOW + 300),)


# round 7: the sender holds a lease; the planner hands off a live `sending` row
LEASE = 300


def sending(kind="open", attempts=1, nxt=NOW + LEASE, ver=1, **kw):
    return dv(kind, "sending", attempts=attempts, nxt=nxt, ver=ver, **kw)


@pytest.mark.parametrize("kind", ["open", "recover"])
@pytest.mark.parametrize("incident", ["open", "resolved", "superseded", "weird", None])
@pytest.mark.parametrize(
    "review", [None, ACK_REVIEW := {"i1": ReviewView("acknowledged", None)}, snooze(100)]
)
def test_a_live_lease_gets_no_action_of_any_kind(kind, incident, review):
    old = NOW - 10 * RET  # even a row that is past its ttl, its lifetime and retention
    row = sending(kind, created=old)
    ds = [row] if kind == "open" else [dv(state="sent", created=old), row]
    incidents = [] if incident is None else [inc(state=incident)]
    got = run(incidents, review or {}, ds)
    assert not [a for a in got if a.kind == kind], got
    assert not [a for a in got if type(a).__name__ == "Forget"]


def test_a_lapsed_lease_is_reclaimed_without_counting_the_attempt_again():
    row = sending(attempts=2, nxt=NOW, ver=7)
    got = run([inc()], deliveries=[row])
    assert got == (Reclaim("i1", "open", NOW + backoff(2, CFG)),)
    assert got[0].expected == Expected("sending", 2, 7)
    back = apply([row], got, NOW)[0]
    assert (back.state, back.attempts, back.version) == ("pending", 2, 8)
    assert run([inc()], deliveries=[back]) == ()


def test_a_lapsed_lease_past_the_budget_fails_and_a_garbled_one_expires():
    spent = sending(attempts=CFG.max_attempts, nxt=NOW - 1)
    assert run([inc()], deliveries=[spent]) == (Fail("i1", "open", "max_attempts"),)
    junk = dataclasses.replace(sending(nxt=NOW - 1), updated_at="soon")  # type: ignore[arg-type]
    assert run([inc()], deliveries=[junk]) == (Expire("i1", "open", "unrecognised_state"),)
    assert run([], deliveries=[sending(nxt=NOW - 1)]) == (Expire("i1", "open", "incident_missing"),)


def test_no_recover_is_enqueued_while_the_open_is_in_flight():
    resolved = inc(state="resolved")
    assert run([resolved], deliveries=[sending()]) == ()
    assert run([resolved], deliveries=[dv(state="sent")]) == (Enqueue("i1", "recover", NOW),)


def test_nothing_is_forgotten_while_any_row_is_sending_or_pending():
    old = NOW - RET - 1
    done = dv(state="sent", created=old)
    for live in (sending("recover", created=old), dv("recover", created=old, nxt=NOW + 5)):
        assert not [
            a
            for a in run([inc(state="superseded")], deliveries=[done, live])
            if isinstance(a, Forget)
        ]
        assert not [a for a in run([], deliveries=[done, live]) if isinstance(a, Forget)]


def test_lease_and_transmit_deadline_are_validated():
    for bad in (0, -1, 1.5, True, "300", float("nan"), 59):
        with pytest.raises(ValueError):
            DeliveryConfig(lease_seconds=bad)  # type: ignore[arg-type]
    for bad in (0, -5, 1.5, True, "30", 151):  # 151 * 2 > 300
        with pytest.raises(ValueError):
            DeliveryConfig(transmit_deadline_seconds=bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DeliveryConfig(lease_seconds=60, transmit_deadline_seconds=31)
    assert DeliveryConfig(lease_seconds=60, transmit_deadline_seconds=30).lease_seconds == 60
    assert DeliveryConfig(transmit_deadline_seconds=150).transmit_deadline_seconds == 150


def test_may_transmit_aborts_at_the_deadline():
    claimed_at, deadline = NOW, CFG.transmit_deadline_seconds
    assert may_transmit(claimed_at, claimed_at, CFG)
    assert may_transmit(claimed_at, claimed_at + deadline - 1, CFG)
    assert not may_transmit(claimed_at, claimed_at + deadline, CFG)
    assert not may_transmit(claimed_at, claimed_at + 10 * deadline, CFG)
    assert not may_transmit(None, NOW, CFG) and not may_transmit(NOW, float("nan"), CFG)


# round 8: the lease boundary, cancellation of a lapsed claim, and the version of a new row
def test_the_lease_is_half_open_and_reclaim_wins_at_the_boundary():
    row = sending(nxt=NOW)  # lease end == now
    assert run([inc()], deliveries=[row]) == (Reclaim("i1", "open", NOW + backoff(1, CFG)),)
    assert run([inc()], deliveries=[sending(nxt=NOW + 1)]) == ()
    store = Store([dv(nxt=NOW - 1)])
    claimed = _claim(store, ("i1", "open"), NOW)
    lapse = NOW + CFG.lease_seconds
    assert _pass(store, "open", {}, lapse - 1) == []
    assert [type(a) for a in _pass(store, "open", {}, lapse)] == [Reclaim]
    assert store.run(sql.COMPLETE_SENT, sql.completion_params(claimed, lapse)) == 0  # lost


@pytest.mark.parametrize(
    "incident,kind,created,expected",
    [
        ("open", "open", NOW - 5, Reclaim("i1", "open", NOW + 60)),
        ("resolved", "open", NOW - 5, Expire("i1", "open", "resolved_before_send")),
        ("superseded", "open", NOW - 5, Expire("i1", "open", "resolved_before_send")),
        ("open", "open", NOW - RET - 1, Expire("i1", "open", "lifetime")),
        (None, "open", NOW - 5, Expire("i1", "open", "incident_missing")),
        ("open", "recover", NOW - 5, Withdraw("i1", "recover")),
        ("superseded", "recover", NOW - 5, Withdraw("i1", "recover")),
        ("resolved", "recover", NOW - 5, Reclaim("i1", "recover", NOW + 60)),
    ],
)
def test_a_lapsed_claim_is_cancelled_by_the_normal_rules_before_it_is_reclaimed(
    incident, kind, created, expected
):
    row = sending(kind, nxt=NOW - 1, created=created)
    ds = [row] if kind == "open" else [dv(state="sent"), row]
    incidents = [] if incident is None else [inc(state=incident)]
    got = [a for a in run(incidents, deliveries=ds) if a.kind == kind]
    assert got == [expected]
    assert got[0].expected == Expected("sending", 1, 1)


def test_a_pending_row_at_the_attempt_budget_fails_instead_of_waiting_for_the_ttl():
    spent = dv(attempts=CFG.max_attempts, nxt=NOW + 500)
    got = run([inc()], deliveries=[spent])
    assert got == (Fail("i1", "open", "max_attempts"),)
    assert got[0].expected == Expected("pending", CFG.max_attempts, 0)
    assert run([inc()], deliveries=[dv(attempts=CFG.max_attempts - 1, nxt=NOW + 500)]) == ()


def test_an_open_that_went_out_before_its_lease_lapsed_gets_no_recover():
    """Pinned (documented at-least-once window): after a lapsed lease we cannot prove the open was
    delivered, so a resolution cancels it and no recover is sent for it."""
    store = Store([dv(nxt=NOW - 1)])
    _claim(store, ("i1", "open"), NOW)  # transmitted, then the sender died
    lapse = NOW + CFG.lease_seconds
    assert [type(a) for a in _pass(store, "open", {}, lapse)] == [Reclaim]
    later = lapse + 5
    assert [type(a) for a in _pass(store, "resolved", {}, later)] == [Expire]
    assert store.rows()[("i1", "open")].state == "expired"
    assert _pass(store, "resolved", {}, later + 1) == []
    assert ("i1", "recover") not in store.rows()
    ack = {"i1": ReviewView("acknowledged", None)}  # an ack in the same gap suppresses it instead
    other = Store([dv(nxt=NOW - 1)])
    _claim(other, ("i1", "open"), NOW)
    _pass(other, "open", {}, lapse)
    assert [type(a) for a in _pass(other, "open", ack, later)] == [Suppress]
    assert ("i1", "recover") not in other.rows()


def test_a_new_row_never_reuses_a_version_a_deleted_row_had():
    """Codex's trace: reclaim, expire, forget, reopen, claim again. The old sender's late
    completion carries the old claim's version and must not land on the new claim."""
    t0 = NOW
    store = Store([dv(nxt=t0 - 1)])
    old = _claim(store, ("i1", "open"), t0)  # version V1; the sender then stalls
    lapse = t0 + CFG.lease_seconds
    _pass(store, "open", {}, lapse)  # Reclaim
    _pass(store, "resolved", {}, lapse + 1)  # Expire (resolved_before_send)
    assert store.rows()[("i1", "open")].state == "expired"
    forgot = lapse + 1 + RET + 1
    assert [type(a) for a in _pass(store, "resolved", {}, forgot)] == [Forget]
    assert store.rows() == {}
    reopened = forgot + 10  # a fresh row, created at this epoch second
    assert [type(a) for a in _pass(store, "open", {}, reopened)] == [Enqueue]
    fresh = store.rows()[("i1", "open")]
    assert fresh.version == reopened and fresh.version > old.version
    new = _claim(store, ("i1", "open"), reopened + 1)
    assert (
        store.run(
            *sql.failure_statement(
                dataclasses.replace(old, attempts=CFG.max_attempts), reopened + 2, CFG
            )
        )
        == 0
    )
    assert store.rows()[("i1", "open")] == new  # the new claim is intact


def test_the_overlap_trace_needs_a_deadline_violation():
    """Codex's A/B overlap: with a lease shorter than twice the deadline B could claim while A was
    still inside its allowed send window. Configuration now forbids it, and a sender that honours
    the deadline has finished transmitting before the earliest possible second claim."""
    with pytest.raises(ValueError):
        DeliveryConfig(lease_seconds=60, transmit_deadline_seconds=40)
    cfg = DeliveryConfig(lease_seconds=60, transmit_deadline_seconds=30)
    store = Store([dv(nxt=NOW - 1)])
    claimed_at = NOW
    assert store.run(sql.CLAIM, sql.claim_params(dv(nxt=NOW - 1), claimed_at, cfg)) == 1
    abiding_end = claimed_at + cfg.transmit_deadline_seconds * 2  # started in time, hard timeout
    lapse = claimed_at + cfg.lease_seconds
    assert plan([inc()], {}, list(store.rows().values()), lapse - 1, cfg) == ()
    (reclaim,) = plan([inc()], {}, list(store.rows().values()), lapse, cfg)
    assert isinstance(reclaim, Reclaim) and reclaim.next_attempt_at > abiding_end
    hung_end = claimed_at + 10 * cfg.lease_seconds  # only a violating sender overlaps
    assert reclaim.next_attempt_at < hung_end


def _lease_world(rows):
    return Store(rows)


def _claim(store, key, now):
    assert store.run(sql.CLAIM, sql.claim_params(store.rows()[key], now, CFG)) == 1
    return store.rows()[key]


def _pass(store, incident, reviews, now):
    actions = plan([inc(state=incident)], reviews, list(store.rows().values()), now, CFG)
    store.apply_pass(actions, now)
    return list(actions)


def test_a_flap_during_a_recover_send_neither_withdraws_nor_resends():
    """Codex's trace: Withdraw+Revive while a recover is in flight used to drop the completion and
    leave the row pending, so it was transmitted again."""
    store = _lease_world([dv(state="sent"), dv("recover", nxt=NOW - 1)])
    claimed = _claim(store, ("i1", "recover"), NOW)  # the one transmission
    assert (claimed.state, claimed.attempts, claimed.next_attempt_at) == ("sending", 1, NOW + LEASE)
    assert _pass(store, "open", {}, NOW + 1) == []  # reopened mid-send: hands off
    assert _pass(store, "resolved", {}, NOW + 2) == []
    assert store.run(sql.COMPLETE_SENT, sql.completion_params(claimed, NOW + 3)) == 1
    done = store.rows()[("i1", "recover")]
    assert (done.state, done.attempts) == ("sent", 1)
    assert _pass(store, "open", {}, NOW + 4) == []  # a sent recover is never touched again


def test_an_ack_during_an_open_send_is_applied_after_it_and_cannot_resend():
    store = _lease_world([dv(nxt=NOW - 1)])
    claimed = _claim(store, ("i1", "open"), NOW)
    ack = {"i1": ReviewView("acknowledged", None)}
    assert _pass(store, "open", ack, NOW + 1) == []
    assert store.run(sql.COMPLETE_SENT, sql.completion_params(claimed, NOW + 2)) == 1
    assert _pass(store, "open", ack, NOW + 3) == []  # a sent row ignores the late ack
    assert _pass(store, "open", {}, NOW + 4) == []  # and the clear
    assert store.rows()[("i1", "open")].state == "sent"


def test_a_snooze_during_a_failing_send_applies_on_the_next_pass():
    store = _lease_world([dv(nxt=NOW - 1)])
    claimed = _claim(store, ("i1", "open"), NOW)
    assert _pass(store, "open", snooze(7200), NOW + 1) == []
    statement, params = sql.failure_statement(claimed, NOW + 2, CFG)
    assert store.run(statement, params) == 1  # the retry time comes from the claimed row only
    assert store.rows()[("i1", "open")].next_attempt_at == NOW + 2 + 60
    assert _pass(store, "open", snooze(7200), NOW + 3) == [Reschedule("i1", "open", NOW + 7200)]


def test_a_stale_or_double_completion_affects_no_row():
    store = _lease_world([dv(nxt=NOW - 1)])
    claimed = _claim(store, ("i1", "open"), NOW)
    stale = dataclasses.replace(claimed, version=claimed.version - 1)
    assert store.run(sql.COMPLETE_SENT, sql.completion_params(stale, NOW + 1)) == 0
    assert store.run(sql.COMPLETE_SENT, sql.completion_params(claimed, NOW + 1)) == 1
    assert store.run(sql.COMPLETE_SENT, sql.completion_params(claimed, NOW + 2)) == 0
    assert store.run(sql.CLAIM, sql.claim_params(store.rows()[("i1", "open")], NOW + 3, CFG)) == 0


def test_flapping_during_sends_never_exceeds_the_attempt_budget():
    """Opus's trace (max_attempts=3): every claim is one transmission and is counted at claim."""
    cfg = DeliveryConfig(max_attempts=3)
    store = _lease_world([dv(state="sent"), dv("recover", nxt=NOW)])
    t, claims = NOW, 0
    for _ in range(8):
        row = store.rows()[("i1", "recover")]
        if row.state != "pending":
            break
        t = max(t, row.next_attempt_at)
        assert store.run(sql.CLAIM, sql.claim_params(row, t, cfg)) == 1
        claims += 1
        claimed = store.rows()[("i1", "recover")]
        for state in ("open", "resolved"):  # flap while the send is in flight
            t += 1
            assert plan([inc(state=state)], {}, list(store.rows().values()), t, cfg) == ()
        assert store.run(*sql.failure_statement(claimed, t, cfg)) == 1
        for state in ("open", "resolved"):  # and flap between sends: Withdraw, then Revive
            t += 1
            acts = plan([inc(state=state)], {}, list(store.rows().values()), t, cfg)
            store.apply_pass(acts, t)
    final = store.rows()[("i1", "recover")]
    assert claims == cfg.max_attempts == final.attempts and final.state == "failed"
