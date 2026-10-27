from __future__ import annotations

import dataclasses
import itertools
import math

import pytest

from vigie_pipeline.delivery_plan import (
    DeliveryConfig,
    DeliveryView,
    Enqueue,
    Expire,
    Fail,
    Forget,
    IncidentView,
    Requeue,
    Reschedule,
    ReviewView,
    Suppress,
    after_failure,
    backoff,
    delivery_id,
    plan,
)

NOW = 1_000_000
CFG = DeliveryConfig()
DAY = 86400


def inc(iid="i1", state="open", detected=NOW - 10):
    return IncidentView(id=iid, state=state, detected_at=detected)


def dv(kind="open", state="pending", iid="i1", attempts=0, nxt=NOW - 5, created=NOW - 5, upd=None):
    return DeliveryView(iid, kind, state, attempts, nxt, created, created if upd is None else upd)


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
    assert run([inc(state="resolved")], deliveries=[old]) == (Forget("i1", kind),)
    announce = (Enqueue("i1", "recover", NOW),) if (kind, state) == ("open", "sent") else ()
    assert run([inc(state="resolved")], deliveries=[edge]) == announce


@pytest.mark.parametrize("state", ["sent", "failed", "expired"])
def test_rows_of_a_still_open_incident_are_kept_so_it_never_re_announces(state):
    assert run([inc()], deliveries=[dv(state=state, created=NOW - 10 * RET)]) == ()


def test_retention_counts_from_updated_at():
    d = dv(state="sent", created=NOW - 10 * RET, upd=NOW - RET)
    assert run([inc(state="resolved")], deliveries=[d]) == (Enqueue("i1", "recover", NOW),)


def test_forgotten_open_row_does_not_spawn_a_late_recover():
    d = dv(state="sent", created=NOW - RET - 1)
    assert run([inc(state="resolved")], deliveries=[d]) == (Forget("i1", "open"),)


def test_orphans_expire_when_pending_and_are_forgotten_when_terminal():
    assert run([], deliveries=[dv()]) == (Expire("i1", "open", "incident_missing"),)
    for state in ("sent", "failed", "suppressed", "expired"):
        assert run([], deliveries=[dv(state=state)]) == (Forget("i1", "open"),)


def test_retention_is_configurable():
    cfg = DeliveryConfig(retention_seconds=100)
    old = dv(state="sent", created=NOW - 101)
    assert run([inc(state="resolved")], deliveries=[old], cfg=cfg) == (Forget("i1", "open"),)


# (7) enable watermark
def test_incidents_older_than_the_watermark_are_ignored():
    cfg = DeliveryConfig(eligible_since=NOW - 5)
    assert run([inc(detected=NOW - 6)], cfg=cfg) == ()
    assert run([inc(detected=NOW - 6, state="resolved")], cfg=cfg) == ()
    assert run([inc(detected=NOW - 5)], cfg=cfg) == (Enqueue("i1", "open", NOW),)
    assert run([inc(detected=NOW - 6)], cfg=DeliveryConfig()) == (Enqueue("i1", "open", NOW),)


def test_rows_of_an_ignored_incident_are_cleaned_up_as_orphans():
    cfg = DeliveryConfig(eligible_since=NOW)
    assert run([inc()], deliveries=[dv()], cfg=cfg) == (Expire("i1", "open", "incident_missing"),)


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


def test_after_failure_reschedules_until_max_attempts_then_fails():
    assert after_failure(dv(attempts=1), NOW, CFG) == Reschedule("i1", "open", NOW + 60)
    assert after_failure(dv(attempts=5), NOW, CFG) == Reschedule("i1", "open", NOW + 960)
    assert after_failure(dv(attempts=6), NOW, CFG) == Fail("i1", "open", "max_attempts")
    assert after_failure(dv(attempts=9), NOW, CFG) == Fail("i1", "open", "max_attempts")


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


@pytest.mark.parametrize("field", ["attempts", "next_attempt_at", "created_at", "updated_at"])
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


@pytest.mark.parametrize("field", ["attempts", "next_attempt_at", "created_at", "updated_at"])
@pytest.mark.parametrize("bad", BAD)
@pytest.mark.parametrize("state", ["sent", "failed", "suppressed", "expired"])
def test_terminal_rows_with_bad_numbers_never_raise_or_re_announce(field, bad, state):
    d = dataclasses.replace(dv(state=state), **{field: bad})
    for incident in (inc(), inc(state="resolved"), inc(state="superseded")):
        got = run([incident], deliveries=[d])
        assert not [a for a in got if isinstance(a, Enqueue) and a.kind == "open"]


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
    by_key = {(d.incident_id, d.kind): d for d in deliveries}
    for a in actions:
        key = (a.incident_id, a.kind)
        old = by_key.get(key)
        if isinstance(a, Enqueue):
            assert old is None, "enqueue over an existing delivery"
            by_key[key] = DeliveryView(a.incident_id, a.kind, "pending", 0, a.not_before, now, now)
        elif isinstance(a, Forget):
            del by_key[key]
        elif isinstance(a, Reschedule):
            by_key[key] = dataclasses.replace(
                old, next_attempt_at=a.next_attempt_at, updated_at=now
            )
        elif isinstance(a, Requeue):
            assert old.state == "suppressed"
            by_key[key] = DeliveryView(
                a.incident_id, a.kind, "pending", 0, a.not_before, old.created_at, now
            )
        else:
            state = {Suppress: "suppressed", Expire: "expired", Fail: "failed"}[type(a)]
            base = old or DeliveryView(a.incident_id, a.kind, state, 0, None, now, now)
            by_key[key] = dataclasses.replace(base, state=state, updated_at=now)
    return tuple(by_key.values())


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
OPEN_D = [None, "pending", "sent", "failed", "suppressed", "expired"]
REC_D = [None, "pending", "sent"]
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


def test_plan_is_idempotent_over_every_generated_state():
    count = 0
    for incidents, reviews, ds in _scenarios():
        first = plan(tuple(incidents), reviews, tuple(ds), NOW, CFG)
        settled = apply(ds, first, NOW)
        again = plan(tuple(incidents), reviews, settled, NOW, CFG)
        assert again == (), (incidents, reviews, ds, first, again)
        keys = [(a.incident_id, a.kind) for a in first]
        assert keys == sorted(set(keys))
        count += 1
    assert count > 4000


def test_orphans_converge_to_nothing_in_two_passes():
    for state in ("pending", "sent", "failed", "suppressed", "expired"):
        ds = (dv(state=state),)
        for _ in range(2):
            ds = apply(ds, plan((), {}, ds, NOW, CFG), NOW)
        assert ds == ()


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
