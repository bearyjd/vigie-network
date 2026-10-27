from __future__ import annotations

import dataclasses
import itertools

import pytest

from vigie_pipeline.delivery_plan import (
    DeliveryConfig,
    DeliveryView,
    Enqueue,
    Expire,
    Fail,
    IncidentView,
    Reschedule,
    ReviewView,
    Suppress,
    after_failure,
    backoff,
    delivery_id,
    plan,
)

NOW = 1_000_000.0
CFG = DeliveryConfig()


def inc(iid="i1", state="open"):
    return IncidentView(id=iid, state=state, detected_at=NOW - 10, last_hour=1)


def dv(kind="open", state="pending", iid="i1", attempts=0, nxt=None, created=NOW - 5):
    return DeliveryView(iid, kind, state, attempts, nxt, created)


def run(incidents, reviews=None, deliveries=(), now=NOW, cfg=CFG):
    return plan(tuple(incidents), reviews or {}, tuple(deliveries), now, cfg)


# (a) loud open incident -> exactly one Enqueue, never a second
def test_new_open_incident_gets_one_open_enqueue():
    assert run([inc()]) == (Enqueue("i1", "open", NOW),)


@pytest.mark.parametrize("state", ["pending", "sent", "failed", "suppressed", "expired"])
def test_an_existing_open_delivery_of_any_state_blocks_a_second_enqueue(state):
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
    reviews = {"i1": ReviewView("snoozed", NOW + delta)}
    assert run([inc()], reviews) == (expected,)


def test_snoozed_incident_that_resolved_is_never_enqueued():
    reviews = {"i1": ReviewView("snoozed", NOW + 100)}
    assert run([inc(state="resolved")], reviews) == ()


def test_snooze_applied_after_enqueue_pushes_a_pending_open_out():
    reviews = {"i1": ReviewView("snoozed", NOW + 100)}
    d = dv(nxt=NOW)
    assert run([inc()], reviews, [d]) == (Reschedule("i1", "open", NOW + 100),)
    assert run([inc()], reviews, [dv(nxt=NOW + 100)]) == ()
    assert run([inc()], reviews, [dv(nxt=NOW + 500)]) == ()  # never pulled earlier


def test_expired_snooze_on_a_pending_open_does_not_reschedule():
    reviews = {"i1": ReviewView("snoozed", NOW)}
    assert run([inc()], reviews, [dv(nxt=NOW - 50)]) == ()


# (d) resolved before send
@pytest.mark.parametrize("state", ["resolved", "superseded"])
def test_pending_open_expires_when_the_incident_closes_and_no_recover_follows(state):
    assert run([inc(state=state)], deliveries=[dv()]) == (
        Expire("i1", "open", "resolved_before_send"),
    )


@pytest.mark.parametrize("deliveries", [[], [dv(state="suppressed")], [dv(state="expired")]])
def test_never_announced_incident_gets_no_recover(deliveries):
    assert run([inc(state="resolved")], deliveries=deliveries) == ()


# (e) recover only for announced incidents, exactly once
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


@pytest.mark.parametrize("state", ["failed", "expired"])
def test_unsent_open_never_triggers_recover(state):
    assert run([inc(state="resolved")], deliveries=[dv(state=state)]) == ()


# (f) ttl
@pytest.mark.parametrize(
    "age,expected",
    [
        (86399, ()),
        (86400, (Expire("i1", "open", "ttl"),)),
        (86401, (Expire("i1", "open", "ttl"),)),
    ],
)
def test_pending_ttl_boundary(age, expected):
    assert run([inc()], deliveries=[dv(created=NOW - age)]) == expected


def test_ttl_applies_to_recover_too():
    ds = [dv(state="sent"), dv(kind="recover", created=NOW - 86400)]
    assert run([inc(state="resolved")], deliveries=ds) == (Expire("i1", "recover", "ttl"),)


def test_ttl_counts_from_the_scheduled_time_for_a_snoozed_delivery():
    d = dv(created=NOW - 200000, nxt=NOW - 10)
    assert run([inc()], deliveries=[d]) == ()
    d = dv(created=NOW - 200000, nxt=NOW - 86400)
    assert run([inc()], deliveries=[d]) == (Expire("i1", "open", "ttl"),)


def test_non_pending_deliveries_never_expire_by_ttl():
    assert run([inc()], deliveries=[dv(state="sent", created=NOW - 10**7)]) == ()


def test_pending_delivery_of_a_pruned_incident_expires():
    assert run([], deliveries=[dv()]) == (Expire("i1", "open", "incident_missing"),)
    assert run([], deliveries=[dv(state="sent")]) == ()


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


# (i) fail closed
@pytest.mark.parametrize("state", ["", "OPEN", "weird", "reopened"])
def test_unknown_incident_state_is_suppressed(state):
    assert run([inc(state=state)]) == (Suppress("i1", "open", "unrecognised_state"),)
    assert run([inc(state=state)], deliveries=[dv(state="suppressed")]) == ()


@pytest.mark.parametrize(
    "review",
    [ReviewView("weird", None), ReviewView("", None), ReviewView("snoozed", None)],
)
def test_unknown_or_malformed_review_is_suppressed(review):
    assert run([inc()], {"i1": review}) == (Suppress("i1", "open", "unrecognised_state"),)


def test_garbage_values_never_raise():
    bad = IncidentView(id="x", state=None, detected_at=None, last_hour=None)  # type: ignore[arg-type]
    assert run([bad], {"x": ReviewView(None, "soon")}) == (  # type: ignore[arg-type]
        Suppress("x", "open", "unrecognised_state"),
    )


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
            by_key[key] = DeliveryView(a.incident_id, a.kind, "pending", 0, a.not_before, now)
        elif isinstance(a, Reschedule):
            by_key[key] = dataclasses.replace(old, next_attempt_at=a.next_attempt_at)
        else:
            state = {Suppress: "suppressed", Expire: "expired", Fail: "failed"}[type(a)]
            base = old or DeliveryView(a.incident_id, a.kind, state, 0, None, now)
            by_key[key] = dataclasses.replace(base, state=state)
    return tuple(by_key.values())


STATES = ["open", "resolved", "superseded", "bogus"]
REVIEWS = [None, "acknowledged", "expected", ("snoozed", 100), ("snoozed", -100), "bogus"]
OPEN_D = [None, "pending", "sent", "failed"]
REC_D = [None, "pending", "sent"]


def _scenarios():
    for state, rv, od, rd, aged in itertools.product(STATES, REVIEWS, OPEN_D, REC_D, (False, True)):
        review = None
        if isinstance(rv, tuple):
            review = ReviewView(rv[0], NOW + rv[1])
        elif rv:
            review = ReviewView(rv, None)
        created = NOW - (90000 if aged else 5)
        ds = [dv(k, s, created=created) for k, s in (("open", od), ("recover", rd)) if s]
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
    assert count == 576


def test_plan_does_not_mutate_its_inputs():
    incidents, reviews, ds = (inc(),), {"i1": ReviewView("snoozed", NOW + 5)}, (dv(),)
    plan(incidents, reviews, ds, NOW, CFG)
    assert incidents == (inc(),) and reviews == {"i1": ReviewView("snoozed", NOW + 5)}
    assert ds == (dv(),)
    with pytest.raises(dataclasses.FrozenInstanceError):
        incidents[0].state = "x"  # type: ignore[misc]


def test_ttl_and_config_are_honoured():
    cfg = DeliveryConfig(pending_ttl_seconds=10)
    assert run([inc()], deliveries=[dv(created=NOW - 10)], cfg=cfg) == (
        Expire("i1", "open", "ttl"),
    )
    assert run([inc()], deliveries=[dv(created=NOW - 9)], cfg=cfg) == ()
