"""End-to-end delivery runner on real SQLite with a FakePublisher and an injected clock."""

from __future__ import annotations

import logging
import threading

import pytest
from delivery_runner_helpers import SINCE, T0, Clock, World, dconf

from vigie_pipeline import delivery_runner
from vigie_pipeline.delivery_plan import Enqueue, Expected, Expire
from vigie_pipeline.delivery_publish import FakePublisher, PublishError
from vigie_pipeline.delivery_runner import run_delivery
from vigie_pipeline.delivery_sql import PassError

_GATES: list[threading.Event] = []


def _gate():
    _GATES.append(threading.Event())
    return _GATES[-1]


@pytest.fixture(autouse=True)
def _no_abandoned_workers():
    """The registry of abandoned publishes is process-wide: every test starts and ends clean."""
    delivery_runner._ABANDONED.clear()
    delivery_runner._wedged_runs = 0
    delivery_runner._IN_FLIGHT = 0
    yield
    for gate in _GATES:
        gate.set()
    _GATES.clear()
    _wait_idle()
    assert delivery_runner._IN_FLIGHT == 0  # no test may leak a reservation


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    yield w
    w.close()


def go(world, pub, clock, config=None, **kw):
    return run_delivery(world.inv, world.ro, pub, config or dconf(), clock, **kw)


def test_open_incident_sends_exactly_one_open_message(world):
    world.incident()
    world.name("dev-1", "Kitchen cam")
    pub, clock = FakePublisher(), Clock()
    report = go(world, pub, clock)
    assert report.sent == 1 and world.states() == {"open": "sent"}
    (msg,) = pub.sent
    assert msg.kind == "open" and "Kitchen cam" in msg.body and msg.link == "/ui/#incident=i1"
    clock.t += 10
    go(world, pub, clock)
    assert len(pub.sent) == 1


def test_label_falls_back_to_device_id(world):
    world.incident(device="dev-9")
    pub = FakePublisher()
    go(world, pub, Clock())
    assert "dev-9" in pub.sent[0].body


def test_acknowledged_incident_is_suppressed_and_never_sent(world):
    world.incident()
    world.decide("i1", "acknowledged")
    pub = FakePublisher()
    go(world, pub, Clock())
    assert pub.attempted == [] and world.states() == {"open": "suppressed"}


def test_future_snooze_waits_until_due(world):
    world.incident()
    world.decide("i1", "snoozed", T0 + 600)
    pub, clock = FakePublisher(), Clock()
    go(world, pub, clock)
    assert pub.attempted == []
    clock.t = T0 + 300
    go(world, pub, clock)
    assert pub.attempted == []
    clock.t = T0 + 601
    go(world, pub, clock)
    assert len(pub.sent) == 1


def test_resolve_after_sent_sends_exactly_one_recover(world):
    world.incident()
    pub, clock = FakePublisher(), Clock()
    go(world, pub, clock)
    world.set_state("i1", "resolved")
    for step in (10, 20, 30):
        clock.t = T0 + step
        go(world, pub, clock)
    assert [m.kind for m in pub.sent] == ["open", "recover"]
    assert world.states() == {"open": "sent", "recover": "sent"}


def test_failure_retries_with_backoff_then_fails_at_budget(world):
    world.incident()
    err = PublishError("down")
    pub, clock = FakePublisher(script=[err, err]), Clock()
    config = dconf(max_attempts=2, backoff_base_seconds=60, backoff_cap_seconds=60)
    report = go(world, pub, clock, config)
    (row,) = world.rows()
    assert report.failed == 1 and row["state"] == "pending" and row["attempts"] == 1
    assert row["next_attempt_at"] == T0 + 60
    clock.t = T0 + 30
    go(world, pub, clock, config)
    assert len(pub.attempted) == 1  # backoff respected
    clock.t = T0 + 60
    go(world, pub, clock, config)
    (row,) = world.rows()
    assert row["state"] == "failed" and row["attempts"] == 2 and len(pub.attempted) == 2
    clock.t = T0 + 1000
    go(world, pub, clock, config)
    assert len(pub.attempted) == 2


def test_any_exception_from_publisher_is_a_failure(world):
    world.incident()
    go(world, FakePublisher(script=[ValueError("boom")]), Clock())
    assert world.states() == {"open": "pending"}


def test_max_per_run_bounds_the_drain(world):
    for i in range(5):
        world.incident(f"i{i}")
    pub, clock = FakePublisher(), Clock()
    go(world, pub, clock, max_per_run=2)
    assert len(pub.sent) == 2
    go(world, pub, clock, max_per_run=2)
    assert len(pub.sent) == 4


def test_unavailable_decision_store_plans_and_sends_nothing(world, caplog):
    world.incident()
    pub = FakePublisher()
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        report = run_delivery(world.inv, None, pub, dconf(), Clock())
    assert pub.attempted == [] and world.rows() == [] and report.skipped
    assert [r.getMessage() for r in caplog.records].count("delivery_decisions_unavailable") == 1


def test_unreadable_decision_store_is_the_same(world, tmp_path):
    world.incident()
    world.ro.close()
    pub = FakePublisher()
    report = run_delivery(world.inv, world.ro, pub, dconf(), Clock())
    assert report.skipped and pub.attempted == [] and world.rows() == []


def test_decision_store_unavailable_does_not_drain_claimable_rows(world):
    world.incident()
    go(world, FakePublisher(script=[PublishError("x")]), Clock())
    pub = FakePublisher()
    run_delivery(world.inv, None, pub, dconf(), Clock(T0 + 600))
    assert pub.attempted == []


def test_old_incident_before_watermark_is_never_announced(world):
    world.incident("old", at=SINCE - 5000)
    pub = FakePublisher()
    go(world, pub, Clock())
    assert pub.attempted == [] and world.rows() == []


class Probe(FakePublisher):
    """Hangs like a dead transport, after checking the database is free."""

    def __init__(self, path):
        super().__init__(script=[_gate()])
        self.path, self.free = path, None

    def publish(self, message, *, timeout_seconds):
        import sqlite3

        other = sqlite3.connect(self.path, timeout=0.2, isolation_level=None)
        try:
            other.execute("BEGIN IMMEDIATE")
            other.execute("ROLLBACK")
            self.free = True
        except sqlite3.Error:
            self.free = False
        finally:
            other.close()
        super().publish(message, timeout_seconds=timeout_seconds)


def test_hung_transport_is_abandoned_at_the_deadline_without_a_held_transaction(world, tmp_path):
    world.incident()
    pub = Probe(tmp_path / "inventory.db")
    report = go(world, pub, Clock())
    assert pub.free is True  # a writer could BEGIN IMMEDIATE during the hang
    assert report.failed == 1 and report.sent == 0
    (row,) = world.rows()
    assert row["state"] == "pending" and row["attempts"] == 1
    assert not world.inv.in_transaction
    assert pub.sent == []  # still hanging: the runner did not wait for it
    pub._script.clear()


def test_hang_stops_the_drain_for_this_run(world, tmp_path):
    world.incident("a")
    world.incident("b")
    pub = FakePublisher(script=[_gate()])
    report = go(world, pub, Clock())
    assert len(pub.attempted) == 1 and report.failed == 1


def test_may_transmit_aborts_without_transmitting(world):
    world.incident()
    reads = []

    def clock():
        reads.append(1)
        return T0 if len(reads) <= 2 else T0 + 5  # plan, claim, then past the 1 s deadline

    pub = FakePublisher()
    report = go(world, pub, clock)
    assert pub.attempted == [] and report.aborted == 1
    (row,) = world.rows()
    assert row["state"] == "pending" and row["attempts"] == 1


def test_pass_error_rolls_back_the_whole_pass(world, monkeypatch):
    world.incident("a")
    world.incident("b")
    good = Enqueue("a", "open", T0)
    bad = Expire("b", "open", "x", Expected("pending", 0, 0, 99))
    monkeypatch.setattr(delivery_runner, "plan", lambda *a, **k: (good, bad))
    pub = FakePublisher()
    with pytest.raises(PassError):
        go(world, pub, Clock())
    assert world.rows() == [] and not world.inv.in_transaction and pub.attempted == []
    monkeypatch.undo()
    go(world, pub, Clock())
    assert len(pub.sent) == 2


def test_hostile_fields_never_reach_the_message(world):
    hostile = '{"dst":"203.0.113.9","domain":"evil.example.com","mac":"aa:bb:cc:dd:ee:ff"}'
    world.incident(device="10.0.0.5\x00\n" + "d" * 3000, evidence=hostile)
    world.name("10.0.0.5\x00\n" + "d" * 3000, "TV 192.168.1.2 aa:bb:cc:dd:ee:ff x.evil.com\x1b[0m")
    pub = FakePublisher()
    go(world, pub, Clock())
    (m,) = pub.sent
    text = " ".join([m.title, m.body, m.link])
    for needle in ("203.0.113.9", "evil.example.com", "aa:bb:cc", "192.168", "10.0.0.5", "999999"):
        assert needle not in text
    assert not any(ord(c) < 32 for c in text) and len(text) < 600


def test_now_is_read_after_begin_immediate_and_claim_is_short(world):
    world.incident()
    seen = []

    def clock():
        seen.append(world.inv.in_transaction)
        return T0

    go(world, FakePublisher(), clock)
    # plan pass, claim, may_transmit, complete: the publish happens between claim and complete
    assert seen == [True, True, False, True]


def test_lost_claim_race_transmits_nothing(world, monkeypatch):
    world.incident()
    go(world, FakePublisher(script=[PublishError("x")]), Clock())
    (row,) = world.rows()
    stale = delivery_runner.DeliveryView(**{**_view(row), "version": row["version"] - 1})
    monkeypatch.setattr(delivery_runner, "_due", lambda *a, **k: [stale])
    pub = FakePublisher()
    report = go(world, pub, Clock(T0 + 600))
    assert pub.attempted == [] and report.claimed == 0


def _view(row):
    keys = "row_id incident_id kind state attempts next_attempt_at created_at updated_at version"
    return {k: row[k] for k in keys.split()}


def _hang_forever(n):
    gates = [_gate() for _ in range(n)]
    return gates, FakePublisher(script=list(gates))


def _wait_idle():
    for _ in range(500):
        if delivery_runner.abandoned_count() == 0:
            return
        threading.Event().wait(0.01)
    raise AssertionError("abandoned workers did not finish")


def test_wedged_transport_is_bounded_across_runs_and_burns_no_attempts(world):
    for name in "abc":
        world.incident(name)
    gates, pub = _hang_forever(3)
    clock = Clock()
    for step in range(3):
        clock.t = T0 + step * 4000  # past any backoff
        go(world, pub, clock, max_abandoned=2)
    # run 1 hangs on a; run 2 skips a (live worker) and hangs on b; run 3 finds the bound full
    assert sorted(r["attempts"] for r in world.rows()) == [0, 1, 1]
    assert len(pub.attempted) == 2 and delivery_runner.abandoned_count() == 2
    workers = [t for t in threading.enumerate() if t.name == "vigie-delivery-publish"]
    assert len(workers) == 2 and all(t.daemon for t in workers)
    for gate in gates:
        gate.set()
    _wait_idle()
    clock.t = T0 + 20000
    go(world, pub, clock, max_abandoned=2)
    assert len(pub.attempted) == 5 and all(r["attempts"] >= 1 for r in world.rows())


def test_wedged_transport_is_logged_once_not_every_run(world, caplog):
    for name in "abc":
        world.incident(name)
    gates, pub = _hang_forever(1)
    go(world, pub, Clock(), max_abandoned=1)
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        for step in range(1, 4):
            report = go(world, pub, Clock(T0 + step * 4000), max_abandoned=1)
            assert report.claimed == 0 and report.skipped is None
    assert [r.getMessage() for r in caplog.records].count("delivery_transport_wedged") == 1
    (rec,) = [r for r in caplog.records if r.getMessage() == "delivery_transport_wedged"]
    assert "1 abandoned publishes still running" in rec.fields["detail"]


def test_late_worker_result_never_touches_rows(world):
    world.incident()
    gates, pub = _hang_forever(1)
    go(world, pub, Clock())
    before = world.rows()
    gates[0].set()  # the hung publish now "succeeds", long after its claim was failed
    _wait_idle()
    assert world.rows() == before and world.states() == {"open": "pending"}


def test_concurrent_drains_cannot_both_start_a_worker(world, tmp_path, monkeypatch):
    """Both drains reach the capacity check together: exactly one may proceed, and the loser must
    not even CLAIM (reserve-then-claim), so its row keeps attempts == 0."""
    from vigie_pipeline.overrides import open_overrides_ro
    from vigie_pipeline.schema import open_pipeline_inventory

    world.incident("a")
    world.incident("b")
    gates, pub = _hang_forever(1)
    barrier = threading.Barrier(2)
    seen: set[int] = set()
    real = delivery_runner._reserve

    def meet(*args):
        ident = threading.get_ident()
        if ident not in seen:
            seen.add(ident)
            try:
                barrier.wait(10)
            except threading.BrokenBarrierError:
                pass
        return real(*args)

    monkeypatch.setattr(delivery_runner, "_reserve", meet)
    errors = []

    def drain():
        inv = open_pipeline_inventory(tmp_path / "inventory.db")
        ro = open_overrides_ro(tmp_path / "overrides.db")
        try:
            run_delivery(inv, ro, pub, dconf(), Clock(), max_abandoned=1)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            inv.close()
            ro.close()

    threads = [threading.Thread(target=drain) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors and len(pub.attempted) == 1
    assert sorted(r["attempts"] for r in world.rows()) == [0, 1]
    assert delivery_runner.abandoned_count() == 1 and delivery_runner._IN_FLIGHT == 0


def test_in_flight_bounds_concurrent_publishes_even_without_abandonment(world):
    world.incident()
    slot = delivery_runner._reserve(1)
    assert slot is not None
    pub = FakePublisher()
    report = go(world, pub, Clock(), max_abandoned=1)
    assert pub.attempted == [] and report.claimed == 0
    assert world.rows()[0]["attempts"] == 0
    delivery_runner._release(slot)
    assert go(world, pub, Clock(T0 + 1), max_abandoned=1).sent == 1


def test_reservation_released_when_the_claim_is_lost(world, monkeypatch):
    world.incident()
    go(world, FakePublisher(script=[PublishError("x")]), Clock())
    (row,) = world.rows()
    stale = delivery_runner.DeliveryView(**{**_view(row), "version": row["version"] - 1})
    monkeypatch.setattr(delivery_runner, "_due", lambda *a, **k: [stale])
    go(world, FakePublisher(), Clock(T0 + 600))
    assert delivery_runner._IN_FLIGHT == 0


def test_reservation_released_on_may_transmit_abort(world):
    world.incident()
    reads = []

    def clock():
        reads.append(1)
        return T0 if len(reads) <= 2 else T0 + 5

    assert go(world, FakePublisher(), clock).aborted == 1
    assert delivery_runner._IN_FLIGHT == 0


def test_reservation_released_when_the_run_raises(world, monkeypatch):
    world.incident()

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(delivery_runner, "_message", boom)
    with pytest.raises(RuntimeError):
        go(world, FakePublisher(), Clock())
    assert delivery_runner._IN_FLIGHT == 0


def test_reservation_released_when_the_worker_cannot_start(world, monkeypatch):
    world.incident()

    def no_start(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", no_start)
    with pytest.raises(RuntimeError):
        go(world, FakePublisher(), Clock())
    monkeypatch.undo()
    assert delivery_runner._IN_FLIGHT == 0 and delivery_runner.abandoned_count() == 0


def test_no_publish_for_a_delivery_with_a_live_worker(world):
    world.incident()
    gates, pub = _hang_forever(1)
    go(world, pub, Clock(), max_abandoned=5)  # abandoned, still hanging
    clock = Clock(T0 + 4000)  # backoff over: the row is due again
    report = go(world, pub, clock, max_abandoned=5)
    assert report.claimed == 0 and len(pub.attempted) == 1
    assert world.rows()[0]["attempts"] == 1
    gates[0].set()
    _wait_idle()
    assert go(world, pub, clock, max_abandoned=5).sent == 1


class Ticking(FakePublisher):
    """Every publish takes `step` seconds of the monotonic clock while the WALL clock goes back."""

    def __init__(self, mono, wall, step):
        super().__init__()
        self.mono, self.wall, self.step = mono, wall, step

    def publish(self, message, *, timeout_seconds):
        self.mono.t += self.step
        self.wall.t -= self.step
        super().publish(message, timeout_seconds=timeout_seconds)


def test_drain_budget_uses_the_monotonic_clock_not_the_wall_clock(world):
    for i in range(5):
        world.incident(f"i{i}")
    go(world, FakePublisher(), Clock(T0), max_per_run=0)  # plan only: rows are due at T0
    wall, mono = Clock(T0 + 5000), Clock(0)
    pub = Ticking(mono, wall, 40)
    report = go(world, pub, wall, drain_budget_seconds=60, monotonic=mono)
    assert report.sent == 2  # 40 s spent < 60: second row; 80 s spent: stop (wall went backwards)
    assert sorted(r["attempts"] for r in world.rows()) == [0, 0, 0, 1, 1]
    assert go(world, pub, wall, drain_budget_seconds=60, monotonic=mono).sent == 2


def test_time_spent_on_skipped_candidates_counts(world, monkeypatch):
    for i in range(4):
        world.incident(f"i{i}")
    rows = _due_rows(world)
    monkeypatch.setattr(delivery_runner, "_due", lambda *a, **k: rows)
    claims = []
    real = delivery_runner._claim

    def spy(*a, **k):
        claims.append(1)
        return real(*a, **k)

    monkeypatch.setattr(delivery_runner, "_claim", spy)
    ticks = iter(range(0, 10_000, 30))  # every monotonic read costs 30 s
    go(world, FakePublisher(), Clock(), drain_budget_seconds=60, monotonic=lambda: next(ticks))
    assert len(claims) == 1  # start 0, first check 30 (claims), second check 60 >= 60: stop


def _due_rows(world):
    go(world, FakePublisher(), Clock(), max_per_run=0)  # plan only
    cur = world.inv.execute(
        "SELECT row_id,incident_id,kind,state,attempts,next_attempt_at,created_at,updated_at,"
        "version FROM incident_deliveries ORDER BY row_id"
    )
    return [delivery_runner._delivery(r) for r in cur.fetchall()]


def test_a_busy_first_row_does_not_starve_the_others(world):
    world.incident("a")
    gates, pub = _hang_forever(1)
    go(world, pub, Clock(), max_per_run=1, max_abandoned=2)  # a hangs and is abandoned
    world.incident("b", at=T0 + 3000)
    clock = Clock(T0 + 4000)  # a is due again and first by order, but its worker is alive
    report = go(world, pub, clock, max_per_run=1, max_abandoned=2)
    assert report.sent == 1 and [m.link for m in pub.sent] == ["/ui/#incident=b"]
    gates[0].set()


def test_budget_smaller_than_one_deadline_is_refused(world):
    world.incident()
    with pytest.raises(ValueError, match="drain_budget"):
        go(
            world,
            FakePublisher(),
            Clock(),
            config=dconf(transmit_deadline_seconds=30, lease_seconds=60),
            drain_budget_seconds=10,
        )
