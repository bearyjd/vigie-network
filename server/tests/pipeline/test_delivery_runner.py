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
        super().__init__(script=[threading.Event()])
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
    pub = FakePublisher(script=[threading.Event()])
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
