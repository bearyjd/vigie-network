"""VIGIE_DELIVERY_DETECTORS: only allowlisted detectors' incidents reach the delivery planner.

Default = the two upload detectors, so production behaviour is unchanged. A foreign detector
(F5 `new_device`) opens no delivery row and never gets a recover/forget unless it is allowlisted.
Policy versions are pinned the same way as test_engine_incident_scope.py.
"""

from __future__ import annotations

import pytest
from delivery_runner_helpers import T0, Clock, World, dconf
from test_probe_freeze import POOLED_VERSION, TOD_VERSION

from vigie_pipeline.config import DeliverySettings, PipelineConfig
from vigie_pipeline.delivery_publish import FakePublisher
from vigie_pipeline.delivery_runner import run_delivery
from vigie_pipeline.processor import monitoring_policy


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    yield w
    w.close()


def go(world, pub, clock, **kw):
    return run_delivery(world.inv, world.ro, pub, dconf(), clock, **kw)


def dump(world):
    keep = ("incident_id", "kind", "state", "attempts", "next_attempt_at", "created_at", "version")
    return [tuple(r[k] for k in keep) for r in world.rows()]


def test_policy_versions_unchanged():
    assert monitoring_policy(PipelineConfig.from_env({})).version == POOLED_VERSION
    tod = PipelineConfig.from_env({"VIGIE_MONITORING_BASELINE": "tod"})
    assert monitoring_policy(tod).version == TOD_VERSION


# Captured on main (77dcfa2) before the allowlist existed.
GOLDEN = [
    ("a", "open", "sent", 1, 1792000070, 1792000010, 2),
    ("b", "open", "sent", 1, 1792000070, 1792000010, 2),
    ("c", "open", "sent", 1, 1792000070, 1792000010, 2),
    ("c", "recover", "sent", 1, 1792000170, 1792000110, 2),
]


def upload_scenario(world):
    world.incident("a", detector="large_upload")
    world.incident("b", detector="upload_deviation", at=T0 + 1)
    world.incident("c", detector="large_upload", at=T0 + 2)
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock)
    world.set_state("c", "resolved")
    world.set_state("b", "superseded")
    clock.t += 100
    go(world, pub, clock)
    clock.t += 100
    go(world, pub, clock)
    return pub


def test_default_allowlist_matches_main_for_upload_incidents(world):
    pub = upload_scenario(world)
    assert [m.kind for m in pub.sent] == ["open", "open", "open", "recover"]
    assert dump(world) == GOLDEN


def foreign_scenario(world, **kw):
    world.incident("f", detector="new_device")
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock, **kw)
    world.set_state("f", "resolved")
    clock.t += 100
    go(world, pub, clock, **kw)
    return pub


def test_main_fixture_detector_upload_is_frozen_under_the_default_allowlist(world):
    """Main's old helper value `upload` is not a real detector: unlike main, it is not delivered."""
    world.incident("old", detector="upload")
    pub = FakePublisher()
    go(world, pub, Clock(T0 + 10))
    assert world.rows() == [] and pub.attempted == []


def test_foreign_detector_creates_no_row_and_no_recover_by_default(world):
    pub = foreign_scenario(world)
    assert world.rows() == [] and pub.attempted == []


def test_allowlisted_foreign_detector_opens_a_row(world):
    world.incident("f", detector="new_device")
    pub = FakePublisher()
    go(world, pub, Clock(T0 + 10), detectors=("large_upload", "upload_deviation", "new_device"))
    assert world.states() == {"open": "sent"} and len(pub.sent) == 1


def test_dropping_a_detector_from_the_allowlist_expires_pending_rows_and_sends_no_recover(world):
    world.incident("f", detector="new_device")
    allow = ("large_upload", "new_device")
    pub, clock = FakePublisher(), Clock(T0)
    go(world, pub, clock, detectors=allow, max_per_run=0)  # enqueued, nothing drained
    assert world.states() == {"open": "pending"}
    go(world, pub, clock, detectors=("large_upload",))
    assert world.states() == {"open": "expired"} and pub.attempted == []
    world.set_state("f", "resolved")
    clock.t += 100
    go(world, pub, clock, detectors=("large_upload",))
    assert world.states() == {"open": "expired"}


@pytest.mark.parametrize("state", ["pending", "sending"])
def test_held_detector_keeps_queued_notice_until_retry(world, state):
    held_detector = "essential_absence"
    allow = ("large_upload", held_detector)
    pub, clock = FakePublisher(), Clock(T0)
    world.incident("held", detector=held_detector)
    world.incident("removed", detector="new_device")
    go(world, pub, clock, detectors=(*allow, "new_device"), max_per_run=0)
    if state == "sending":
        world.inv.execute(
            "UPDATE incident_deliveries SET state='sending',attempts=1,next_attempt_at=?"
            " WHERE incident_id='held'",
            (T0 + 60,),
        )
    before = world.rows()[0]
    world.incident("upload")
    clock.t += 60
    go(
        world,
        pub,
        clock,
        detectors=allow,
        held=frozenset({held_detector, "new_device"}),
        max_per_run=1,
    )
    after, removed, _upload = world.rows()
    assert after == before
    assert removed["state"] == "expired"
    assert [m.link for m in pub.sent] == ["/ui/#incident=upload"]

    go(world, pub, clock, detectors=allow)
    if state == "sending":
        reclaimed = world.rows()[0]
        assert (reclaimed["state"], reclaimed["attempts"]) == ("pending", 1)
        assert reclaimed["next_attempt_at"] == clock.t + 60
        assert len(pub.sent) == 1
        clock.t += 60
        go(world, pub, clock, detectors=allow)
    assert [m.link for m in pub.sent] == ["/ui/#incident=upload", "/ui/#incident=held"]


def test_held_notice_uses_normal_ttl_after_release(world):
    detector = "essential_absence"
    world.incident(detector=detector)
    pub, clock = FakePublisher(), Clock(T0)
    go(world, pub, clock, detectors=(detector,), max_per_run=0)
    before = world.rows()

    clock.t += dconf().pending_ttl_seconds
    go(world, pub, clock, detectors=(detector,), held=frozenset({detector}))
    assert world.rows() == before

    go(world, pub, clock, detectors=(detector,))
    assert world.states() == {"open": "expired"} and pub.attempted == []


def test_dropping_a_detector_after_send_never_sends_recover(world):
    world.incident("f", detector="new_device")
    allow = ("large_upload", "new_device")
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock, detectors=allow)
    assert world.states() == {"open": "sent"}
    world.set_state("f", "resolved")
    clock.t += 100
    go(world, pub, clock, detectors=("large_upload",))
    assert world.states() == {"open": "sent"} and [m.kind for m in pub.sent] == ["open"]


def det(value=None):
    env = {} if value is None else {"VIGIE_DELIVERY_DETECTORS": value}
    return PipelineConfig.from_env({"VIGIE_DATA_DIR": "/nonexistent/x", **env}).delivery.detectors


def test_default_detectors():
    assert det() == ("large_upload", "upload_deviation")
    assert DeliverySettings().detectors == ("large_upload", "upload_deviation")


@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("large_upload", ("large_upload",)),
        (" large_upload , new_device ", ("large_upload", "new_device")),
        ("a,b,c,d,e,f,g,h", tuple("abcdefgh")),
        ("a1_" + "b" * 28, ("a1_" + "b" * 28,)),
    ],
)
def test_detector_values(value, want):
    assert det(value) == want


@pytest.mark.parametrize(
    "value",
    ["", "  ", ",", "a,", ",a", "a,,b", "a,a", "Large", "1abc", "a-b", "a b", "x" * 33,
     "a,b,c,d,e,f,g,h,i", "\u00e9", "a\nb"],
)  # fmt: skip
def test_bad_detector_values_fail_fast_without_echoing_them(value):
    with pytest.raises(ValueError, match="VIGIE_DELIVERY_DETECTORS") as err:
        det(value)
    assert len(value) < 3 or value not in str(err.value)


NARROW = ("large_upload",)
PAST_RETENTION = dconf().retention_seconds + 1000


def test_remove_then_add_back_after_retention_does_not_reannounce_an_open_incident(world):
    world.incident("u", detector="upload_deviation")
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock)
    clock.t += PAST_RETENTION
    go(world, pub, clock, detectors=NARROW)
    assert world.states() == {"open": "sent"}  # frozen: never deleted while the incident is open
    go(world, pub, clock)
    assert [m.kind for m in pub.sent] == ["open"]


def test_frozen_open_incident_keeps_rows_and_gets_no_new_ones(world):
    world.incident("u", detector="upload_deviation")
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock)
    before = dump(world)
    for _ in range(3):
        clock.t += 86400
        go(world, pub, clock, detectors=NARROW)
    assert dump(world) == before and len(pub.sent) == 1


def test_frozen_incident_with_no_rows_gets_none(world):
    world.incident("u", detector="upload_deviation")
    go(world, FakePublisher(), Clock(T0 + 10), detectors=NARROW)
    assert world.rows() == []


def test_pending_row_of_a_frozen_incident_expires(world):
    world.incident("u", detector="upload_deviation")
    pub, clock = FakePublisher(), Clock(T0)
    go(world, pub, clock, max_per_run=0)
    assert world.states() == {"open": "pending"}
    go(world, pub, clock, detectors=NARROW)
    assert world.states() == {"open": "expired"} and pub.attempted == []


def test_closed_non_allowlisted_incident_rows_are_deleted_after_retention_like_main(world):
    world.incident("u", detector="upload_deviation")
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock)
    world.set_state("u", "resolved")
    clock.t += 100
    go(world, pub, clock, detectors=NARROW)
    assert world.states() == {"open": "sent"}  # no recover while frozen
    clock.t += PAST_RETENTION
    go(world, pub, clock, detectors=NARROW)
    assert world.rows() == []


@pytest.mark.parametrize("bad", ["large_upload", (), [], frozenset()])
def test_run_delivery_rejects_a_str_or_empty_detectors(world, bad):
    world.incident("u")
    with pytest.raises(ValueError, match="detectors"):
        go(world, FakePublisher(), Clock(T0 + 10), detectors=bad)
    assert world.rows() == []


@pytest.mark.parametrize("bad", [("Bad",), (), ("a", "a")])
def test_settings_reject_bad_detectors_directly(bad):
    with pytest.raises(ValueError, match="VIGIE_DELIVERY_DETECTORS"):
        DeliverySettings(detectors=bad)
