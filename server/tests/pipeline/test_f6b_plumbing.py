"""F6-b plumbing: open-only delivery (allowlist AND enabled), text, prune exemption."""

from __future__ import annotations

import json
import unicodedata

import pytest
from delivery_runner_helpers import T0, Clock, World, dconf
from test_f5_s2a_plumbing import HOSTILE, HOUR, ids, put, seed_row
from test_monitoring_engine import seeded

from vigie_pipeline.delivery_publish import (
    DETECTOR_BODIES,
    DETECTOR_TITLES,
    MAX_LABEL,
    FakePublisher,
    alias,
    build_message,
)
from vigie_pipeline.delivery_runner import run_delivery
from vigie_pipeline.delivery_types import DEFAULT_DETECTORS, OPEN_ONLY_DETECTORS
from vigie_pipeline.monitoring_engine import prune_monitoring

D = "essential_absence"
ALLOW = (*DEFAULT_DETECTORS, D)


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    yield w
    w.close()


def go(world, pub, clock, **kw):
    return run_delivery(world.inv, world.ro, pub, dconf(), clock, **kw)


def build(kind, label, device="dev-x"):
    return build_message("d" * 32, kind, "inc-1", label, device, D)


def test_registered_as_open_only_with_text_and_not_in_the_default_allowlist():
    assert D in OPEN_ONLY_DETECTORS and (D, "open") in DETECTOR_TITLES
    assert (D, "open") in DETECTOR_BODIES and (D, "recover") not in DETECTOR_TITLES
    assert D not in DEFAULT_DETECTORS


def test_text_uses_the_label_and_never_says_it_is_a_new_device():
    m = build("open", "Camera A")
    assert m.title == "Camera A has not been seen" and "Camera A has not been seen" in m.body
    assert m.link in m.body and "New device" not in m.title


def test_text_falls_back_to_the_alias_and_has_no_recover():
    assert build("open", None, "dev-x").title.startswith(alias("dev-x"))
    with pytest.raises(ValueError, match="open-only"):
        build("recover", "Camera A")


@pytest.mark.parametrize("label", HOSTILE, ids=range(len(HOSTILE)))
def test_text_is_sanitised_bounded_and_carries_no_mac(label):
    m = build("open", label, "dev-x")
    for text in (m.title, m.body):
        assert not any(
            unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp") for c in text
        )
        assert len(text) < 300
    clean = m.title.removesuffix(" has not been seen")
    assert clean == alias("dev-x") or (clean == label and len(clean) <= MAX_LABEL)
    assert json.dumps({"t": m.title, "b": m.body})


def test_not_delivered_unless_allowlisted(world):
    world.incident("e", detector=D)
    pub = FakePublisher()
    go(world, pub, Clock(T0 + 10))
    assert world.rows() == [] and pub.attempted == []


def test_allowlisted_opens_once_and_never_recovers(world):
    world.incident("e", detector=D)
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock, detectors=ALLOW)
    world.set_state("e", "resolved")
    for _ in range(3):
        clock.t += 100
        go(world, pub, clock, detectors=ALLOW)
    assert [m.kind for m in pub.sent] == ["open"] and world.states() == {"open": "sent"}


def test_an_incident_resolved_before_delivery_is_not_sent(world):
    world.incident("e", state="resolved", detector=D)
    pub = FakePublisher()
    go(world, pub, Clock(T0 + 10), detectors=ALLOW)
    assert pub.attempted == []


def test_an_existing_recover_row_is_never_sent(world):
    world.incident("e", state="resolved", detector=D)
    seed_row(world, "e", "open", "sent")
    seed_row(world, "e", "recover", "pending", T0)
    pub, clock = FakePublisher(), Clock(T0 + 100)
    go(world, pub, clock, detectors=ALLOW)
    assert pub.attempted == []


def test_prune_keeps_open_and_delivered_pruning_the_rest(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        put(inv, "ea-open", D, "open")
        put(inv, "ea-resolved", D, "resolved")
        put(inv, "ea-kept", D, "resolved")
        inv.execute(
            "INSERT INTO incident_deliveries(delivery_id,incident_id,kind,state,attempts,"
            "created_at,updated_at,version) VALUES (?,?,?,?,0,?,?,0)",
            ("k" * 32, "ea-kept", "open", "sent", T0, T0),
        )
        prune_monitoring(inv, HOUR + 200 * 86400)
        assert ids(inv) == {"ea-open", "ea-kept"}
        inv.execute("DELETE FROM incident_deliveries")
        prune_monitoring(inv, HOUR + 200 * 86400)
        assert ids(inv) == {"ea-open"}
    finally:
        inv.close()
        ov.close()
