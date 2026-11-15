"""F5 S2a plumbing: nothing creates a `new_device` incident yet, but every layer must be ready.

Prune keeps OPEN non-upload incidents; the delivery planner is open-only for `new_device`; its
text carries the alias only. Rows are inserted directly (cloned shape, as test_engine_incident_scope
does). Policy versions are pinned through the shared freeze pins; never regenerate goldens.
"""

from __future__ import annotations

import json
import unicodedata

import pytest
from delivery_runner_helpers import T0, Clock, World, dconf
from test_monitoring_engine import HOUR, seeded
from test_probe_freeze import POOLED_VERSION, TOD_VERSION

from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.delivery_publish import MAX_LABEL, FakePublisher, alias, build_message
from vigie_pipeline.delivery_runner import run_delivery
from vigie_pipeline.monitoring_engine import prune_monitoring
from vigie_pipeline.processor import monitoring_policy

ALLOW = ("large_upload", "upload_deviation", "new_device")


def test_policy_versions_unchanged():
    assert monitoring_policy(PipelineConfig.from_env({})).version == POOLED_VERSION
    tod = PipelineConfig.from_env({"VIGIE_MONITORING_BASELINE": "tod"})
    assert monitoring_policy(tod).version == TOD_VERSION


# ---- prune -------------------------------------------------------------------------------------
def put(inv, iid, detector, state, last_hour=HOUR):
    inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)"
        " VALUES (?,'c1','d1','L',?,?,?,?,'2026-01-01T00:00:00Z',NULL,0,0,'{}')",
        (iid, detector, state, last_hour, last_hour),
    )


def ids(inv):
    return {r[0] for r in inv.execute("SELECT id FROM monitoring_incidents")}


def test_prune_keeps_open_non_upload_and_prunes_everything_else_old(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        put(inv, "nd-open", "new_device", "open")
        put(inv, "nd-resolved", "new_device", "resolved")
        put(inv, "nd-superseded", "new_device", "superseded")
        for detector in ("large_upload", "upload_deviation"):
            for state in ("open", "resolved", "superseded"):
                put(inv, f"{detector}-{state}", detector, state)
        put(inv, "nd-recent", "new_device", "resolved", HOUR + 99 * 86400)
        prune_monitoring(inv, HOUR + 100 * 86400)
        assert ids(inv) == {"nd-open", "nd-recent"}
    finally:
        inv.close()
        ov.close()


# ---- delivery: open-only -----------------------------------------------------------------------
@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    yield w
    w.close()


def go(world, pub, clock, **kw):
    kw.setdefault("detectors", ALLOW)
    return run_delivery(world.inv, world.ro, pub, dconf(), clock, **kw)


@pytest.mark.parametrize("closed", ["resolved", "superseded"])
def test_new_device_open_is_sent_and_never_followed_by_a_recover(world, closed):
    world.incident("n", detector="new_device")
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock)
    assert world.states() == {"open": "sent"}
    world.set_state("n", closed)
    for _ in range(3):
        clock.t += 100
        go(world, pub, clock)
    assert world.states() == {"open": "sent"}  # an already-sent open stays sent
    assert [m.kind for m in pub.sent] == ["open"]


@pytest.mark.parametrize("closed", ["resolved", "superseded"])
def test_new_device_closed_before_send_gets_no_recover_row(world, closed):
    world.incident("n", detector="new_device")
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock, max_per_run=0)
    assert world.states() == {"open": "pending"}
    world.set_state("n", closed)
    clock.t += 100
    go(world, pub, clock)
    assert "recover" not in {r["kind"] for r in world.rows()} and pub.attempted == []


def test_new_device_is_not_delivered_with_the_default_allowlist(world):
    world.incident("n", detector="new_device")
    pub, clock = FakePublisher(), Clock(T0 + 10)
    default = ("large_upload", "upload_deviation")
    go(world, pub, clock, detectors=default)
    world.set_state("n", "resolved")
    clock.t += 100
    go(world, pub, clock, detectors=default)
    assert world.rows() == [] and pub.attempted == []


def test_upload_incident_still_gets_its_recover_when_new_device_is_allowlisted(world):
    world.incident("u", detector="upload_deviation")
    world.incident("n", detector="new_device", at=T0 + 1)
    pub, clock = FakePublisher(), Clock(T0 + 10)
    go(world, pub, clock)
    world.set_state("u", "resolved")
    world.set_state("n", "resolved")
    clock.t += 100
    go(world, pub, clock)
    assert sorted((m.kind, m.title[:6]) for m in pub.sent) == [
        ("open", "New de"),
        ("open", "Vigie:"),
        ("recover", "Vigie:"),
    ]


# ---- delivery: text ----------------------------------------------------------------------------
def build(kind, label, device="dev-x", detector="new_device"):
    return build_message("d" * 32, kind, "inc-1", label, device, detector)


def test_new_device_text_uses_the_label_only():
    m = build("open", "Kitchen tablet")
    assert m.title == "New device on your network: Kitchen tablet"
    assert m.body.startswith("New device on your network: Kitchen tablet.")
    assert m.link in m.body


def test_new_device_text_falls_back_to_the_alias():
    assert build("open", None, "dev-x").title.endswith(alias("dev-x"))


def test_upload_texts_are_byte_identical():
    o = build_message("d" * 32, "open", "i", "Phone", "dev")
    r = build_message("d" * 32, "recover", "i", "Phone", "dev")
    assert o.title == "Vigie: check Phone"
    assert o.body == "Phone: unusual activity detected. Review it here: /ui/#incident=i"
    assert r.title == "Vigie: Phone is back to normal"
    assert r.body == "Phone: the activity has returned to normal. Details: /ui/#incident=i"
    assert build_message("d" * 32, "open", "i", "Phone", "dev", "large_upload") == o


HOSTILE = [
    "a\nb", "a\r\nSubject: x", "tab\there", "\x00nul", "\x1b[31mred", "‮evil", "x" * 5000,
    "<script>alert(1)</script>", "[x](http://e.example)", "`rm -rf`", "{label}{link}", "%s%d",
    "é́", "\U0001f600 party", "aa:bb:cc:dd:ee:ff", "aabbccddeeff", "Ａbc", "  pad  ",
    "ntfy: Title: x", "", None, 5,
]  # fmt: skip


@pytest.mark.parametrize("label", HOSTILE, ids=range(len(HOSTILE)))
def test_new_device_text_is_sanitised_and_bounded(label):
    m = build("open", label, "dev-x")
    for text in (m.title, m.body):
        assert not any(
            unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp") for c in text
        )
        assert len(text) < 300
    clean = m.title.removeprefix("New device on your network: ")
    assert clean == alias("dev-x") or (clean == label and len(clean) <= MAX_LABEL)
    assert json.dumps({"t": m.title, "b": m.body})
