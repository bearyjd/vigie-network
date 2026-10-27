"""Pipeline wiring: default off, one watermark, failures never reach the pipeline pass."""

from __future__ import annotations

import logging
from dataclasses import replace

import pytest
from delivery_runner_helpers import T0, Clock, World
from pipeline_helpers import Data, data  # noqa: F401

from vigie_pipeline import delivery_wiring, processor
from vigie_pipeline.config import DeliverySettings, PipelineConfig
from vigie_pipeline.delivery_publish import FakePublisher
from vigie_pipeline.delivery_wiring import WATERMARK_KEY, run_delivery_stage
from vigie_pipeline.processor import run_once


def settings(tmp_path, **kw):
    return DeliverySettings(enabled=True, file=tmp_path / "out.jsonl", **kw)


def cfg(tmp_path, delivery):
    return PipelineConfig(data_dir=tmp_path, delivery=delivery)


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    yield w
    w.close()


def watermark(world):
    row = world.inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (WATERMARK_KEY,))
    got = row.fetchone()
    return None if got is None else int(got[0])


def test_disabled_by_default_runner_not_called_nothing_created(world, tmp_path, monkeypatch):
    world.incident()
    called = []
    monkeypatch.setattr(delivery_wiring, "run_delivery", lambda *a, **k: called.append(1))
    out = run_delivery_stage(world.inv, world.ro, cfg(tmp_path, DeliverySettings()), Clock())
    assert out is None and not called and world.rows() == [] and watermark(world) is None


def test_run_once_does_not_touch_delivery_when_disabled(data, monkeypatch):  # noqa: F811
    monkeypatch.setattr(delivery_wiring, "run_delivery", lambda *a, **k: pytest.fail("called"))
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 10)
    assert data.q("SELECT * FROM incident_deliveries") == []
    assert data.q("SELECT * FROM pipeline_meta WHERE key=?", WATERMARK_KEY) == []


def test_run_once_runs_the_stage_when_enabled(data, tmp_path, monkeypatch):  # noqa: F811
    seen = []
    monkeypatch.setattr(processor, "run_delivery_stage", lambda *a, **k: seen.append(a[2]))
    run_once(PipelineConfig(data_dir=data.root, delivery=settings(tmp_path)), now=T0 + 10)
    assert len(seen) == 1 and seen[0].delivery.enabled


def test_first_enabled_run_records_floor_watermark_and_sends(world, tmp_path):
    world.incident(at=T0 + 2)
    pub = FakePublisher()
    c = cfg(tmp_path, settings(tmp_path))
    out = run_delivery_stage(world.inv, world.ro, c, Clock(T0 + 2.7), publisher=pub)
    assert watermark(world) == T0 + 2 and out.planned == 1 and pub.attempted == []  # due at T0+3
    run_delivery_stage(world.inv, world.ro, c, Clock(T0 + 4), publisher=pub)
    assert len(pub.sent) == 1


def test_old_open_incidents_are_not_announced_on_first_enable(world, tmp_path):
    world.incident("old", at=T0 - 5000)
    pub = FakePublisher()
    run_delivery_stage(
        world.inv, world.ro, cfg(tmp_path, settings(tmp_path)), Clock(), publisher=pub
    )
    assert pub.attempted == [] and world.rows() == []


def test_enable_disable_enable_keeps_first_watermark(world, tmp_path):
    on, off = cfg(tmp_path, settings(tmp_path)), cfg(tmp_path, DeliverySettings())
    pub = FakePublisher()
    run_delivery_stage(world.inv, world.ro, on, Clock(T0), publisher=pub)
    run_delivery_stage(world.inv, world.ro, off, Clock(T0 + 500), publisher=pub)
    world.incident("mid", at=T0 + 200)  # detected while disabled
    run_delivery_stage(world.inv, world.ro, on, Clock(T0 + 1000), publisher=pub)
    assert watermark(world) == T0
    assert len(pub.sent) == 1  # a later enable does not move the watermark: "mid" is newer


def test_runner_exception_is_caught_and_logged_once(world, tmp_path, monkeypatch, caplog):
    def boom(*a, **k):
        raise RuntimeError("kaput")

    monkeypatch.setattr(delivery_wiring, "run_delivery", boom)
    monkeypatch.setattr(delivery_wiring, "_failures", 0)
    c = cfg(tmp_path, settings(tmp_path))
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        for _ in range(5):
            assert run_delivery_stage(world.inv, world.ro, c, Clock()) is None
    assert [r.getMessage() for r in caplog.records].count("delivery_stage_failed") == 1


def test_pass_error_is_contained_and_state_intact(world, tmp_path, monkeypatch):
    from vigie_pipeline.delivery_plan import Expected, Expire

    world.incident()
    bad = Expire("i1", "open", "x", Expected("pending", 0, 0, 99))
    monkeypatch.setattr("vigie_pipeline.delivery_runner.plan", lambda *a, **k: (bad,))
    monkeypatch.setattr(delivery_wiring, "_failures", 0)
    c = cfg(tmp_path, replace(settings(tmp_path)))
    pub = FakePublisher()
    assert run_delivery_stage(world.inv, world.ro, c, Clock(), publisher=pub) is None
    assert world.rows() == [] and pub.attempted == [] and not world.inv.in_transaction


def test_corrupt_watermark_skips_the_stage(world, tmp_path):
    world.inv.execute("INSERT INTO pipeline_meta VALUES (?, 'garbage')", (WATERMARK_KEY,))
    world.incident()
    pub = FakePublisher()
    c = cfg(tmp_path, settings(tmp_path))
    assert run_delivery_stage(world.inv, world.ro, c, Clock(), publisher=pub) is None
    assert pub.attempted == []


def test_wiring_passes_the_abandoned_bound_to_the_runner(world, tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(delivery_wiring, "run_delivery", lambda *a, **k: seen.update(k))
    c = cfg(
        tmp_path,
        settings(tmp_path, max_abandoned=5, max_per_run=3, drain_budget_s=45, include_label=True),
    )
    run_delivery_stage(world.inv, world.ro, c, Clock())
    assert seen == {
        "max_per_run": 3,
        "max_abandoned": 5,
        "drain_budget_seconds": 45,
        "include_label": True,
    }
