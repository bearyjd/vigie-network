"""F6-b fix round 2, pipeline wiring: flag default and gates, the first push, stale passes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from test_f6b_essential_absence import (  # noqa: F401
    Env,
    config_for,
    env,
    now_after,
)
from test_f6b_fix2 import two_hours

from vigie_pipeline import processor
from vigie_pipeline.config import DeliverySettings, PipelineConfig
from vigie_pipeline.delivery_types import DEFAULT_DETECTORS
from vigie_pipeline.delivery_wiring import WATERMARK_KEY
from vigie_pipeline.processor import run_once

D = "essential_absence"


def deliver_cfg(env, **kw):
    out = env.root / "out.jsonl"
    settings = DeliverySettings(enabled=True, file=out, detectors=(*DEFAULT_DETECTORS, D))
    return PipelineConfig(data_dir=env.root, delivery=settings, **kw), out


def sent(out) -> int:
    return len(out.read_text().splitlines()) if out.exists() else 0


def old_watermark(env) -> None:
    """The delivery watermark was set long ago: only the stale-pass logic decides what is sent."""
    env.inv.execute("INSERT INTO pipeline_meta (key, value) VALUES (?, '1')", (WATERMARK_KEY,))
    env.inv.commit()


def stale_shard(monkeypatch) -> None:
    def fail(inv, ov, cfg, failures):
        failures.append(processor.ShardReadError("x"))
        return {"batches": 0, "macs": 0, "new_devices": 0, "skipped_macs": 0}

    monkeypatch.setattr(processor, "_process_batches", fail)


# ---- R1-30: default off, the usable gate and the clock argument ---------------------------------
def test_the_dataclass_default_is_off_and_a_marked_absent_device_opens_nothing(env):
    assert PipelineConfig(data_dir=env.root).essential_absence is False
    two_hours(env)
    run_once(PipelineConfig(data_dir=env.root), now=now_after(2))
    assert env.rows() == []


def test_the_sweep_receives_the_pass_clock(env, monkeypatch):
    calls = []
    monkeypatch.setattr(processor, "sweep_essential_absence", lambda *a: calls.append(a))
    run_once(config_for(env.root, essential_absence=True), now=now_after(2))
    assert [a[2] for a in calls] == [now_after(2)]


def test_an_unusable_overrides_db_never_reaches_the_sweep(tmp_path, monkeypatch):
    (tmp_path / "overrides.db").write_bytes(b"this is not a database" * 100)
    calls = []
    monkeypatch.setattr(processor, "sweep_essential_absence", lambda *a: calls.append(a))
    run_once(config_for(tmp_path, essential_absence=True, migrate=True), now=1_792_000_000)
    assert calls == []


# ---- R1-12: detection and delivery enabled together: the first push is never dropped ------------
def test_the_first_push_survives_a_slow_pass(env, monkeypatch):
    two_hours(env)
    cfg, out = deliver_cfg(env, essential_absence=True)
    base = now_after(2)
    ticks = iter(range(10_000))
    fake = SimpleNamespace(time=lambda: base + 2 * next(ticks))  # every clock read is 2 s later
    monkeypatch.setattr(processor, "time", fake)
    run_once(cfg)
    run_once(cfg)
    assert len(env.rows()) == 1 and sent(out) == 1


# ---- R1-10: nothing is sent on a pass whose view is stale ---------------------------------------
def test_a_stale_pass_with_the_flag_on_sends_nothing_and_the_next_pass_does(env, monkeypatch):
    two_hours(env)
    env.sweep(now_after(2))
    old_watermark(env)
    cfg, out = deliver_cfg(env, essential_absence=True)
    stale_shard(monkeypatch)
    with pytest.raises(processor.ShardReadError):
        run_once(cfg, now=now_after(2) + 5)
    assert sent(out) == 0
    monkeypatch.undo()
    run_once(cfg, now=now_after(2) + 60)
    assert sent(out) == 1


def test_a_stale_pass_with_the_flag_off_still_delivers(env, monkeypatch):
    two_hours(env)
    env.sweep(now_after(2))
    old_watermark(env)
    cfg, out = deliver_cfg(env)
    stale_shard(monkeypatch)
    with pytest.raises(processor.ShardReadError):
        run_once(cfg, now=now_after(2) + 5)
    assert sent(out) == 1


@pytest.mark.parametrize(("flag", "at_pass_start"), [(True, True), (False, False)])
def test_only_the_flag_moves_the_first_watermark_to_the_pass_start(
    env, monkeypatch, flag, at_pass_start
):
    cfg, _ = deliver_cfg(env, essential_absence=flag)
    base = now_after(2)
    ticks = iter(range(10_000))
    monkeypatch.setattr(processor, "time", SimpleNamespace(time=lambda: base + 2 * next(ticks)))
    run_once(cfg)
    row = env.inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (WATERMARK_KEY,))
    assert (int(row.fetchone()[0]) == base) is at_pass_start
