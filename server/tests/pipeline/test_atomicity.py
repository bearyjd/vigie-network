from __future__ import annotations

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401

from vigie_pipeline import processor
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

PHONE = "aa:bb:cc:00:00:01"


def run(data: Data):
    return run_once(PipelineConfig(data_dir=data.root), now=T0 + 10)


def counts(data: Data) -> tuple[int, int, int]:
    return (
        data.q("SELECT COUNT(*) c FROM devices")[0]["c"],
        data.q("SELECT COUNT(*) c FROM events WHERE kind='new_device'")[0]["c"],
        data.q("SELECT COUNT(*) c FROM pipeline_cursor")[0]["c"],
    )


def test_crash_before_cursor_commit_leaves_nothing_and_retry_makes_one_event(data, monkeypatch):
    """The real event-once guard: batch effects and the cursor share one transaction, so a crash
    before the cursor commits rolls the whole batch back and the retry creates exactly one
    device and one event."""
    data.add_batch(neigh=[PHONE])

    def boom(*args, **kwargs):
        raise RuntimeError("crash before cursor commit")

    monkeypatch.setattr(processor, "_advance_cursor", boom)
    with pytest.raises(RuntimeError):
        run(data)
    assert counts(data) == (0, 0, 0)
    monkeypatch.undo()
    run(data)
    assert counts(data) == (1, 1, 1)
    run(data)
    assert counts(data) == (1, 1, 1)


def test_crash_after_apply_but_in_second_batch_keeps_first_batch(data, monkeypatch):
    data.add_batch(T0, neigh=[PHONE])
    data.add_batch(T0 + 60, neigh=["00:11:22:33:44:55"])
    real = processor._advance_cursor
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("boom")
        return real(*args, **kwargs)

    monkeypatch.setattr(processor, "_advance_cursor", flaky)
    with pytest.raises(RuntimeError):
        run(data)
    assert counts(data) == (1, 1, 1)  # batch 1 committed atomically, batch 2 rolled back
    monkeypatch.undo()
    run(data)
    assert counts(data) == (2, 2, 1)
