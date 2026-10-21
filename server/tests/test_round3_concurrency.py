"""Round-3 F8: SHARD_LOCK serialises apply_batch from precheck through inventory commit."""

from __future__ import annotations

import threading

import pytest
from conftest import NOW, Env, make_batch
from test_review import rows
from test_round2 import _parsed

from vigie_ingest import store

PAUSE_S = 0.4


def _run(env: Env, batch: dict, results: dict[str, str], name: str, done: threading.Event):
    def target() -> None:
        results[name] = store.apply_batch(
            env.settings.inventory_path, env.settings.data_dir, _parsed(batch), NOW, 300
        )
        done.set()

    thread = threading.Thread(target=target, name=name)
    thread.start()
    return thread


def test_f8_retry_and_other_requests_cannot_interleave_with_a_paused_apply(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, other = make_batch(seq=1), make_batch(seq=2)
    in_hook, release = threading.Event(), threading.Event()
    calls: list[str] = []

    def pause_first_caller() -> None:
        calls.append(threading.current_thread().name)
        if threading.current_thread().name == "A":
            in_hook.set()
            assert release.wait(10)

    monkeypatch.setattr(store, "_after_shard_commit", pause_first_caller)
    results: dict[str, str] = {}
    done = {n: threading.Event() for n in "ABC"}
    a = _run(env, first, results, "A", done["A"])
    assert in_hook.wait(10)  # A holds the lock with its shard rows committed, inventory not yet
    b = _run(env, first, results, "B", done["B"])  # retry of the same batch
    c = _run(env, other, results, "C", done["C"])  # unrelated request
    assert not done["B"].wait(PAUSE_S) and not done["C"].is_set()  # both blocked behind A
    assert "B" not in calls and "C" not in calls  # neither reached the shard-commit seam
    release.set()
    for t in (a, b, c):
        t.join(10)
    assert results["A"] == "applied" and results["B"] == "duplicate" and results["C"] == "applied"
    assert sorted(r["batch_id"] for r in rows(env, "raw_dns")) == sorted(
        [first["batch_id"], other["batch_id"]]
    )  # A's rows survive exactly once
