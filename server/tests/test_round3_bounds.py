"""Round-3 F1: bound the time spent under SHARD_LOCK."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable

import pytest
from conftest import COLLECTOR, NOW, Env, make_batch
from test_review import inv, rows
from test_round2 import _parsed

from vigie_ingest import db, store

MIDNIGHT = (int(NOW) // 86400) * 86400  # start of NOW's UTC day


def _two_day_batch(seq: int = 1) -> dict:
    dns = make_batch()["dns"][0]
    return make_batch(
        seq=seq,
        window_start=MIDNIGHT - 100,
        window_end=int(NOW),
        dns=[{**dns, "ts": MIDNIGHT - 50}, {**dns, "ts": int(NOW) - 5}],
    )


def test_f1_batch_spanning_more_shard_days_than_the_cap_is_422(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_per_window=1000, max_shard_days=1)
    resp = env.post(_two_day_batch())
    assert resp.status_code == 422
    assert not list(env.settings.data_dir.glob("raw-*.db"))  # nothing written
    assert inv(env, "SELECT parse_failures FROM collectors")[0][0] == 1


def test_f1_cap_is_inclusive_and_defaults_to_three(make_env: Callable[..., Env]) -> None:
    two = make_env(rate_limit_per_window=1000, max_shard_days=2)
    assert two.post(_two_day_batch()).status_code == 200
    assert two.settings.max_shard_days == 2
    assert make_env(rate_limit_per_window=1000).settings.max_shard_days == 3


def test_f1_locked_connections_use_a_short_busy_timeout(env: Env) -> None:
    holder = env.inventory()
    holder.execute("BEGIN IMMEDIATE")  # another process holds the inventory write lock
    started = time.monotonic()
    try:
        with pytest.raises(sqlite3.OperationalError):
            store.apply_batch(
                env.settings.inventory_path, env.settings.data_dir, _parsed(make_batch()), NOW, 300
            )
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert time.monotonic() - started < 3.0  # was 5 s+ with the general busy timeout
    assert db.LOCKED_BUSY_TIMEOUT_MS < db.BUSY_TIMEOUT_MS
    assert db.SHARD_LOCK.acquire(blocking=False)  # lock was released by the failure
    db.SHARD_LOCK.release()


def _apply_in_thread(env: Env, batch: dict, out: list[str], started: threading.Event):
    def target() -> None:
        started.set()
        out.append(
            store.apply_batch(
                env.settings.inventory_path, env.settings.data_dir, _parsed(batch), NOW, 300
            )
        )

    thread = threading.Thread(target=target)
    thread.start()
    return thread


def _hold_lock(release: threading.Event, held: threading.Event) -> threading.Thread:
    def target() -> None:
        with db.SHARD_LOCK:
            held.set()
            release.wait(10)

    thread = threading.Thread(target=target)
    thread.start()
    return thread


def test_f1_duplicate_retry_is_answered_without_waiting_for_the_lock(env: Env) -> None:
    batch = make_batch(seq=1)
    assert env.post(batch).status_code == 200
    release, held, started = threading.Event(), threading.Event(), threading.Event()
    holder = _hold_lock(release, held)
    assert held.wait(5)
    out: list[str] = []
    worker = _apply_in_thread(env, batch, out, started)
    worker.join(2)  # must finish while another thread still holds SHARD_LOCK
    finished = not worker.is_alive()
    release.set()
    worker.join(10)
    holder.join(10)
    assert finished and out == ["duplicate"]


def test_f1_duplicate_is_rechecked_under_the_lock(env: Env) -> None:
    batch = make_batch(seq=1)
    release, held, started = threading.Event(), threading.Event(), threading.Event()
    holder = _hold_lock(release, held)
    assert held.wait(5)
    out: list[str] = []
    worker = _apply_in_thread(env, batch, out, started)  # passes the fast precheck, blocks
    assert started.wait(5)
    time.sleep(0.3)
    conn = env.inventory()
    conn.execute(  # another process records the batch while we wait for the lock
        "INSERT INTO batches (collector_id, batch_id, received_at) VALUES (?,?,'t')",
        (COLLECTOR, batch["batch_id"]),
    )
    conn.close()
    release.set()
    worker.join(10)
    holder.join(10)
    assert out == ["duplicate"]
    assert rows(env, "raw_dns") == []  # the stale fast check did not let it write shard rows
