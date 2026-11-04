from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from conftest import BOOT, COLLECTOR, KEY, NOW, Env, encode, make_batch, signed_headers, uuid7

from vigie_ingest import app as app_module
from vigie_ingest import auth, store
from vigie_ingest.config import Settings
from vigie_ingest.db import SHARD_LOCK, connect, shard_name

UNAUTH = {"error": "unauthorized"}


def shard_path(env: Env, ts: float = NOW):
    return env.settings.data_dir / shard_name(datetime.fromtimestamp(ts, tz=UTC).date())


def shard_count(env: Env, table: str, ts: float = NOW) -> int:
    conn = sqlite3.connect(shard_path(env, ts))
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
    finally:
        conn.close()


def collector_row(env: Env) -> sqlite3.Row:
    conn = env.inventory()
    try:
        return conn.execute("SELECT * FROM collectors WHERE id=?", (COLLECTOR,)).fetchone()
    finally:
        conn.close()


def batch_count(env: Env) -> int:
    conn = env.inventory()
    try:
        return conn.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
    finally:
        conn.close()


# ---- happy path -------------------------------------------------------------------------


def test_valid_batch_is_applied(env: Env) -> None:
    resp = env.post(make_batch(seq=1))
    assert resp.status_code == 200 and resp.json() == {"duplicate": False}
    assert shard_count(env, "raw_dns") == 1
    assert shard_count(env, "raw_flow") == 1
    row = collector_row(env)
    assert (row["last_seq"], row["boot_id"]) == (1, BOOT)
    assert batch_count(env) == 1


def test_shard_rows_carry_collector_id(env: Env) -> None:
    env.post(make_batch(seq=1))
    conn = sqlite3.connect(shard_path(env))
    assert conn.execute("SELECT DISTINCT collector_id FROM raw_dns").fetchall() == [(COLLECTOR,)]
    assert conn.execute("SELECT DISTINCT collector_id FROM raw_flow").fetchall() == [(COLLECTOR,)]
    conn.close()


# ---- authentication: uniform 401, nothing applied ---------------------------------------


def assert_unauth_and_unapplied(env: Env, resp) -> None:
    assert resp.status_code == 401
    assert resp.json() == UNAUTH
    assert batch_count(env) == 0
    assert collector_row(env)["last_seq"] == 0
    assert not list(env.settings.data_dir.glob("raw-*.db"))


def test_bad_hmac(env: Env) -> None:
    batch = make_batch()
    body = encode(batch)
    resp = env.client.post(
        "/v1/batch", content=body, headers=signed_headers(body, batch, key=b"\x01" * 32)
    )
    assert_unauth_and_unapplied(env, resp)


def test_tampered_body(env: Env) -> None:
    batch = make_batch()
    headers = signed_headers(encode(batch), batch)
    tampered = encode({**batch, "dropped_batches": 99})
    resp = env.client.post("/v1/batch", content=tampered, headers=headers)
    assert_unauth_and_unapplied(env, resp)


def test_tampered_header_field(env: Env) -> None:
    batch = make_batch()
    body = encode(batch)
    resp = env.client.post(
        "/v1/batch", content=body, headers=signed_headers(body, batch, **{"X-Vigie-Seq": "2"})
    )
    assert_unauth_and_unapplied(env, resp)


def test_wrong_key_id(env: Env) -> None:
    batch = make_batch(key_id="k2")  # no key file for k2, collector registered with k1
    resp = env.post(batch)
    assert_unauth_and_unapplied(env, resp)


def test_key_id_not_registered_for_collector_even_with_valid_key_file(env: Env) -> None:
    (env.settings.secrets_dir / "collector_key_k2").write_text(KEY.hex())
    resp = env.post(make_batch(key_id="k2"))
    assert_unauth_and_unapplied(env, resp)


def test_unknown_collector(env: Env) -> None:
    resp = env.post(make_batch(collector_id="ghost"))
    assert_unauth_and_unapplied(env, resp)


def test_revoked_collector(env: Env) -> None:
    conn = env.inventory()
    assert store.revoke_collector(conn, COLLECTOR)
    conn.close()
    resp = env.post(make_batch())
    assert_unauth_and_unapplied(env, resp)


def test_missing_or_malformed_headers_are_uniform_401(env: Env) -> None:
    batch = make_batch()
    body = encode(batch)
    assert env.client.post("/v1/batch", content=body).json() == UNAUTH
    bad = signed_headers(body, batch, **{"X-Vigie-Signature": "zz"})
    assert env.client.post("/v1/batch", content=body, headers=bad).status_code == 401
    pipe = signed_headers(body, batch, **{"X-Vigie-Collector-Id": "a|b"})
    assert env.client.post("/v1/batch", content=body, headers=pipe).status_code == 401


@pytest.mark.parametrize("content", ["", "abcd", "00" * 16])  # empty, non-hex-length, too short
def test_unusable_key_file_rejects(env: Env, content: str) -> None:
    (env.settings.secrets_dir / "collector_key_k1").write_text(content)
    assert_unauth_and_unapplied(env, env.post(make_batch()))


def test_missing_key_file_rejects(env: Env) -> None:
    (env.settings.secrets_dir / "collector_key_k1").unlink()
    assert_unauth_and_unapplied(env, env.post(make_batch()))


def test_load_key_rejects_path_traversal_and_oversize(env: Env) -> None:
    secrets = env.settings.secrets_dir
    (secrets.parent / "evil").write_text(KEY.hex())
    assert auth.load_key(secrets, "../evil") is None
    (secrets / "collector_key_big").write_text("a" * 5000)
    assert auth.load_key(secrets, "big") is None
    assert auth.load_key(secrets, "k1") == KEY


def test_hmac_compare_is_constant_time(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = auth.hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(auth.hmac, "compare_digest", spy)
    env.post(make_batch(seq=1))
    env.post(make_batch(collector_id="ghost"))  # no key path still runs a compare
    assert len(calls) == 2


def test_verify_never_uses_equality_on_signatures() -> None:
    import inspect

    source = inspect.getsource(auth.verify)
    assert "compare_digest" in source
    assert "==" not in source


# ---- replay / duplicates ----------------------------------------------------------------


def test_replay_same_batch_id_applies_once(env: Env) -> None:
    batch = make_batch(seq=1)
    assert env.post(batch).json() == {"duplicate": False}
    second = env.post(batch)
    assert second.status_code == 200 and second.json() == {"duplicate": True}
    assert shard_count(env, "raw_dns") == 1
    assert batch_count(env) == 1


def test_lost_ack_retry_with_new_sent_ts_is_duplicate(env: Env) -> None:
    batch = make_batch(seq=1)
    assert env.post(batch).status_code == 200
    env.clock[0] = NOW + 30
    retry = {**batch, "sent_ts": int(NOW) + 30}  # re-stamped on each send attempt
    resp = env.post(retry)
    assert resp.status_code == 200 and resp.json() == {"duplicate": True}
    assert shard_count(env, "raw_flow") == 1


def test_duplicate_check_precedes_timestamp_and_seq_checks(env: Env) -> None:
    batch = make_batch(seq=5)
    env.post(batch)
    env.clock[0] = NOW + 10_000  # now far outside skew, seq also not > last_seq
    resp = env.post({**batch, "sent_ts": int(NOW) + 10_000, "window_end": int(NOW)})
    assert resp.json() == {"duplicate": True}


def test_concurrent_duplicate_posts_apply_exactly_once(env: Env) -> None:
    batch = make_batch(seq=1)
    body = encode(batch)
    headers = {k.lower(): v for k, v in signed_headers(body, batch).items()}
    envelope = app_module._parse_envelope(headers)
    assert envelope is not None
    barrier = threading.Barrier(8)

    def attempt(_: int) -> tuple[int, dict]:
        barrier.wait()
        return app_module.process_batch(env.settings, envelope, body, NOW)

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert all(status == 200 for status, _ in results)
    assert sum(1 for _, p in results if p == {"duplicate": False}) == 1
    assert sum(1 for _, p in results if p == {"duplicate": True}) == 7
    assert batch_count(env) == 1
    assert shard_count(env, "raw_dns") == 1 and shard_count(env, "raw_flow") == 1


# ---- sent_ts -----------------------------------------------------------------------------


@pytest.mark.parametrize("delta,expected", [(301, 400), (-301, 400), (300, 200), (-300, 200)])
def test_sent_ts_window(env: Env, delta: int, expected: int) -> None:
    sent = int(NOW) + delta
    batch = make_batch(seq=1, sent_ts=sent, window_end=int(NOW), window_start=int(NOW) - 60)
    resp = env.post(batch)
    assert resp.status_code == expected
    if expected == 400:
        assert batch_count(env) == 0


def test_spooled_old_window_accepted_when_sent_ts_fresh(env: Env) -> None:
    old_end = int(NOW) - 20 * 3600  # spooled ~20h, previous UTC day
    dns = {**make_batch()["dns"][0], "ts": old_end - 5}
    batch = make_batch(seq=1, window_start=old_end - 60, window_end=old_end, dns=[dns])
    resp = env.post(batch)
    assert resp.status_code == 200
    assert shard_count(env, "raw_dns", ts=old_end - 5) == 1
    assert shard_count(env, "raw_flow", ts=old_end) == 1


# ---- seq / boot_id -----------------------------------------------------------------------


def test_seq_regression_rejected(env: Env) -> None:
    assert env.post(make_batch(seq=5)).status_code == 200
    equal = env.post(make_batch(seq=5))
    lower = env.post(make_batch(seq=4))
    assert (equal.status_code, equal.json()) == (409, {"error": "seq_regression"})
    assert lower.status_code == 409
    assert collector_row(env)["last_seq"] == 5
    assert batch_count(env) == 1


def test_seq_gap_allowed(env: Env) -> None:
    assert env.post(make_batch(seq=1)).status_code == 200
    assert env.post(make_batch(seq=50)).status_code == 200
    assert collector_row(env)["last_seq"] == 50


def test_new_boot_id_resets_seq(env: Env) -> None:
    assert env.post(make_batch(seq=100)).status_code == 200
    assert env.post(make_batch(seq=1, boot_id="boot-b")).status_code == 200
    row = collector_row(env)
    assert (row["boot_id"], row["last_seq"]) == ("boot-b", 1)
    assert env.post(make_batch(seq=1, boot_id="boot-b")).status_code == 409


# ---- size cap / rate limit before body processing ---------------------------------------


def test_oversized_body_rejected_before_parsing(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("body must not be parsed or authenticated")

    monkeypatch.setattr(app_module, "process_batch", boom)
    monkeypatch.setattr(app_module.Batch, "model_validate_json", boom)
    big = b"x" * (512 * 1024 + 1)
    headers = signed_headers(big, make_batch())
    resp = env.client.post("/v1/batch", content=big, headers=headers)
    assert resp.status_code == 413


def test_oversized_chunked_body_without_content_length(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "process_batch", lambda *_a: pytest.fail("parsed"))

    def chunks():
        for _ in range(9):
            yield b"y" * (64 * 1024)

    headers = signed_headers(b"", make_batch())
    resp = env.client.post("/v1/batch", content=chunks(), headers=headers)
    assert resp.status_code == 413


def test_body_exactly_at_cap_is_not_413(env: Env) -> None:
    resp = env.client.post("/v1/batch", content=b"x" * (512 * 1024))
    assert resp.status_code == 401  # reached auth, which rejects (no headers)


def test_invalid_content_length_rejected(env: Env) -> None:
    headers = signed_headers(b"", make_batch(), **{"Content-Length": "abc"})
    resp = env.client.post("/v1/batch", content=b"{}", headers=headers)
    assert resp.status_code in (400, 413)


def test_rate_limit_applies_before_body_is_read(
    make_env: Callable[..., Env], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(rate_limit_preauth_per_min=3)
    for _ in range(3):
        assert env.client.post("/v1/batch", content=b"{}").status_code == 401

    async def boom(*_a, **_k):
        raise AssertionError("body must not be read once rate limited")

    monkeypatch.setattr(app_module, "read_limited_body", boom)
    resp = env.client.post("/v1/batch", content=b"{}")
    assert resp.status_code == 429


def test_rate_limit_recovers_after_window(make_env: Callable[..., Env]) -> None:
    env = make_env(rate_limit_preauth_per_min=1, rate_limit_window_s=60)
    assert env.client.post("/v1/batch", content=b"{}").status_code == 401
    assert env.client.post("/v1/batch", content=b"{}").status_code == 429
    env.clock[0] += 61
    assert env.client.post("/v1/batch", content=b"{}").status_code == 401


# ---- post-auth parse failures ------------------------------------------------------------


def test_malformed_json_after_valid_hmac_is_counted_not_applied(env: Env) -> None:
    batch = make_batch(seq=1)
    resp = env.post_raw(b"{not json", batch)
    assert resp.status_code == 422
    row = collector_row(env)
    assert (row["parse_failures"], row["last_seq"]) == (1, 0)
    assert batch_count(env) == 0
    assert not list(env.settings.data_dir.glob("raw-*.db"))


def test_schema_violation_is_counted_not_applied(env: Env) -> None:
    assert env.post(make_batch(seq=1, unexpected="x")).status_code == 422
    assert collector_row(env)["parse_failures"] == 1
    assert batch_count(env) == 0


def test_body_fields_must_match_signed_headers(env: Env) -> None:
    batch = make_batch(seq=1)
    body = encode({**batch, "seq": 2})  # signed headers say seq=1
    resp = env.client.post("/v1/batch", content=body, headers=signed_headers(body, batch))
    assert resp.status_code == 422 and resp.json() == {"error": "envelope_mismatch"}
    assert collector_row(env)["parse_failures"] == 1


def test_revoked_during_apply_is_rejected(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    batch = make_batch(seq=1)

    def revoke_after_shard_commit() -> None:  # e.g. the admin CLI in another process
        conn = env.inventory()
        store.revoke_collector(conn, COLLECTOR)
        conn.close()

    monkeypatch.setattr(store, "_after_shard_commit", revoke_after_shard_commit)
    resp = env.post(batch)
    assert resp.status_code == 401 and resp.json() == UNAUTH
    assert batch_count(env) == 0
    assert shard_count(env, "raw_dns") == 0 and shard_count(env, "raw_flow") == 0


def test_connections_use_secure_delete_and_wal(env: Env) -> None:
    env.post(make_batch(seq=1))
    for path in (env.settings.inventory_path, shard_path(env)):
        conn = connect(path)
        assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        conn.close()


def test_unique_batch_ids_distinguish_batches(env: Env) -> None:
    assert env.post(make_batch(seq=1)).json() == {"duplicate": False}
    assert env.post(make_batch(seq=2, batch_id=uuid7(99))).json() == {"duplicate": False}
    assert batch_count(env) == 2


# --- transient SQLite lock contention (host stalls) ---------------------------------------------


@pytest.fixture
def short_locks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "LOCKED_BUSY_TIMEOUT_MS", 100)


def hold_inventory_write_lock(env: Env, seconds: float) -> threading.Thread:
    """Hold the inventory write lock from a second connection, as a stalled writer would."""
    ready = threading.Event()

    def hold() -> None:
        conn = connect(env.settings.inventory_path)
        conn.execute("BEGIN IMMEDIATE")
        ready.set()
        threading.Event().wait(seconds)
        conn.execute("ROLLBACK")
        conn.close()

    thread = threading.Thread(target=hold)
    thread.start()
    assert ready.wait(5)
    return thread


def test_lock_released_within_budget_applies_once(env: Env, short_locks: None) -> None:
    batch = make_batch(seq=1)
    holder = hold_inventory_write_lock(env, 1.0)
    resp = env.post(batch)
    holder.join()
    assert resp.status_code == 200 and resp.json() == {"duplicate": False}
    assert batch_count(env) == 1 and shard_count(env, "raw_dns") == 1
    again = env.post(batch)  # lost-ACK retry after success
    assert again.json() == {"duplicate": True}
    assert batch_count(env) == 1 and shard_count(env, "raw_dns") == 1


def test_lock_budget_exhausted_is_503_and_unacknowledged(
    make_env: Callable[..., Env], short_locks: None
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=0.5)
    batch = make_batch(seq=1)
    holder = hold_inventory_write_lock(env, 2.0)
    resp = env.post(batch)
    holder.join()
    assert resp.status_code == 503
    assert resp.json() == {"error": "busy"}
    assert resp.headers["retry-after"] == "5"
    assert "locked" not in resp.text
    assert batch_count(env) == 0  # never acknowledged, never recorded as received
    retry = env.post(batch)  # collector retry once the stall is over
    assert retry.status_code == 200 and retry.json() == {"duplicate": False}
    assert batch_count(env) == 1 and shard_count(env, "raw_dns") == 1  # no duplicate rows


def test_non_lock_operational_error_is_not_masked(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_a, **_k):
        raise sqlite3.OperationalError("no such table: batches")

    monkeypatch.setattr(store, "apply_batch", broken)
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        env.post(make_batch(seq=1))


# --- the retry budget truly bounds the request ---------------------------------------------------


def test_budget_bounds_request_with_inventory_lock_held(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=0.2)  # default 1.5 s timeouts
    holder = hold_inventory_write_lock(env, 4.0)
    start = time.monotonic()
    resp = env.post(make_batch(seq=1))
    elapsed = time.monotonic() - start
    holder.join()
    assert resp.status_code == 503
    assert elapsed < 0.2 + 1.0, elapsed
    assert batch_count(env) == 0


def test_request_queued_behind_shard_lock_gets_503_within_budget(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=0.3)
    held, release = threading.Event(), threading.Event()

    def hold() -> None:
        with SHARD_LOCK:
            held.set()
            release.wait(10)

    thread = threading.Thread(target=hold)
    thread.start()
    assert held.wait(5)
    start = time.monotonic()
    resp = env.post(make_batch(seq=1))
    elapsed = time.monotonic() - start
    release.set()
    thread.join()
    assert resp.status_code == 503 and elapsed < 0.3 + 1.0, elapsed
    assert batch_count(env) == 0
    assert env.post(make_batch(seq=1)).status_code == 200  # unaffected once the lock is free


def test_backoff_schedule_is_capped(
    make_env: Callable[..., Env], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=20)
    sleeps: list[float] = []
    calls = [0]

    def locked(*_a, **_k):
        calls[0] += 1
        if calls[0] <= 7:
            raise sqlite3.OperationalError("database is locked")
        return "applied"

    monkeypatch.setattr(app_module.time, "sleep", sleeps.append)
    monkeypatch.setattr(store, "apply_batch", locked)
    assert env.post(make_batch(seq=1)).status_code == 200
    assert sleeps == pytest.approx([0.1, 0.2, 0.4, 0.8, 1.0, 1.0, 1.0])


def test_lookalike_non_lock_error_is_not_retried(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_a, **_k):
        exc = sqlite3.OperationalError("unable to open database file (device busy)")
        exc.sqlite_errorcode = sqlite3.SQLITE_CANTOPEN
        raise exc

    monkeypatch.setattr(store, "apply_batch", broken)
    with pytest.raises(sqlite3.OperationalError, match="device busy"):
        env.post(make_batch(seq=1))


def test_extended_busy_errorcode_is_retried(
    make_env: Callable[..., Env], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=0.3)
    exc = sqlite3.OperationalError("odd message")
    exc.sqlite_errorcode = sqlite3.SQLITE_BUSY | (2 << 8)  # SQLITE_BUSY_SNAPSHOT-style extended
    monkeypatch.setattr(store, "apply_batch", lambda *_a, **_k: (_ for _ in ()).throw(exc))
    assert env.post(make_batch(seq=1)).status_code == 503


def test_failed_attempt_leaves_no_orphan_shard_rows(
    make_env: Callable[..., Env], short_locks: None
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=0.3)
    holder = hold_inventory_write_lock(env, 2.0)
    assert env.post(make_batch(seq=1)).status_code == 503
    holder.join()
    assert batch_count(env) == 0
    assert shard_count(env, "raw_dns") == 0  # written, then compensated


@pytest.mark.parametrize("value", ["nan", "inf", "-1", "20.5", "25", "-inf"])
def test_lock_retry_budget_rejects_bad_values(value: str, tmp_path) -> None:
    with pytest.raises(ValueError, match="lock_retry_budget_s"):
        Settings.from_env({"VIGIE_DATA_DIR": str(tmp_path), "VIGIE_LOCK_RETRY_BUDGET_S": value})
    with pytest.raises(ValueError, match="lock_retry_budget_s"):
        Settings(data_dir=tmp_path, secrets_dir=tmp_path, lock_retry_budget_s=float(value))


@pytest.mark.parametrize("value", [0.0, 15.0, 20.0])
def test_lock_retry_budget_accepts_range(value: float, tmp_path) -> None:
    assert Settings(data_dir=tmp_path, secrets_dir=tmp_path, lock_retry_budget_s=value)


def test_body_timeout_rejects_nan(tmp_path) -> None:
    with pytest.raises(ValueError, match="body_timeout_s"):
        Settings(data_dir=tmp_path, secrets_dir=tmp_path, body_timeout_s=float("nan"))


# --- fix round 2 ---------------------------------------------------------------------------------


@pytest.mark.parametrize("budget", [0.0, -0.0])
def test_zero_budget_still_makes_one_attempt(make_env: Callable[..., Env], budget: float) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=budget)
    resp = env.post(make_batch(seq=1))
    assert resp.status_code == 200 and resp.json() == {"duplicate": False}


def test_zero_budget_with_held_lock_is_503_quickly(make_env: Callable[..., Env]) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=0)
    holder = hold_inventory_write_lock(env, 4.0)
    start = time.monotonic()
    resp = env.post(make_batch(seq=1))
    elapsed = time.monotonic() - start
    holder.join()
    assert resp.status_code == 503 and elapsed < 1.0, elapsed
    assert batch_count(env) == 0


def test_cleanup_never_deletes_a_recorded_batch(
    make_env: Callable[..., Env], monkeypatch: pytest.MonkeyPatch
) -> None:
    """COMMIT reported failure but persisted: the retry sees a duplicate and the rows survive."""
    from contextlib import contextmanager

    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=5)
    real, calls = store.immediate, [0]

    @contextmanager
    def flaky(conn):
        calls[0] += 1
        with real(conn):
            yield
        if calls[0] == 2:  # the inventory commit, after it persisted
            raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "immediate", flaky)
    monkeypatch.setattr(app_module.time, "sleep", lambda _s: None)
    resp = env.post(make_batch(seq=1))
    assert resp.status_code == 200 and resp.json() == {"duplicate": True}
    assert batch_count(env) == 1 and shard_count(env, "raw_dns") == 1


@pytest.mark.parametrize("error", [sqlite3.DatabaseError("boom"), OSError("disk")])
def test_cleanup_failure_does_not_mask_busy(
    make_env: Callable[..., Env], monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=0)

    def raising(*_a, **_k):
        raise sqlite3.OperationalError("database is locked")

    def bad_cleanup(*_a, **_k):
        raise error

    monkeypatch.setattr(store, "_commit_inventory", raising)
    monkeypatch.setattr(store, "_remove_shard_rows", bad_cleanup)
    resp = env.post(make_batch(seq=1))
    assert resp.status_code == 503 and resp.json() == {"error": "busy"}


def test_deadline_passing_before_lock_acquire_is_budget_exhaustion_not_valueerror(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigie_ingest.models import Batch

    batch = Batch.model_validate(make_batch(seq=1), context={"max_spool_age_s": 10**9})
    clock = [1000.0]
    monkeypatch.setattr(store.time, "monotonic", lambda: clock[0])

    def duplicate_check_passes_deadline(*_a, **_k) -> bool:
        clock[0] += 50  # deadline (clock+10) is now in the past
        return False

    monkeypatch.setattr(store, "_is_duplicate", duplicate_check_passes_deadline)
    with pytest.raises(store.LockBudgetExhausted):
        store.apply_batch(
            env.settings.inventory_path, env.settings.data_dir, batch, NOW, 300, deadline=1010.0
        )


def test_budget_exhaustion_error_is_never_retried(
    make_env: Callable[..., Env], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=20)

    def no_sleep(_s: float) -> None:
        raise AssertionError("must not retry after LockBudgetExhausted")

    def exhausted(*_a, **_k):
        raise store.LockBudgetExhausted("shard lock wait exceeded the budget")

    monkeypatch.setattr(app_module.time, "sleep", no_sleep)
    monkeypatch.setattr(store, "apply_batch", exhausted)
    assert env.post(make_batch(seq=1)).status_code == 503


@pytest.mark.parametrize("value", ["nan", "inf", "0", "301"])
def test_body_timeout_env_rejects_bad_values(value: str, tmp_path) -> None:
    with pytest.raises(ValueError, match="body_timeout_s"):
        Settings.from_env({"VIGIE_DATA_DIR": str(tmp_path), "VIGIE_BODY_TIMEOUT_S": value})


# --- fix round 3 ---------------------------------------------------------------------------------


def test_wal_switch_respects_budget_and_releases_shard_lock(
    make_env: Callable[..., Env],
) -> None:
    """Shard still in rollback-journal mode + a reader: the WAL switch cannot spin for seconds."""
    from vigie_ingest.db import SHARD_MIGRATIONS, migrate

    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=0.25)
    path = shard_path(env)
    plain = sqlite3.connect(path, isolation_level=None)
    plain.execute("PRAGMA journal_mode=DELETE")
    migrate(plain, SHARD_MIGRATIONS)
    reader = sqlite3.connect(path, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM raw_dns").fetchall()
    start = time.monotonic()
    try:
        resp = env.post(make_batch(seq=1))
        elapsed = time.monotonic() - start
        assert SHARD_LOCK.acquire(timeout=0)  # not left held by the failed request
        SHARD_LOCK.release()
    finally:
        reader.close()
        plain.close()
    assert resp.status_code == 503 and elapsed < 0.25 + 1.0, elapsed
    assert batch_count(env) == 0


def test_budget_counts_from_request_arrival(make_env: Callable[..., Env]) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=5)
    batch = make_batch(seq=1)
    body = encode(batch)
    headers = {k.lower(): v for k, v in signed_headers(body, batch).items()}
    envelope = app_module._parse_envelope(headers)
    holder = hold_inventory_write_lock(env, 3.0)
    start = time.monotonic()
    status, _ = app_module.process_batch(
        env.settings, envelope, body, NOW, arrived=time.monotonic() - 100
    )
    elapsed = time.monotonic() - start
    holder.join()
    assert status == 503 and elapsed < 1.5, elapsed  # waited at most the first-attempt floor


def test_no_retry_starts_with_less_than_min_attempt_left(
    make_env: Callable[..., Env], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(rate_limit_per_window=1000, lock_retry_budget_s=1.6)
    clock = [1000.0]
    starts: list[float] = []

    def locked(*_a, **_k):
        starts.append(clock[0])
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(app_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(app_module.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    monkeypatch.setattr(store, "apply_batch", locked)
    assert env.post(make_batch(seq=1)).status_code == 503
    assert len(starts) > 1
    assert all(1000.0 + 1.6 - t >= store.MIN_ATTEMPT_S for t in starts[1:])


@pytest.mark.parametrize("error", [sqlite3.DatabaseError("malformed"), OSError("disk")])
def test_non_lock_failure_after_shard_write_leaves_no_orphans(
    env: Env, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def boom(*_a, **_k):
        raise error

    monkeypatch.setattr(store, "_commit_inventory", boom)
    with pytest.raises(type(error)):
        env.post(make_batch(seq=1))
    assert batch_count(env) == 0 and shard_count(env, "raw_dns") == 0


def test_non_lock_failure_never_deletes_a_recorded_batch(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import contextmanager

    real, calls = store.immediate, [0]

    @contextmanager
    def flaky(conn):
        calls[0] += 1
        with real(conn):
            yield
        if calls[0] == 2:
            raise sqlite3.DatabaseError("malformed")

    monkeypatch.setattr(store, "immediate", flaky)
    with pytest.raises(sqlite3.DatabaseError):
        env.post(make_batch(seq=1))
    assert batch_count(env) == 1 and shard_count(env, "raw_dns") == 1


def test_max_shard_days_has_an_upper_bound(tmp_path) -> None:
    with pytest.raises(ValueError, match="max_shard_days"):
        Settings(data_dir=tmp_path, secrets_dir=tmp_path, max_shard_days=31)


# --- fix round 4 ---------------------------------------------------------------------------------


class _FailingWal:
    """Connection stand-in: reports a non-WAL journal and fails the switch with `error`."""

    def __init__(self, error: sqlite3.OperationalError) -> None:
        self.error = error

    def execute(self, sql: str):
        if sql == "PRAGMA journal_mode":
            return type("R", (), {"fetchone": lambda _s: ("delete",)})()
        raise self.error


def _coded(message: str, code: int) -> sqlite3.OperationalError:
    exc = sqlite3.OperationalError(message)
    exc.sqlite_errorcode = code
    return exc


def test_wal_switch_on_read_only_db_propagates_the_real_error(tmp_path) -> None:
    from vigie_ingest import db

    path = tmp_path / "ro.db"
    seed = sqlite3.connect(path)
    seed.execute("PRAGMA journal_mode=DELETE")
    seed.execute("CREATE TABLE t (x)")
    seed.commit()
    seed.close()
    ro = sqlite3.connect(f"file:{path}?mode=ro", uri=True, isolation_level=None)
    try:
        with pytest.raises(sqlite3.OperationalError) as info:
            db._enable_wal(ro, time.monotonic() + 0.25)
    finally:
        ro.close()
    assert not isinstance(info.value, db.LockBudgetExhausted)


def test_wal_switch_non_lock_error_is_raised_unretried(monkeypatch: pytest.MonkeyPatch) -> None:
    from vigie_ingest import db

    def no_sleep(_s: float) -> None:
        raise AssertionError("a non-lock error must not be retried")

    monkeypatch.setattr(db.time, "sleep", no_sleep)
    error = _coded("attempt to write a readonly database", sqlite3.SQLITE_READONLY)
    with pytest.raises(sqlite3.OperationalError) as info:
        db._enable_wal(_FailingWal(error), time.monotonic() + 0.25)
    assert info.value is error


def test_wal_switch_lock_error_with_expired_budget_is_budget_exhausted() -> None:
    from vigie_ingest import db

    with pytest.raises(db.LockBudgetExhausted):
        db._enable_wal(
            _FailingWal(_coded("database is locked", sqlite3.SQLITE_BUSY)), time.monotonic() - 1
        )


@pytest.mark.parametrize("error", [sqlite3.OperationalError("database is locked"), OSError("x")])
def test_revoked_branch_cleanup_failure_keeps_the_real_outcome(
    env: Env, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def revoke() -> None:
        conn = env.inventory()
        store.revoke_collector(conn, COLLECTOR)
        conn.close()

    def bad_cleanup(*_a, **_k):
        raise error

    monkeypatch.setattr(store, "_after_shard_commit", revoke)
    monkeypatch.setattr(store, "_remove_shard_rows", bad_cleanup)
    resp = env.post(make_batch(seq=1))
    assert resp.status_code == 401 and resp.json() == UNAUTH
