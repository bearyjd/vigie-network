from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from conftest import BOOT, COLLECTOR, KEY, NOW, Env, encode, make_batch, signed_headers, uuid7

from vigie_ingest import app as app_module
from vigie_ingest import auth, store
from vigie_ingest.db import connect, shard_name

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
    batch = make_batch(
        seq=1, window_start=old_end - 60, window_end=old_end, dns=[dns]
    )
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
    env = make_env(rate_limit_per_window=3)
    for _ in range(3):
        assert env.client.post("/v1/batch", content=b"{}").status_code == 401

    async def boom(*_a, **_k):
        raise AssertionError("body must not be read once rate limited")

    monkeypatch.setattr(app_module, "read_limited_body", boom)
    resp = env.client.post("/v1/batch", content=b"{}")
    assert resp.status_code == 429


def test_rate_limit_recovers_after_window(make_env: Callable[..., Env]) -> None:
    env = make_env(rate_limit_per_window=1, rate_limit_window_s=60)
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
