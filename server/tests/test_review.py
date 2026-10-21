"""Tests for the Opus security-review findings (items 1-11 plus surviving-mutant gaps)."""

from __future__ import annotations

import ast
import asyncio
import inspect
import ipaddress
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import (
    COLLECTOR,
    KEY,
    NOW,
    Env,
    encode,
    make_batch,
    signed_headers,
)
from fastapi.testclient import TestClient

from vigie_ingest import app as app_module
from vigie_ingest import auth, db, store
from vigie_ingest.app import create_app
from vigie_ingest.config import Settings
from vigie_ingest.db import SHARD_TABLES, open_inventory
from vigie_ingest.ratelimit import RateLimiter
from vigie_ingest.retention import purge_batches, purge_shards

SRC = Path(__file__).resolve().parents[1] / "src"
DAY = 86400


def shard_files(env: Env) -> list[Path]:
    return sorted(env.settings.data_dir.glob("raw-*.db"))


def rows(env: Env, table: str) -> list[sqlite3.Row]:
    out: list[sqlite3.Row] = []
    for path in shard_files(env):
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        out += conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
        conn.close()
    return out


def inv(env: Env, sql: str, *args):
    conn = env.inventory()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# ---- 1. cross-file atomicity -------------------------------------------------------------

CRASH_SCRIPT = """
import os, sys
from pathlib import Path
from vigie_ingest import store
from vigie_ingest.models import Batch
store._after_shard_commit = lambda: os._exit(9)
batch = Batch.model_validate_json(Path(sys.argv[3]).read_bytes())
store.apply_batch(Path(sys.argv[1]), Path(sys.argv[2]), batch, float(sys.argv[4]), 300)
"""


def test_crash_between_shard_commit_and_inventory_commit_retries_exactly_once(
    env: Env, tmp_path: Path
) -> None:
    batch = make_batch(seq=1)
    body_file = tmp_path / "batch.json"
    body_file.write_bytes(encode(batch))
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable, "-c", CRASH_SCRIPT, str(env.settings.inventory_path),
            str(env.settings.data_dir), str(body_file), str(NOW),
        ],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 9, proc.stderr.decode()
    assert inv(env, "SELECT COUNT(*) FROM batches")[0][0] == 0  # inventory never committed
    assert len(rows(env, "raw_dns")) == 1  # shard rows were durable

    resp = env.post(batch)  # collector retries (no ACK was ever received)
    assert resp.status_code == 200 and resp.json() == {"duplicate": False}
    assert len(rows(env, "raw_dns")) == 1 and len(rows(env, "raw_flow")) == 1
    assert inv(env, "SELECT COUNT(*) FROM batches")[0][0] == 1
    assert env.post(batch).json() == {"duplicate": True}


def test_failed_inventory_commit_leaves_inventory_untouched_and_retry_converges(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    batch = make_batch(seq=1)
    real = store._commit_inventory

    def boom(*_a, **_k):
        raise RuntimeError("commit failed")

    monkeypatch.setattr(store, "_commit_inventory", boom)
    with pytest.raises(RuntimeError):
        env.post(batch)
    assert inv(env, "SELECT COUNT(*) FROM batches")[0][0] == 0
    assert inv(env, "SELECT last_seq FROM collectors")[0][0] == 0
    monkeypatch.setattr(store, "_commit_inventory", real)
    assert env.post(batch).json() == {"duplicate": False}
    assert len(rows(env, "raw_dns")) == 1


def test_insert_statements_cover_every_shard_table() -> None:
    assert set(store._INSERTS) == set(SHARD_TABLES)


def test_every_shard_table_has_batch_id_and_collector_id(env: Env) -> None:
    env.post(make_batch(seq=1))
    conn = sqlite3.connect(shard_files(env)[0])
    for table in SHARD_TABLES:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}  # noqa: S608
        assert {"batch_id", "collector_id"} <= cols, table
    conn.close()


# ---- 3. boot_id rollback -----------------------------------------------------------------


def test_boot_id_rollback_replay_is_rejected(env: Env) -> None:
    assert env.post(make_batch(seq=5, boot_id="B1")).status_code == 200
    env.clock[0] = NOW + 10
    t2 = int(NOW) + 10
    assert env.post(make_batch(seq=1, boot_id="B2", sent_ts=t2, window_end=t2,
                               window_start=t2 - 60)).status_code == 200  # fmt: skip
    t3 = int(NOW) + 5  # captured B1 batch, signed earlier than B2's last batch
    replay = env.post(make_batch(seq=3, boot_id="B1", sent_ts=t3, window_end=t3,
                                 window_start=t3 - 60))  # fmt: skip
    assert replay.status_code == 409 and replay.json() == {"error": "seq_regression"}
    row = inv(env, "SELECT boot_id, last_seq, last_sent_ts FROM collectors")[0]
    assert (row[0], row[1], row[2]) == ("B2", 1, t2)


# ---- 4. rate limiter ---------------------------------------------------------------------


def test_rate_limiter_tracked_sources_never_exceed_cap() -> None:
    limiter = RateLimiter(5, 60, lambda: 1000.0)
    for i in range(50_000):
        limiter.allow(str(ipaddress.IPv6Address((i << 64) + 1)))
    assert len(limiter._hits) <= 4096


def test_rate_limiter_ipv6_keyed_by_slash_64() -> None:
    limiter = RateLimiter(2, 60, lambda: 0.0, ipv6_prefix=64)
    assert limiter.allow("2001:db8:1:2::1") and limiter.allow("2001:db8:1:2:ffff::9")
    assert limiter.allow("2001:db8:1:2::77") is False  # same /64 shares one budget
    assert limiter.allow("2001:db8:1:3::1") is True  # different /64


def test_rate_limiter_two_ipv4_clients_are_independent() -> None:
    limiter = RateLimiter(1, 60, lambda: 0.0)
    assert limiter.allow("192.168.8.2") and not limiter.allow("192.168.8.2")
    assert limiter.allow("192.168.8.3")


# ---- 5. pre-auth work --------------------------------------------------------------------


def _forbid_connect(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def spy(*_a, **_k):
        calls.append("connect")
        raise AssertionError("database touched before authentication")

    monkeypatch.setattr(app_module, "connect", spy)
    monkeypatch.setattr(store, "connect", spy)
    return calls


def test_invalid_headers_never_touch_database(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _forbid_connect(monkeypatch)
    batch = make_batch()
    body = encode(batch)
    bad = signed_headers(body, batch, **{"X-Vigie-Signature": "nope"})
    assert env.client.post("/v1/batch", content=body, headers=bad).status_code == 401
    assert env.client.post("/v1/batch", content=body).status_code == 401
    assert calls == []


def test_bad_signature_never_touches_database(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _forbid_connect(monkeypatch)
    batch = make_batch()
    body = encode(batch)
    headers = signed_headers(body, batch, key=b"\x07" * 32)
    assert env.client.post("/v1/batch", content=body, headers=headers).status_code == 401
    assert calls == []


def test_invalid_headers_rejected_before_body_is_read(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(*_a, **_k):
        raise AssertionError("body read despite invalid headers")

    monkeypatch.setattr(app_module, "read_limited_body", boom)
    assert env.client.post("/v1/batch", content=b"{}").status_code == 401


def test_trickling_body_times_out(make_env: Callable[..., Env]) -> None:
    env = make_env(rate_limit_per_window=1000, body_timeout_s=0.3)
    headers = signed_headers(b"", make_batch())
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": "/v1/batch", "raw_path": b"/v1/batch", "query_string": b"",
        "root_path": "", "client": ("10.0.0.9", 5000), "server": ("t", 80),
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }  # fmt: skip
    sent: list[dict] = []

    async def receive():
        await asyncio.sleep(0.05)
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def send(message):
        sent.append(message)

    started = time.monotonic()
    asyncio.run(env.client.app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    assert status == 408
    assert time.monotonic() - started < 3


# ---- 6. persist the formerly discarded payloads ------------------------------------------


def test_leases_neigh_sightings_health_and_counters_are_persisted(env: Env) -> None:
    batch = make_batch(seq=1, truncated={"dns": 3}, dropped_batches=2,
                       health={"dns_log_quiet": True, "rss_kb": 9000})  # fmt: skip
    assert env.post(batch).status_code == 200
    lease = rows(env, "raw_lease")[0]
    assert (lease["mac"], lease["ip"], lease["hostname"], lease["opt60"]) == (
        "aa:bb:cc:00:00:01", "192.168.8.10", "phone", "android-dhcp-14",
    )  # fmt: skip
    assert json.loads(lease["opt55"]) == [1, 3, 6]
    assert lease["batch_id"] == batch["batch_id"] and lease["collector_id"] == COLLECTOR
    assert rows(env, "raw_neigh")[0]["family"] == "inet6"
    assert rows(env, "raw_sighting")[0]["name"] == "Pixel"
    health = rows(env, "raw_health")[0]
    assert (health["dns_log_quiet"], health["rss_kb"]) == (1, 9000)
    meta = inv(env, "SELECT truncated, dropped_batches FROM batches")[0]
    assert json.loads(meta[0]) == {"dns": 3} and meta[1] == 2


def test_records_are_sharded_by_own_ts_clamped_to_window(env: Env) -> None:
    midnight = (int(NOW) // DAY + 1) * DAY
    env.clock[0] = midnight + 30
    sent = midnight + 30
    dns = [
        {**make_batch()["dns"][0], "ts": midnight - 10},
        {**make_batch()["dns"][0], "ts": midnight - 40 - 100},  # before window_start: clamped
    ]
    batch = make_batch(seq=1, sent_ts=sent, window_start=midnight - 40, window_end=midnight + 20,
                       dns=dns)  # fmt: skip
    assert env.post(batch).status_code == 200
    names = [p.name for p in shard_files(env)]
    assert len(names) == 2  # prior day (dns) and the new day (flows, leases at window_end)
    stored = sorted(r["ts"] for r in rows(env, "raw_dns"))
    assert stored == [midnight - 40, midnight - 10]
    assert len(rows(env, "raw_lease")) == 1
    assert rows(env, "raw_lease")[0]["ts"] == midnight + 20


# ---- 7. purge ---------------------------------------------------------------------------


def test_purge_batches_checkpoints_wal(tmp_path: Path) -> None:
    conn = open_inventory(tmp_path / "inventory.db")
    seen: list[str] = []
    conn.set_trace_callback(seen.append)
    purge_batches(conn, NOW, 7)
    assert any("wal_checkpoint(TRUNCATE)" in s for s in seen)


def test_purge_shards_serialises_with_apply_via_shared_lock(tmp_path: Path) -> None:
    old = tmp_path / "raw-20200101.db"
    old.write_bytes(b"x")
    done = threading.Event()

    def run() -> None:
        purge_shards(tmp_path, NOW, 7)
        done.set()

    with db.SHARD_LOCK:
        worker = threading.Thread(target=run)
        worker.start()
        assert not done.wait(0.3)
        assert old.exists()
    worker.join(5)
    assert done.is_set() and not old.exists()


# ---- 8. spool age ------------------------------------------------------------------------


def test_epoch_zero_window_cannot_create_arbitrary_shards(env: Env) -> None:
    batch = make_batch(seq=1, window_start=40, window_end=100, dns=[])
    resp = env.post(batch)
    assert resp.status_code == 422
    assert not list(env.settings.data_dir.glob("raw-1970*.db"))
    assert inv(env, "SELECT parse_failures FROM collectors")[0][0] == 1


def test_window_just_inside_spool_age_is_accepted(env: Env) -> None:
    end = int(NOW) - DAY + 10
    batch = make_batch(seq=1, window_start=end - 60, window_end=end,
                       dns=[{**make_batch()["dns"][0], "ts": end - 5}])  # fmt: skip
    assert env.post(batch).status_code == 200


# ---- 9. duplicate lookup scoped by collector --------------------------------------------


def test_collector_cannot_suppress_another_collectors_batch(env: Env) -> None:
    key2 = b"\x22" * 32
    env.add_collector("rtr-2", "k2", key2)
    a = make_batch(seq=1)
    assert env.post(a).json() == {"duplicate": False}
    b = make_batch(seq=1, collector_id="rtr-2", key_id="k2", batch_id=a["batch_id"])
    body = encode(b)
    resp = env.client.post("/v1/batch", content=body, headers=signed_headers(body, b, key=key2))
    assert resp.status_code == 200 and resp.json() == {"duplicate": False}
    assert inv(env, "SELECT COUNT(*) FROM batches")[0][0] == 2


# ---- 10. provisioning --------------------------------------------------------------------


def test_reprovisioning_revoked_collector_requires_force_and_resets_state(env: Env) -> None:
    env.post(make_batch(seq=9))
    conn = env.inventory()
    store.revoke_collector(conn, COLLECTOR)
    with pytest.raises(ValueError):
        store.provision_collector(conn, COLLECTOR, "k1")
    assert store.get_collector(conn, COLLECTOR).revoked  # type: ignore[union-attr]
    store.provision_collector(conn, COLLECTOR, "k1", force=True)
    row = store.get_collector(conn, COLLECTOR)
    assert row is not None
    assert (row.revoked, row.last_seq, row.boot_id, row.last_sent_ts) == (False, 0, None, 0)
    conn.close()


def test_admin_force_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigie_ingest import admin

    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    assert admin.main(["provision", "c", "k"]) == 0
    assert admin.main(["revoke", "c"]) == 0
    assert admin.main(["provision", "c", "k"]) == 1
    assert admin.main(["provision", "--force", "c", "k"]) == 0


# ---- 11. startup fail-fast / key read path ----------------------------------------------


def _start(tmp_path: Path, key_content: str | None, revoked: bool = False) -> None:
    data, secrets = tmp_path / "d", tmp_path / "s"
    data.mkdir()
    secrets.mkdir()
    settings = Settings(data_dir=data, secrets_dir=secrets)
    conn = open_inventory(settings.inventory_path)
    store.provision_collector(conn, "c1", "kx")
    if revoked:
        store.revoke_collector(conn, "c1")
    conn.close()
    if key_content is not None:
        (secrets / "collector_key_kx").write_text(key_content)
    with TestClient(create_app(settings)):
        pass


def test_startup_refuses_when_active_collector_has_no_key(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="c1"):
        _start(tmp_path, None)


def test_startup_refuses_when_key_is_too_short(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        _start(tmp_path, "ab" * 16)


def test_startup_ok_for_revoked_collector_without_key(tmp_path: Path) -> None:
    _start(tmp_path, None, revoked=True)


@pytest.mark.parametrize("key_id", ["k1", "absent", "../evil"])
def test_load_key_always_takes_the_same_file_read_path(
    env: Env, monkeypatch: pytest.MonkeyPatch, key_id: str
) -> None:
    reads: list[Path] = []
    real = auth._read_secret

    def spy(path: Path) -> bytes:
        reads.append(path)
        return real(path)

    monkeypatch.setattr(auth, "_read_secret", spy)
    auth.load_key(env.settings.secrets_dir, key_id)
    assert len(reads) == 2


# ---- test gaps (previously surviving mutants) --------------------------------------------


def _collect_401(env: Env) -> list:
    out = []
    batch = make_batch(seq=1)
    body = encode(batch)
    out.append(env.client.post("/v1/batch", content=body, headers=signed_headers(
        body, batch, key=b"\x01" * 32)))  # bad hmac
    out.append(env.client.post("/v1/batch", content=body))  # no headers
    out.append(env.post(make_batch(seq=1, collector_id="ghost")))  # unknown collector
    (env.settings.secrets_dir / "collector_key_k1").unlink()
    out.append(env.post(make_batch(seq=1)))  # key file missing
    return out


def test_signing_with_all_zero_key_when_key_file_missing_is_rejected(env: Env) -> None:
    (env.settings.secrets_dir / "collector_key_k1").unlink()
    batch = make_batch(seq=1)
    body = encode(batch)
    headers = signed_headers(body, batch, key=b"\0" * 32)
    resp = env.client.post("/v1/batch", content=body, headers=headers)
    assert resp.status_code == 401
    assert inv(env, "SELECT COUNT(*) FROM batches")[0][0] == 0


def test_all_401_responses_are_byte_identical(env: Env) -> None:
    responses = _collect_401(env)
    batch = make_batch(seq=1)
    body = encode(batch)
    responses.append(env.client.post("/v1/batch", content=body, headers=signed_headers(
        body, batch, **{"X-Vigie-Signature": "zz"})))  # malformed signature
    assert {r.status_code for r in responses} == {401}
    assert len({r.content for r in responses}) == 1
    assert len({tuple(sorted(r.headers.items())) for r in responses}) == 1


def test_revoked_collector_401_is_identical_to_other_401s(env: Env) -> None:
    baseline = env.client.post("/v1/batch", content=b"{}")
    conn = env.inventory()
    store.revoke_collector(conn, COLLECTOR)
    conn.close()
    revoked = env.post(make_batch(seq=1))
    assert revoked.status_code == 401
    assert revoked.content == baseline.content
    assert dict(revoked.headers) == dict(baseline.headers)


def test_replay_of_applied_batch_with_invalid_signature_is_plain_401(env: Env) -> None:
    batch = make_batch(seq=1)
    assert env.post(batch).status_code == 200
    body = encode(batch)
    forged = signed_headers(body, batch, key=b"\x09" * 32)
    resp = env.client.post("/v1/batch", content=body, headers=forged)
    other = env.client.post("/v1/batch", content=b"{}")
    assert resp.status_code == 401
    assert resp.content == other.content and dict(resp.headers) == dict(other.headers)


def test_body_key_id_differing_from_header_is_422(env: Env) -> None:
    (env.settings.secrets_dir / "collector_key_k2").write_text(KEY.hex())
    batch = make_batch(seq=1)
    body = encode({**batch, "key_id": "k2"})  # headers still say k1 (and are signed for k1)
    resp = env.client.post("/v1/batch", content=body, headers=signed_headers(body, batch))
    assert resp.status_code == 422 and resp.json() == {"error": "envelope_mismatch"}


def test_sixteen_byte_key_file_is_rejected_even_when_used_to_sign(env: Env) -> None:
    short = bytes(range(16))
    (env.settings.secrets_dir / "collector_key_k1").write_text(short.hex())
    assert auth.load_key(env.settings.secrets_dir, "k1") is None
    batch = make_batch(seq=1)
    body = encode(batch)
    resp = env.client.post("/v1/batch", content=body, headers=signed_headers(body, batch, short))
    assert resp.status_code == 401


def test_invalid_body_with_bad_signature_is_401_and_not_counted(env: Env) -> None:
    batch = make_batch(seq=1)
    resp = env.post_raw(b"{garbage", batch, key=b"\x05" * 32)
    assert resp.status_code == 401
    assert inv(env, "SELECT parse_failures FROM collectors")[0][0] == 0


def test_decision_flows_through_hmac_compare_digest(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(auth.hmac, "compare_digest", lambda a, b: False)
    assert env.post(make_batch(seq=1)).status_code == 401  # valid sig rejected
    monkeypatch.setattr(auth.hmac, "compare_digest", lambda a, b: True)
    batch = make_batch(seq=1)
    body = encode(batch)
    forged = signed_headers(body, batch, key=b"\x03" * 32)
    assert env.client.post("/v1/batch", content=body, headers=forged).status_code == 200


def test_verify_uses_no_equality_comparison() -> None:
    tree = ast.parse(inspect.getsource(auth.verify).lstrip())
    ops = [op for n in ast.walk(tree) if isinstance(n, ast.Compare) for op in n.ops]
    assert not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in ops)
    assert "compare_digest" in inspect.getsource(auth.verify)
