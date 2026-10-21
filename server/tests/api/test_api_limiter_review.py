"""Re-review fixes: failure limiter keys, valid tokens never blocked, eviction, no DB work."""

from __future__ import annotations

from pathlib import Path

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from fastapi.testclient import TestClient

import vigie_api.app as app_module
from vigie_api import ratelimit, tokens
from vigie_api.app import create_app
from vigie_api.config import Settings
from vigie_api.ratelimit import FailureLimiter, source_key
from vigie_api.schema import open_overrides

BAD = {"Authorization": "Bearer vgt_x.abcdef"}


def _app(tmp_path: Path, limit: int = 3):
    settings = Settings(data_dir=tmp_path, rate_limit_per_window=limit, rate_limit_window_s=60)
    ov = open_overrides(settings.overrides_path)
    _, token = tokens.create_token(ov, "t")
    return create_app(settings, clock=lambda: NOW), {"Authorization": f"Bearer {token}"}, ov


def test_ipv4_mapped_ipv6_keys_as_the_ipv4_address() -> None:
    assert source_key("::ffff:192.168.1.5") == source_key("192.168.1.5") == "192.168.1.5"
    assert source_key("::ffff:192.168.1.5") != source_key("::ffff:10.0.0.9")


def test_ipv4_clients_on_a_dual_stack_listener_do_not_share_a_bucket(tmp_path: Path) -> None:
    app, _, _ = _app(tmp_path, limit=2)
    with TestClient(app, client=("::ffff:192.168.1.5", 1)) as a:
        assert [a.get("/devices", headers=BAD).status_code for _ in range(3)] == [401, 401, 429]
    with TestClient(app, client=("::ffff:10.0.0.9", 1)) as b:
        assert b.get("/devices", headers=BAD).status_code == 401


def test_valid_token_from_an_over_limit_address_still_gets_200(tmp_path: Path) -> None:
    app, good, _ = _app(tmp_path, limit=3)
    with TestClient(app) as client:
        codes = [client.get("/devices", headers=BAD).status_code for _ in range(125)]
        assert codes[:3] == [401] * 3 and set(codes[3:]) == {429}
        assert client.get("/devices", headers=good).status_code in (200, 503)


def test_revoked_token_retried_does_not_lock_a_different_valid_token(tmp_path: Path) -> None:
    app, good, ov = _app(tmp_path, limit=3)
    _, revoked = tokens.create_token(ov, "old")
    tokens.revoke_token(ov, "old")
    old = {"Authorization": f"Bearer {revoked}"}
    with TestClient(app) as client:
        codes = [client.get("/devices", headers=old).status_code for _ in range(200)]
        assert set(codes) == {401, 429}
        assert client.get("/devices", headers=good).status_code in (200, 503)
        assert client.get("/devices", headers=old).status_code == 429  # still pinned


def test_failing_token_from_an_over_limit_address_is_429_with_retry_after(tmp_path: Path) -> None:
    app, _, _ = _app(tmp_path, limit=2)
    with TestClient(app) as client:
        for _ in range(2):
            assert client.get("/devices", headers=BAD).status_code == 401
        for headers in (BAD, {}, {"Authorization": "Bearer junk"}):
            r = client.get("/devices", headers=headers)
            assert r.status_code == 429 and 1 <= int(r.headers["retry-after"]) <= 60


def test_blocked_source_without_a_plausible_token_opens_no_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _, _ = _app(tmp_path, limit=2)
    with TestClient(app) as client:
        for _ in range(2):
            client.get("/devices", headers=BAD)
        opened: list[Path] = []
        real = open_overrides
        monkeypatch.setattr(app_module, "open_overrides", lambda p: opened.append(p) or real(p))
        monkeypatch.setattr(
            app_module, "open_inventory_ro", lambda p: opened.append(p) or pytest.fail("inv")
        )
        for headers in ({}, {"Authorization": "Bearer junk"}, {"Authorization": "Basic zzz"}):
            assert client.get("/devices", headers=headers).status_code == 429
            assert (
                client.patch("/devices/d1", json={"name": "x"}, headers=headers).status_code == 429
            )
        assert opened == []


def test_limiter_evicts_oldest_idle_entries_instead_of_sharing_an_overflow_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ratelimit, "MAX_SOURCES", 4)
    now = [NOW]
    limiter = FailureLimiter(2, 60, lambda: now[0])
    for i in range(4):  # an attacker saturates every slot from distinct sources
        for _ in range(2):
            limiter.record(f"10.0.0.{i}")
        now[0] += 1
    assert limiter.retry_after("192.168.9.9") is None  # a legitimate new source is not blocked
    limiter.record("192.168.9.9")
    assert limiter.retry_after("192.168.9.9") is None  # its own bucket, one failure
    limiter.record("192.168.9.9")
    assert limiter.retry_after("192.168.9.9") is not None
    assert limiter.retry_after("10.0.0.0") is None  # the oldest entry was the one evicted
    assert limiter.retry_after("10.0.0.3") is not None
    assert len(limiter._hits) <= 4
