"""Review fixes: auth before body validation, failure limiter, Retry-After, safe logging."""

from __future__ import annotations

import logging
import math
from pathlib import Path

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from fastapi.testclient import TestClient

from vigie_api import tokens
from vigie_api.app import create_app
from vigie_api.config import Settings
from vigie_api.schema import open_overrides


def _shape(r) -> tuple[int, dict, str | None]:
    return r.status_code, r.json(), r.headers.get("www-authenticate")


def test_unauthenticated_malformed_json_gets_the_uniform_401(env: Env) -> None:
    env.device("d1")
    baseline = _shape(env.client.get("/devices"))
    assert baseline[0] == 401
    for auth in ({}, {"Authorization": "Bearer vgt_nosuchid.abcdef"}):
        r = env.client.patch(
            "/devices/d1",
            content=b"{bad",
            headers={"Content-Type": "application/json", "If-Match": "0", **auth},
        )
        assert _shape(r) == baseline


def test_unauthenticated_invalid_schema_body_gets_the_uniform_401(env: Env) -> None:
    baseline = _shape(env.client.get("/devices"))
    r = env.client.patch("/devices/d1", json={"nope": 1})
    assert _shape(r) == baseline


def test_authenticated_malformed_json_is_still_a_422(env: Env) -> None:
    r = env.client.patch(
        "/devices/d1", content=b"{bad", headers={**env.auth, "Content-Type": "application/json"}
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"


def test_malformed_json_without_auth_counts_against_failure_limiter(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, rate_limit_per_window=3)
    with TestClient(create_app(settings, clock=lambda: NOW)) as client:
        codes = [
            client.patch(
                "/devices/d1", content=b"{bad", headers={"Content-Type": "application/json"}
            ).status_code
            for _ in range(5)
        ]
    assert codes == [401, 401, 401, 429, 429]


class Clock:
    now = NOW

    def __call__(self) -> float:
        return self.now


def _limited(tmp_path: Path, limit: int = 3, **client_kw):
    settings = Settings(data_dir=tmp_path, rate_limit_per_window=limit, rate_limit_window_s=60)
    clock = Clock()
    ov = open_overrides(settings.overrides_path)
    _, token = tokens.create_token(ov, "t")
    return TestClient(create_app(settings, clock=clock), **client_kw), clock, token


def test_failure_limit_blocks_source_with_retry_after_then_recovers(tmp_path: Path) -> None:
    client, clock, token = _limited(tmp_path)
    with client:
        bad = {"Authorization": "Bearer vgt_x.abcdef"}
        assert [client.get("/devices", headers=bad).status_code for _ in range(3)] == [401] * 3
        r = client.get("/devices", headers=bad)
        assert r.status_code == 429 and r.json()["error"]["code"] == "rate_limited"
        assert 1 <= int(r.headers["retry-after"]) <= 60
        clock.now += 61
        assert client.get("/devices", headers={"Authorization": f"Bearer {token}"}).status_code in (
            200,
            503,
        )


def test_over_limit_source_without_a_plausible_token_is_refused_before_any_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _, token = _limited(tmp_path)
    with client:
        bad = {"Authorization": "Bearer vgt_x.abcdef"}
        for _ in range(3):
            client.get("/devices", headers=bad)
        lookups: list[str] = []
        real = tokens.verify_token
        monkeypatch.setattr(tokens, "verify_token", lambda c, p: lookups.append(p) or real(c, p))
        assert client.get("/devices", headers={"Authorization": "Bearer junk"}).status_code == 429
        assert not lookups
        # a well-formed token is looked up, and a valid one is served (never blocked)
        r = client.get("/devices", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code in (200, 503) and len(lookups) == 1


def test_ipv6_sources_are_limited_by_slash_64(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, rate_limit_per_window=2)
    app = create_app(settings, clock=lambda: NOW)
    bad = {"Authorization": "Bearer vgt_x.abcdef"}
    with TestClient(app, client=("2001:db8:1:2::1", 1)) as first:
        assert [first.get("/devices", headers=bad).status_code for _ in range(2)] == [401, 401]
    with TestClient(app, client=("2001:db8:1:2:dead:beef:0:99", 1)) as same_64:
        assert same_64.get("/devices", headers=bad).status_code == 429
    with TestClient(app, client=("2001:db8:1:3::1", 1)) as other_64:
        assert other_64.get("/devices", headers=bad).status_code == 401


def test_token_rate_limit_429_has_retry_after(env: Env) -> None:
    for _ in range(env.settings.rate_limit_per_window):
        env.client.get("/devices", headers=env.auth)
    r = env.client.get("/devices", headers=env.auth)
    assert r.status_code == 429
    assert 1 <= int(r.headers["retry-after"]) <= math.ceil(env.settings.rate_limit_window_s)


def test_failed_auth_logged_at_warning_without_token_material(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "supersecretvalue123"
    with caplog.at_level(logging.WARNING, logger="vigie_api"):
        env.client.get("/devices", headers={"Authorization": f"Bearer vgt_t.{secret}"})
        env.client.get("/devices")
    records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(records) == 2
    text = " ".join(r.getMessage() for r in records)
    assert secret not in text and "vgt_" not in text and "testclient" in text
