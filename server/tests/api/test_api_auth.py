from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from api_helpers import Env, env  # noqa: F401

from vigie_api import tokens
from vigie_api.schema import open_overrides


def test_healthz_is_unauthenticated(env: Env) -> None:
    r = env.client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "data": "ok", "error": None, "page": None}


def test_valid_token_is_accepted(env: Env) -> None:
    assert env.client.get("/devices", headers=env.auth).status_code == 200


def _uniform(env: Env, headers: dict[str, str]) -> tuple[int, dict, str | None]:
    r = env.client.get("/devices", headers=headers)
    return r.status_code, r.json(), r.headers.get("www-authenticate")


def test_all_auth_failures_are_byte_identical(env: Env) -> None:
    other_id, other = tokens.create_token(env.ov, "revokee")
    tokens.revoke_token(env.ov, other_id)
    wrong_secret = env.token.rsplit(".", 1)[0] + ".deadbeef"
    cases = [
        {},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer garbage"},
        {"Authorization": "Bearer vgt_nosuchid.abcdef"},
        {"Authorization": f"Bearer {wrong_secret}"},
        {"Authorization": f"Bearer {other}"},  # revoked
    ]
    results = [_uniform(env, h) for h in cases]
    assert results[0][0] == 401
    assert all(r == results[0] for r in results)
    assert results[0][1]["error"]["code"] == "unauthorized"
    assert results[0][2] == "Bearer"


def test_wrong_scope_token_rejected_uniformly(env: Env) -> None:
    env.ov.execute("UPDATE api_tokens SET scope='collector'")
    status, body, _ = _uniform(env, env.auth)
    assert status == 401 and body["error"]["code"] == "unauthorized"


def test_tokens_stored_hashed_not_plaintext(env: Env) -> None:
    secret = env.token.rsplit(".", 1)[1]
    rows = env.ov.execute("SELECT token_hash FROM api_tokens").fetchall()
    assert rows and all(secret not in r[0] and len(r[0]) == 64 for r in rows)


def test_verify_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch, env: Env) -> None:
    calls: list[int] = []
    real = tokens.hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(tokens.hmac, "compare_digest", spy)
    assert tokens.verify_token(env.ov, "vgt_nosuchid.abc") is None  # unknown id still compares
    assert tokens.verify_token(env.ov, env.token) is not None
    assert len(calls) == 2


def test_revoke_unknown_returns_false(env: Env) -> None:
    assert tokens.revoke_token(env.ov, "nope") is False


def test_create_rejects_bad_label(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    with pytest.raises(ValueError):
        tokens.create_token(conn, "bad label!")


def test_create_rejects_duplicate_label(tmp_path: Path) -> None:
    conn = open_overrides(tmp_path / "o.db")
    tokens.create_token(conn, "dup")
    with pytest.raises(sqlite3.IntegrityError):
        tokens.create_token(conn, "dup")


def test_per_token_rate_limit(env: Env) -> None:
    limit = env.settings.rate_limit_per_window
    codes = [env.client.get("/devices", headers=env.auth).status_code for _ in range(limit + 1)]
    assert codes[:limit] == [200] * limit and codes[-1] == 429
    # another token is unaffected
    _, other = tokens.create_token(env.ov, "other")
    r = env.client.get("/devices", headers={"Authorization": f"Bearer {other}"})
    assert r.status_code == 200


def test_oversized_body_rejected_413(env: Env) -> None:
    env.device("d1")
    big = {"name": "x" * (env.settings.max_body_bytes + 10)}
    r = env.patch("/devices/d1", big, "0")
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"


def test_no_cors_headers(env: Env) -> None:
    r = env.client.options(
        "/devices",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in r.headers
    r = env.client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers
