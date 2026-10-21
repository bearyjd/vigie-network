"""Round-4: peer-table exhaustion cannot lock out a verified collector."""

from __future__ import annotations

from collections.abc import Callable

from conftest import Env, make_batch
from fastapi.testclient import TestClient

from vigie_ingest.config import Settings
from vigie_ingest.ratelimit import RateLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_ipv6_prefix_defaults_to_64_and_can_be_disabled(tmp_path) -> None:
    assert Settings(tmp_path, tmp_path).rate_limit_ipv6_prefix == 64
    assert Settings.from_env({}).rate_limit_ipv6_prefix == 64
    assert Settings.from_env({"VIGIE_RATE_LIMIT_IPV6_PREFIX": "48"}).rate_limit_ipv6_prefix == 48
    for off in ("0", "none", "None"):
        env = {"VIGIE_RATE_LIMIT_IPV6_PREFIX": off}
        assert Settings.from_env(env).rate_limit_ipv6_prefix is None


def test_full_table_evicts_oldest_idle_entry_instead_of_overflowing() -> None:
    clock = Clock()
    lim = RateLimiter(5, 60, clock, max_sources=3)
    for name in ("a", "b", "c"):
        assert lim.allow(name)
    clock.now = 20
    assert lim.allow("a")  # a is now the freshest, b the oldest
    clock.now = 31  # b idle 31s (> 30), still inside the 60s window
    assert lim.allow("d")
    assert "b" not in lim._hits and "d" in lim._hits and len(lim._hits) == 3
    assert len(lim._overflow) == 0


def test_full_table_of_fresh_entries_sends_newcomers_to_overflow() -> None:
    clock = Clock()
    lim = RateLimiter(5, 60, clock, max_sources=3)
    for name in ("a", "b", "c"):
        lim.allow(name)
    clock.now = 10  # oldest idle only 10s: no eviction
    assert lim.allow("d")
    assert "d" not in lim._hits and len(lim._overflow) == 1 and len(lim._hits) == 3


def test_verified_peer_skips_overflow_but_counts_against_own_bucket() -> None:
    clock = Clock()
    lim = RateLimiter(3, 60, clock, max_sources=3, trusted_capacity=4)
    lim.mark_verified("coll")
    for name in ("a", "b", "c"):
        lim.allow(name)
    clock.now = 1
    assert [lim.allow("coll") for _ in range(4)] == [True, True, True, False]
    assert "coll" in lim._hits and len(lim._hits) <= 3
    assert len(lim._overflow) == 0
    assert not lim.allow("stranger") or "stranger" not in lim._hits  # never gets a slot


def test_allowlist_is_bounded_lru() -> None:
    lim = RateLimiter(3, 60, Clock(), trusted_capacity=2)
    for name in ("a", "b", "a", "c"):
        lim.mark_verified(name)
    assert set(lim._trusted) == {"a", "c"}  # b was least recently verified
    lim.set_trusted_capacity(1)
    assert len(lim._trusted) == 1
    lim.set_trusted_capacity(0)
    lim.mark_verified("z")
    assert len(lim._trusted) == 0


def test_allowlist_entries_expire_after_an_hour_without_verification() -> None:
    clock = Clock()
    lim = RateLimiter(5, 60, clock, max_sources=1, trusted_capacity=2)
    lim.mark_verified("coll")
    lim.allow("x")  # fills the single slot
    clock.now = 3599
    lim.allow("x")  # keeps x fresh so nothing is evictable
    lim.allow("coll")
    assert "coll" in lim._hits  # still trusted: bypasses overflow
    lim2 = RateLimiter(5, 60, clock, max_sources=1, trusted_capacity=2)
    clock.now = 0
    lim2.mark_verified("coll")
    lim2.allow("x")
    clock.now = 3601
    lim2.allow("x")
    lim2.allow("coll")
    assert "coll" not in lim2._hits and len(lim2._overflow) == 1
    assert "coll" not in lim2._trusted


def test_reviewer_attack_cannot_lock_out_an_allowlisted_collector(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_per_window=1000, rate_limit_preauth_per_min=120)
    assert env.post(make_batch(seq=1)).status_code == 200  # HMAC verifies: peer allowlisted
    env.clock[0] += 61  # its table entry goes idle
    peers = env.client.app.state.peer_limiter
    for i in range(4200):  # one /64 owner spraying source addresses
        peers.allow(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}")
    assert len(peers._hits) <= 4096
    for _ in range(130):  # ...then hammering the shared overflow bucket from one address
        peers.allow("203.0.113.5")
    codes = [env.post(make_batch(seq=s)).status_code for s in range(2, 102)]
    assert codes == [200] * 100


def test_never_seen_peer_goes_to_overflow_when_table_is_hostile_full(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_per_window=1000, rate_limit_preauth_per_min=120)
    peers = env.client.app.state.peer_limiter
    for i in range(4200):
        peers.allow(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}")
    stranger = TestClient(env.client.app, client=("192.0.2.9", 1))
    stranger.post("/v1/batch", content=b"{}")
    assert "192.0.2.9" not in peers._hits and len(peers._overflow) >= 1


def test_unverified_request_does_not_allowlist_its_peer(make_env: Callable[..., Env]) -> None:
    env = make_env(rate_limit_per_window=1000)
    forger = TestClient(env.client.app, client=("192.0.2.66", 1))
    body_batch = make_batch(seq=1)
    from conftest import KEY, encode, signed_headers

    body = encode(body_batch)
    resp = forger.post(
        "/v1/batch", content=body, headers=signed_headers(body, body_batch, key=b"\x09" * 32)
    )
    assert resp.status_code == 401
    assert "192.0.2.66" not in env.client.app.state.peer_limiter._trusted
    assert KEY  # signing key differs from the provisioned one


def test_allowlist_capacity_tracks_provisioned_collectors(make_env: Callable[..., Env]) -> None:
    env = make_env()
    assert env.client.app.state.peer_limiter._trusted_capacity == 4  # 1 collector * 4
