"""Round-2 N3: overflow bucket and IPv6 grouping (pre-auth keying is covered in round 3)."""

from __future__ import annotations

from vigie_ingest.config import Settings
from vigie_ingest.ratelimit import RateLimiter


def test_table_full_routes_new_sources_to_a_shared_overflow_bucket() -> None:
    limiter = RateLimiter(2, 60, lambda: 100.0, max_sources=2)
    assert limiter.allow("10.0.0.1") and limiter.allow("10.0.0.2")  # table now full of live keys
    assert limiter.allow("10.0.0.3")  # new source is not refused outright
    assert limiter.allow("10.0.0.4")
    assert limiter.allow("10.0.0.5") is False  # overflow bucket has its own (shared) limit
    assert len(limiter._hits) == 2  # and the table never grew
    assert limiter.allow("10.0.0.1")  # known sources keep their own bucket


def test_ipv6_is_keyed_by_full_address_unless_prefix_configured() -> None:
    full = RateLimiter(1, 60, lambda: 0.0)
    assert full.allow("2001:db8:1:2::1") and full.allow("2001:db8:1:2::2")
    grouped = RateLimiter(1, 60, lambda: 0.0, ipv6_prefix=64)
    assert grouped.allow("2001:db8:1:2::1") and not grouped.allow("2001:db8:1:2::2")


def test_settings_ipv6_prefix(tmp_path) -> None:
    assert Settings(tmp_path, tmp_path).rate_limit_ipv6_prefix is None
    env = {"VIGIE_RATE_LIMIT_IPV6_PREFIX": "64"}
    assert Settings.from_env(env).rate_limit_ipv6_prefix == 64
