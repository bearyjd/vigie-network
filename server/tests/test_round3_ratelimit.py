"""Round-3 F5/F6: pre-auth limiter keyed by peer only; per-collector limiter charged post-HMAC."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from conftest import COLLECTOR, Env, encode, make_batch, signed_headers
from fastapi.testclient import TestClient

ATTACKER = ("10.0.0.66", 4000)
VICTIM = ("10.0.0.7", 4001)


def _garbage_post(client: TestClient, collector_id: str, n: int = 0):
    batch = make_batch(seq=n + 1, collector_id=collector_id)
    body = encode(batch)
    headers = signed_headers(body, batch, key=b"\x01" * 32)  # wrong key: bad HMAC
    return client.post("/v1/batch", content=body, headers=headers)


def test_f5a_attacker_claiming_victim_id_cannot_429_the_victim(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_per_window=5, rate_limit_preauth_per_min=20)
    attacker = TestClient(env.client.app, client=ATTACKER)
    victim = TestClient(env.client.app, client=VICTIM)
    codes = {_garbage_post(attacker, COLLECTOR, i).status_code for i in range(50)}
    assert codes == {401, 429}  # the attacker is limited by its own address, nothing else
    for seq in range(1, 4):
        batch = make_batch(seq=seq)
        body = encode(batch)
        resp = victim.post("/v1/batch", content=body, headers=signed_headers(body, batch))
        assert resp.status_code == 200


@pytest.mark.timeout(90)
def test_f5b_unauthenticated_claimed_ids_create_no_collector_table_entries(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_preauth_per_min=100_000)
    for i in range(5000):
        assert _garbage_post(env.client, f"fake-{i}", i).status_code == 401
    assert len(env.client.app.state.collector_limiter._hits) == 0
    assert len(env.client.app.state.collector_limiter._overflow) == 0


def test_f5c_authenticated_collector_is_still_rate_limited(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_per_window=3, rate_limit_preauth_per_min=1000)
    codes = [env.post(make_batch(seq=s)).status_code for s in range(1, 6)]
    assert codes == [200, 200, 200, 429, 429]
    env.clock[0] += 61
    assert env.post(make_batch(seq=4)).status_code == 200  # window slid


def test_f5d_pure_flood_from_one_address_hits_the_peer_limit(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(rate_limit_preauth_per_min=5)
    attacker = TestClient(env.client.app, client=ATTACKER)
    codes = [attacker.post("/v1/batch", content=b"{}").status_code for _ in range(10)]
    assert codes[:5] == [401] * 5 and set(codes[5:]) == {429}
    other = TestClient(env.client.app, client=VICTIM)
    assert other.post("/v1/batch", content=b"{}").status_code == 401  # other peers unaffected
