"""Round-2 N4: tests for previously surviving mutants."""

from __future__ import annotations

from collections.abc import Callable

from conftest import COLLECTOR, NOW, Env, encode, make_batch, signed_headers
from test_review import inv, rows

from vigie_ingest.config import Settings


def test_same_boot_batch_with_lower_sent_ts_never_lowers_last_sent_ts(env: Env) -> None:
    env.clock[0] = NOW + 10
    late = int(NOW) + 10
    first = make_batch(seq=1, sent_ts=late, window_start=late - 60, window_end=late)
    assert env.post(first).status_code == 200
    earlier = int(NOW) + 5  # within skew of the clock, lower than the stored value
    second = make_batch(seq=2, sent_ts=earlier, window_start=earlier - 60, window_end=earlier)
    assert env.post(second).status_code == 200
    assert inv(env, "SELECT last_sent_ts FROM collectors")[0][0] == late


def test_other_collector_posting_same_batch_id_leaves_first_collectors_rows(env: Env) -> None:
    key2 = b"\x33" * 32
    env.add_collector("rtr-2", "k2", key2)
    a = make_batch(seq=1)
    assert env.post(a).status_code == 200
    b = make_batch(
        seq=1,
        collector_id="rtr-2",
        key_id="k2",
        batch_id=a["batch_id"],
        dns=[{**a["dns"][0], "qname": "b.example"}],
    )
    body = encode(b)
    resp = env.client.post("/v1/batch", content=body, headers=signed_headers(body, b, key=key2))
    assert resp.status_code == 200 and resp.json() == {"duplicate": False}
    by_collector = {r["collector_id"]: r["qname"] for r in rows(env, "raw_dns")}
    assert by_collector == {COLLECTOR: "example.com", "rtr-2": "b.example"}


def test_spool_age_boundary_with_non_default_setting(make_env: Callable[..., Env]) -> None:
    env = make_env(rate_limit_per_window=1000, max_spool_age_s=3600)
    sent = int(NOW)

    def window(seq: int, end: int) -> dict:
        return make_batch(seq=seq, window_start=end - 60, window_end=end, dns=[])

    assert env.post(window(1, sent - 3600)).status_code == 200  # exactly max_age: accepted
    too_old = env.post(window(2, sent - 3601))  # max_age + 1: rejected
    assert too_old.status_code == 422 and too_old.json() == {"error": "invalid_batch"}


def test_settings_from_env_reads_max_spool_age(tmp_path) -> None:
    assert Settings.from_env({"VIGIE_MAX_SPOOL_AGE_S": "3600"}).max_spool_age_s == 3600
    assert Settings(tmp_path, tmp_path).max_spool_age_s == 86400
