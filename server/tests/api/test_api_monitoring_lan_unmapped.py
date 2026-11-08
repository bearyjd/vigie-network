"""Collector summary: ct_lan_unmapped_* sums, separate from the legacy ct_unmapped_* pair."""

import json

from api_helpers import Env, env  # noqa: F401
from test_api_monitoring import HOUR, _ct_collector, _ct_rows, seed


def test_ct_lan_unmapped_sums_are_separate_from_the_legacy_pair(env: Env):
    seed(env)
    both = (
        '{"ct_unmapped_bytes":10,"ct_unmapped_flows":1,'
        '"ct_lan_unmapped_bytes":300,"ct_lan_unmapped_flows":4}'
    )
    lan = '{"ct_lan_unmapped_bytes":5,"ct_lan_unmapped_flows":1}'
    bad = '{"ct_lan_unmapped_bytes":"9","ct_lan_unmapped_flows":1.5}'
    _ct_rows(
        env,
        [
            ("a", "2026-01-01T00:00:01Z", both),
            ("b", "2026-01-01T00:00:02Z", lan),
            ("c", "2026-01-01T00:00:03Z", '{"ct_unmapped_bytes":7}'),
            ("d", "2026-01-01T00:00:04Z", bad),
            ("e", "2026-01-01T00:00:05Z", '{"ct_lan_unmapped_bytes":true}'),
        ],
    )
    value = _ct_collector(env)
    assert value["ct_unmapped_bytes_in_retained_detail"] == 17
    assert value["ct_unmapped_flows_in_retained_detail"] == 1
    assert value["ct_lan_unmapped_bytes_in_retained_detail"] == 305
    assert value["ct_lan_unmapped_flows_in_retained_detail"] == 5
    assert value["ct_unmapped_exact"] is True


def test_ct_lan_unmapped_sums_are_uncapped_beyond_10000_rows(env: Env):
    seed(env)
    rows = [
        (
            f"a{i:05}",
            f"2026-01-{1 + i // 1440:02}T{i % 1440 // 60:02}:{i % 60:02}:00Z",
            '{"ct_lan_unmapped_bytes":2,"ct_lan_unmapped_flows":1}',
        )
        for i in range(10050)
    ]
    _ct_rows(env, rows)
    value = _ct_collector(env)
    assert value["summary_capped"] is True
    assert value["ct_lan_unmapped_bytes_in_retained_detail"] == 20100
    assert value["ct_lan_unmapped_flows_in_retained_detail"] == 10050


def test_ct_lan_unmapped_overflow_is_not_exact_and_zeroes_all_sums(env: Env):
    seed(env)
    big = json.dumps({"ct_lan_unmapped_bytes": 2**62, "ct_unmapped_bytes": 3})
    _ct_rows(env, [(f"o{i}", f"2026-01-01T00:00:0{i}Z", big) for i in range(4)])
    value = _ct_collector(env)
    assert value["ct_unmapped_exact"] is False
    assert value["ct_lan_unmapped_bytes_in_retained_detail"] == 0
    assert value["ct_lan_unmapped_flows_in_retained_detail"] == 0


def test_ct_lan_unmapped_does_not_leak_across_collectors(env: Env):
    seed(env)
    _ct_rows(env, [("m", "2026-01-01T00:00:01Z", '{"ct_lan_unmapped_bytes":5}')])
    env.inv.execute(
        "INSERT INTO batches(collector_id,batch_id,received_at,truncated) "
        "VALUES ('c2','x','2026-01-01T00:00:02Z','{\"ct_lan_unmapped_bytes\":1000}')"
    )
    assert _ct_collector(env)["ct_lan_unmapped_bytes_in_retained_detail"] == 5


def test_hour_with_lan_unmapped_share_reason_is_not_eligible(env: Env):
    seed(env)
    query = {"collector_id": "c1", "from_hour": HOUR, "to_hour": HOUR + 3600}
    assert env.get("/coverage", **query).json()["data"]["hours"][0]["state"] == "eligible"
    env.inv.execute("UPDATE coverage_hourly SET reasons=?", ('["lan_unmapped_share"]',))
    hour = env.get("/coverage", **query).json()["data"]["hours"][0]
    assert hour["state"] == "partial"
    assert hour["reasons"] == ["lan_unmapped_share"]
