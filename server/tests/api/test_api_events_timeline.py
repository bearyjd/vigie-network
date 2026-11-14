"""Additive /events params for the GUI timeline: `device_id` and `order=desc` (newest first)."""

from __future__ import annotations

import pytest
from api_helpers import Env, env, ts  # noqa: F401

from vigie_api.effective import decode_cursor, encode_cursor


def ids(r) -> list[str]:
    return [e["id"] for e in r.json()["data"]]


def audit(env: Env, row_id: str, action: str, target: str | None, when: float = 0) -> None:
    env.ov.execute(
        "INSERT INTO audit_log (id, ts, principal, action, target) VALUES (?,?,?,?,?)",
        (row_id, ts(when), "app:x", action, target),
    )


def test_device_filter_returns_only_that_devices_events_from_both_sources(env: Env) -> None:
    env.device("d1")
    env.device("d2")
    a = env.event("d1", -300, "new_device")
    env.event("d2", -200, "new_device")
    env.event(None, -100, "rule_malformed")
    audit(env, "au1", "device.patch", "d1")
    audit(env, "au2", "device.patch", "d2")
    got = env.get("/events", device_id="d1")
    assert got.status_code == 200
    assert ids(got) == [a, "au1"]
    assert {e["device_id"] for e in got.json()["data"]} == {"d1"}


def test_device_filter_excludes_device_less_audit_rows(env: Env) -> None:
    """Rows that render with a null device_id never match a device filter."""
    env.device("d1")
    audit(env, "inc", "monitoring.incident.ack", "d1")
    audit(env, "tok", "token.create", "d1")
    assert ids(env.get("/events", device_id="d1")) == []


def test_device_filter_is_exact_not_a_pattern(env: Env) -> None:
    env.device("d1")
    env.event("d1", -5, "anomaly")
    for pattern in ("%", "d_", "D1", "d1%"):
        assert ids(env.get("/events", device_id=pattern)) == []


@pytest.mark.parametrize("bad", ["x" * 65, ""])
def test_device_filter_is_bounded(env: Env, bad: str) -> None:
    assert env.get("/events", device_id=bad).status_code == 422


def test_device_filter_pages_without_gaps(env: Env) -> None:
    env.device("d1")
    env.device("d2")
    for i in range(6):
        env.event("d1" if i % 2 else "d2", -100 + i, "anomaly")
    seen, cursor = [], None
    for _ in range(4):
        params = {"device_id": "d1", "limit": 1, **({"since": cursor} if cursor else {})}
        body = env.get("/events", **params).json()
        if not body["data"]:
            break
        seen += [e["id"] for e in body["data"]]
        cursor = body["page"]["next_cursor"]
    assert len(seen) == 3 == len(set(seen))


def test_default_order_is_ascending_and_unchanged(env: Env) -> None:
    env.device("d1")
    a = env.event("d1", -300, "anomaly")
    b = env.event("d1", -100, "anomaly")
    assert ids(env.get("/events")) == ids(env.get("/events", order="asc")) == [a, b]
    assert decode_cursor(env.get("/events").json()["page"]["next_cursor"]) == '{"audit":0,"inv":2}'


def test_default_response_is_identical_to_the_pre_param_shape(env: Env) -> None:
    env.device("d1")
    eid = env.event("d1", -300, "anomaly", "warn")
    assert env.get("/events").json() == {
        "ok": True,
        "error": None,
        "data": [
            {
                "id": eid,
                "device_id": "d1",
                "ts": ts(-300),
                "kind": "anomaly",
                "severity": "warn",
                "summary": "anomaly d1",
                "source": "inventory",
            }
        ],
        "page": {"next_cursor": encode_cursor('{"audit":0,"inv":1}')},
    }


def test_desc_returns_newest_rows_first_and_pages_without_gaps_or_repeats(env: Env) -> None:
    env.device("d1")
    made = [env.event("d1", -500 + i, "anomaly") for i in range(5)]
    first = env.get("/events", order="desc", limit=2).json()
    assert [e["id"] for e in first["data"]] == [made[4], made[3]]
    second = env.get("/events", order="desc", limit=2, since=first["page"]["next_cursor"]).json()
    third = env.get("/events", order="desc", limit=2, since=second["page"]["next_cursor"]).json()
    got = [e["id"] for p in (first, second, third) for e in p["data"]]
    assert got == list(reversed(made))
    empty = env.get("/events", order="desc", since=third["page"]["next_cursor"]).json()
    assert empty["data"] == [] and empty["page"]["next_cursor"] == third["page"]["next_cursor"]


def test_desc_merges_both_sources_by_time_newest_first(env: Env) -> None:
    env.device("d1")
    a = env.event("d1", -300, "new_device")
    audit(env, "au1", "device.patch", "d1", when=-200)
    b = env.event("d1", -100, "anomaly")
    assert ids(env.get("/events", order="desc")) == [b, "au1", a]


def test_desc_rows_inserted_after_the_cursor_are_not_repeated_or_skipped(env: Env) -> None:
    env.device("d1")
    old = [env.event("d1", -500 + i, "anomaly") for i in range(3)]
    first = env.get("/events", order="desc", limit=2).json()
    env.event("d1", -10, "anomaly")  # newer than anything already served
    rest = env.get("/events", order="desc", limit=2, since=first["page"]["next_cursor"]).json()
    assert [e["id"] for e in rest["data"]] == [old[0]]


def test_desc_late_row_with_older_ts_inserted_before_first_page_is_served(env: Env) -> None:
    env.device("d1")
    a = env.event("d1", -60, "anomaly")
    late = env.event("d1", -500, "anomaly")  # higher rowid, older ts
    assert set(ids(env.get("/events", order="desc"))) == {a, late}


def test_desc_with_filters(env: Env) -> None:
    env.device("d1")
    env.device("d2")
    a = env.event("d1", -300, "anomaly", "warn")
    env.event("d2", -200, "anomaly", "warn")
    c = env.event("d1", -100, "anomaly", "warn")
    env.event("d1", -50, "new_device")
    assert ids(env.get("/events", order="desc", device_id="d1", kind="anomaly")) == [c, a]


def test_cursors_do_not_cross_orders(env: Env) -> None:
    env.device("d1")
    env.event("d1", -5, "anomaly")
    asc = env.get("/events").json()["page"]["next_cursor"]
    desc = env.get("/events", order="desc").json()["page"]["next_cursor"]
    assert decode_cursor(desc) == '{"dir":"desc","inv":1}'
    for params in (
        {"order": "desc", "since": asc},
        {"since": desc},
        {"order": "asc", "since": desc},
    ):
        r = env.get("/events", **params)
        assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_cursor"


@pytest.mark.parametrize(
    "bad",
    [
        encode_cursor('{"dir":"up","inv":1}'),
        encode_cursor('{"dir":1}'),
        encode_cursor('{"dir":"desc","inv":-1}'),
        encode_cursor('{"dir":"desc","evil":1}'),
        encode_cursor('{"dir":"desc","inv":99999999999999999999}'),
    ],
)
def test_desc_bad_cursor_is_400(env: Env, bad: str) -> None:
    r = env.get("/events", order="desc", since=bad)
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_cursor"


def test_unknown_order_is_422(env: Env) -> None:
    assert env.get("/events", order="sideways").status_code == 422
