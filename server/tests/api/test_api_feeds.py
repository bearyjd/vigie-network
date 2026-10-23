from __future__ import annotations

import pytest
from api_helpers import Env, env, ts  # noqa: F401

from vigie_api.effective import decode_cursor, encode_cursor


def kinds(r) -> list[str]:
    return [e["kind"] for e in r.json()["data"]]


def test_events_union_inventory_and_human_actions_in_time_order(env: Env) -> None:
    env.device("d1")
    env.event("d1", -300, "new_device")
    env.event("d1", -100, "anomaly", "warn")
    env.patch("/devices/d1", {"name": "A"}, "0")  # audit at NOW (offset 0)
    r = env.get("/events")
    assert kinds(r) == ["new_device", "anomaly", "device.patch"]
    assert [e["source"] for e in r.json()["data"]] == ["inventory", "inventory", "audit"]
    audit = r.json()["data"][2]
    assert (
        audit["device_id"] == "d1"
        and audit["summary"].startswith("app ")
        and "test" not in audit["summary"]
    )


def test_events_filters(env: Env) -> None:
    env.device("d1")
    env.event("d1", -300, "new_device")
    env.event("d1", -100, "anomaly", "warn")
    env.patch("/devices/d1", {"name": "A"}, "0")
    assert kinds(env.get("/events", kind="anomaly")) == ["anomaly"]
    assert kinds(env.get("/events", severity="warn")) == ["anomaly"]
    assert kinds(env.get("/events", kind="device.patch")) == ["device.patch"]
    assert sorted(kinds(env.get("/events", severity="info"))) == ["device.patch", "new_device"]


def test_events_since_cursor_resumes_without_gaps_or_repeats(env: Env) -> None:
    env.device("d1")
    for i in range(5):
        env.event("d1", -500 + i, "anomaly")
    first = env.get("/events", limit=2).json()
    second = env.get("/events", limit=2, since=first["page"]["next_cursor"]).json()
    third = env.get("/events", limit=2, since=second["page"]["next_cursor"]).json()
    got = [e["id"] for p in (first, second, third) for e in p["data"]]
    assert len(got) == 5 == len(set(got))
    empty = env.get("/events", since=third["page"]["next_cursor"]).json()
    assert empty["data"] == [] and empty["page"]["next_cursor"] == third["page"]["next_cursor"]


def test_events_same_timestamp_ties_do_not_skip(env: Env) -> None:
    env.device("d1")
    for _ in range(4):
        env.event("d1", -10, "anomaly")
    seen: list[str] = []
    cursor = None
    for _ in range(5):
        params = {"limit": 1, **({"since": cursor} if cursor else {})}
        body = env.get("/events", **params).json()
        if not body["data"]:
            break
        seen += [e["id"] for e in body["data"]]
        cursor = body["page"]["next_cursor"]
    assert len(seen) == 4 == len(set(seen))


def test_events_late_arriving_event_is_not_skipped(env: Env) -> None:
    """Pipeline stamps events with observation time, so a later insert can carry an older ts."""
    env.device("d1")
    e2 = env.event("d1", -60, "anomaly")  # "12:00"
    first = env.get("/events").json()
    assert [e["id"] for e in first["data"]] == [e2]
    e1 = env.event("d1", -120, "anomaly")  # "11:59", inserted after the cursor was taken
    again = env.get("/events", since=first["page"]["next_cursor"]).json()
    assert [e["id"] for e in again["data"]] == [e1]


def test_events_late_audit_row_is_not_skipped(env: Env) -> None:
    env.device("d1")
    env.event("d1", -60, "anomaly")
    cursor = env.get("/events").json()["page"]["next_cursor"]
    env.ov.execute(
        "INSERT INTO audit_log (id, ts, principal, action, target) VALUES ('late',?,?,?,?)",
        (ts(-500), "app:other", "device.patch", None),
    )
    got = env.get("/events", since=cursor).json()["data"]
    assert [e["id"] for e in got] == ["late"]


def test_events_page_is_display_sorted_by_ts_and_limit_is_total(env: Env) -> None:
    env.device("d1")
    for when in (-10, -50, -30):
        env.event("d1", when, "anomaly")
    page = env.get("/events", limit=3).json()["data"]
    assert [e["ts"] for e in page] == sorted(e["ts"] for e in page)
    assert len(env.get("/events", limit=2).json()["data"]) == 2


@pytest.mark.parametrize(
    "bad",
    [
        "!!",
        encode_cursor("nopipe"),
        encode_cursor("[1,2]"),
        encode_cursor('{"inv": -1}'),
        encode_cursor('{"inv": "x"}'),
        encode_cursor('{"inv": 1.5}'),
        encode_cursor('{"inv": true}'),
        encode_cursor('{"evil": 1}'),
        encode_cursor('{"inv": 99999999999999999999}'),
    ],
)
def test_events_bad_or_tampered_cursor_is_400(env: Env, bad: str) -> None:
    r = env.get("/events", since=bad)
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_cursor"


def test_events_next_cursor_is_resume_point_and_opaque(env: Env) -> None:
    """next_cursor = last included row per source; empty page echoes `since` unchanged."""
    env.device("d1")
    env.event("d1", -5, "anomaly")
    cursor = env.get("/events").json()["page"]["next_cursor"]
    assert decode_cursor(cursor) == '{"audit":0,"inv":1}'
    empty = env.get("/events", since=cursor).json()
    assert empty["data"] == [] and empty["page"]["next_cursor"] == cursor


def test_suggestion_effective_state_computed_on_read(env: Env) -> None:
    env.device("d1")
    env.suggestion("s-pending", expires=+1000)
    env.suggestion("s-expired", expires=-1)
    env.suggestion("s-accepted", expires=-1)  # decision wins over expiry
    env.suggestion("s-rejected", expires=+1000)
    env.ov.executemany(
        "INSERT INTO suggestion_decisions VALUES (?,?,?,?,NULL)",
        [("s-accepted", "accepted", "u", "t"), ("s-rejected", "rejected", "u", "t")],
    )
    got = {s["id"]: s for s in env.get("/suggestions").json()["data"]}
    assert {k: v["state"] for k, v in got.items()} == {
        "s-pending": "pending",
        "s-expired": "expired",
        "s-accepted": "accepted",
        "s-rejected": "rejected",
    }
    assert got["s-accepted"]["decided_by"] == "u"
    assert [s["id"] for s in env.get("/suggestions", state="expired").json()["data"]] == [
        "s-expired"
    ]


def test_suggestion_expires_strictly_after_expires_at(env: Env) -> None:
    env.suggestion("edge", expires=0)  # expires_at == now: still pending
    assert env.get("/suggestions").json()["data"][0]["state"] == "pending"


def test_suggestions_are_read_only_and_parsed(env: Env) -> None:
    env.suggestion("s1", expires=+100)
    s = env.get("/suggestions").json()["data"][0]
    assert s["device_ids"] == ["d1"] and s["payload"] == {"name": "x"} and s["basis"] == {"d1": 0}
    for method in ("post", "patch", "delete", "put"):
        r = getattr(env.client, method)("/suggestions", headers=env.auth)
        assert r.status_code == 405
    assert env.client.post("/suggestions/s1/accept", headers=env.auth).status_code == 422


def test_prose_hidden_for_trust_changing_actions(env: Env) -> None:
    env.inv.execute(
        "INSERT INTO suggestions VALUES ('m','merge_identity','[\"a\",\"b\"]','{}','rc',"
        "'LLM says same device','{}','2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')"
    )
    env.inv.execute(
        "INSERT INTO suggestions VALUES ('l','label','[\"a\"]','{}','rc','harmless prose','{}',"
        "'2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')"
    )
    got = {s["id"]: s["reason_text"] for s in env.get("/suggestions").json()["data"]}
    assert got == {"m": None, "l": "harmless prose"}


def test_suggestions_pagination(env: Env) -> None:
    for i in range(3):
        env.suggestion(f"s{i}", expires=+100)
    first = env.get("/suggestions", limit=2).json()
    assert len(first["data"]) == 2
    rest = env.get("/suggestions", limit=2, cursor=first["page"]["next_cursor"]).json()
    assert [s["id"] for s in rest["data"]] == ["s2"] and rest["page"]["next_cursor"] is None


def test_missing_suggestions_and_events_tables_read_as_empty(env: Env) -> None:
    env.inv.execute("DROP TABLE suggestions")
    env.inv.execute("DROP TABLE events")
    assert env.get("/suggestions").json()["data"] == []
    assert env.get("/events").json()["data"] == []


def _audit_rows(env: Env, count: int, action: str = "device.patch") -> None:
    for i in range(count):
        env.ov.execute(
            "INSERT INTO audit_log (id, ts, principal, action, target) VALUES (?,?,?,?,?)",
            (f"a{i:03d}", ts(i), "app:test", action, "d1"),
        )


def test_audit_only_paging_beyond_limit_has_no_duplicates_or_skips(env: Env) -> None:
    _audit_rows(env, 7)
    seen: list[str] = []
    cursor = None
    for _ in range(10):
        params = {"limit": 3, **({"since": cursor} if cursor else {})}
        page = env.get("/events", **params).json()
        if not page["data"]:
            break
        seen += [e["id"] for e in page["data"]]
        cursor = page["page"]["next_cursor"]
    assert seen == [f"a{i:03d}" for i in range(7)]


def test_token_lifecycle_events_and_token_ids_are_not_in_the_feed(env: Env) -> None:
    env.device("d1")
    env.ov.execute(
        "INSERT INTO audit_log (id, ts, principal, action, target) VALUES"
        " ('t1',?,'cli','token.create','secret-id'), ('t2',?,'cli','token.revoke','secret-id')",
        (ts(1), ts(2)),
    )
    _audit_rows(env, 1)
    got = env.get("/events").json()["data"]
    assert [e["id"] for e in got] == ["a000"]
    assert got[0]["summary"].startswith("app ") and "test" not in got[0]["summary"]
    assert env.get("/events", kind="token.create").json()["data"] == []
    assert "secret-id" not in env.get("/events").text
