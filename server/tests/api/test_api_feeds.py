from __future__ import annotations

from api_helpers import Env, env  # noqa: F401


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
    assert audit["device_id"] == "d1" and "app:test" in audit["summary"]


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


def test_events_bad_cursor(env: Env) -> None:
    assert env.get("/events", since="!!").status_code == 422
    from vigie_api.effective import encode_cursor

    assert env.get("/events", since=encode_cursor("nopipe")).status_code == 422


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
    assert env.client.post("/suggestions/s1/accept", headers=env.auth).status_code == 404


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
