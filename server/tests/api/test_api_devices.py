from __future__ import annotations

from api_helpers import Env, env, ts  # noqa: F401


def ids(r) -> list[str]:
    return [d["id"] for d in r.json()["data"]]


def test_effective_type_prefers_override_then_inferred_then_unknown(env: Env) -> None:
    env.device("a", inferred_type="tv", source="rules", confidence=0.9)
    env.device("b", inferred_type="tv", source="ml", confidence=0.7)
    env.device("c")
    env.ov.execute(
        "INSERT INTO device_overrides (device_id, type, updated_at, updated_by)"
        " VALUES ('b','laptop','t','u')"
    )
    got = {d["id"]: d for d in env.get("/devices").json()["data"]}
    assert (got["a"]["type"], got["a"]["type_provenance"]) == (
        "tv",
        {"source": "rules", "confidence": 0.9},
    )
    assert (got["b"]["type"], got["b"]["type_provenance"]["source"]) == ("laptop", "human")
    assert (got["c"]["type"], got["c"]["type_provenance"]["source"]) == ("unknown", None)


def test_group_comes_only_from_override_never_inferred(env: Env) -> None:
    env.device("cam", inferred_type="camera", source="rules", confidence=1.0)
    env.device("plug", inferred_type="iot", source="rules", confidence=1.0)
    assert [d["group_id"] for d in env.get("/devices").json()["data"]] == [None, None]
    env.ov.execute(
        "INSERT INTO device_overrides (device_id, group_id, updated_at, updated_by)"
        " VALUES ('plug','guest','t','u')"
    )
    got = {d["id"]: d["group_id"] for d in env.get("/devices").json()["data"]}
    assert got == {"cam": None, "plug": "guest"}
    assert env.get("/devices/cam").json()["data"]["group_id"] is None


def test_transient_hidden_by_default_and_shown_on_request(env: Env) -> None:
    env.device("act")
    env.device("tra", status="transient")
    assert ids(env.get("/devices")) == ["act"]
    assert ids(env.get("/devices", include_transient=1)) == ["act", "tra"]
    assert ids(env.get("/devices", status="transient")) == ["tra"]


def test_identity_state_is_exposed_and_filterable(env: Env) -> None:
    env.device("ok1")
    env.device("c1", identity_state="conflict")
    env.device("p1", identity_state="pending_confirm")
    got = {d["id"]: d["identity_state"] for d in env.get("/devices").json()["data"]}
    assert got == {"ok1": "ok", "c1": "conflict", "p1": "pending_confirm"}
    assert ids(env.get("/devices", identity_state="conflict")) == ["c1"]


def test_filters_type_group_updated_since(env: Env) -> None:
    env.device("a", inferred_type="tv", source="rules", confidence=1, last_seen=-500)
    env.device("b", inferred_type="phone", source="rules", confidence=1, last_seen=-10)
    env.ov.execute(
        "INSERT INTO device_overrides (device_id, group_id, updated_at, updated_by)"
        " VALUES ('a','kids',?,'u')",
        (ts(-400),),
    )
    assert ids(env.get("/devices", type="tv")) == ["a"]
    assert ids(env.get("/devices", group="kids")) == ["a"]
    assert ids(env.get("/devices", group="unassigned")) == ["b"]
    assert ids(env.get("/devices", updated_since=ts(-100))) == ["b"]
    assert env.get("/devices", type="toaster").status_code == 422


def test_cursor_pagination_walks_all_without_repeats(env: Env) -> None:
    for i in range(5):
        env.device(f"d{i}")
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
        body = env.get("/devices", **params).json()
        seen += [d["id"] for d in body["data"]]
        cursor = body["page"]["next_cursor"]
        pages += 1
        if cursor is None:
            break
    assert seen == [f"d{i}" for i in range(5)] and pages == 3


def test_exact_page_boundary_has_no_dangling_cursor(env: Env) -> None:
    env.device("a")
    env.device("b")
    assert env.get("/devices", limit=2).json()["page"]["next_cursor"] is None


def test_bad_cursor_is_400(env: Env) -> None:
    assert env.get("/devices", cursor="!!!").status_code == 400


def test_alias_follows_identity_link(env: Env) -> None:
    env.device("canon", inferred_type="phone", source="rules", confidence=1)
    env.device("alias")
    env.mac("aa:bb:cc:00:00:01", "canon", last=-50)
    env.mac("ae:bb:cc:00:00:02", "alias", link_source="human", last=0)
    env.link("alias", "canon")
    listing = {
        d["id"]: d["merged_into"] for d in env.get("/devices", include_aliases=1).json()["data"]
    }
    assert listing == {"canon": None, "alias": "canon"}
    detail = env.get("/devices/alias").json()["data"]
    assert detail["id"] == "canon" and detail["merged_into"] == "canon"
    assert detail["requested_id"] == "alias"
    assert {m["mac"] for m in detail["macs"]} == {"aa:bb:cc:00:00:01", "ae:bb:cc:00:00:02"}
    direct = env.get("/devices/canon").json()["data"]
    assert direct["merged_into"] is None and len(direct["macs"]) == 2


def test_detail_macs_events_and_etag(env: Env) -> None:
    env.device("d1", inferred_type="tv", source="rules", confidence=1)
    env.mac("aa:bb:cc:00:00:01", "d1", link_source="rule", rule="r1", first=-900, last=-100)
    env.mac("00:11:22:33:44:55", "d1", first=-800, last=-5)
    env.event("d1", -50)
    r = env.get("/devices/d1")
    data = r.json()["data"]
    assert r.headers["etag"] == '"0"'
    by_mac = {m["mac"]: m for m in data["macs"]}
    rolled = by_mac["aa:bb:cc:00:00:01"]
    assert (rolled["link_source"], rolled["link_rule_id"], rolled["current"]) == (
        "rule",
        "r1",
        False,
    )
    assert by_mac["00:11:22:33:44:55"]["current"] is True
    assert rolled["first_seen"] == ts(-900) and rolled["last_seen"] == ts(-100)
    assert [e["kind"] for e in data["recent_events"]] == ["new_device"]


def test_unknown_device_404_envelope(env: Env) -> None:
    r = env.get("/devices/nope")
    assert r.status_code == 404
    assert r.json() == {
        "ok": False,
        "data": None,
        "error": {"code": "not_found", "message": "device not found"},
        "page": None,
    }


def test_mac_resolution_any_case_and_separator(env: Env) -> None:
    env.device("d1")
    env.mac("aa:bb:cc:00:00:01", "d1", link_source="rule", rule="r1")
    for form in ("aa:bb:cc:00:00:01", "AA:BB:CC:00:00:01", "AA-BB-CC-00-00-01",
                 "aabb.cc00.0001", "AABBCC000001"):  # fmt: skip
        data = env.get(f"/macs/{form}").json()["data"]
        assert data["device_id"] == "d1" and data["link_source"] == "rule", form
        assert data["identity_state"] == "ok"


def test_mac_follows_links_and_reports_identity_state(env: Env) -> None:
    env.device("canon", identity_state="conflict")
    env.device("alias")
    env.mac("ae:bb:cc:00:00:02", "alias", link_source="human")
    env.link("alias", "canon")
    data = env.get("/macs/ae:bb:cc:00:00:02").json()["data"]
    assert data["device_id"] == "canon" and data["observed_device_id"] == "alias"
    assert data["identity_state"] == "conflict"


def test_unknown_and_malformed_mac(env: Env) -> None:
    assert env.get("/macs/aa:bb:cc:00:00:99").status_code == 404
    assert env.get("/macs/not-a-mac").status_code == 422


def test_inventory_missing_is_503(env: Env) -> None:
    env.inv.close()
    (env.root / "inventory.db").unlink()
    for suffix in ("-wal", "-shm"):
        (env.root / f"inventory.db{suffix}").unlink(missing_ok=True)
    assert env.get("/devices").status_code == 503
    assert env.client.get("/healthz").status_code == 200


def test_unknown_route_uses_envelope(env: Env) -> None:
    r = env.get("/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"
    r = env.client.post("/devices", headers=env.auth)
    assert r.status_code == 405 and r.json()["error"]["code"] == "method_not_allowed"
