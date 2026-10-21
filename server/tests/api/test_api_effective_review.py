"""Review fixes: alias/canonical override semantics, worst identity_state, list filters."""

from __future__ import annotations

import time

import pytest
from api_helpers import Env, env, ts  # noqa: F401

from vigie_api import effective


def ids(r) -> list[str]:
    return [d["id"] for d in r.json()["data"]]


def _merged_pair(env: Env) -> None:
    """a trusted (alias), c guest (canonical); a -> c."""
    env.device("a")
    env.device("c")
    assert env.patch("/devices/a", {"name": "Old", "group_id": "trusted"}, "0").status_code == 200
    assert env.patch("/devices/c", {"name": "New", "group_id": "guest"}, "0").status_code == 200
    env.link("a", "c")


def test_alias_uses_canonical_override_not_its_own(env: Env) -> None:
    _merged_pair(env)
    assert ids(env.get("/devices", group="trusted")) == []
    assert ids(env.get("/devices", group="trusted", include_aliases=1)) == []
    both = {d["id"]: d for d in env.get("/devices", include_aliases=1).json()["data"]}
    assert both["a"]["group_id"] == "guest" and both["a"]["name"] == "New"
    assert both["a"]["merged_into"] == "c"
    detail = env.get("/devices/a").json()["data"]
    assert detail["id"] == "c" and detail["group_id"] == "guest" and detail["merged_into"] == "c"


def test_aliases_excluded_from_default_list(env: Env) -> None:
    _merged_pair(env)
    assert ids(env.get("/devices")) == ["c"]
    assert ids(env.get("/devices", include_aliases=1)) == ["a", "c"]


def test_type_filter_follows_canonical_override_for_aliases(env: Env) -> None:
    env.device("a", inferred_type="phone")
    env.device("c", inferred_type="tv")
    env.patch("/devices/c", {"type": "camera"}, "0")
    env.link("a", "c")
    assert ids(env.get("/devices", type="camera", include_aliases=1)) == ["a", "c"]
    assert ids(env.get("/devices", type="phone", include_aliases=1)) == []
    assert ids(env.get("/devices", type="tv", include_aliases=1)) == []


def test_group_unassigned_and_updated_since_use_canonical(env: Env) -> None:
    env.device("a", last_seen=-5000)
    env.device("c", last_seen=-5000)
    env.device("z", last_seen=-5000)
    env.patch("/devices/c", {"group_id": "kids"}, "0")  # override updated_at == NOW
    env.link("a", "c")
    assert ids(env.get("/devices", group="unassigned", include_aliases=1)) == ["z"]
    assert ids(env.get("/devices", group="kids", include_aliases=1)) == ["a", "c"]
    assert ids(env.get("/devices", updated_since=ts(-10), include_aliases=1)) == ["a", "c"]


@pytest.mark.parametrize(
    ("observed", "canonical", "expected"),
    [
        ("ok", "conflict", "conflict"),
        ("conflict", "ok", "conflict"),
        ("ok", "pending_confirm", "pending_confirm"),
        ("pending_confirm", "ok", "pending_confirm"),
        ("conflict", "pending_confirm", "conflict"),
        ("ok", "ok", "ok"),
    ],
)
def test_mac_reports_worst_state_of_observed_and_canonical(
    env: Env, observed: str, canonical: str, expected: str
) -> None:
    env.device("a", identity_state=observed)
    env.device("c", identity_state=canonical)
    env.mac("aa:bb:cc:00:00:01", "a")
    env.link("a", "c")
    assert env.get("/macs/aa:bb:cc:00:00:01").json()["data"]["identity_state"] == expected


def test_detail_reports_worst_state_across_members(env: Env) -> None:
    env.device("c", identity_state="ok")
    env.device("a", identity_state="pending_confirm")
    env.device("b", identity_state="conflict")
    env.link("a", "c")
    env.link("b", "c")
    assert env.get("/devices/c").json()["data"]["identity_state"] == "conflict"
    assert env.get("/devices/a").json()["data"]["identity_state"] == "conflict"


def test_retired_devices_excluded_by_default(env: Env) -> None:
    env.device("live")
    env.device("gone", status="retired")
    assert ids(env.get("/devices")) == ["live"]
    assert ids(env.get("/devices", include_retired=1)) == ["gone", "live"]
    assert ids(env.get("/devices", status="retired")) == ["gone"]


@pytest.mark.parametrize(
    "value", ["yesterday", "2026-01-01", "2026-01-01T00:00:00", "2026-01-01T00:00:00+01:00",
              "2026-13-01T00:00:00Z", "2026-01-01 00:00:00Z", "x" * 40],
)  # fmt: skip
def test_updated_since_must_be_iso_utc(env: Env, value: str) -> None:
    r = env.get("/devices", updated_since=value)
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_updated_since"


def test_updated_since_fractional_seconds_accepted(env: Env) -> None:
    env.device("a", last_seen=-50)
    assert ids(env.get("/devices", updated_since=ts(-100)[:-1] + ".750Z")) == ["a"]
    assert ids(env.get("/devices", updated_since=ts(+100))) == []


def test_filters_are_pushed_into_sql_and_bounded_in_time(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.inv.execute("BEGIN")
    env.inv.executemany(
        "INSERT INTO devices (id, first_seen, last_seen, inferred_type, identity_state, status)"
        " VALUES (?,?,?,?,?,?)",
        [(f"d{i:06d}", ts(-9), ts(-9), "phone" if i % 2 else "tv", "ok", "active")
         for i in range(20_000)],
    )  # fmt: skip
    env.inv.execute("COMMIT")
    calls = []
    real = effective.effective_device
    monkeypatch.setattr(
        effective, "effective_device", lambda *a, **k: calls.append(1) or real(*a, **k)
    )
    started = time.monotonic()
    r = env.get("/devices", type="phone", group="unassigned", limit=100)
    assert time.monotonic() - started < 1.0
    assert len(r.json()["data"]) == 100 and len(calls) <= 101
    calls.clear()
    assert env.get("/devices", type="console").json()["data"] == [] and not calls


def _states(env: Env, **params) -> dict[str, str]:
    return {d["id"]: d["identity_state"] for d in env.get("/devices", **params).json()["data"]}


def test_list_identity_state_is_worst_across_alias_members(env: Env) -> None:
    env.device("c2", identity_state="ok")
    env.device("a2", identity_state="conflict")
    env.device("p2", identity_state="pending_confirm")
    env.device("solo", identity_state="ok")
    env.link("a2", "c2")
    env.link("p2", "c2")
    assert _states(env) == {"c2": "conflict", "solo": "ok"}
    assert _states(env, include_aliases="1") == {
        "c2": "conflict", "a2": "conflict", "p2": "conflict", "solo": "ok",
    }  # fmt: skip
    detail = env.get("/devices/c2").json()["data"]["identity_state"]
    assert detail == _states(env)["c2"]


def test_list_identity_state_filter_uses_the_worst_value(env: Env) -> None:
    env.device("c2", identity_state="ok")
    env.device("a2", identity_state="conflict")
    env.device("pc", identity_state="pending_confirm")
    env.device("pa", identity_state="ok")
    env.device("solo", identity_state="ok")
    env.link("a2", "c2")
    env.link("pa", "pc")
    assert set(_states(env, identity_state="conflict")) == {"c2"}
    assert set(_states(env, identity_state="ok")) == {"solo"}  # c2 is no longer ok
    assert set(_states(env, identity_state="pending_confirm")) == {"pc"}
    both = _states(env, identity_state="conflict", include_aliases="1")
    assert set(both) == {"c2", "a2"}
