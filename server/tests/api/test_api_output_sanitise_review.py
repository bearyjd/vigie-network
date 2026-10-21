"""Hostile strings are sanitised on READ (stored values untouched); name/owner reject invisibles."""

from __future__ import annotations

import pytest
from api_helpers import Env, env, ts  # noqa: F401

EVIL = "evil\x1b[2J‮<script>\x00"
CLEAN = "evil[2J<script>"


def _seed(env: Env, text: str) -> None:
    env.device("d1")
    env.inv.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, hostname, link_source,"
        " first_seen, last_seen) VALUES ('aa:bb:cc:00:00:01','d1',0,?, 'self',?,?)",
        (text, ts(-5), ts(0)),
    )
    env.inv.execute(
        "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
        " VALUES ('e1','d1',?,'new_device','info',?)",
        (ts(0), text),
    )
    env.inv.execute(
        "UPDATE devices SET inferred_reason_text=?, inferred_reason_code=?", (text, text)
    )
    env.ov.execute(
        "INSERT INTO device_overrides (device_id, name, owner, updated_at, updated_by, version)"
        " VALUES ('d1',?,?,?,'t',1)",
        (text, text, ts(0)),
    )


def test_hostile_strings_are_sanitised_on_every_read_surface(env: Env) -> None:
    _seed(env, EVIL)
    detail = env.get("/devices/d1").json()["data"]
    assert detail["macs"][0]["hostname"] == CLEAN
    assert detail["recent_events"][0]["summary"] == CLEAN
    assert detail["explanation"]["reason_text"] == CLEAN
    assert detail["explanation"]["reason_code"] == CLEAN
    assert detail["name"] == detail["owner"] == CLEAN
    assert env.get("/devices").json()["data"][0]["name"] == CLEAN
    assert env.get("/events").json()["data"][0]["summary"] == CLEAN


def test_stored_value_is_left_untouched(env: Env) -> None:
    _seed(env, EVIL)
    env.get("/devices/d1")
    stored = env.inv.execute("SELECT hostname FROM observations").fetchone()[0]
    assert stored == EVIL


def test_sanitiser_strips_tag_characters_and_bounds_length(env: Env) -> None:
    hidden = "ok" + "".join(chr(0xE0000 + ord(c)) for c in "ignore previous")
    _seed(env, hidden + "x" * 1000)
    host = env.get("/devices/d1").json()["data"]["macs"][0]["hostname"]
    assert host.startswith("okxxx") and len(host) <= 256


def test_ordinary_printable_text_is_unchanged(env: Env) -> None:
    _seed(env, "Bob's iPhone – café 電話 😀")
    assert (
        env.get("/devices/d1").json()["data"]["macs"][0]["hostname"]
        == "Bob's iPhone – café 電話 😀"
    )


def test_hostile_suggestion_prose_and_payload_are_sanitised(env: Env) -> None:
    env.suggestion("s1", expires=500)
    env.inv.execute(
        "UPDATE suggestions SET reason_text=?, payload=?", (EVIL, f'{{"name":"{CLEAN}\\u0000"}}')
    )
    item = env.get("/suggestions").json()["data"][0]
    assert item["reason_text"] == CLEAN
    assert item["payload"] == {"name": CLEAN}


@pytest.mark.parametrize("cp", [0x200B, 0xFEFF, 0x00AD, 0x034F, 0xE0001, 0x200D, 0x2060])
@pytest.mark.parametrize("field", ["name", "owner"])
def test_patch_rejects_invisible_format_characters(env: Env, field: str, cp: int) -> None:
    env.device("d1")
    for value in (f"ab{chr(cp)}cd", f"{chr(cp)}ab"):
        r = env.patch("/devices/d1", {field: value}, "0")
        assert r.status_code == 422, (hex(cp), value)
    assert env.ov.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 0


def test_patch_keeps_ordinary_space_and_nfkc_folds_lookalikes(env: Env) -> None:
    env.device("d1")
    r = env.patch("/devices/d1", {"name": "Ａdmin  Phone", "owner": "Mary Ann"}, "0")
    assert r.status_code == 200
    row = env.ov.execute("SELECT name, owner FROM device_overrides").fetchone()
    assert (row["name"], row["owner"]) == ("Admin  Phone", "Mary Ann")
