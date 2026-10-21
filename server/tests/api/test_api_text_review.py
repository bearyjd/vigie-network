"""Hostile strings: patch text hygiene and the reason_text allowlist."""

from __future__ import annotations

import pytest
from api_helpers import Env, env  # noqa: F401

HOSTILE = [
    *map(chr, range(0x00, 0x20)),  # C0 incl. NUL, TAB, LF, CR, ESC
    *map(chr, range(0x7F, 0xA0)),  # DEL + C1 incl. NEL
    *map(chr, (0x061C, 0x200E, 0x200F, 0x2028, 0x2029)),
    *map(chr, range(0x202A, 0x202F)),  # bidi embeddings/overrides
    *map(chr, range(0x2066, 0x206A)),  # bidi isolates
]


@pytest.mark.parametrize("field", ["name", "owner"])
@pytest.mark.parametrize("char", HOSTILE, ids=lambda c: f"U+{ord(c):04X}")
def test_patch_rejects_control_and_bidi_characters(env: Env, field: str, char: str) -> None:
    env.device("d1")
    for value in (f"ab{char}cd", f"{char}ab", f"ab{char}"):
        r = env.patch("/devices/d1", {field: value}, "0")
        assert r.status_code == 422, repr(value)
    assert env.ov.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 0


def test_patch_nfc_normalizes_and_strips(env: Env) -> None:
    env.device("d1")
    r = env.patch("/devices/d1", {"name": "  Café  ", "owner": "Å  "}, "0")
    assert r.status_code == 200
    row = env.ov.execute("SELECT name, owner FROM device_overrides").fetchone()
    assert (row["name"], row["owner"]) == ("Café", "Å")


def test_patch_length_is_enforced_after_normalization(env: Env) -> None:
    env.device("d1")
    assert env.patch("/devices/d1", {"name": "x" * 128}, "0").status_code == 200
    assert env.patch("/devices/d1", {"name": "x" * 129}, "1").status_code == 422
    # U+0344 is one char that NFC expands to two: 65 of them pass the raw cap but not the real one
    assert env.patch("/devices/d1", {"name": "̈́" * 65}, "1").status_code == 422


@pytest.mark.parametrize("blank", ["", "   ", " 　"])
def test_blank_text_is_rejected_but_null_clears(env: Env, blank: str) -> None:
    env.device("d1")
    assert env.patch("/devices/d1", {"name": "Bob"}, "0").status_code == 200
    assert env.patch("/devices/d1", {"name": blank}, "1").status_code == 422
    assert env.patch("/devices/d1", {"name": None}, "1").status_code == 200


def _suggestions_without_action_check(env: Env) -> None:
    env.inv.execute("DROP TABLE suggestions")
    env.inv.execute(
        """CREATE TABLE suggestions (id TEXT PRIMARY KEY, action TEXT NOT NULL,
        device_ids TEXT NOT NULL, payload TEXT NOT NULL, reason_code TEXT NOT NULL,
        reason_text TEXT, basis TEXT NOT NULL, created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL)"""
    )


def _suggest(
    env: Env, sid: str, action: str, devices: list[str], expires: str = "2099-01-01T00:00:00Z"
):
    env.inv.execute(
        "INSERT INTO suggestions VALUES (?,?,?,?,?,?,?,?,?)",
        (sid, action, str(devices).replace("'", '"'), "{}", "rc", f"prose {sid}", "{}",
         "2026-01-01T00:00:00Z", expires),
    )  # fmt: skip


def test_reason_text_only_for_label_actions_allowlist(env: Env) -> None:
    _suggestions_without_action_check(env)
    for action in ("label", "move_group", "quarantine", "merge_identity", "brand_new_action", ""):
        _suggest(env, f"s-{action or 'empty'}", action, ["d1"])
    got = {s["action"]: s["reason_text"] for s in env.get("/suggestions").json()["data"]}
    assert got["label"] == "prose s-label"
    assert all(v is None for k, v in got.items() if k != "label")


def _detail_prose(env: Env) -> str | None:
    return env.get("/devices/d1").json()["data"]["explanation"]["reason_text"]


def test_detail_prose_suppressed_while_any_trust_suggestion_is_pending(env: Env) -> None:
    _suggestions_without_action_check(env)
    env.device("d1")
    env.inv.execute("UPDATE devices SET inferred_reason_text='LLM says it is a toaster'")
    assert _detail_prose(env) == "LLM says it is a toaster"
    _suggest(env, "label1", "label", ["d1"])  # a label suggestion does not suppress
    assert _detail_prose(env) == "LLM says it is a toaster"
    for action in ("move_group", "quarantine", "merge_identity", "future_action"):
        env.inv.execute("DELETE FROM suggestions WHERE id <> 'label1'")
        _suggest(env, "trust", action, ["other", "d1"])
        assert _detail_prose(env) is None, action


def test_detail_prose_returns_once_the_suggestion_is_decided_or_expired(env: Env) -> None:
    _suggestions_without_action_check(env)
    env.device("d1")
    env.inv.execute("UPDATE devices SET inferred_reason_text='prose'")
    _suggest(env, "m", "move_group", ["d1"])
    assert _detail_prose(env) is None
    env.ov.execute("INSERT INTO suggestion_decisions VALUES ('m','rejected','u','t',NULL)")
    assert _detail_prose(env) == "prose"
    env.ov.execute("DELETE FROM suggestion_decisions")
    env.inv.execute("UPDATE suggestions SET expires_at='2000-01-01T00:00:00Z'")
    assert _detail_prose(env) == "prose"


def test_detail_prose_suppressed_for_suggestion_on_an_alias_member(env: Env) -> None:
    _suggestions_without_action_check(env)
    env.device("d1")
    env.device("old")
    env.link("old", "d1")
    env.inv.execute("UPDATE devices SET inferred_reason_text='prose'")
    _suggest(env, "m", "quarantine", ["old"])
    assert _detail_prose(env) is None
    other = env.get("/devices/old").json()["data"]["explanation"]["reason_text"]
    assert other is None


def test_detail_prose_unaffected_by_suggestions_for_other_devices(env: Env) -> None:
    _suggestions_without_action_check(env)
    env.device("d1")
    env.device("d2")
    env.inv.execute("UPDATE devices SET inferred_reason_text='prose'")
    _suggest(env, "m", "quarantine", ["d2"])
    assert _detail_prose(env) == "prose"
