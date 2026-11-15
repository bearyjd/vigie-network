from __future__ import annotations

import json

import pytest
from api_helpers import Env, env  # noqa: F401

from vigie_api import cli


def run(env: Env, *argv: str) -> int:
    return cli.main(["essential", "--data-dir", str(env.root), *argv])


def test_set_list_clear_roundtrip_with_audit(env: Env, capsys) -> None:
    env.device("d1")
    assert run(env, "set", "d1", "86400") == 0
    assert run(env, "list") == 0
    assert "d1\t86400" in capsys.readouterr().out
    assert run(env, "clear", "d1") == 0
    assert run(env, "list") == 0 and capsys.readouterr().out == ""
    actions = [r[0] for r in env.ov.execute("SELECT action FROM audit_log ORDER BY seq")]
    assert actions == ["device.essential.set", "device.essential.clear"]
    detail = env.ov.execute("SELECT principal, detail FROM audit_log ORDER BY seq").fetchone()
    assert detail[0] == "cli:local" and json.loads(detail[1])["after"] == 86400


@pytest.mark.parametrize("seconds", ["0", "3599", "604801", "-5"])
def test_out_of_range_refused_before_any_write(env: Env, seconds: str) -> None:
    env.device("d1")
    assert run(env, "set", "d1", seconds) == 2
    assert env.ov.execute("SELECT COUNT(*) FROM essential_devices").fetchone()[0] == 0


def test_unknown_device_and_unmark_unmarked_fail(env: Env, capsys) -> None:
    env.device("d1")
    assert run(env, "set", "nope", "3600") == 1
    assert run(env, "clear", "d1") == 1
    assert "not_essential" in capsys.readouterr().err
