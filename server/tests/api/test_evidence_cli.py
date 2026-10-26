"""vigie-api evidence export: same functions as the endpoint, run locally and audited."""

from __future__ import annotations

import json
import os
import stat

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from incident_helpers import seed_collector

from vigie_api import cli, evidence_cli

MAC = "aa:bb:cc:12:34:56"


@pytest.fixture
def e(env: Env, monkeypatch) -> Env:  # noqa: F811
    import vigie_api.effective as effective

    monkeypatch.setattr(effective.time, "time", lambda: NOW)
    seed_collector(env, "d1")
    env.inv.execute("UPDATE observations SET hostname='cli-canary-host', mac=?", (MAC,))
    return env


def run(e: Env, out, *extra: str) -> int:
    argv = ["evidence", "--data-dir", str(e.root), "export", "d1", "-o", str(out), *extra]
    return cli.main(argv)


def audit_rows(e: Env) -> list[dict]:
    return [
        dict(r)
        for r in e.ov.execute("SELECT * FROM audit_log WHERE action='device.evidence_export'")
    ]


def test_export_writes_a_private_file_and_audits_as_cli_local(e, tmp_path):
    out = tmp_path / "pack.json"
    previous = os.umask(0)  # the mode must come from the code, not from main()'s umask
    try:
        argv = ["--data-dir", str(e.root), "export", "d1", "-o", str(out)]
        assert evidence_cli.main(argv, "t") == 0
    finally:
        os.umask(previous)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    doc = json.loads(out.read_text())
    assert doc["redaction"]["level"] == "pseudonymized" and "cli-canary-host" not in out.read_text()
    (row,) = audit_rows(e)
    assert row["principal"] == "cli:local"
    detail = json.loads(row["detail"])
    assert detail["pack_sha256"] == doc["content_sha256"] and detail["format"] == "json"
    assert "cli-canary-host" not in json.dumps(row)


def test_markdown_format_and_minimal_level(e, tmp_path):
    out = tmp_path / "pack.md"
    assert run(e, out, "--format", "markdown", "--redaction", "minimal") == 0
    assert "BEGIN UNTRUSTED DEVICE DATA" in out.read_text()
    assert json.loads(audit_rows(e)[0]["detail"])["level"] == "minimal"


def test_refuses_to_overwrite_an_existing_file(e, tmp_path, capsys):
    out = tmp_path / "pack.json"
    out.write_text("precious")
    assert run(e, out) == 2
    assert out.read_text() == "precious"
    assert audit_rows(e) == [] and "exists" in capsys.readouterr().err


def test_refuses_to_follow_a_symlink_at_the_target(e, tmp_path):
    target = tmp_path / "victim"
    target.write_text("keep")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert run(e, link) == 2
    assert target.read_text() == "keep" and audit_rows(e) == []


def test_full_needs_confirmation_flag(e, tmp_path, capsys):
    out = tmp_path / "full.json"
    assert run(e, out, "--redaction", "full") == 2
    assert not out.exists() and audit_rows(e) == []
    assert run(e, out, "--redaction", "full", "--confirm-full") == 0
    assert "cli-canary-host" in out.read_text()


def test_unknown_device_creates_no_file_and_no_audit(e, tmp_path, capsys):
    out = tmp_path / "x.json"
    argv = ["evidence", "--data-dir", str(e.root), "export", "nope", "-o", str(out)]
    assert cli.main(argv) == 1
    assert not out.exists() and audit_rows(e) == []
    assert "not_found" in capsys.readouterr().err


def test_audit_failure_leaves_no_file(e, tmp_path):
    e.ov.execute(
        "CREATE TRIGGER no_export BEFORE INSERT ON audit_log"
        " WHEN NEW.action='device.evidence_export'"
        " BEGIN SELECT RAISE(ABORT, 'audit down'); END"
    )
    out = tmp_path / "pack.json"
    assert run(e, out) == 3
    assert not out.exists()


def test_missing_inventory_is_an_error(tmp_path):
    out = tmp_path / "pack.json"
    argv = ["evidence", "--data-dir", str(tmp_path), "export", "d1", "-o", str(out)]
    assert cli.main(argv) == 1 and not out.exists()
