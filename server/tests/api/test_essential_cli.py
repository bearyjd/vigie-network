from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from api_helpers import Env, env  # noqa: F401

from vigie_api import cli, essential_cli
from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides


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


def test_clear_works_after_the_device_was_merged(env: Env) -> None:
    env.device("a")
    env.device("c")
    assert run(env, "set", "a", "3600") == 0
    env.link("a", "c")
    assert run(env, "clear", "a") == 0
    assert env.ov.execute("SELECT absent_after_s FROM essential_devices").fetchone()[0] is None


def test_mistyped_data_dir_creates_nothing(tmp_path: Path, capsys) -> None:
    typo = tmp_path / "typo"
    assert cli.main(["essential", "--data-dir", str(typo), "list"]) == 1
    assert not typo.exists()
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.main(["essential", "--data-dir", str(empty), "list"]) == 1
    assert list(empty.iterdir()) == []
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.count("\n") == 2


def test_refuses_to_migrate_an_older_database(tmp_path: Path, capsys) -> None:
    path = tmp_path / "overrides.db"
    conn = sqlite3.connect(path, isolation_level=None)
    for statement in OVERRIDES_MIGRATIONS[0]:
        conn.execute(statement)
    conn.execute("PRAGMA user_version=1")
    conn.close()
    for argv in (["list"], ["clear", "d"]):
        assert cli.main(["essential", "--data-dir", str(tmp_path), *argv]) == 1
    assert "run the API image once to migrate" in capsys.readouterr().err
    check = sqlite3.connect(path)
    assert check.execute("PRAGMA user_version").fetchone()[0] == 1
    names = check.execute("SELECT name FROM sqlite_master WHERE name='essential_devices'")
    assert names.fetchone() is None


def test_newer_schema_is_a_clean_error(tmp_path: Path, capsys) -> None:
    open_overrides(tmp_path / "overrides.db").close()
    raw = sqlite3.connect(tmp_path / "overrides.db")
    raw.execute(f"PRAGMA user_version={len(OVERRIDES_MIGRATIONS) + 1}")
    raw.close()
    assert cli.main(["essential", "--data-dir", str(tmp_path), "list"]) == 1
    err = capsys.readouterr().err
    assert "newer than this build" in err and "Traceback" not in err


def test_locked_database_is_a_clean_error(
    env: Env, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    env.device("d1")
    monkeypatch.setattr(essential_cli, "BUSY_TIMEOUT_S", 0.1)
    blocker = open_overrides(env.root / "overrides.db")
    blocker.execute("BEGIN IMMEDIATE")
    try:
        assert run(env, "set", "d1", "3600") == 1
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    err = capsys.readouterr().err
    assert "locked" in err and "Traceback" not in err


def test_unreadable_location_is_a_clean_error(tmp_path: Path, capsys) -> None:
    (tmp_path / "overrides.db").mkdir()  # a directory where the file should be
    assert cli.main(["essential", "--data-dir", str(tmp_path), "list"]) == 1
    assert "Traceback" not in capsys.readouterr().err


def test_list_works_on_a_read_only_file_and_writes_fail_cleanly(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    env.device("d1")
    assert run(env, "set", "d1", "3600") == 0
    env.ov.close()  # checkpoint and drop the WAL so the file can be opened read-only
    env.inv.close()
    path = env.root / "overrides.db"
    path.chmod(0o444)
    env.root.chmod(0o555)
    try:
        assert run(env, "list") == 0
        assert "d1\t3600" in capsys.readouterr().out
        for argv in (["set", "d1", "7200"], ["clear", "d1"]):
            assert run(env, *argv) == 1
        err = capsys.readouterr().err
        assert "Traceback" not in err and err.count("\n") == 2
    finally:
        env.root.chmod(0o755)
        path.chmod(0o600)


def test_list_opens_read_only_and_writes_open_read_write(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.device("d1")
    uris: list[str] = []
    real = sqlite3.connect

    def spy(target, *args, **kwargs):
        uris.append(str(target))
        return real(target, *args, **kwargs)

    monkeypatch.setattr(essential_cli.sqlite3, "connect", spy)
    assert run(env, "list") == 0
    assert run(env, "set", "d1", "3600") == 0
    assert [u.rsplit("?", 1)[1] for u in uris if "overrides.db" in u] == ["mode=ro", "mode=rw"]
