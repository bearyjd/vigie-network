"""Round-4: the data-dir flock lives in create_app's lifespan too; flock OSErrors are reported."""

from __future__ import annotations

import errno
import fcntl
from pathlib import Path

import pytest
from conftest import COLLECTOR, KEY, KEY_ID
from fastapi.testclient import TestClient

from vigie_ingest import cli, store
from vigie_ingest.app import create_app
from vigie_ingest.config import Settings
from vigie_ingest.db import open_inventory
from vigie_ingest.lock import LockHeld


def _settings(tmp_path: Path) -> Settings:
    data, secrets = tmp_path / "data", tmp_path / "secrets"
    data.mkdir()
    secrets.mkdir()
    (secrets / f"collector_key_{KEY_ID}").write_text(KEY.hex())
    conn = open_inventory(data / "inventory.db")
    store.provision_collector(conn, COLLECTOR, KEY_ID)
    conn.close()
    return Settings(data_dir=data, secrets_dir=secrets)


def test_second_lifespan_on_same_data_dir_fails_startup(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with TestClient(create_app(settings)):
        with pytest.raises(LockHeld, match=r"\.ingest\.lock"):
            with TestClient(create_app(settings)):
                pass
    with TestClient(create_app(settings)):  # released on shutdown: restart works
        pass


def test_cli_flock_oserror_is_reported_with_exit_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path / "data"))
    ran: list[object] = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **k: ran.append(1))

    def boom(*_: object, **__: object) -> None:
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(fcntl, "flock", boom)
    assert cli.main(["--insecure-dev"]) == 2
    err = capsys.readouterr().err
    assert "flock" in err and "filesystem" in err
    assert ran == []


def test_lifespan_flock_oserror_fails_startup_clearly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        fcntl, "flock", lambda *a, **k: (_ for _ in ()).throw(OSError(errno.EOPNOTSUPP, "nope"))
    )
    with pytest.raises(LockHeld, match="filesystem"):
        with TestClient(create_app(settings)):
            pass
