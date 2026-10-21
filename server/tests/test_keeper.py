"""Keepers: a writer holds one open connection so read-only consumers can attach to -wal/-shm."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest
from conftest import make_batch
from fastapi.testclient import TestClient

from vigie_api.app import create_app as create_api
from vigie_api.config import Settings as ApiSettings
from vigie_ingest import keeper, retention
from vigie_ingest.db import ensure_shard, open_inventory, shard_name, utc_day
from vigie_ingest.keeper import Keeper
from vigie_pipeline import cli as pipeline_cli


def _db(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t(x)")
    conn.commit()
    conn.close()
    return path


def _has_sidecars(path: Path) -> bool:
    return Path(f"{path}-shm").exists() and Path(f"{path}-wal").exists()


def test_hold_keeps_wal_sidecars_alive_until_released(tmp_path: Path) -> None:
    db = _db(tmp_path / "x.db")
    assert not _has_sidecars(db)  # a clean close removed them
    k = Keeper()
    assert k.hold(db) is True
    assert _has_sidecars(db)
    assert k.hold(db) is True  # idempotent
    assert k.held() == [db]
    k.release(db)
    assert not _has_sidecars(db)
    k.release(db)  # releasing something not held is fine


def test_hold_never_creates_a_database(tmp_path: Path) -> None:
    k = Keeper()
    assert k.hold(tmp_path / "absent.db") is False
    assert not (tmp_path / "absent.db").exists()


def test_hold_survives_an_unreadable_file(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not sqlite" * 100)
    assert Keeper().hold(bad) is False
    assert "keeper cannot hold" in caplog.text


def test_close_releases_everything(tmp_path: Path) -> None:
    a, b = _db(tmp_path / "a.db"), _db(tmp_path / "b.db")
    k = Keeper()
    k.hold(a)
    k.hold(b)
    k.close()
    assert k.held() == [] and not _has_sidecars(a) and not _has_sidecars(b)


def test_api_lifespan_holds_overrides_db(tmp_path: Path) -> None:
    settings = ApiSettings(data_dir=tmp_path, overrides_db=tmp_path / "ovr.db")
    app = create_api(settings)
    ovr = tmp_path / "ovr.db"
    assert not _has_sidecars(ovr)  # created and closed at construction
    with TestClient(app):
        assert _has_sidecars(ovr)
    assert not _has_sidecars(ovr)


def test_ingest_lifespan_holds_inventory_and_existing_shards(make_env) -> None:
    env = make_env()
    day = utc_day(int(env.clock[0]))
    ensure_shard(env.settings.data_dir, day)
    assert keeper.ACTIVE is not None
    assert env.settings.inventory_path in keeper.ACTIVE.held()
    env.client.__exit__(None, None, None)
    env.client.__enter__()  # restart: lifespan reopens keepers for shards already on disk
    assert env.settings.data_dir / shard_name(day) in keeper.ACTIVE.held()


def test_ingest_holds_a_shard_it_creates_and_releases_it_on_purge(make_env, tmp_path) -> None:
    env = make_env()
    old = utc_day(int(env.clock[0]) - 3 * 86400)
    path = ensure_shard(env.settings.data_dir, old)
    assert keeper.ACTIVE is not None
    assert keeper.ACTIVE.hold(path)
    removed = retention.purge_shards(env.settings.data_dir, env.clock[0], 1)
    assert path.name in removed
    assert path not in keeper.ACTIVE.held()
    assert not path.exists()


def test_pipeline_loop_holds_inventory_while_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inv = tmp_path / "inventory.db"
    open_inventory(inv).close()
    seen: list[bool] = []

    def fake_run_once(config) -> None:
        seen.append(_has_sidecars(inv))

    def stop(_: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline_cli, "run_once", fake_run_once)
    monkeypatch.setattr(time, "sleep", stop)
    assert pipeline_cli.main(["run", "--loop", "5"]) == 0
    assert seen == [True]
    assert not _has_sidecars(inv)  # released on exit


def test_pipeline_once_does_not_hold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inv = tmp_path / "inventory.db"
    open_inventory(inv).close()
    seen: list[bool] = []
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline_cli, "run_once", lambda c: seen.append(_has_sidecars(inv)))
    assert pipeline_cli.main(["run", "--once"]) == 0
    assert seen == [False]


def test_pipeline_loop_touches_the_health_file_only_after_a_good_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    health = tmp_path / "ok"
    calls: list[int] = []

    def flaky_run_once(config) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise sqlite3.OperationalError("boom")

    def after_tick(_: float) -> None:
        if len(calls) == 1:
            assert not health.exists()  # a failed pass is not a heartbeat
        else:
            raise KeyboardInterrupt

    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VIGIE_HEALTH_FILE", str(health))
    monkeypatch.setattr(pipeline_cli, "run_once", flaky_run_once)
    monkeypatch.setattr(time, "sleep", after_tick)
    assert pipeline_cli.main(["run", "--loop", "5"]) == 0
    assert health.exists()


def test_a_shard_created_by_a_batch_is_held_with_live_sidecars(make_env) -> None:
    env = make_env()
    assert keeper.ACTIVE is not None
    before = set(keeper.ACTIVE.held())
    assert env.post(make_batch(seq=1)).status_code == 200
    shards = [p for p in keeper.ACTIVE.held() if p not in before]
    assert shards and all(p.name.startswith("raw-") for p in shards)
    assert all(_has_sidecars(p) for p in shards)  # what the pipeline's read-only mount needs
