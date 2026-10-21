from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vigie_ingest import admin, store
from vigie_ingest.config import Settings
from vigie_ingest.db import (
    INVENTORY_MIGRATIONS,
    connect,
    ensure_shard,
    iso_utc,
    migrate,
    open_inventory,
)
from vigie_ingest.ratelimit import RateLimiter
from vigie_ingest.retention import purge_batches, purge_shards, run_maintenance

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC).timestamp()


def tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows}


# ---- migrations --------------------------------------------------------------------------


def test_inventory_schema_has_prp_tables(tmp_path: Path) -> None:
    conn = open_inventory(tmp_path / "inventory.db")
    assert {"devices", "observations", "collectors", "batches"} <= tables(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(collectors)")}
    assert {"id", "key_id", "last_seq", "boot_id", "revoked", "parse_failures"} <= cols
    assert conn.execute("PRAGMA user_version").fetchone()[0] == len(INVENTORY_MIGRATIONS)


def test_migrations_are_idempotent_and_incremental(tmp_path: Path) -> None:
    conn = connect(tmp_path / "x.db")
    assert migrate(conn, INVENTORY_MIGRATIONS[:1]) == 1
    conn.execute("INSERT INTO collectors (id, key_id) VALUES ('c','k')")
    assert migrate(conn, INVENTORY_MIGRATIONS) == 2
    assert migrate(conn, INVENTORY_MIGRATIONS) == 2
    assert conn.execute("SELECT parse_failures FROM collectors").fetchone()[0] == 0


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    conn = connect(tmp_path / "x.db")
    conn.execute("PRAGMA user_version=99")
    with pytest.raises(RuntimeError):
        migrate(conn, INVENTORY_MIGRATIONS)


def test_failed_migration_rolls_back(tmp_path: Path) -> None:
    conn = connect(tmp_path / "x.db")
    with pytest.raises(sqlite3.OperationalError):
        migrate(conn, ("CREATE TABLE a (x);\nCREATE TABLE a (x);",))
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    assert "a" not in tables(conn)


def test_devices_cannot_be_deleted(tmp_path: Path) -> None:
    conn = open_inventory(tmp_path / "inventory.db")
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM devices WHERE id='d'")


def test_shard_schema_and_pragmas(tmp_path: Path) -> None:
    path = ensure_shard(tmp_path, NOW_DAY := datetime(2026, 10, 20).date())
    assert path.name == "raw-20261020.db" and NOW_DAY
    conn = connect(path)
    assert {"raw_dns", "raw_flow"} <= tables(conn)
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    flow_cols = {r[1] for r in conn.execute("PRAGMA table_info(raw_flow)")}
    assert "collector_id" in flow_cols


# ---- retention ---------------------------------------------------------------------------


def make_shard(directory: Path, day: datetime, sidecars: bool = True) -> Path:
    path = directory / f"raw-{day:%Y%m%d}.db"
    path.write_bytes(b"x")
    if sidecars:
        Path(f"{path}-wal").write_bytes(b"w")
        Path(f"{path}-shm").write_bytes(b"s")
    return path


def test_purge_shards_default_retention(tmp_path: Path) -> None:
    today = datetime.fromtimestamp(NOW, tz=UTC)
    old = make_shard(tmp_path, today - timedelta(days=8))
    boundary = make_shard(tmp_path, today - timedelta(days=7))
    recent = make_shard(tmp_path, today - timedelta(days=1))
    current = make_shard(tmp_path, today)
    decoys = [tmp_path / n for n in ("raw-2026102.db", "raw-20261001.db.bak", "notes.txt",
                                     "raw-20269999.db", "inventory.db")]  # fmt: skip
    for d in decoys:
        d.write_bytes(b"keep")
    removed = purge_shards(tmp_path, NOW, 7)
    assert removed == [old.name]
    assert not old.exists() and not Path(f"{old}-wal").exists() and not Path(f"{old}-shm").exists()
    assert boundary.exists() and recent.exists() and current.exists()
    assert all(d.exists() for d in decoys)


def test_purge_shards_custom_retention_and_hard_max(tmp_path: Path) -> None:
    today = datetime.fromtimestamp(NOW, tz=UTC)
    d10 = make_shard(tmp_path, today - timedelta(days=10), sidecars=False)
    d31 = make_shard(tmp_path, today - timedelta(days=31), sidecars=False)
    assert purge_shards(tmp_path, NOW, 30) == [d31.name]
    assert d10.exists()
    with pytest.raises(ValueError):
        purge_shards(tmp_path, NOW, 31)
    with pytest.raises(ValueError):
        purge_shards(tmp_path, NOW, 0)
    assert d10.exists()


def test_purge_shards_ignores_symlinks_and_directories(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_bytes(b"precious")
    link = tmp_path / "raw-20200101.db"
    link.symlink_to(target)
    (tmp_path / "raw-20200102.db").mkdir()
    assert purge_shards(tmp_path, NOW, 7) == []
    assert target.exists() and link.is_symlink()


def test_settings_enforce_retention_bounds(tmp_path: Path) -> None:
    Settings(tmp_path, tmp_path, shard_retention_days=30)
    for bad in (0, 31):
        with pytest.raises(ValueError):
            Settings(tmp_path, tmp_path, shard_retention_days=bad)
    with pytest.raises(ValueError):
        Settings(tmp_path, tmp_path, max_body_bytes=0)


def test_settings_from_env(tmp_path: Path) -> None:
    s = Settings.from_env(
        {
            "VIGIE_DATA_DIR": str(tmp_path),
            "VIGIE_SECRETS_DIR": "/s",
            "VIGIE_SHARD_RETENTION_DAYS": "3",
        }
    )
    assert (s.data_dir, s.shard_retention_days) == (tmp_path, 3)
    assert Settings.from_env({}).shard_retention_days == 7


def test_purge_batches_older_than_seven_days(tmp_path: Path) -> None:
    conn = open_inventory(tmp_path / "inventory.db")
    for bid, age_days in (("old", 8), ("edge", 6), ("new", 0)):
        conn.execute(
            "INSERT INTO batches VALUES (?,?,?)", (bid, "c", iso_utc(NOW - age_days * 86400))
        )
    assert purge_batches(conn, NOW, 7) == 1
    left = {r[0] for r in conn.execute("SELECT batch_id FROM batches")}
    assert left == {"edge", "new"}


def test_run_maintenance(tmp_path: Path) -> None:
    settings = Settings(tmp_path, tmp_path)
    conn = open_inventory(settings.inventory_path)
    conn.execute("INSERT INTO batches VALUES ('b','c',?)", (iso_utc(NOW - 9 * 86400),))
    conn.close()
    old = make_shard(tmp_path, datetime.fromtimestamp(NOW, tz=UTC) - timedelta(days=9))
    removed, purged = run_maintenance(settings, NOW)
    assert removed == [old.name] and purged == 1


# ---- rate limiter / admin ----------------------------------------------------------------


def test_rate_limiter_is_per_source_and_slides() -> None:
    t = [0.0]
    limiter = RateLimiter(2, 10, lambda: t[0])
    assert limiter.allow("a") and limiter.allow("a") and not limiter.allow("a")
    assert limiter.allow("b")
    t[0] = 10.5
    assert limiter.allow("a")


def test_rate_limiter_bounds_tracked_sources() -> None:
    t = [0.0]
    limiter = RateLimiter(1, 10, lambda: t[0])
    for i in range(4096):
        limiter.allow(f"ip{i}")
    t[0] = 100.0
    assert limiter.allow("fresh")
    assert len(limiter._hits) < 4096


def test_admin_provision_and_revoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path / "d"))
    assert admin.main(["provision", "rtr-9", "k9"]) == 0
    conn = open_inventory(tmp_path / "d" / "inventory.db")
    assert store.get_collector(conn, "rtr-9").key_id == "k9"  # type: ignore[union-attr]
    conn.close()
    assert admin.main(["revoke", "rtr-9"]) == 0
    assert admin.main(["revoke", "nobody"]) == 1
    conn = open_inventory(tmp_path / "d" / "inventory.db")
    assert store.get_collector(conn, "rtr-9").revoked  # type: ignore[union-attr]
    conn.close()
