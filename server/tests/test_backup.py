from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import threading
from pathlib import Path

import pytest

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides
from vigie_ingest.db import INVENTORY_MIGRATIONS, open_inventory
from vigie_pipeline import backup
from vigie_pipeline.backup_cli import main
from vigie_pipeline.schema import PIPELINE_MIGRATIONS, apply_pipeline_migrations


@pytest.fixture
def sources(tmp_path: Path):
    """Real schema helpers; the connections stay open so the WAL files persist."""
    src = tmp_path / "src"
    src.mkdir()
    inv = open_inventory(src / "inventory.db")
    apply_pipeline_migrations(inv)
    ov = open_overrides(src / "overrides.db")
    inv.execute("CREATE TABLE IF NOT EXISTS probe (n INTEGER)")
    inv.execute("INSERT INTO probe VALUES (1)")
    yield src / "inventory.db", src / "overrides.db"
    inv.close()
    ov.close()


@pytest.fixture
def dest(tmp_path: Path) -> Path:
    d = tmp_path / "dest"
    d.mkdir()
    d.chmod(0o700)
    return d


def _digest(*paths: Path) -> list[str]:
    return [hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "-" for p in paths]


def _live_files(db: Path) -> list[Path]:
    return [db, db.with_name(db.name + "-wal")]


def test_backup_creates_valid_0600_copies_and_manifest(sources, dest: Path) -> None:
    inv, ov = sources
    manifest = backup.backup(dest, inventory=inv, overrides=ov)
    assert sorted(p.name for p in dest.iterdir()) == [
        "inventory.db",
        "manifest.json",
        "overrides.db",
    ]
    for p in dest.iterdir():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    c = sqlite3.connect(f"file:{dest / 'inventory.db'}?mode=ro", uri=True)
    assert c.execute("SELECT count(*) FROM probe").fetchone()[0] == 1
    c.close()
    on_disk = json.loads((dest / "manifest.json").read_text())
    assert on_disk == manifest
    entry = {e["name"]: e for e in manifest["files"]}
    assert entry["inventory.db"]["user_version"] == len(INVENTORY_MIGRATIONS)
    assert entry["overrides.db"]["user_version"] == len(OVERRIDES_MIGRATIONS)
    assert entry["overrides.db"]["sha256"] == _digest(dest / "overrides.db")[0]
    assert entry["overrides.db"]["size"] == (dest / "overrides.db").stat().st_size
    assert manifest["created_utc"].endswith("Z")
    assert str(dest.parent) not in (dest / "manifest.json").read_text()
    assert not list(dest.glob("*-wal")) and not list(dest.glob("*-shm"))


def test_umask_cannot_change_mode(sources, dest: Path) -> None:
    old = os.umask(0o277)  # strips owner bits from the create mode
    try:
        backup.backup(dest, inventory=sources[0], overrides=None)
    finally:
        os.umask(old)
    assert stat.S_IMODE((dest / "inventory.db").stat().st_mode) == 0o600


def test_source_is_untouched(sources, dest: Path) -> None:
    inv, ov = sources
    files = [*_live_files(inv), *_live_files(ov)]
    assert inv.with_name("inventory.db-wal").exists()
    before = _digest(*files)
    backup.backup(dest, inventory=inv, overrides=ov)
    assert _digest(*files) == before


def test_source_connection_is_read_only(sources, monkeypatch: pytest.MonkeyPatch, dest) -> None:
    seen: list[sqlite3.Connection] = []
    real = backup._copy_db

    def spy(src: sqlite3.Connection, dst: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.OperationalError):
            src.execute("CREATE TABLE evil (x)")
        seen.append(src)
        real(src, dst)

    monkeypatch.setattr(backup, "_copy_db", spy)
    backup.backup(dest, inventory=sources[0], overrides=None)
    assert seen


def test_backup_under_concurrent_wal_writes_is_consistent(sources, dest: Path) -> None:
    inv, _ = sources
    stop = threading.Event()
    errors: list[Exception] = []

    def writer() -> None:
        w = sqlite3.connect(inv, timeout=10, isolation_level=None)
        try:
            while not stop.is_set():
                w.execute("BEGIN IMMEDIATE")
                w.execute("INSERT INTO probe VALUES (2)")
                w.execute("INSERT INTO probe VALUES (2)")  # pairs: odd count = torn snapshot
                w.execute("COMMIT")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            w.close()

    t = threading.Thread(target=writer)
    t.start()
    try:
        counts = []
        for i in range(5):
            d = dest / f"b{i}"
            d.mkdir(mode=0o700)
            backup.backup(d, inventory=inv, overrides=None)
            c = sqlite3.connect(f"file:{d / 'inventory.db'}?mode=ro", uri=True)
            assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            counts.append(c.execute("SELECT count(*) FROM probe").fetchone()[0])
            c.close()
    finally:
        stop.set()
        t.join()
    assert not errors
    assert all(n >= 1 and (n - 1) % 2 == 0 for n in counts)
    assert counts == sorted(counts)


def test_refuses_symlinked_dest(sources, tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(backup.BackupError):
        backup.backup(link, inventory=sources[0], overrides=None)
    assert list(real.iterdir()) == []


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o777, 0o720])
def test_refuses_group_or_world_writable_dest(sources, dest: Path, mode: int) -> None:
    dest.chmod(mode)
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=sources[0], overrides=None)
    assert list(dest.iterdir()) == []


def test_refuses_dest_not_owned_by_caller(sources, dest: Path, monkeypatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(dest).st_uid + 1)
    with pytest.raises(backup.BackupError, match="not owned"):
        backup.backup(dest, inventory=sources[0], overrides=None)


def test_refuses_missing_or_file_dest(sources, tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_text("x")
    for bad in (tmp_path / "nope", f):
        with pytest.raises(backup.BackupError):
            backup.backup(bad, inventory=sources[0], overrides=None)


def test_refuses_to_overwrite_and_leaves_existing_intact(sources, dest: Path) -> None:
    (dest / "overrides.db").write_bytes(b"precious")
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=sources[0], overrides=sources[1])
    assert (dest / "overrides.db").read_bytes() == b"precious"
    assert not (dest / "inventory.db").exists()  # checked before anything is written
    (dest / "overrides.db").unlink()
    backup.backup(dest, inventory=sources[0], overrides=sources[1])
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=sources[0], overrides=sources[1])


def test_exclusive_create_even_if_precheck_is_skipped(sources, dest: Path, monkeypatch) -> None:
    monkeypatch.setattr(backup, "_check_no_clobber", lambda *a, **k: None)
    (dest / "inventory.db").write_bytes(b"precious")
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=sources[0], overrides=None)
    assert (dest / "inventory.db").read_bytes() == b"precious"


def test_refuses_dangling_symlink_at_target_name(sources, dest: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    (dest / "inventory.db").symlink_to(victim)
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=sources[0], overrides=None)
    assert not victim.exists()


def test_partial_files_removed_when_backup_fails_midway(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = backup._copy_db
    calls = {"n": 0}

    def flaky(src: sqlite3.Connection, dst: sqlite3.Connection) -> None:
        calls["n"] += 1
        real(src, dst)
        if calls["n"] == 2:
            dst.execute("CREATE TABLE half (x)")  # partial work on the second file
            raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(backup, "_copy_db", flaky)
    with pytest.raises(backup.BackupError) as exc:
        backup.backup(dest, inventory=sources[0], overrides=sources[1])
    assert list(dest.iterdir()) == []
    assert str(dest) not in str(exc.value)
    assert "overrides.db" in str(exc.value) and "OperationalError" in str(exc.value)


def test_missing_source_fails_closed_and_does_not_create_it(sources, dest: Path, tmp_path) -> None:
    ghost = tmp_path / "ghost.db"
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=ghost, overrides=None)
    assert not ghost.exists() and list(dest.iterdir()) == []


def test_requires_at_least_one_source(dest: Path) -> None:
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=None, overrides=None)


def test_verify_accepts_fresh_backup_and_restores_onto_scratch(sources, dest, tmp_path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=sources[1])
    results = backup.verify(dest)
    assert {r["name"] for r in results} == {"inventory.db", "overrides.db"}
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    for name in ("inventory.db", "overrides.db"):
        (scratch / name).write_bytes((dest / name).read_bytes())
    (scratch / "manifest.json").write_bytes((dest / "manifest.json").read_bytes())
    # The restored copy opens with the repo's own openers and is writable and migrated.
    open_overrides(scratch / "overrides.db").close()
    inv = open_inventory(scratch / "inventory.db")
    assert apply_pipeline_migrations(inv) == len(PIPELINE_MIGRATIONS)
    assert inv.execute("SELECT count(*) FROM probe").fetchone()[0] == 1
    assert inv.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    inv.close()
    # Opened for write by the repo's openers since, so it no longer matches the manifest.
    results = backup.verify(scratch, require_manifest=False)
    assert [r["name"] for r in results] == ["inventory.db", "overrides.db"]


def test_verify_rejects_corrupted_copy(sources, dest: Path) -> None:
    c = sqlite3.connect(sources[1])
    c.execute("CREATE TABLE IF NOT EXISTS pad (x TEXT)")
    c.executemany("INSERT INTO pad VALUES (?)", [("x" * 500,)] * 400)
    c.commit()
    c.close()
    backup.backup(dest, inventory=None, overrides=sources[1])
    p = dest / "overrides.db"
    raw = bytearray(p.read_bytes())
    for off in range(4096, len(raw), 4096):
        raw[off : off + 64] = b"\xff" * 64
    p.write_bytes(bytes(raw))
    with pytest.raises(backup.VerifyError):
        backup.verify(dest, require_manifest=False)  # the integrity check itself, not the sha256


def test_verify_rejects_garbage_and_truncated_files(dest: Path) -> None:
    (dest / "overrides.db").write_bytes(b"not a database at all" * 100)
    with pytest.raises(backup.VerifyError):
        backup.verify(dest, require_manifest=False)


def test_verify_rejects_wrong_user_version(sources, dest: Path) -> None:
    backup.backup(dest, inventory=None, overrides=sources[1])
    c = sqlite3.connect(dest / "overrides.db")
    c.execute(f"PRAGMA user_version={len(OVERRIDES_MIGRATIONS) + 1}")
    c.commit()
    c.close()
    with pytest.raises(backup.VerifyError, match="user_version"):
        backup.verify(dest, require_manifest=False)


def test_verify_rejects_sha_mismatch_against_manifest(sources, dest: Path) -> None:
    backup.backup(dest, inventory=None, overrides=sources[1])
    c = sqlite3.connect(dest / "overrides.db")
    c.execute("CREATE TABLE tamper (x)")  # still a valid db, same user_version
    c.commit()
    c.close()
    with pytest.raises(backup.VerifyError, match="sha256"):
        backup.verify(dest)


def test_verify_is_read_only_and_needs_something_to_check(sources, dest: Path) -> None:
    with pytest.raises(backup.VerifyError):
        backup.verify(dest)
    backup.backup(dest, inventory=sources[0], overrides=sources[1])
    files = sorted(dest.iterdir())
    before = _digest(*files)
    backup.verify(dest)
    assert _digest(*files) == before and sorted(dest.iterdir()) == files


def test_cli_roundtrip_and_exit_codes(sources, dest: Path, capsys) -> None:
    inv, ov = sources
    args = ["backup", "--dest", str(dest), "--inventory", str(inv), "--overrides", str(ov)]
    assert main(args) == 0
    assert main(args) == 1  # refuses to overwrite
    err = capsys.readouterr().err
    assert str(dest) not in err
    assert main(["verify", str(dest)]) == 0
    (dest / "overrides.db").write_bytes(b"x" * 8192)
    assert main(["verify", str(dest)]) == 1
    with pytest.raises(SystemExit) as exc:
        main(["backup", "--dest", str(dest)])
    assert exc.value.code == 2
