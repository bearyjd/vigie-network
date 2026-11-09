from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path

import pytest

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides
from vigie_ingest.db import open_inventory
from vigie_pipeline import backup
from vigie_pipeline.backup_cli import main
from vigie_pipeline.schema import apply_pipeline_migrations


@pytest.fixture
def sources(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    inv = open_inventory(src / "inventory.db")
    apply_pipeline_migrations(inv)
    ov = open_overrides(src / "overrides.db")
    yield src / "inventory.db", src / "overrides.db"
    inv.close()
    ov.close()


@pytest.fixture
def dest(tmp_path: Path) -> Path:
    d = tmp_path / "dest"
    d.mkdir()
    d.chmod(0o700)
    return d


def _sql(path: Path, statement: str) -> None:
    c = sqlite3.connect(path)
    c.execute(statement)
    c.commit()
    c.close()


# --- 1: every write/stat/hash is anchored to the validated directory ---------------------------


@pytest.mark.parametrize("what", ["dest", "ancestor"])
def test_swapped_destination_fails_closed_and_writes_nothing_outside(
    sources, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, what: str
) -> None:
    parent = tmp_path / "a"
    parent.mkdir(mode=0o700)
    d = parent / "dest"
    d.mkdir(mode=0o700)
    evil_root = tmp_path / "evil"
    (evil_root / "dest").mkdir(parents=True, mode=0o700)
    real = backup._check_no_clobber

    def swap(dfd: int, names: list[str]) -> None:
        real(dfd, names)
        if what == "dest":
            d.rename(tmp_path / "moved")
            d.symlink_to(evil_root / "dest")
        else:
            parent.rename(tmp_path / "moved")
            parent.symlink_to(evil_root)

    monkeypatch.setattr(backup, "_check_no_clobber", swap)
    with pytest.raises(backup.BackupError):
        backup.backup(d, inventory=sources[0], overrides=sources[1])
    assert list((evil_root / "dest").iterdir()) == []
    moved = tmp_path / "moved"
    leftovers = list(moved.rglob("*"))
    assert [p for p in leftovers if p.is_file()] == []  # fail closed: copies were removed


@pytest.mark.parametrize("mode", [0o777, 0o775, 0o757])
def test_refuses_unsafe_ancestor(sources, tmp_path: Path, mode: int) -> None:
    parent = tmp_path / "open"
    parent.mkdir()
    parent.chmod(mode)
    d = parent / "dest"
    d.mkdir(mode=0o700)
    with pytest.raises(backup.BackupError, match="parent"):
        backup.backup(d, inventory=sources[0], overrides=None)
    assert list(d.iterdir()) == []


def test_sticky_caller_owned_ancestor_is_allowed(sources, tmp_path: Path) -> None:
    parent = tmp_path / "tmpish"
    parent.mkdir()
    parent.chmod(0o1777)
    d = parent / "dest"
    d.mkdir(mode=0o700)
    backup.backup(d, inventory=sources[0], overrides=None)


# --- 2: source ownership ------------------------------------------------------------------------


@pytest.mark.skipif(os.geteuid() == 0, reason="needs a source owned by someone else")
def test_refuses_source_owned_by_another_user(dest: Path) -> None:
    with pytest.raises(backup.BackupError, match="not owned"):
        backup.backup(dest, inventory=Path("/etc/passwd"), overrides=None)
    assert list(dest.iterdir()) == []


def test_verify_never_creates_sidecars(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=sources[1])
    backup.verify(dest)
    assert sorted(p.name for p in dest.iterdir()) == [
        "inventory.db",
        "manifest.json",
        "overrides.db",
    ]


# --- 3: backup validates every copy before writing the manifest --------------------------------


def test_empty_source_is_refused_and_leaves_nothing(
    dest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty.db"
    empty.touch()
    monkeypatch.setattr(backup, "_store", lambda *a: pytest.fail("must refuse before writing"))
    with pytest.raises(backup.BackupError, match="user_version"):
        backup.backup(dest, inventory=empty, overrides=None)
    assert list(dest.iterdir()) == []


def test_swapped_flags_are_refused_with_no_manifest(sources, dest: Path) -> None:
    inv, ov = sources
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=ov, overrides=inv)
    assert list(dest.iterdir()) == []


# --- 4: verify strictness ------------------------------------------------------------------------


def test_verify_requires_manifest_unless_told_otherwise(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=sources[1])
    (dest / "manifest.json").unlink()
    with pytest.raises(backup.VerifyError, match="missing"):
        backup.verify(dest)
    assert len(backup.verify(dest, require_manifest=False)) == 2


def test_verify_rejects_empty_or_partial_manifest(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=sources[1])
    (dest / "manifest.json").write_text(json.dumps({"files": []}))
    with pytest.raises(backup.VerifyError, match="exactly"):
        backup.verify(dest)


def test_verify_rejects_unlisted_database_file(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    shutil.copy(sources[1], dest / "overrides.db")  # never hash-checked before
    with pytest.raises(backup.VerifyError, match="exactly"):
        backup.verify(dest)


def test_verify_checks_every_manifest_entry_not_just_the_first(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=sources[1])
    _sql(dest / "overrides.db", "CREATE TABLE tamper (x)")  # the SECOND entry
    with pytest.raises(backup.VerifyError, match="sha256"):
        backup.verify(dest)


def test_verify_does_not_follow_symlink_to_a_device(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    (dest / "overrides.db").symlink_to("/dev/zero")
    with pytest.raises(backup.VerifyError):
        backup.verify(dest, require_manifest=False)


def test_verify_does_not_wait_on_a_fifo(dest: Path) -> None:
    os.mkfifo(dest / "overrides.db")
    with pytest.raises(backup.VerifyError, match="regular"):
        backup.verify(dest, require_manifest=False)


def test_verify_caps_manifest_size(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    pad = " " * (backup.MAX_MANIFEST_BYTES + 10)
    (dest / "manifest.json").write_text(json.dumps({"files": []}) + pad)
    with pytest.raises(backup.VerifyError, match="limit"):
        backup.verify(dest)


def test_verify_checks_directory_mode_and_owner(sources, dest: Path, monkeypatch) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    dest.chmod(0o770)
    with pytest.raises(backup.VerifyError, match="writable"):
        backup.verify(dest)
    dest.chmod(0o700)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(dest).st_uid + 1)
    with pytest.raises(backup.VerifyError):
        backup.verify(dest)


# --- 5: sidecar names are protected, only own files are removed -------------------------------


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_refuses_when_a_sidecar_name_exists(sources, dest: Path, suffix: str) -> None:
    (dest / f"overrides.db{suffix}").write_bytes(b"not yours")
    with pytest.raises(backup.BackupError, match="overwrite"):
        backup.backup(dest, inventory=sources[0], overrides=sources[1])
    assert [p.name for p in dest.iterdir()] == [f"overrides.db{suffix}"]
    assert (dest / f"overrides.db{suffix}").read_bytes() == b"not yours"


def test_cleanup_leaves_a_file_swapped_in_after_our_create(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = backup._store

    def store(dfd, name, data, created):
        real(dfd, name, data, created)
        (dest / name).unlink()
        (dest / name).write_bytes(b"someone else's")
        raise sqlite3.OperationalError("boom")

    monkeypatch.setattr(backup, "_store", store)
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=sources[0], overrides=None)
    assert (dest / "inventory.db").read_bytes() == b"someone else's"


# --- 6: former surviving mutants ------------------------------------------------------------------


def test_verify_rejects_user_version_below_expected(sources, dest: Path) -> None:
    backup.backup(dest, inventory=None, overrides=sources[1])
    _sql(dest / "overrides.db", f"PRAGMA user_version={len(OVERRIDES_MIGRATIONS) - 1}")
    with pytest.raises(backup.VerifyError, match="user_version"):
        backup.verify(dest, require_manifest=False)


def test_verify_and_backup_reject_mismatched_pipeline_schema(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    _sql(dest / "inventory.db", "UPDATE pipeline_schema SET version = version - 1")
    with pytest.raises(backup.VerifyError, match="pipeline_schema"):
        backup.verify(dest, require_manifest=False)
    other = dest.parent / "d2"
    other.mkdir(mode=0o700)
    _sql(
        sources[0],
        "DELETE FROM pipeline_schema WHERE version = (SELECT MAX(version) FROM pipeline_schema)",
    )
    with pytest.raises(backup.BackupError, match="pipeline_schema"):
        backup.backup(other, inventory=sources[0], overrides=None)


# --- 7: copy format, error text, durability, interrupts ----------------------------------------


def test_copy_is_a_rollback_journal_file_not_wal(sources, dest: Path) -> None:
    src_head = sources[1].read_bytes()[18:20]
    assert src_head == b"\x02\x02"  # the live source really is WAL
    backup.backup(dest, inventory=None, overrides=sources[1])
    assert (dest / "overrides.db").read_bytes()[18:20] == b"\x01\x01"


def test_failure_message_names_the_database_and_error_class_not_a_path(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(src, dst):
        raise sqlite3.OperationalError(f"disk I/O error at {dest}")

    monkeypatch.setattr(backup, "_copy_db", boom)
    with pytest.raises(backup.BackupError) as exc:
        backup.backup(dest, inventory=sources[0], overrides=None)
    text = str(exc.value)
    assert "inventory.db" in text and "OperationalError" in text
    assert str(dest) not in text and str(sources[0]) not in text


def test_copy_manifest_and_directory_are_fsynced(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kinds: list[str] = []
    real = os.fsync

    def spy(fd: int) -> None:
        kinds.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    backup.backup(dest, inventory=sources[0], overrides=None)
    assert kinds.count("file") >= 2 and kinds.count("dir") == 1


def test_oversized_source_is_refused(sources, dest: Path, monkeypatch) -> None:
    monkeypatch.setattr(backup, "MAX_DB_BYTES", 1024)
    monkeypatch.setattr(backup, "_store", lambda *a: pytest.fail("must refuse before writing"))
    with pytest.raises(backup.BackupError, match="larger"):
        backup.backup(dest, inventory=sources[0], overrides=None)
    assert list(dest.iterdir()) == []


def test_keyboard_interrupt_cleans_up_and_exits_nonzero_without_traceback(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    calls = {"n": 0}
    real = backup._copy_db

    def interrupt(src, dst):
        calls["n"] += 1
        real(src, dst)
        if calls["n"] == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(backup, "_copy_db", interrupt)
    args = ["backup", "--dest", str(dest), "--inventory", str(sources[0])]
    assert main([*args, "--overrides", str(sources[1])]) == 130
    assert list(dest.iterdir()) == []
    err = capsys.readouterr().err
    assert "Traceback" not in err and str(dest) not in err


def test_unexpected_error_exits_1_with_fixed_message(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    def boom(*a, **k):
        raise RuntimeError(f"secret {dest}")

    monkeypatch.setattr(backup, "_copy_db", boom)
    assert main(["backup", "--dest", str(dest), "--inventory", str(sources[0])]) == 1
    err = capsys.readouterr().err
    assert str(dest) not in err and "RuntimeError" in err and list(dest.iterdir()) == []


def test_cli_verify_no_manifest_flag(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    (dest / "manifest.json").unlink()
    assert main(["verify", str(dest)]) == 1
    assert main(["verify", str(dest), "--no-manifest"]) == 0


def test_verify_rejects_duplicate_manifest_entries(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    entry = json.loads((dest / "manifest.json").read_text())["files"][0]
    (dest / "manifest.json").write_text(json.dumps({"files": [entry, entry]}))
    with pytest.raises(backup.VerifyError, match="malformed"):
        backup.verify(dest)


def test_ancestor_owned_by_another_user_is_refused(dest: Path, monkeypatch) -> None:
    fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY)
    try:
        backup._check_ancestors(fd, dest, backup.BackupError)  # sane for the real user
        monkeypatch.setattr(os, "geteuid", lambda: os.stat(dest).st_uid + 1)
        with pytest.raises(backup.BackupError, match="owned by another"):
            backup._check_ancestors(fd, dest, backup.BackupError)
    finally:
        os.close(fd)


def test_copy_that_does_not_read_back_identical_is_refused(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = backup._write_all
    monkeypatch.setattr(backup, "_write_all", lambda fd, data: real(fd, data + b"\0" * 4096))
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=sources[0], overrides=None)
    assert list(dest.iterdir()) == []
