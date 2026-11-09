from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides
from vigie_ingest.db import INVENTORY_MIGRATIONS, open_inventory
from vigie_pipeline import backup
from vigie_pipeline.backup_cli import main
from vigie_pipeline.schema import apply_pipeline_migrations

SRC = str(Path(backup.__file__).resolve().parents[1])


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


def _patch_header(path: Path, b18: int, b19: int) -> None:
    raw = bytearray(path.read_bytes())
    raw[18], raw[19] = b18, b19
    path.write_bytes(bytes(raw))


# --- A: bounded memory ---

_MEASURE = """
import os, resource, sys
sys.path.insert(0, {src!r})
from pathlib import Path
from vigie_pipeline import backup
mode, work = sys.argv[1], Path(sys.argv[2])
dest = work / "dest"
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
if mode == "backup":
    backup.backup(dest, inventory=None, overrides=work / "overrides.db")
else:
    backup.verify(dest)
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print((after - before) * 1024)
"""


def _measure(mode: str, work: Path) -> tuple[float, int]:
    out = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", _MEASURE.format(src=SRC), mode, str(work)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert out.returncode == 0, out.stderr[-300:]
    return float(out.stdout.strip()), (work / "overrides.db").stat().st_size


def test_peak_memory_is_a_small_multiple_of_the_database(tmp_path: Path) -> None:
    work = tmp_path / "w"
    work.mkdir()
    (work / "dest").mkdir(mode=0o700)
    conn = open_overrides(work / "overrides.db")
    conn.execute("CREATE TABLE pad (b BLOB)")
    conn.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 32000) "
        "INSERT INTO pad SELECT randomblob(1000) FROM n"
    )
    conn.close()
    grown, size = _measure("backup", work)
    assert size > 30 * 1024 * 1024
    # Measured: backup about 2.7x (the in-memory copy plus serialize()'s buffer and bytes object),
    # verify about 1.6x. MAX_DB_BYTES (128 MiB) x 3 + interpreter stays under the 512 MiB limit.
    assert grown < 3.0 * size, f"backup peak {grown / size:.2f}x the database"
    grown, _ = _measure("verify", work)
    assert grown < 2.0 * size, f"verify peak {grown / size:.2f}x the database"


def test_cap_is_well_under_the_container_limit() -> None:
    assert backup.MAX_DB_BYTES <= 128 * 1024 * 1024


def test_source_that_grows_after_the_size_check_is_refused_by_serialized_length(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = sqlite3.connect(sources[1])
    size = backup._source_size(conn)
    conn.close()
    monkeypatch.setattr(backup, "MAX_DB_BYTES", size * 4)
    monkeypatch.setattr(backup, "_store", lambda *a: pytest.fail("must refuse before writing"))
    real = backup._copy_db

    def grow(src: sqlite3.Connection, dst: sqlite3.Connection) -> None:
        real(src, dst)
        dst.execute("CREATE TABLE g (b BLOB)")
        dst.execute("INSERT INTO g VALUES (zeroblob(?))", (size * 8,))
        dst.commit()

    monkeypatch.setattr(backup, "_copy_db", grow)
    with pytest.raises(backup.BackupError, match="host-level backup"):
        backup.backup(dest, inventory=None, overrides=sources[1])
    assert list(dest.iterdir()) == []


def test_oversized_source_message_points_to_host_level_backup(
    sources, dest: Path, monkeypatch
) -> None:
    monkeypatch.setattr(backup, "MAX_DB_BYTES", 1024)
    monkeypatch.setattr(backup, "_copy_db", lambda *a: pytest.fail("must refuse before copying"))
    with pytest.raises(backup.BackupError, match="use a host-level backup"):
        backup.backup(dest, inventory=sources[0], overrides=None)


def test_readback_hashes_in_chunks_not_whole_file(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup, "_CHUNK", 4096)
    seen: list[int] = []
    real = os.read

    def spy(fd: int, n: int) -> bytes:
        seen.append(n)
        return real(fd, n)

    monkeypatch.setattr(os, "read", spy)
    backup.backup(dest, inventory=sources[0], overrides=None)
    assert seen and max(seen) <= 4096


# --- B: hostile images ---


def _fresh_copy(sources, dest: Path) -> Path:
    backup.backup(dest, inventory=None, overrides=sources[1])
    (dest / "manifest.json").unlink()
    return dest / "overrides.db"


def test_verify_rejects_pipeline_schema_that_is_a_view(dest: Path) -> None:
    path = dest / "inventory.db"
    c = sqlite3.connect(path)
    c.execute(
        "CREATE VIEW pipeline_schema AS WITH RECURSIVE r(n) AS "
        "(SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT max(n) AS version FROM r"
    )
    c.execute(f"PRAGMA user_version={len(INVENTORY_MIGRATIONS)}")
    c.commit()
    c.close()
    path.chmod(0o600)
    t0 = time.monotonic()
    with pytest.raises(backup.VerifyError, match="pipeline_schema"):
        backup.verify(dest, require_manifest=False)
    assert time.monotonic() - t0 < 5
    assert main(["verify", str(dest), "--no-manifest"]) == 1


def test_verify_rejects_expression_index_that_allocates_huge_values(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup, "VALUE_LIMIT_BYTES", 1 << 20)
    p = _fresh_copy(sources, dest)
    _sql(p, "CREATE TABLE z (x)")
    _sql(p, "INSERT INTO z VALUES (1)")
    _sql(p, "CREATE INDEX zi ON z (zeroblob(4000000))")
    t0 = time.monotonic()
    with pytest.raises(backup.VerifyError):
        backup.verify(dest, require_manifest=False)
    assert time.monotonic() - t0 < 5


def test_legitimate_large_value_still_verifies(sources, dest: Path) -> None:
    p = _fresh_copy(sources, dest)
    _sql(p, "CREATE TABLE big (b BLOB)")
    _sql(p, "INSERT INTO big VALUES (zeroblob(2000000))")
    assert backup.verify(dest, require_manifest=False)[0]["status"] == "ok"


def test_hardened_connection_budget_defensive_and_untrusted_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(backup, "CHECK_BUDGET_S", 0.3)
    conn = sqlite3.connect(":memory:")
    hit = backup._harden(conn)
    assert conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
    conn.execute("CREATE TABLE t (x)")
    with pytest.raises(sqlite3.Error):
        conn.execute("PRAGMA writable_schema=ON")
        conn.execute("UPDATE sqlite_master SET sql = sql")
    t0 = time.monotonic()
    with pytest.raises(sqlite3.OperationalError):
        conn.execute(
            "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT max(n) FROM r"
        ).fetchall()
    assert time.monotonic() - t0 < 5 and hit == [True]
    conn.close()


# --- C/D: WAL leftovers and header ---


def test_verify_refuses_a_copy_that_needs_a_wal_even_with_user_version_in_it(
    sources, dest: Path
) -> None:
    p = _fresh_copy(sources, dest)
    c = sqlite3.connect(p)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA user_version=999")  # lives in the -wal while the connection is open
    c.commit()
    try:
        with pytest.raises(backup.VerifyError):
            backup.verify(dest, require_manifest=False)
        assert main(["verify", str(dest), "--no-manifest"]) == 1
    finally:
        c.close()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_verify_refuses_leftover_sidecars_with_and_without_manifest(
    sources, dest: Path, suffix: str
) -> None:
    backup.backup(dest, inventory=None, overrides=sources[1])
    (dest / f"overrides.db{suffix}").write_bytes(b"")
    for kw in ({}, {"require_manifest": False}):
        with pytest.raises(backup.VerifyError, match=suffix):
            backup.verify(dest, **kw)


@pytest.mark.parametrize("pair", [(0xFF, 0xFF), (2, 2), (0, 0), (1, 2), (2, 1)])
def test_verify_requires_exactly_the_rollback_header(sources, dest: Path, pair) -> None:
    p = _fresh_copy(sources, dest)
    _patch_header(p, *pair)
    with pytest.raises(backup.VerifyError, match="header"):
        backup.verify(dest, require_manifest=False)


def test_verify_rejects_truncated_header(dest: Path) -> None:
    (dest / "overrides.db").write_bytes(b"SQLite format 3\x00" + b"\x01" * 20)
    with pytest.raises(backup.VerifyError):
        backup.verify(dest, require_manifest=False)


# --- E: sticky ancestor owner ---


def _fake_lstat(monkeypatch: pytest.MonkeyPatch, target: Path, uid: int) -> None:
    real = os.lstat

    def lstat(path, *a, **k):
        st = real(path, *a, **k)
        if Path(path) == target:
            return os.stat_result(
                (stat.S_IFDIR | 0o1777, st.st_ino, st.st_dev, 2, uid, 0, 0, 0, 0, 0)
            )
        return st

    monkeypatch.setattr(os, "lstat", lstat)


def test_sticky_ancestor_owned_by_a_stranger_is_refused(
    sources, tmp_path: Path, dest: Path, monkeypatch
) -> None:
    _fake_lstat(monkeypatch, tmp_path, 4242)
    with pytest.raises(backup.BackupError, match="owned by another"):
        backup.backup(dest, inventory=sources[0], overrides=None)


@pytest.mark.parametrize("who", ["root", "me", "rootfs"])
def test_sticky_ancestor_owned_by_a_trusted_user_is_allowed(
    sources, tmp_path: Path, dest: Path, monkeypatch, who: str
) -> None:
    uid = {"root": 0, "me": os.geteuid(), "rootfs": os.stat("/").st_uid}[who]
    _fake_lstat(monkeypatch, tmp_path, uid)
    backup.backup(dest, inventory=sources[0], overrides=None)


# --- F: best-effort cleanup ---


def test_cleanup_failure_does_not_mask_the_error_and_continues(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_same = backup._same_dir
    calls = []

    def same_dir(*a):
        calls.append(1)
        return real_same(*a) if len(calls) == 1 else False  # only the final re-check fails

    monkeypatch.setattr(backup, "_same_dir", same_dir)
    real = os.unlink

    def unlink(name, *a, **k):
        if name == "inventory.db":
            raise PermissionError(f"nope {dest}")
        return real(name, *a, **k)

    monkeypatch.setattr(os, "unlink", unlink)
    with pytest.raises(backup.BackupError, match="destination changed") as exc:
        backup.backup(dest, inventory=sources[0], overrides=sources[1])
    notes = " ".join(exc.value.__notes__)
    assert "inventory.db" in notes and str(dest) not in notes
    assert sorted(p.name for p in dest.iterdir()) == ["inventory.db"]  # the rest was removed


# --- G: small hardening ---


def test_deeply_nested_manifest_is_a_clean_verify_error(sources, dest: Path) -> None:
    backup.backup(dest, inventory=None, overrides=sources[1])
    nest = 100_000
    (dest / "manifest.json").write_text('{"files": ' + "[" * nest + "]" * nest + "}")
    with pytest.raises(backup.VerifyError, match="malformed"):
        backup.verify(dest)
    assert main(["verify", str(dest)]) == 1


def test_ctrl_c_message_only_claims_cleanup_for_backup(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    def interrupt(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(backup, "verify", interrupt)
    assert main(["verify", str(dest)]) == 130
    assert "partial files" not in capsys.readouterr().err
    monkeypatch.setattr(backup, "backup", interrupt)
    assert main(["backup", "--dest", str(dest), "--inventory", str(sources[0])]) == 130
    assert "partial files were removed" in capsys.readouterr().err


def test_fifo_or_symlink_source_is_refused_without_blocking(sources, dest: Path, tmp_path) -> None:
    fifo = tmp_path / "fifo.db"
    os.mkfifo(fifo)
    with pytest.raises(backup.BackupError, match="regular"):
        backup.backup(dest, inventory=fifo, overrides=None)
    link = tmp_path / "link.db"
    link.symlink_to(sources[1])
    with pytest.raises(backup.BackupError):
        backup.backup(dest, inventory=None, overrides=link)
    assert list(dest.iterdir()) == []


# --- H: the fd checks themselves ---


def _dir_fd(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY)


def test_open_regular_checks_owner(dest: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (dest / "f").write_bytes(b"x")
    dfd = _dir_fd(dest)
    try:
        monkeypatch.setattr(os, "geteuid", lambda: os.stat(dest).st_uid + 1)
        with pytest.raises(backup.VerifyError, match="not owned"):
            backup._open_regular(dfd, "f", backup.VerifyError)
    finally:
        os.close(dfd)


def test_open_regular_rechecks_the_inode_after_open(
    dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (dest / "f").write_bytes(b"x")
    dfd = _dir_fd(dest)
    real = os.fstat

    def fstat(fd):
        st = real(fd)
        if stat.S_ISREG(st.st_mode):
            return os.stat_result((st.st_mode, st.st_ino + 1, *tuple(st)[2:10]))
        return st

    try:
        monkeypatch.setattr(os, "fstat", fstat)
        with pytest.raises(backup.VerifyError, match="changed"):
            backup._open_regular(dfd, "f", backup.VerifyError)
    finally:
        os.close(dfd)


def test_verify_refuses_a_copy_above_the_memory_cap(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    monkeypatch.setattr(backup, "MAX_DB_BYTES", 1024)
    with pytest.raises(backup.VerifyError, match="larger"):
        backup.verify(dest)


def test_expected_versions_are_unchanged() -> None:
    assert backup._EXPECTED == {
        "inventory.db": len(INVENTORY_MIGRATIONS),
        "overrides.db": len(OVERRIDES_MIGRATIONS),
    }


def test_budget_hit_is_reported_as_a_budget_error_not_corruption() -> None:
    conn = sqlite3.connect(":memory:")
    conn.close()  # any statement now raises a sqlite3.Error
    with pytest.raises(backup.VerifyError, match="budget"):
        backup._check_conn(conn, "overrides.db", [True])
    with pytest.raises(backup.VerifyError, match="unreadable or corrupt"):
        backup._check_conn(conn, "overrides.db", [False])


def test_file_that_grows_while_being_read_is_refused(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup.backup(dest, inventory=sources[0], overrides=None)
    real = os.fstat

    def fstat(fd):
        st = real(fd)
        if stat.S_ISREG(st.st_mode):  # claim the file is one byte shorter than it is
            return os.stat_result((*tuple(st)[:6], st.st_size - 1, *tuple(st)[7:10]))
        return st

    monkeypatch.setattr(os, "fstat", fstat)
    dfd = _dir_fd(dest)
    try:
        with pytest.raises(backup.VerifyError, match="changed"):
            backup._read_image(dfd, "inventory.db", backup.MAX_DB_BYTES, backup.VerifyError)
    finally:
        os.close(dfd)


def _failing_cleanup(dest: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = os.unlink

    def unlink(name, *a, **k):
        if name == "inventory.db":
            raise PermissionError(f"nope {dest}")
        return real(name, *a, **k)

    monkeypatch.setattr(os, "unlink", unlink)


def test_cleanup_failure_after_an_oserror_is_reported_on_the_wrapped_error(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(fd: int, image: bytes):
        raise OSError(5, f"I/O error {dest}")

    monkeypatch.setattr(backup, "_write_image", boom)
    _failing_cleanup(dest, monkeypatch)
    with pytest.raises(backup.BackupError, match="backup failed") as exc:
        backup.backup(dest, inventory=sources[0], overrides=None)
    assert "inventory.db" in " ".join(exc.value.__notes__)
    assert "partial files were removed" not in str(exc.value)  # not claimed when cleanup failed


def test_cli_reports_a_failed_cleanup_without_paths(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(backup, "_write_image", lambda *a: (_ for _ in ()).throw(OSError(5, "x")))
    _failing_cleanup(dest, monkeypatch)
    assert main(["backup", "--dest", str(dest), "--inventory", str(sources[0])]) == 1
    err = capsys.readouterr().err
    assert "could not remove: inventory.db" in err and str(dest) not in err
