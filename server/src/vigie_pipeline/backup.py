"""Consistent SQLite backup and restore-verify for inventory.db and overrides.db.

Sources are opened read-only (mode=ro URI) and copied with `Connection.backup` into an in-memory
database, validated, serialized and written through a file descriptor created with
O_CREAT|O_EXCL|O_NOFOLLOW (0600) in a directory fd that was validated once: SQLite never touches
the destination by path, so a swapped destination or ancestor cannot redirect the copy. The
destination must be a real directory owned by the caller, not group/world-writable, with no
ancestor writable by others (a sticky root/caller-owned one such as /tmp is fine). Verification
reads the copy through an fd and deserializes it in memory: nothing on disk is opened by SQLite, so
no -wal/-shm is ever created. Any failure removes what this run created. Messages name databases
by logical name only, never by path.

The pipeline tables live inside inventory.db (`pipeline_schema`); there is no separate pipeline DB.
Run as the user that owns the live databases (the service user, or inside the container): the
read-only open of a WAL source creates -wal/-shm beside it, so a different owner is refused.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any
from urllib.parse import quote

from vigie_api.schema import OVERRIDES_MIGRATIONS
from vigie_ingest.db import INVENTORY_MIGRATIONS
from vigie_pipeline.schema import PIPELINE_MIGRATIONS

INVENTORY = "inventory.db"
OVERRIDES = "overrides.db"
MANIFEST = "manifest.json"
SOURCE_TIMEOUT_S = 5.0
MAX_DB_BYTES = 512 * 1024 * 1024  # copies are held in memory: bounded
MAX_MANIFEST_BYTES = 1024 * 1024
_SIDECARS = ("-wal", "-shm", "-journal")
_EXPECTED = {INVENTORY: len(INVENTORY_MIGRATIONS), OVERRIDES: len(OVERRIDES_MIGRATIONS)}
_NAMES = (INVENTORY, OVERRIDES)
_WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH


class BackupError(Exception):
    """A backup was refused or failed; nothing it created is left behind."""


class VerifyError(Exception):
    """A backup copy is not a valid restore candidate."""


def _check_ancestors(fd: int, path: Path, exc_cls: type[Exception]) -> None:
    """Refuse an ancestor someone else could rename or replace (StrictModes-like)."""
    try:
        real = Path(os.readlink(f"/proc/self/fd/{fd}"))
    except OSError:
        real = path.resolve()
    for parent in real.parents:
        st = os.lstat(parent)
        if st.st_mode & stat.S_ISVTX:
            continue  # sticky (/tmp style): others cannot rename our entries; its owner may be a
            # namespace-mapped root, so it is exempt from the owner rule
        if st.st_uid not in (0, os.geteuid()):
            raise exc_cls("a parent directory is owned by another user")
        if st.st_mode & _WRITABLE_BY_OTHERS:
            raise exc_cls("a parent directory is group- or world-writable (and not sticky)")


def _same_dir(path: Path, fd: int) -> bool:
    try:
        a, b = os.stat(path), os.fstat(fd)
    except OSError:
        return False
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _open_dir(path: Path, exc_cls: type[Exception]) -> int:
    """Open `path` as a directory fd, refusing symlinks and unsafe ownership/modes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise exc_cls("directory must exist and must not be a symlink") from exc
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            raise exc_cls("directory is not owned by the current user")
        if st.st_mode & _WRITABLE_BY_OTHERS:
            raise exc_cls("directory must not be group- or world-writable")
        _check_ancestors(fd, path, exc_cls)
        if not _same_dir(path, fd):
            raise exc_cls("directory changed while it was being checked")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _exists(dfd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _check_no_clobber(dfd: int, names: list[str]) -> None:
    for name in names:
        for suffix in ("", *_SIDECARS):
            if _exists(dfd, name + suffix):
                raise BackupError(f"refusing to overwrite existing {name}{suffix}")


def _create(dfd: int, name: str, created: dict[str, int]) -> int:
    """Exclusive, symlink-refusing create with mode 0600 whatever the umask; tracked by inode."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, 0o600, dir_fd=dfd)
    except OSError as exc:
        raise BackupError(f"cannot create {name} (it may already exist)") from exc
    created[name] = os.fstat(fd).st_ino
    os.fchmod(fd, 0o600)
    return fd


def _remove_created(dfd: int, created: dict[str, int]) -> None:
    """Delete only what this run created (same inode); sidecars were proven absent up front."""
    for name, ino in created.items():
        try:
            if os.stat(name, dir_fd=dfd, follow_symlinks=False).st_ino == ino:
                os.unlink(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
        for suffix in _SIDECARS:
            try:
                os.unlink(name + suffix, dir_fd=dfd)
            except FileNotFoundError:
                pass


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]
    os.fsync(fd)


def _copy_db(src: sqlite3.Connection, dst: sqlite3.Connection) -> None:
    src.backup(dst)  # one step: a single consistent snapshot of the WAL database


def _check_conn(conn: sqlite3.Connection, name: str) -> int:
    """The same checks the apps' openers imply; returns user_version."""
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != _EXPECTED[name]:
            raise VerifyError(f"{name} user_version {version}, expected {_EXPECTED[name]}")
        if conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise VerifyError(f"{name} failed integrity_check")
        if (
            name == INVENTORY
            and conn.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_schema'").fetchone()
        ):
            pv = conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] or 0
            if pv != len(PIPELINE_MIGRATIONS):
                raise VerifyError(
                    f"{name} pipeline_schema {pv}, expected {len(PIPELINE_MIGRATIONS)}"
                )
    except sqlite3.Error as exc:
        raise VerifyError(f"{name} is unreadable or corrupt ({type(exc).__name__})") from exc
    return version


def _read_fd(dfd: int, name: str, cap: int, exc_cls: type[Exception]) -> tuple[bytes, int]:
    """Read a regular file through the directory fd: lstat first, then O_NOFOLLOW|O_NONBLOCK, so a
    symlink, FIFO or device is never followed or waited on. Returns (bytes, inode)."""
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            raise exc_cls(f"{name} is not a regular file")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except OSError as exc:
        raise exc_cls(f"{name} cannot be opened ({type(exc).__name__})") from exc
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_ino != st.st_ino:
            raise exc_cls(f"{name} changed while it was being read")
        if st.st_uid != os.geteuid():
            raise exc_cls(f"{name} is not owned by the current user")
        if fst.st_size > cap:
            raise exc_cls(f"{name} is larger than the {cap}-byte limit")
        chunks, total = [], 0
        while chunk := os.read(fd, 1 << 20):
            total += len(chunk)
            if total > cap:
                raise exc_cls(f"{name} is larger than the {cap}-byte limit")
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks), fst.st_ino


def _check_bytes(data: bytes, name: str) -> int:
    if not data:
        raise VerifyError(f"{name} is empty")
    image = bytearray(data)
    if len(image) > 19:
        image[18] = image[19] = 1  # an in-memory image cannot be WAL; the bytes are what we check
    conn = sqlite3.connect(":memory:")
    try:
        try:
            conn.deserialize(image)
        except (sqlite3.Error, ValueError, OverflowError) as exc:
            raise VerifyError(f"{name} is not a database ({type(exc).__name__})") from exc
        return _check_conn(conn, name)
    finally:
        conn.close()


def _snapshot(name: str, source: Path) -> bytes:
    """Consistent copy of `source` as database bytes (a rollback-journal file, no sidecars)."""
    try:
        if os.stat(source).st_uid != os.geteuid():
            raise BackupError(f"{name} source is not owned by the current user; run as its owner")
        src = sqlite3.connect(
            f"file:{quote(str(source.resolve()))}?mode=ro", uri=True, timeout=SOURCE_TIMEOUT_S
        )
    except OSError as exc:
        raise BackupError(f"{name} source cannot be read ({type(exc).__name__})") from exc
    except sqlite3.Error as exc:
        raise BackupError(f"{name} source cannot be opened ({type(exc).__name__})") from exc
    dst = sqlite3.connect(":memory:")
    try:
        size = (
            src.execute("PRAGMA page_count").fetchone()[0]
            * src.execute("PRAGMA page_size").fetchone()[0]
        )
        if size > MAX_DB_BYTES:
            raise BackupError(f"{name} source is larger than the {MAX_DB_BYTES}-byte limit")
        _copy_db(src, dst)
        try:
            _check_conn(dst, name)
        except VerifyError as exc:
            raise BackupError(f"{exc}; refusing to back it up (wrong or empty source?)") from exc
        data = bytearray(dst.serialize())
    except sqlite3.Error as exc:
        raise BackupError(f"{name} backup failed ({type(exc).__name__})") from exc
    finally:
        dst.close()
        src.close()
    data[18] = data[19] = 1  # file-format versions: rollback journal, never WAL
    return bytes(data)


def _store(dfd: int, name: str, data: bytes, created: dict[str, int]) -> dict[str, Any]:
    fd = _create(dfd, name, created)
    try:
        _write_all(fd, data)
    finally:
        os.close(fd)
    back, ino = _read_fd(dfd, name, MAX_DB_BYTES, BackupError)
    if ino != created[name] or back != data:
        raise BackupError(f"{name} was not written as expected")
    try:
        version = _check_bytes(back, name)
    except VerifyError as exc:
        raise BackupError(str(exc)) from exc
    return {
        "name": name,
        "size": len(back),
        "user_version": version,
        "sha256": hashlib.sha256(back).hexdigest(),
    }


def backup(dest: Path, *, inventory: Path | None, overrides: Path | None) -> dict[str, Any]:
    """Back up the given databases into `dest`; returns (and writes) the manifest."""
    jobs = [(n, p) for n, p in ((INVENTORY, inventory), (OVERRIDES, overrides)) if p is not None]
    if not jobs:
        raise BackupError("give at least one source database")
    dfd = _open_dir(dest, BackupError)
    created: dict[str, int] = {}
    try:
        _check_no_clobber(dfd, [*(n for n, _ in jobs), MANIFEST])
        files = [_store(dfd, name, _snapshot(name, source), created) for name, source in jobs]
        manifest = {
            "created_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": files,
        }
        mfd = _create(dfd, MANIFEST, created)
        try:
            _write_all(mfd, json.dumps(manifest, indent=2).encode())
        finally:
            os.close(mfd)
        os.fsync(dfd)
        if not _same_dir(dest, dfd):
            raise BackupError("destination changed during the backup")
        return manifest
    except BaseException as exc:
        _remove_created(dfd, created)
        if isinstance(exc, (sqlite3.Error, OSError)) and not isinstance(exc, BackupError):
            raise BackupError(
                f"backup failed ({type(exc).__name__}); partial files were removed"
            ) from exc
        raise
    finally:
        os.close(dfd)


def _load_manifest(dfd: int, present: list[str], data: dict[str, tuple[bytes, int]]) -> None:
    raw, _ = _read_fd(dfd, MANIFEST, MAX_MANIFEST_BYTES, VerifyError)
    try:
        entries = json.loads(raw)["files"]
        listed = {e["name"]: e["sha256"] for e in entries}
        if len(listed) != len(entries):
            raise ValueError("duplicate")
    except (ValueError, KeyError, TypeError) as exc:
        raise VerifyError("manifest.json is malformed") from exc
    if set(listed) != set(present):
        raise VerifyError("manifest.json does not list exactly the database files present")
    for name, expected in listed.items():
        if hashlib.sha256(data[name][0]).hexdigest() != expected:
            raise VerifyError(f"{name} sha256 does not match the manifest")


def verify(directory: Path, *, require_manifest: bool = True) -> list[dict[str, Any]]:
    """Check each backup copy through an fd, in memory: manifest hashes (required unless
    `require_manifest` is False, for manual copies), user_version, integrity, pipeline_schema."""
    dfd = _open_dir(directory, VerifyError)
    try:
        present = [n for n in _NAMES if _exists(dfd, n)]
        if not present:
            raise VerifyError("no inventory.db or overrides.db found to verify")
        data = {n: _read_fd(dfd, n, MAX_DB_BYTES, VerifyError) for n in present}
        if require_manifest:
            if not _exists(dfd, MANIFEST):
                raise VerifyError("manifest.json is missing (--no-manifest is for manual copies)")
            _load_manifest(dfd, present, data)
        return [
            {
                "name": n,
                "size": len(data[n][0]),
                "user_version": _check_bytes(data[n][0], n),
                "status": "ok",
            }
            for n in present
        ]
    finally:
        os.close(dfd)
