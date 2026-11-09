"""Consistent SQLite backup and restore-verify for inventory.db and overrides.db.

Sources are opened read-only (mode=ro URI) and copied with `Connection.backup` into an in-memory
database, validated, serialized and written through a file descriptor created with
O_CREAT|O_EXCL|O_NOFOLLOW (0600) in a directory fd that was validated once: SQLite never touches
the destination by path, so a swapped destination or ancestor cannot redirect the copy. The
destination must be a real directory owned by the caller, not group/world-writable, with no
ancestor writable by others (a sticky one such as /tmp is fine if its owner is trusted).
Verification reads one copy at a time through an fd and deserializes it in memory: nothing on disk
is opened by SQLite, so no -wal/-shm is ever created. The in-memory connection is hardened against
hostile images (defensive mode, untrusted schema, value-size limit, time budget). Copies are always
written with the rollback-journal header (bytes 18/19 == 1/1) and `verify` refuses anything else,
and any -wal/-shm/-journal sidecar. Any failure removes what this run created. Messages name
databases by logical name only, never by path.

Memory: copies are held in memory (peak about 3x the database for `backup`, about 2x for `verify`,
see MAX_DB_BYTES): larger databases need a host-level backup.

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
import time
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
MAX_DB_BYTES = 128 * 1024 * 1024  # copies are held in memory: bounded (container limit 512 MiB)
MAX_MANIFEST_BYTES = 1024 * 1024
CHECK_BUDGET_S = 30.0  # time budget for the checks on one image
VALUE_LIMIT_BYTES = 16 * 1024 * 1024  # SQLITE_LIMIT_LENGTH while checking
HEADER_BYTES = 100
TOO_LARGE = "database too large for the in-memory backup: use a host-level backup"
_CHUNK = 1 << 20
_SIDECARS = ("-wal", "-shm", "-journal")
_EXPECTED = {INVENTORY: len(INVENTORY_MIGRATIONS), OVERRIDES: len(OVERRIDES_MIGRATIONS)}
_NAMES = (INVENTORY, OVERRIDES)
_WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH


class BackupError(Exception):
    """A backup was refused or failed; nothing it created is left behind."""


class VerifyError(Exception):
    """A backup copy is not a valid restore candidate."""


def _trusted_owners() -> set[int]:
    owners = {0, os.geteuid(), os.stat("/").st_uid}
    try:  # the uid a user namespace shows for an unmapped (root) owner
        owners.add(int(Path("/proc/sys/kernel/overflowuid").read_text()))
    except (OSError, ValueError):
        pass
    return owners


def _check_ancestors(fd: int, path: Path, exc_cls: type[Exception]) -> None:
    """Refuse an ancestor someone else could rename or replace (StrictModes-like)."""
    try:
        real = Path(os.readlink(f"/proc/self/fd/{fd}"))
    except OSError:
        real = path.resolve()
    owners = _trusted_owners()
    for parent in real.parents:
        st = os.lstat(parent)
        if st.st_mode & stat.S_ISVTX:  # sticky (/tmp style): others cannot rename our entries
            if st.st_uid not in owners:
                raise exc_cls("a sticky parent directory is owned by another user")
            continue
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


def _remove_created(dfd: int, created: dict[str, int]) -> list[str]:
    """Best effort: delete only what this run created (same inode). Returns the names that could
    not be removed; never raises."""
    failed = []
    for name, ino in created.items():
        try:
            if os.stat(name, dir_fd=dfd, follow_symlinks=False).st_ino == ino:
                os.unlink(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
        except OSError:
            failed.append(name)
    return failed


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]
    os.fsync(fd)


def _write_image(fd: int, image: bytes) -> tuple[str, int]:
    """Write the image in chunks with the rollback-journal header (bytes 18/19 = 1/1); the only
    copy made is the 100-byte header. Returns (sha256, size) of what was written."""
    view = memoryview(image)
    head = bytearray(view[:HEADER_BYTES])
    if len(head) > 19:
        head[18] = head[19] = 1
    digest = hashlib.sha256()
    for part in (memoryview(head), view[HEADER_BYTES:]):
        for off in range(0, len(part), _CHUNK):
            chunk = part[off : off + _CHUNK]
            digest.update(chunk)
            while chunk:
                chunk = chunk[os.write(fd, chunk) :]
    os.fsync(fd)
    return digest.hexdigest(), len(image)


def _copy_db(src: sqlite3.Connection, dst: sqlite3.Connection) -> None:
    src.backup(dst)  # one step: a single consistent snapshot of the WAL database


def _harden(conn: sqlite3.Connection) -> list[bool]:
    """Make a connection to an untrusted image safe to query: defensive mode, untrusted schema, a
    value-size limit and a time budget. The returned flag turns True if the budget was hit."""
    conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, VALUE_LIMIT_BYTES)
    deadline = time.monotonic() + CHECK_BUDGET_S
    hit = [False]

    def over_budget() -> int:
        if time.monotonic() > deadline:
            hit[0] = True
            return 1
        return 0

    conn.set_progress_handler(over_budget, 1000)
    return hit


def _check_conn(conn: sqlite3.Connection, name: str, hit: list[bool]) -> int:
    """The same checks the apps' openers imply; returns user_version."""
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != _EXPECTED[name]:
            raise VerifyError(f"{name} user_version {version}, expected {_EXPECTED[name]}")
        if conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise VerifyError(f"{name} failed integrity_check")
        row = conn.execute("SELECT type FROM sqlite_master WHERE name='pipeline_schema'").fetchone()
        if name == INVENTORY and row:
            if row[0] != "table":
                raise VerifyError(f"{name} pipeline_schema is not a table")
            pv = conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] or 0
            if pv != len(PIPELINE_MIGRATIONS):
                raise VerifyError(
                    f"{name} pipeline_schema {pv}, expected {len(PIPELINE_MIGRATIONS)}"
                )
    except sqlite3.Error as exc:
        if hit[0]:
            raise VerifyError(f"{name} check exceeded its {CHECK_BUDGET_S:.0f} s budget") from exc
        raise VerifyError(f"{name} is unreadable or corrupt ({type(exc).__name__})") from exc
    return version


def _open_regular(dfd: int, name: str, exc_cls: type[Exception]) -> tuple[int, os.stat_result]:
    """Open a regular file owned by the caller through the directory fd: lstat first, then
    O_NOFOLLOW|O_NONBLOCK, so a symlink, FIFO or device is never followed or waited on."""
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
    except BaseException:
        os.close(fd)
        raise
    return fd, fst


def _digest_file(dfd: int, name: str, exc_cls: type[Exception]) -> tuple[str, int, int]:
    """Stream a file in chunks: (sha256, size, inode). Never holds more than one chunk."""
    fd, fst = _open_regular(dfd, name, exc_cls)
    try:
        digest, total = hashlib.sha256(), 0
        while chunk := os.read(fd, _CHUNK):
            digest.update(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest(), total, fst.st_ino


def _read_image(dfd: int, name: str, cap: int, exc_cls: type[Exception]) -> tuple[bytearray, str]:
    """Read a file into one preallocated buffer, hashing as it goes: (bytes, sha256)."""
    fd, fst = _open_regular(dfd, name, exc_cls)
    try:
        if fst.st_size > cap:
            raise exc_cls(f"{name} is larger than the {cap}-byte limit")
        buf = bytearray(fst.st_size)
        digest, off = hashlib.sha256(), 0
        with memoryview(buf) as view:
            while off < len(buf):
                n = os.readv(fd, [view[off : off + _CHUNK]])
                if n == 0:
                    raise exc_cls(f"{name} changed while it was being read")
                digest.update(view[off : off + n])
                off += n
        if os.read(fd, 1):
            raise exc_cls(f"{name} changed while it was being read")
    finally:
        os.close(fd)
    return buf, digest.hexdigest()


def _check_image(image: bytearray, name: str) -> int:
    """Validate the ORIGINAL header first (we only ever write 1/1), then check the content."""
    if len(image) < HEADER_BYTES or image[18] != 1 or image[19] != 1:
        raise VerifyError(f"{name} header is not the rollback-journal format we write (1/1)")
    conn = sqlite3.connect(":memory:")
    try:
        try:
            conn.deserialize(image)
        except (sqlite3.Error, ValueError, OverflowError) as exc:
            raise VerifyError(f"{name} is not a database ({type(exc).__name__})") from exc
        return _check_conn(conn, name, _harden(conn))
    finally:
        conn.close()


def _source_size(conn: sqlite3.Connection) -> int:
    return (
        conn.execute("PRAGMA page_count").fetchone()[0]
        * conn.execute("PRAGMA page_size").fetchone()[0]
    )


def _open_source(name: str, source: Path) -> sqlite3.Connection:
    """Refuse a symlink, FIFO, device or foreign-owned source before SQLite opens it by path (it
    cannot take an fd, so the path is opened right after this check)."""
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as exc:
        raise BackupError(f"{name} source cannot be read ({type(exc).__name__})") from exc
    try:
        st = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISREG(st.st_mode):
        raise BackupError(f"{name} source is not a regular file")
    if st.st_uid != os.geteuid():
        raise BackupError(f"{name} source is not owned by the current user; run as its owner")
    try:
        return sqlite3.connect(
            f"file:{quote(os.path.abspath(source))}?mode=ro", uri=True, timeout=SOURCE_TIMEOUT_S
        )
    except sqlite3.Error as exc:
        raise BackupError(f"{name} source cannot be opened ({type(exc).__name__})") from exc


def _snapshot(name: str, source: Path) -> tuple[bytes, int]:
    """Consistent, validated copy of `source` as database bytes, and its user_version."""
    src = _open_source(name, source)
    dst = sqlite3.connect(":memory:")
    try:
        if _source_size(src) > MAX_DB_BYTES:
            raise BackupError(f"{name}: {TOO_LARGE}")
        _copy_db(src, dst)
        src.close()
        if _source_size(dst) > MAX_DB_BYTES:  # it may have grown since the check above
            raise BackupError(f"{name}: {TOO_LARGE}")
        try:
            version = _check_conn(dst, name, _harden(dst))
        except VerifyError as exc:
            raise BackupError(f"{exc}; refusing to back it up (wrong or empty source?)") from exc
        image = dst.serialize()  # its length is the page count x page size checked above
    except sqlite3.Error as exc:
        raise BackupError(f"{name} backup failed ({type(exc).__name__})") from exc
    finally:
        dst.close()
        src.close()
    return image, version


def _store(
    dfd: int, name: str, image: bytes, version: int, created: dict[str, int]
) -> dict[str, Any]:
    fd = _create(dfd, name, created)
    try:
        sha, size = _write_image(fd, image)
    finally:
        os.close(fd)
    back_sha, back_size, ino = _digest_file(dfd, name, BackupError)  # streamed read-back
    if ino != created[name] or back_sha != sha or back_size != size:
        raise BackupError(f"{name} was not written as expected")
    return {"name": name, "size": size, "user_version": version, "sha256": sha}


def _backup_one(dfd: int, name: str, source: Path, created: dict[str, int]) -> dict[str, Any]:
    image, version = _snapshot(name, source)
    entry = _store(dfd, name, image, version, created)
    del image
    return entry


def backup(dest: Path, *, inventory: Path | None, overrides: Path | None) -> dict[str, Any]:
    """Back up the given databases into `dest`; returns (and writes) the manifest."""
    jobs = [(n, p) for n, p in ((INVENTORY, inventory), (OVERRIDES, overrides)) if p is not None]
    if not jobs:
        raise BackupError("give at least one source database")
    dfd = _open_dir(dest, BackupError)
    created: dict[str, int] = {}
    try:
        _check_no_clobber(dfd, [*(n for n, _ in jobs), MANIFEST])
        files = [_backup_one(dfd, name, source, created) for name, source in jobs]
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
        failed = _remove_created(dfd, created)
        note = f"could not remove: {', '.join(failed)}; delete it by hand" if failed else ""
        if isinstance(exc, (sqlite3.Error, OSError)) and not isinstance(exc, BackupError):
            wrapped = BackupError(
                f"backup failed ({type(exc).__name__})"
                + ("" if failed else "; partial files were removed")
            )
            if note:
                wrapped.add_note(note)
            raise wrapped from exc
        if note:
            exc.add_note(note)
        raise
    finally:
        os.close(dfd)


def _load_manifest(dfd: int, present: list[str]) -> dict[str, str]:
    raw, _ = _read_image(dfd, MANIFEST, MAX_MANIFEST_BYTES, VerifyError)
    try:
        entries = json.loads(raw)["files"]
        listed = {e["name"]: e["sha256"] for e in entries}
        if len(listed) != len(entries):
            raise ValueError("duplicate")
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        raise VerifyError("manifest.json is malformed") from exc
    if set(listed) != set(present):
        raise VerifyError("manifest.json does not list exactly the database files present")
    return listed


def _verify_one(dfd: int, name: str, expected_sha: str | None) -> dict[str, Any]:
    """One file at a time: sidecars refused, hash checked, then validated in memory."""
    for suffix in _SIDECARS:
        if _exists(dfd, name + suffix):
            raise VerifyError(f"{name}{suffix} exists: a copy that needs it is refused")
    image, sha = _read_image(dfd, name, MAX_DB_BYTES, VerifyError)
    if expected_sha is not None and sha != expected_sha:
        raise VerifyError(f"{name} sha256 does not match the manifest")
    size = len(image)
    version = _check_image(image, name)
    return {"name": name, "size": size, "user_version": version, "status": "ok"}


def verify(directory: Path, *, require_manifest: bool = True) -> list[dict[str, Any]]:
    """Check each backup copy through an fd, in memory: manifest hashes (required unless
    `require_manifest` is False, for manual copies), header, user_version, integrity,
    pipeline_schema."""
    dfd = _open_dir(directory, VerifyError)
    try:
        present = [n for n in _NAMES if _exists(dfd, n)]
        if not present:
            raise VerifyError("no inventory.db or overrides.db found to verify")
        listed: dict[str, str] = {}
        if require_manifest:
            if not _exists(dfd, MANIFEST):
                raise VerifyError("manifest.json is missing (--no-manifest is for manual copies)")
            listed = _load_manifest(dfd, present)
        return [_verify_one(dfd, n, listed.get(n)) for n in present]
    finally:
        os.close(dfd)
