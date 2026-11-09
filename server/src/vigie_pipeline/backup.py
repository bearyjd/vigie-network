"""Consistent SQLite backup and restore-verify for inventory.db and overrides.db.

Sources are opened read-only (mode=ro URI) and copied with `Connection.backup`, never by file
copy (the live databases are WAL). Copies are created 0600 with O_CREAT|O_EXCL|O_NOFOLLOW inside a
destination directory that must be a real directory, owned by the caller and not group/world
writable. Any failure removes everything this run created. Messages name files by their logical
name only, never by path.

The pipeline tables live inside inventory.db (`pipeline_schema`); there is no separate pipeline DB.
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
_SIDECARS = ("-wal", "-shm", "-journal")
_EXPECTED = {INVENTORY: len(INVENTORY_MIGRATIONS), OVERRIDES: len(OVERRIDES_MIGRATIONS)}


class BackupError(Exception):
    """A backup was refused or failed; nothing it created is left behind."""


class VerifyError(Exception):
    """A backup copy is not a valid restore candidate."""


def _open_dest_dir(dest: Path) -> int:
    """Open the destination as a directory fd, refusing symlinks and unsafe ownership/modes."""
    try:
        fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise BackupError("destination must be an existing directory and not a symlink") from exc
    st = os.fstat(fd)
    if st.st_uid != os.geteuid():
        os.close(fd)
        raise BackupError("destination directory is not owned by the current user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        os.close(fd)
        raise BackupError("destination directory must not be group- or world-writable")
    return fd


def _check_no_clobber(dfd: int, names: list[str]) -> None:
    for name in names:
        try:
            os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise BackupError(f"refusing to overwrite existing {name}")


def _create(dfd: int, name: str) -> int:
    """Exclusive, symlink-refusing create with mode 0600 whatever the umask."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, 0o600, dir_fd=dfd)
    except OSError as exc:
        raise BackupError(f"cannot create {name} (it may already exist)") from exc
    os.fchmod(fd, 0o600)
    return fd


def _remove(dfd: int, name: str) -> None:
    for suffix in ("", *_SIDECARS):
        try:
            os.unlink(name + suffix, dir_fd=dfd)
        except FileNotFoundError:
            pass


def _copy_db(src: sqlite3.Connection, dst: sqlite3.Connection) -> None:
    src.backup(dst)  # one step: a single consistent snapshot of the WAL database


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _backup_one(dfd: int, dest: Path, name: str, source: Path) -> dict[str, Any]:
    target = dest / name
    src = sqlite3.connect(
        f"file:{quote(str(source.resolve()))}?mode=ro", uri=True, timeout=SOURCE_TIMEOUT_S
    )
    dst = sqlite3.connect(target)
    try:
        _copy_db(src, dst)
        dst.execute("PRAGMA journal_mode=DELETE").fetchone()  # one self-contained file
        if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise sqlite3.DatabaseError("integrity check of the copy failed")
        version = dst.execute("PRAGMA user_version").fetchone()[0]
    finally:
        dst.close()
        src.close()
    return {
        "name": name,
        "size": target.stat().st_size,
        "user_version": version,
        "sha256": _sha256(target),
    }


def backup(dest: Path, *, inventory: Path | None, overrides: Path | None) -> dict[str, Any]:
    """Back up the given databases into `dest`; returns (and writes) the manifest."""
    jobs = [(n, p) for n, p in ((INVENTORY, inventory), (OVERRIDES, overrides)) if p is not None]
    if not jobs:
        raise BackupError("give at least one source database")
    dfd = _open_dest_dir(dest)
    created: list[str] = []
    try:
        _check_no_clobber(dfd, [*(n for n, _ in jobs), MANIFEST])
        files = []
        for name, source in jobs:
            os.close(_create(dfd, name))
            created.append(name)  # only after our own exclusive create: never delete others' files
            files.append(_backup_one(dfd, dest, name, source))
        manifest = {
            "created_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": files,
        }
        mfd = _create(dfd, MANIFEST)
        created.append(MANIFEST)
        with os.fdopen(mfd, "w") as fh:
            json.dump(manifest, fh, indent=2)
        return manifest
    except BaseException as exc:
        for name in created:
            _remove(dfd, name)
        if isinstance(exc, (sqlite3.Error, OSError)) and not isinstance(exc, BackupError):
            raise BackupError("backup failed; partial files were removed") from exc
        raise
    finally:
        os.close(dfd)


def _check_db(path: Path, name: str) -> dict[str, Any]:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise VerifyError(f"{name} is not a regular file")
    try:
        conn = sqlite3.connect(f"file:{quote(str(path.resolve()))}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        raise VerifyError(f"{name} cannot be opened read-only") from exc
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
        raise VerifyError(f"{name} is unreadable or corrupt") from exc
    finally:
        conn.close()
    return {"name": name, "size": st.st_size, "user_version": version, "status": "ok"}


def _check_manifest(directory: Path, present: list[str]) -> None:
    path = directory / MANIFEST
    if not path.is_file():
        return
    try:
        listed = {e["name"]: e for e in json.loads(path.read_text())["files"]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise VerifyError("manifest.json is unreadable") from exc
    for name, entry in listed.items():
        if name not in present:
            raise VerifyError(f"{name} is listed in the manifest but missing")
        if _sha256(directory / name) != entry.get("sha256"):
            raise VerifyError(f"{name} sha256 does not match the manifest")


def verify(directory: Path) -> list[dict[str, Any]]:
    """Open each backup copy read-only; check manifest hashes, user_version and integrity."""
    present = [
        n
        for n in (INVENTORY, OVERRIDES)
        if (directory / n).is_symlink() or (directory / n).exists()
    ]
    if not present:
        raise VerifyError("no inventory.db or overrides.db found to verify")
    _check_manifest(directory, present)
    return [_check_db(directory / name, name) for name in present]
