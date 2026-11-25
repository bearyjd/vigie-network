"""Open a checkpointed SQLite copy read-only without touching its directory.

Each database is opened `immutable=1`, so no -wal/-shm sidecar is ever created (a plain `mode=ro`
open of a WAL-mode file needs a -shm beside it). An immutable open also skips WAL and hot-journal
recovery, so a database with a non-empty -wal or -journal is refused rather than read short, and so
is a symlink or hardlink (its sidecars could sit beside another name). Same discipline as
tools/endpoint_e0/router.py. It takes no locks: nothing may write to the copy while it is read.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from urllib.parse import quote

_SIDECARS = ("-wal", "-journal")
_LINKED = "database is a symlink or hardlink: copy the file, do not link it"
_CHANGED = "database changed while being read: run on a checkpointed copy"


class InputRefused(ValueError):
    """A refused input; the message is fixed text with no path or data in it."""


def _state(path: Path, fd: int) -> tuple:
    """Identity of the opened file and of the path, plus sidecar sizes: any change (rewrite,
    rename over the path, a new sidecar) during the read makes the result unequal."""
    held, named = os.fstat(fd), os.lstat(path)
    sizes = []
    for suffix in _SIDECARS:
        side = path.with_name(path.name + suffix)
        sizes.append(side.stat().st_size if side.exists() else None)
    return (
        (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
        held.st_ino, held.st_nlink, held.st_size, held.st_mtime_ns,
        named.st_ino, named.st_nlink, named.st_size, named.st_mtime_ns,
        *sizes,
    )  # fmt: skip


def open_snapshot(path: Path) -> tuple[sqlite3.Connection, int]:
    """Open a checkpointed copy immutable and query-only, plus a held descriptor of the same
    inode (O_NOFOLLOW, O_NONBLOCK: a FIFO swapped in never blocks) to check identity against."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise InputRefused("database file missing") from None
    if stat.S_ISLNK(st.st_mode):
        raise InputRefused(_LINKED)
    if not stat.S_ISREG(st.st_mode):
        raise InputRefused("database is not a regular file")
    if st.st_nlink != 1:
        raise InputRefused(_LINKED)
    for suffix in _SIDECARS:
        side = path.with_name(path.name + suffix)
        if side.is_file() and side.stat().st_size > 0:
            raise InputRefused(
                "database has a non-empty -wal or -journal file (live or unclean): "
                "checkpoint it or run on a verified backup copy"
            )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        held = os.fstat(fd)
        if (held.st_dev, held.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(held.st_mode):
            raise InputRefused(_CHANGED)
        conn = sqlite3.connect(
            f"file:{quote(str(path.absolute()))}?mode=ro&immutable=1", uri=True, timeout=2
        )
    except BaseException:
        os.close(fd)
        raise
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn, fd


@contextmanager
def reading(path: Path) -> Iterator[sqlite3.Connection]:
    conn, fd = open_snapshot(path)
    try:
        with closing(conn):
            before = _state(path, fd)  # nothing is read before the first query
            if not before[0]:
                raise InputRefused(_CHANGED)
            yield conn
        if _state(path, fd) != before:
            raise InputRefused(_CHANGED)
    finally:
        os.close(fd)
