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


class InputRefused(ValueError):
    """A refused input; the message is fixed text with no path or data in it."""


def _state(path: Path) -> tuple:
    """Main-file identity plus sidecar sizes, to detect a change during the read."""
    st = os.lstat(path)
    sizes = []
    for suffix in _SIDECARS:
        side = path.with_name(path.name + suffix)
        sizes.append(side.stat().st_size if side.exists() else None)
    return (st.st_ino, st.st_nlink, st.st_size, st.st_mtime_ns, *sizes)


def open_snapshot(path: Path) -> sqlite3.Connection:
    """Open a checkpointed copy immutable and query-only (same discipline as tools/endpoint_e0)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise InputRefused("database file missing") from None
    if stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
        raise InputRefused("database is a symlink or hardlink: copy the file, do not link it")
    if not stat.S_ISREG(st.st_mode):
        raise InputRefused("database is not a regular file")
    for suffix in _SIDECARS:
        side = path.with_name(path.name + suffix)
        if side.is_file() and side.stat().st_size > 0:
            raise InputRefused(
                "database has a non-empty -wal or -journal file (live or unclean): "
                "checkpoint it or run on a verified backup copy"
            )
    conn = sqlite3.connect(
        f"file:{quote(str(path.absolute()))}?mode=ro&immutable=1", uri=True, timeout=2
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


@contextmanager
def reading(path: Path) -> Iterator[sqlite3.Connection]:
    with closing(open_snapshot(path)) as conn:
        before = _state(path)  # nothing is read before the first query
        yield conn
    if _state(path) != before:
        raise InputRefused("database changed while being read: run on a checkpointed copy")
