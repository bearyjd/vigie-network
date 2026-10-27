"""Keepers: hold one open connection to a WAL database so read-only consumers can attach.

A SQLite WAL database that nobody has open is checkpointed and its -wal/-shm sidecars are deleted.
A reader on a read-only mount cannot create them again and fails ("unable to open database
file"). While a writer keeps ONE connection open the sidecars stay, and read-only readers in other
containers work (tests/test_ro_mount_wal.py proves both halves). The connection is never used to
write; it only keeps the wal-index attached. After a clean close a reader finds no sidecars and
fails; a crashed writer can leave readable sidecars (a stale snapshot), so consumers that must
notice a dead writer need their own freshness check rather than relying on the open error.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from urllib.parse import quote

log = logging.getLogger("vigie.keeper")


class Keeper:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._conns: dict[Path, sqlite3.Connection] = {}

    def hold(self, path: Path) -> bool:
        """Keep `path` attached. Never creates the file; returns False (and logs) when it cannot."""
        with self._lock:
            if path in self._conns:
                return True
            try:
                conn = sqlite3.connect(
                    f"file:{quote(str(path.resolve()))}?mode=rw",
                    uri=True,
                    timeout=5.0,
                    check_same_thread=False,
                    isolation_level=None,
                )
                conn.execute("SELECT count(*) FROM sqlite_master").fetchone()  # attach -shm
            except sqlite3.Error as exc:
                log.warning("keeper cannot hold %s: %s", path, exc)
                return False
            self._conns[path] = conn
            return True

    def release(self, path: Path) -> None:
        with self._lock:
            conn = self._conns.pop(path, None)
        if conn is not None:
            conn.close()

    def held(self) -> list[Path]:
        with self._lock:
            return sorted(self._conns)

    def close(self) -> None:
        for path in self.held():
            self.release(path)


# The keeper of the running ingest service (set by its lifespan; None in tools and unit tests).
ACTIVE: Keeper | None = None


def hold_active(path: Path) -> None:
    if ACTIVE is not None:
        ACTIVE.hold(path)


def release_active(path: Path) -> None:
    if ACTIVE is not None:
        ACTIVE.release(path)
