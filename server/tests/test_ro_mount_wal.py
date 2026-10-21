"""What a `:ro` mount of a SQLite WAL database needs. Backs the mount matrix in docs/deploy.md.

Findings these tests pin (bubblewrap read-only bind mount, SQLite 3.50):
  * a writer process holding a connection ("keeper") keeps -wal/-shm alive: read-only readers work;
  * once the last writer closed cleanly the reader cannot open the database: it FAILS CLOSED;
  * a writer that died uncleanly leaves -wal/-shm behind (see the test for what a reader sees).
"""

from __future__ import annotations

import signal
import sqlite3
from pathlib import Path

import pytest
from ro_wal_harness import bwrap_usable, read_ro, start_writer

pytestmark = pytest.mark.skipif(not bwrap_usable(), reason="bubblewrap read-only mounts unavailable")


def test_reader_works_while_a_writer_holds_a_connection(tmp_path: Path) -> None:
    db = tmp_path / "x.db"
    writer = start_writer(db, "hold")
    try:
        result = read_ro(db, reads=5)
    finally:
        writer.kill()
        writer.wait()
    assert result["errors"] == 0 and result["ok"] == 5


def test_reader_fails_closed_after_a_clean_close(tmp_path: Path) -> None:
    db = tmp_path / "x.db"
    writer = start_writer(db, "close")
    writer.wait(timeout=10)
    assert not (tmp_path / "x.db-shm").exists()  # a clean close removes the sidecars
    result = read_ro(db)
    assert result["ok"] == 0 and result["errors"] == 1
    assert "unable to open" in str(result["first_error"]) or "readonly" in str(result["first_error"])


def test_reader_after_a_killed_writer_is_recorded(tmp_path: Path) -> None:
    db = tmp_path / "x.db"
    writer = start_writer(db, "hold")
    writer.send_signal(signal.SIGKILL)
    writer.wait()
    assert (tmp_path / "x.db-wal").exists() and (tmp_path / "x.db-shm").exists()
    result = read_ro(db)
    # Either outcome is safe for the services (they fail closed or read a consistent snapshot);
    # this test records which one actually happens so docs/deploy.md can state it.
    assert result["ok"] + result["errors"] == 1, result
    print("killed-writer reader outcome:", result)


def test_many_reads_while_a_writer_commits_continuously(tmp_path: Path) -> None:
    db = tmp_path / "x.db"
    writer = start_writer(db, "churn")
    try:
        result = read_ro(db, reads=300)
    finally:
        writer.kill()
        writer.wait()
    print("churn outcome:", result)
    assert result["errors"] == 0, result


def test_plain_chmod_directory_is_not_a_read_only_mount(tmp_path: Path) -> None:
    """Why the harness uses a real read-only mount: a same-uid reader still opens the old -shm
    read-write in a chmod a-w directory, so a chmod-only test would pass trivially."""
    db = tmp_path / "x.db"
    writer = start_writer(db, "hold")
    try:
        tmp_path.chmod(0o500)
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        assert conn.execute("SELECT count(*) FROM t").fetchone()[0] >= 1
        conn.close()
    finally:
        tmp_path.chmod(0o700)
        writer.kill()
        writer.wait()
