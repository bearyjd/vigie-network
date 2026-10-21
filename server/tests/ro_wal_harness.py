"""Helpers for proving what a read-only mount of a WAL database needs (see test_ro_mount_wal.py).

A real read-only mount is simulated with bubblewrap (`--ro-bind`): the reader process sees the
directory on a read-only filesystem, exactly as a container with `:ro` does, while a writer outside
keeps the same files open read-write. Where bubblewrap is unusable the harness reports None.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

READER = r"""
import sqlite3, sys, json
path, n = sys.argv[1], int(sys.argv[2])
ok = errors = 0
first_error = ""
for _ in range(n):
    try:
        c = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=5)
        c.execute("PRAGMA query_only=ON")
        c.execute("SELECT count(*) FROM t").fetchone()
        c.close()
        ok += 1
    except sqlite3.Error as exc:
        errors += 1
        first_error = first_error or str(exc)
print(json.dumps({"ok": ok, "errors": errors, "first_error": first_error}))
"""

WRITER = r"""
import sqlite3, sys, time
path, mode = sys.argv[1], sys.argv[2]
c = sqlite3.connect(path, isolation_level=None)
c.execute("PRAGMA journal_mode=WAL")
c.execute("CREATE TABLE IF NOT EXISTS t(x)")
c.execute("INSERT INTO t VALUES (1)")
print("ready", flush=True)
if mode == "hold":
    time.sleep(120)
elif mode == "churn":
    while True:
        c.execute("INSERT INTO t VALUES (1)")
        time.sleep(0.002)
else:
    c.close()
"""


def bwrap_usable() -> bool:
    exe = shutil.which("bwrap")
    if exe is None:
        return False
    probe = subprocess.run(
        [exe, "--ro-bind", "/", "/", "--dev", "/dev", "true"],
        capture_output=True,
        check=False,
    )
    return probe.returncode == 0


def start_writer(db: Path, mode: str) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", WRITER, str(db), mode],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "ready"
    return proc


def read_ro(db: Path, reads: int = 1) -> dict[str, object]:
    """Run `reads` open/query/close cycles from a process whose view of db.parent is read-only."""
    import json

    cmd = [
        shutil.which("bwrap") or "bwrap",
        "--ro-bind", "/", "/",
        "--ro-bind", str(db.parent), str(db.parent),
        "--dev", "/dev",
        "--proc", "/proc",
        sys.executable, "-I", "-c", READER, str(db), str(reads),
    ]  # fmt: skip
    done = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(done.stdout)
