---
title: "Run the Vigie server test suite with its temp dir on a user-owned RAM tmpfs under /run/user, and clear it after each run"
author: Bearyjd
date: 2026-11-25
branch: docs/fix-test-tmpdir-learning
id: l-aa239cdd
scope: repo
status: active
replaces: l-d5c5df6d
src: agent
touches:
  - scripts/ci.sh
---

## Decided
Local full-suite runs of the server tests (and `scripts/ci.sh server deploy`) use `TMPDIR=/run/user/$(id -u)/<dir>`, which is user-owned RAM tmpfs. Do not raise the 20 s pytest timeout. Delete your scratch dir after each full run: one full gate leaves 2-5 GB there and the tmpfs is only about 6 GB.

## Tried and ruled out
- `/tmp`: tmpfs shared with worktrees and agent output, quota-limited; near 80% full it produced `sqlite3 disk I/O error` and "Disk quota exceeded" across dozens of tests. It is also owned by `nobody` in this user namespace.
- `/var/tmp`: avoids the quota but sits on fuse-overlayfs with very slow fsync (about 148 ms per SQLite commit vs about 7 ms on tmpfs). Eight tests with thousands of separate commits then hit the 20 s timeout and the ingest 503 test misses its 0.3 s lock-retry budget.
- `/dev/shm`: fast, but owned by `nobody` and mounted `noexec`, so 123 backup, GUI-preview and ro-mount tests fail ("a parent directory is owned by another user", "native Python interpreter unavailable or untrusted").
- Raising the timeout hides the slow disk and the 503 test still fails.

## Watch out
- A full `/run/user/$(id -u)` (it also holds the desktop session's sockets) makes tests fail with "database or disk is full" and can disturb desktop apps; check `df -h /run/user/$(id -u)` before a run and delete only your own scratch dirs.
- `uv run` from another worktree reinstalls the editable project package into a shared venv; run `uv sync --frozen --offline` in the worktree's own venv and check `vigie_pipeline.__file__`.
- Hosted CI uses an ordinary VM disk and is the authoritative full-suite gate.

In the code: pyproject.toml timeout = 20; tests/test_ingest.py:489-506 (503 budget). With TMPDIR under /run/user/1000 every previously failing file passes (844 passed in about 54 s).
