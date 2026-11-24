---
title: "Run the Vigie server test suite with its temp dir on RAM-backed storage, not /var/tmp"
author: Bearyjd
date: 2026-11-24
branch: main
cost: { minutes: 138, tokens: 224827 }
id: l-d5c5df6d
scope: repo
status: active
src: agent
---

## Decided
Local full-suite runs of the server tests use a user-owned RAM-backed temp dir (`TMPDIR=/run/user/$(id -u)/<dir>` plus `--basetemp=/run/user/$(id -u)/<dir>/bt`). Do not raise the 20 s pytest timeout.

## Tried and ruled out
- Default `/tmp` is a quota-limited tmpfs shared with worktrees and agent output; at ~80% full it produced `sqlite3 disk I/O error` and "Disk quota exceeded" across dozens of tests.
- `/var/tmp` avoids that but sits on fuse-overlayfs where fsync is very slow (about 148 ms per SQLite commit in DELETE mode vs about 7 ms on tmpfs). Eight tests that do thousands of separately committed writes then hit the 20 s timeout, and the ingest 503 test fails because its 0.3 s lock-retry budget cannot be met. They fail identically on base-equivalent server code.
- Raising the timeout would hide the slow disk and the 503 test would still fail.

- `/dev/shm` (and `/tmp`) are owned by `nobody` in this user namespace and `/dev/shm` is `noexec`: 123 backup, GUI-preview and ro-mount tests then fail with 'a parent directory is owned by another user' and 'native Python interpreter unavailable or untrusted'.

## Watch out
- `uv run` from another worktree reinstalls the editable project package into a shared venv; run `uv sync --frozen --offline` in the worktree's own venv before using it again, and check `vigie_pipeline.__file__` resolves to that worktree.
- Hosted CI uses an ordinary VM disk and is the authoritative full-suite gate.

In the code: pyproject.toml timeout = 20; tests/test_ingest.py:489-506 (503 budget); the eight slow tests are the "uncapped beyond 10000 rows", "updated thousands of times", f5 sweep fix1/fix4 and shard-lock 503 tests. With TMPDIR under /run/user/1000 every previously failing file passes (844 passed in about 54 s).
