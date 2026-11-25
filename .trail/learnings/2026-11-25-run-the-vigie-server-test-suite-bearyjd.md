---
title: "Clear your scratch dir under /run/user after each full Vigie test run; a full tmpfs breaks the tests and the desktop"
author: Bearyjd
date: 2026-11-25
branch: docs/fix-test-tmpdir-learning
id: l-aa239cdd
scope: repo
status: active
src: agent
touches:
  - scripts/ci.sh
---

## Decided
The working temp dir for full server runs is a user-owned tmpfs under `/run/user/$(id -u)` (see the 2026-11-24 learning). It is only about 6 GB, and one `scripts/ci.sh server deploy` run leaves 2 to 5 GB of pytest temp files in it. Delete your own scratch dir (and nothing else there) after each run, and check `df -h /run/user/$(id -u)` before starting.

## Tried and ruled out
Leaving earlier runs' dirs in place: after a few runs the tmpfs hit 100% and tests failed with "database or disk is full" (sqlite) at setup, which looks like a code failure but is not.

## Watch out
- `/run/user/$(id -u)` also holds the desktop session's sockets; at 100% full it can disturb desktop apps.
- `uv run` from another worktree reinstalls the editable project package into a shared venv; run `uv sync --frozen --offline` in the worktree's own venv and check `vigie_pipeline.__file__` resolves to it.
