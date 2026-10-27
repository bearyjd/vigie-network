---
title: "Vigie test flakiness on this host: root causes and fixes"
author: Bearyjd
date: 2026-10-27
branch: docs/repo-glowup
cost: { minutes: 304, tokens: 303240 }
touches:
  - ".omc/plans/overnight-2026-10-27.md"
---

## Decided
- GUI preview tests failed on this host because the live preview owns :18745; the `namespace` fixture now points `preview.PORT` at a bound, non-listening probe port. Never let a unit test see the real port.
- After `Popen`, `/proc/<pid>/cmdline` shows the parent's argv (or nothing) until exec finishes. Use `settled_identity(proc)` (waits for the exact `Popen.args`), never a bare `process_identity(pid)`.
- Tests that build 10k-500k row tables get `pytest.mark.timeout(120-180)`; their assertions are deterministic VM-step counts, so only the 20 s default is load-sensitive. The few explicit wall-clock budgets (<1-3 s) in test_stitch_bounds_perf.py remain load-sensitive on purpose.

## Tried and ruled out
- "Load-flaky" was not the whole story: two tests failed deterministically (live preview), others were the fork/exec argv race. Check failure messages before assuming timing.
- Full-suite runs with `--basetemp` on disk were slower, not faster: sqlite/fsync-heavy tests; /tmp (tmpfs) is fine when it is not full.

## Watch out
- Host load average here reaches 85-120 on 22 cores (hook processes from many sessions); a collection-time subprocess probe with a 20 s timeout aborted a whole run. Keep collection-time probes at >=120 s.
- `/tmp` is a 32 GB tmpfs shared by all projects: a full run beside other sessions' scratch can hit `Disk quota exceeded` (Errno 122), which looks like 50+ unrelated failures.
