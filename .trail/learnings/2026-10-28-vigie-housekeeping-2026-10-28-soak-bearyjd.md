---
title: "Vigie housekeeping 2026-10-28: soak failed at ~31h, stale branches and worktrees"
author: Bearyjd
date: 2026-10-28
branch: main
cost: { minutes: 1, tokens: 6524 }
---

## Decided
- Pruned the 3 dead /tmp worktrees (vigie-mvp-20261024, vigie-last-observed-ip, vigie-gui-mvp) with `git worktree prune`. Nothing else was removed.
- The real 48h soak is not running. Unit `vigie-monitoring-20261024-soak-v2.service` exited status 1 on 2026-10-26 12:51 PDT after ~111060s (~30.85h of 48h). Its report: status fail, coverage 0.993, reasons dns_probe_failed, invalid_metrics, missing_metrics, parsed_dns_stale, quality note unmapped_conntrack. Read via `systemctl --user status` on the unit.
- Earlier learnings that call the soak "still PENDING, earliest completion 2026-10-27 13:00 UTC" are out of date.

## Tried and ruled out
- No branch or worktree deletion yet. ~48 local branches are merged into main and ~40 worktrees (~/.cache/vigie-wt-*, .claude/worktrees/agent-*, .omc/worktrees/*) are still present.
- Root cause of the soak failure not investigated (journals and soak output files not read).

## Watch out
- The owned services vigie_monitoring_20261024-api/-ingest/-pipeline are still active. Check none runs from a worktree directory before removing worktrees.
- Unmerged branches to decide on: docs/prp-002-couvre-feu, docs/repo-glowup, docs/snitchwatch-endpoint-events (PR #21), worktree-agent-a3038507..., worktree-agent-a309112e....
- Open PRs: #21 (Snitchwatch note), #1 (Renovate config). Background CI watchers for PR 32 exited 0, which means the watcher ended, not that CI passed.
- `systemctl status` on a failed unit returns non-zero; the "command failed" hook notice is not a real error.
