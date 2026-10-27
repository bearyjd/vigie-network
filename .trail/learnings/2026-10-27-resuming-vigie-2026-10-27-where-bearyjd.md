---
title: "Resuming Vigie 2026-10-27: where #23 and #24 stood"
author: Bearyjd
date: 2026-10-27
branch: docs/repo-glowup
cost: { minutes: 1, tokens: 53718 }
touches:
  - ".omc/RESUME.md"
  - ".omc/STATE.md"
---

## Decided
- Resume order: read .omc/RESUME.md whole, then STATE.md (its "UPDATE 2026-10-27" block at the bottom supersedes earlier lines). Then check both worktrees with git status/log and `gh pr list`.
- #23 first: fix commit ce641c7 sits locally on top of unpushed D7 commit 142fc16. Verify, rebase onto main, push over SSH, CI, narrow Codex re-check, merge.

## Tried and ruled out
- RESUME.md is stale (says main = 1a51097). STATE.md says main = 760edf1. STATE.md is the better snapshot, but verify main against git and the remote (`git ls-remote`) before acting; both files go stale.

## Watch out
- the evidence-pack worktree under ~/.cache has an uncommitted edit to server/src/vigie_api/evidence_redact.py and is behind origin/main by 2. Look at the diff before committing or rebasing.
- #24 still owes two doc fixes (Keeper fail-closed wording, lineage-mismatch claim) before the Codex re-check.
