---
title: "Vigie resume 2026-11-02: RESUME.md has the newest state, local main is stale"
author: Bearyjd
date: 2026-11-02
branch: main
cost: { minutes: 1, tokens: 61228 }
touches:
  - ".omc/RESUME.md"
---

## Decided
- Resume order again worked: .omc/RESUME.md whole (its UPDATE blocks at the bottom supersede the top), STATE.md head only, newest .trail/learnings, then `git fetch` plus a live check (journal tail, systemctl is-active, worktree logs, gh pr list).
- State at 2026-11-02 02:50Z: soak 2 active, ~34/48h, cannot pass formally (5 dns_probe failures); origin/main f2db68d (#59-#61); open PRs #62 cutover runbook (round 5, needs Opus+Codex re-review), Renovate #57/#58; stopsig branch b445299 has local commits only.

## Tried and ruled out
- Trusting local main: it was still 0def191 while origin/main was f2db68d; always fetch first.
- STATE.md is stale (dated 2026-10-26); it was only used for the process notes.

## Watch out
- Do not restart or reboot anything live before soak 2 ends (~2026-11-02 18:49Z); cutover needs the owner's explicit go.
- RESUME.md said runbook round 4 was pending but round 5 was already committed in the worktree; check `git log` in ~/.cache/vigie-wt-* before redoing work.
