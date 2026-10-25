---
title: "Resuming Vigie after a Codex handoff: where state lives"
author: Bearyjd
date: 2026-10-25
branch: main
cost: { minutes: 1, tokens: 80383 }
touches:
  - ".omc/RESUME.md"
  - ".omc/STATE.md"
---

## Decided
- Sync check = `.omc/RESUME.md` (15 lines, read whole) + head of `.omc/STATE.md`, then `git log -4`, `git worktree list`. Branch-to-worktree map is in RESUME.md.
- Open threads at 2026-10-25: 48h soak running (earliest done 2026-10-27 13:00:47Z), read-only GUI on feat/read-only-gui, last-observed-ip on feat/last-observed-ip. Both branches are unpushed.

## Tried and ruled out
- Reading `.omc/STATE.md` whole: it is about 35 KB despite the 60-line cap, so use line ranges.

## Watch out
- The GUI commit changes image provenance, so the last-IP rollout pack must be re-reviewed before any combined deploy.
- No push or deploy without explicit user permission. Don't upgrade during the soak.
