---
title: "Vigie resume 2026-10-28: state files stale, tower back on LAN, soak 2 awaits owner"
author: Bearyjd
date: 2026-10-29
branch: main
cost: { minutes: 1, tokens: 58834 }
---

## Decided
- Resume order that worked: RESUME.md, head of STATE.md, then the newest .trail/learnings (they are fresher than both). STATE.md and RESUME.md predate the soak failure and #33-#36.
- main = 242fa6c (#36 docs private-info lint). Only open PR is #1 (Renovate). Nothing in flight, nothing deployed.
- Tower is back on the LAN (wlp9s0f0, port 18443 bound, router POSTs every 60s with 200 OK). Soak 2 is ready to start but is the owner's call: 48h live job, tower must stay on the LAN throughout. The #35 precheck now fails fast if ingest is unbound.

## Tried and ruled out
- Did not start the soak or touch any live service.
- Offline candidates not started: tod baseline engine wiring (freeze trained_until), dataset accept/reject unit 3b, Renovate PR #1.

## Watch out
- STATE.md still says the soak is pending and lists #32 as open; both are out of date.
