---
title: "Vigie overnight run: what worked and what burned time"
author: Bearyjd
date: 2026-10-27
branch: docs/repo-glowup
cost: { minutes: 29, tokens: 30274 }
---

## Decided
- Free text cannot be made provably safe by detect-and-remove scrubbing: three review rounds of bypasses (separators, unicode, homoglyphs). Use a strict acceptor (verbatim or alias) and make "no free text" the default; make the label an explicit opt-in.
- Concurrency fencing must not depend on the wall clock: AUTOINCREMENT row_id as the incarnation token plus a claim lease (CLAIM counts the attempt, planner hands off live leases) replaced four rounds of version/created_at tricks.
- Compare with floor, stamp with ceil (never act early, never promise early).
- The deploy CI gate enforces the PRP-001 s5 volume matrix: do not add volumes to a service; put files on an existing writable volume.

## Tried and ruled out
- Patching each reviewer finding in isolation: each fix round introduced a neighbouring hole. When two rounds find the same root cause, redesign.
- Full-suite runs on this host under load average 85-120: use targeted tests locally and let CI be the full run.

## Watch out
- Codex needs --timeout >= 900 on this host and sometimes exits 1 with no output; rerun in the foreground with output logged.
- Stale CI-watch notifications for old heads arrive after merges: always match the exact head SHA.
