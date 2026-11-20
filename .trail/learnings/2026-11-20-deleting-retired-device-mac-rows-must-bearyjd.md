---
title: "Deleting retired-device MAC rows must fail closed, and what a safe prune has to guard against"
author: Bearyjd
date: 2026-11-20
branch: main
cost: { minutes: 1, tokens: 2185 }
id: l-77fef775
scope: repo
status: active
src: agent
touches:
  - server/src/vigie_pipeline/processor.py
  - server/src/vigie_pipeline/overrides.py
  - server/src/vigie_pipeline/prune_exclusions.py
  - server/tests/pipeline/test_identity_links_single_module.py
---

## Decided
Retired-MAC pruning is irreversible, so "cannot tell" means "prune nothing": it needs a readable, supported overrides.db with text device ids, re-checked at commit.

Three design points:
- Re-check `PRAGMA data_version` plus the file's st_dev/st_ino on a connection opened for the prune alone. `identity_version` misses names, marks, merges and incident decisions; a shared connection's open cursor freezes it.
- The age clock is a server-side stamp written at each retirement, on a time every collector's newest batch corroborates. A collector timestamp, or one collector following a server clock step, proves nothing.
- Every batch must be shown processed: identity-check the batch mark and each collector's cursor against a real row, because retention reuses rowids and strands cursors.

## Watch out
A guard test that passes with its guard deleted guards nothing: mutate each one.
