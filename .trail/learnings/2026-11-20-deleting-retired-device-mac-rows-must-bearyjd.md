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
  - server/src/vigie_pipeline/prune.py
  - server/src/vigie_pipeline/overrides.py
  - server/src/vigie_pipeline/prune_exclusions.py
  - server/tests/pipeline/test_identity_links_single_module.py
---

## Decided
Retired-MAC pruning is irreversible, so "cannot tell" means "prune nothing": a readable, supported overrides.db with text ids, re-checked at commit.

- Re-check `PRAGMA data_version` plus the file's st_dev/st_ino on a connection opened for the prune alone; `identity_version` misses names, marks, merges and incident decisions.
- The age is a server stamp written at each retirement, never earlier than the newest batch receipt. The clock is the older of server time and the oldest non-revoked `collectors.last_sent_ts`: ingest keeps it as a never-purged running maximum within a skew window of server time.
- An owner's decision on a suggestion lives only in overrides.db keyed by suggestion id; protect the devices of the inventory row.
- We removed the batch-deferral machinery because proving no return is in flight kept failing review; a returning randomized MAC getting a new id is acceptable. An unread batch just skips the pass.

## Watch out
A guard test that passes with its guard deleted guards nothing: mutate each one.
