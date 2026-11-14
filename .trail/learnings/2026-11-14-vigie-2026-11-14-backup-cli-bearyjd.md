---
title: "Vigie 2026-11-14: backup CLI fixed for SQLite 3.40 and verified in the production image"
author: Bearyjd
date: 2026-11-14
branch: main
cost: { minutes: 24, tokens: 80417 }
touches:
  - deploy/tests/check_refs.py
  - deploy/persistent/probe_runner.py
  - deploy/tests/test_probe_runner.py
  - docs/deploy.md
  - server/src/vigie_pipeline/backup.py
  - server/tests/test_backup_round3.py
---

## Decided
#99 dropped PRAGMA trusted_schema=OFF from vigie-backup's _harden(): on the production image (Debian SQLite 3.40.1) it made integrity_check fail on the real inventory schema (json_extract expression indexes are not innocuous before 3.45); a split rule is impossible (verify of our own backups fails under OFF too). Hostile-image bound is defensive mode + value limit + progress budget + RLIMIT_CPU + memory cap. Acceptance = build the image from the PR head, load it on the VM, run backup + verify against the live volumes in a one-shot container (rc 0/0).
## Tried and ruled out
Trusting CI/dev tests for SQLite behaviour: they run 3.50. A regression test can only assert OFF is never set (spy) and a skip-marked old-SQLite test.
## Watch out
Docs edits that add command examples need `check_refs.py --release` run AFTER the edit (it rejected a podman --network flag; THIRD_PARTY_FLAGS now has it). CI server-stage failures seen locally (rate-limit tests, 4 'uncapped beyond 10000 rows' tests) were load/environment: CI was green.
