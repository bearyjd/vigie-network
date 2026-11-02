---
title: "Vigie soak 2 started 2026-10-31: expired metrics grant was the blocker, drops gate redesigned"
author: Bearyjd
date: 2026-10-31
branch: main
cost: { minutes: 28, tokens: 638171 }
touches:
  - docs/datasets.md
  - server/src/vigie_api/dataset_cli.py
  - server/src/vigie_api/dataset_writes.py
  - server/src/vigie_api/schema.py
  - server/tests/api/test_api_schema.py
  - server/tests/api/test_dataset_decide.py
  - server/tests/pipeline/test_identity_version.py
  - server/tests/api/test_dataset_cli.py
  - server/tests/api/test_dataset_writes.py
  - deploy/persistent/run_soak.py
---

## Decided
- Soak 1's missing/invalid metrics were NOT a router bug: the metrics key only works while /etc/vigie-metrics/expiry (one line: boot_id issued expires issued_up expires_up, window <= 194400 s) is valid. It had expired. Reissue with the admin key (couvre-feu-admin, passphrase-protected; the user loads it with ssh-add), 53 h, and keep the old file as expiry.prev-*.
- dropped_batches gate now = drops RECEIVED SINCE RUN START (API param dropped_since, field dropped_batches_since; PRs #42), because the old retained-window total is capped (>10000 rows) and poisoned for a week after the outage.
- Deployed only the API image (localhost/vigie-server:main-0def191); pipeline and ingest stay on the old image because the pipeline reads overrides.db read-only with no schema check. Overrides is now v9: an older API image refuses to start, so rollback needs the pre-v9 tar in ~/.cache/vigie-deploy-backup.
- Soak 2 started 2026-10-31 18:49 UTC, unit vigie-monitoring-20261024-soak-v3.service, journal real-48h-r2. 48 h ends about 2026-11-02 18:49 UTC; metrics grant lapses 2026-11-02 23:48 UTC.

## Tried and ruled out
- Baseline/window designs for the drops gate: any retention purge moved the window and failed the run, and the capped total is always withheld at steady state.
- Reusing the old journal dir: its stale first sample would set the run start days ago.

## Watch out
- Every fix round on the soak gate introduced a regression the next review caught (once a critical: later samples did not get the run start). Keep the loop tests that assert every collect gets the same T0.
- The ssh-add agent was empty yet the admin ssh worked in this shell; do not assume which credential was used.
