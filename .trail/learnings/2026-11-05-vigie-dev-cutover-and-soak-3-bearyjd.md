---
title: "vigie-dev cutover and soak 3 start (2026-11-05): what broke and what worked"
author: Bearyjd
date: 2026-11-05
branch: main
cost: { minutes: 183, tokens: 1196667 }
touches:
  - api/openapi.yaml
  - deploy/persistent/README.md
  - deploy/persistent/run_soak.py
  - deploy/tests/test_soak_adapters.py
  - docs/api.md
  - server/src/vigie_api/models.py
  - server/src/vigie_api/monitoring.py
  - server/tests/api/test_api_monitoring.py
  - server/tests/pipeline/test_pipeline_signals.py
  - deploy/.env.example
---

## Decided
- Cutover to vigie-dev worked: router flipped at 00:21:25Z (collector.conf edit via `cat tmp > conf` to keep owner/mode, pin2 = standby pin, backup .pre-cutover), first 200 on the standby at T0+9.5 min (collector backoff), no drops, backlog 0. Scripts per runbook step (router / Tower drain+backup+ship / standby restore) in the main thread, logged step by step in ~/.cache/vigie-dev-prep/CUTOVER-LOG.md.
- Soak 3 started 2026-11-05T02:01:19Z on vigie-dev (user vigie, unit vigie-soak.service). Router metrics grant window max 194400 s: reissue /etc/vigie-metrics/expiry right before the start. Needs host-side runner scripts from the SAME commit as the image.
- Server tests: use server/.venv (system python3 has an old Starlette, rate-limit tests fail on main too). Soak meter tests need a TMPDIR outside /tmp.

## Tried and ruled out
- Runbook Step 3 order (stop Tower ingest, then wait for the pipeline drain): fails when a batch arrived seconds before the stop, because a stopped ingest closes the raw shards (WAL gone) and the read-only pipeline can no longer read them. Drain FIRST with ingest running, then stop ingest.
- `podman logs <ns>_pipeline` after the stop: quadlet containers are removed on stop; read the journal (`journalctl --user -t <ns>_pipeline`).
- Running the soak with the Tower unit's `systemd-inhibit` wrapper on a headless service account: "Failed to inhibit: Access denied". Run python directly.
- Starting the soak before PR #76: the coverage summary is capped at 10000 batch rows (7 days retention = 10080), so ct_unmapped_* were unknown and no pass was possible. Fixed by ct_unmapped_exact.

## Watch out
- A stray `chmod 755 /home/vigie` on the VM loosened the home dir for ~2 min (restored to 750). Never chmod parent dirs to satisfy ancestor checks.
- Soak rules were left unchanged for soak 3 (DNS probe failures are isolated single samples; #73 now records failure causes). Decide any DNS-rule relaxation BEFORE a run, not after.
- ntfy on vigie-dev is deliberately enabled only after the soak ends; apt timers on the VM are disabled for the run and must be restored after.
