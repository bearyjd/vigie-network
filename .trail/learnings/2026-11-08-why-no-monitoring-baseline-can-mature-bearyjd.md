---
title: "Why no monitoring baseline can mature: every hour is flow_degraded + overlapping_window"
author: Bearyjd
date: 2026-11-08
branch: main
cost: { minutes: 28, tokens: 176559 }
touches:
  - docs/CONTRIBUTING.md
  - docs/prp/004-home-assistant-integration.md
  - deploy/persistent/soak.py
  - deploy/tests/test_soak_diagnostics.py
  - deploy/persistent/README.md
  - deploy/persistent/run_soak.py
  - deploy/persistent/ha_h0_check.py
  - deploy/tests/test_ha_sender.py
  - docs/monitoring.md
  - deploy/Containerfile
---

## Decided
Zero mature profiles on vigie-dev is not a cutover artifact. Via the read-only API (/coverage?collector_id=...&from_hour&to_hour&limit=200, soak token, 2 s between calls to avoid 429), every hour since 2026-10-25 on Tower and vigie-dev has qualified_seconds 0 with reasons flow_degraded + overlapping_window; earlier hours are missing. An hour counts only with qualified_seconds >= 3420 and no reasons.

## Tried and ruled out
Not the baseline family (pooled vs tod), not the vigie-dev image, not the cutover. Not a rate limit: the per-token limiter returned 429 when I called ~60 times fast; keep reads slow because the soak shares that token.

## Watch out
flow_degraded: measurements.py counts ANY non-zero ct_* key in truncated, and the collector puts ct_unmapped_flows there (present in 100% of soak samples), while the soak treats unmapped conntrack as a caveat. overlapping_window cause is UNVERIFIED (hypothesis: window start from monotonic clock vs end from wall clock, 1 s truncation overlap); confirming needs real batch windows, so do not open live raw shards. Decide whether unmapped conntrack should disqualify an hour before the 7-day pilot.
