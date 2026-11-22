---
title: Build monitoring detectors before the field pilot matures
author: Bearyjd
date: 2026-11-22
branch: feat/dns-volume-baseline
id: l-3001f9f8
scope: repo
status: active
src: agent
touches:
  - docs/monitoring.md
  - server/src/vigie_pipeline/monitoring_dns.py
  - server/src/vigie_pipeline/monitoring_engine.py
  - server/src/vigie_pipeline/monitoring_identity.py
  - server/src/vigie_pipeline/processor.py
  - server/tests/pipeline/test_monitoring_dns.py
---

## Decided
Build and merge monitoring detector code through fixture-driven TDD, independent adversarial review, and CI on the reviewed commit. Field qualification stays an activation and evaluation gate because replay fixtures can verify implementation and migration behavior while the live pilot gathers maturity, precision, coverage, and delivery evidence. The owner will tune detector settings after the build.
## Tried and ruled out
Waiting for the upload pilot to mature before wiring the DNS detector delayed source delivery because it required live observations to start work already testable with fixtures. The owner directed us to build the capability first.
## Watch out
In the code: dns_deviation uses a separate policy, stays off by default, and requires qualified observations for scoring. Enabling the detector or changing the live pilot needs operator action. VIGIE_MONITORING_DNS_MIN_QUERIES is the operator-adjustable median floor.
