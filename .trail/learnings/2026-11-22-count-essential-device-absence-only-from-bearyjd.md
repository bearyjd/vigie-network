---
title: Count essential-device absence only from durable observed hours
author: Bearyjd
date: 2026-11-22
id: l-66d0ac9b
scope: repo
status: active
src: agent
touches:
  - docs/deploy.md
  - docs/monitoring.md
  - server/src/vigie_ingest/store.py
  - server/src/vigie_pipeline/README.md
  - server/src/vigie_pipeline/delivery_runner.py
  - server/src/vigie_pipeline/delivery_wiring.py
  - server/src/vigie_pipeline/essential_absence.py
  - server/src/vigie_pipeline/monitoring_engine.py
  - server/src/vigie_pipeline/processor.py
  - server/src/vigie_pipeline/schema.py
---

## Decided
Keep the full 168-hour setting by recording positive observation evidence and the latest active sighting while accepting a batch. Store a union of clean window seconds and a sticky veto for dirty overlaps. An hour needs both this evidence and ordinary clean coverage. Keep the evidence for the monitoring history period and keep the shared policy and coverage unchanged. A stale pass or withdrawn verdict defers queued notices without expiring their retry state.

## Tried and ruled out
Inferring a clean hour from surviving batch records misclassified hours after ingest retention removed the record of a drop. Moving the seven-day cutoff earlier to include clock allowances made accepted one-week settings unreachable. Removing essential absence from the delivery allowlist for one stale pass used the permanent disable path and expired notices that should have retried.

## Watch out
Record evidence in the accepted receipt transaction. Expiry of raw or receipt data must not erase a dirty-hour veto. A durable set of outstanding receipts avoids repeated scans and counters coupled to other tables' retention. Historical coverage before activation cannot authorize alerts. Preserve known-clean versus unknown boundaries through flag toggles and mixed-version ingest. The older pipeline needs the pre-upgrade inventory snapshot for rollback. Re-verify the exact pushed revision.

In the code: `server/src/vigie_ingest/essential_evidence.py`, `server/src/vigie_pipeline/essential_absence.py`, `server/src/vigie_pipeline/delivery_runner.py`, `server/tests/pipeline/test_essential_observed_hours.py`.
