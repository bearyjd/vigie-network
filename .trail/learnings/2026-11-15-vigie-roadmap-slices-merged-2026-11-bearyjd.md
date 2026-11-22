---
title: "Vigie roadmap slices merged 2026-11-15: how the review and merge loop actually ran, and what to watch"
author: Bearyjd
date: 2026-11-15
branch: main
cost: { minutes: 22, tokens: 30500 }
id: l-b64766ed
scope: repo
status: active
src: agent
touches:
  - api/openapi.yaml
  - docs/api.md
  - docs/monitoring.md
  - server/src/vigie_api/evidence_determinations.py
  - server/src/vigie_api/models.py
  - server/src/vigie_api/monitoring.py
  - server/src/vigie_api/pilot_report.py
  - server/src/vigie_api/ui/views.js
  - server/src/vigie_pipeline/delivery_plan.py
  - server/src/vigie_pipeline/delivery_publish.py
---

## Decided
Merged to main this session: replay harness, tod evidence keys, GUI events timeline, probes status route, and F5 slices S0 (engine scoping), S1 (delivery allowlist with frozen incidents), S2a (new_device plumbing), plus F6-a (essential-device marking, overrides migration v10). Owner accepted the design-note recommendations for F5/F6/F7. Nothing is deployed; the pilot freeze (policy versions f2326b78a328 / eb1f1e88) holds until the day-14 evaluation around 2026-11-28. A small script waits for CI and merges pinned to the exact head (gh pr merge --match-head-commit); a merge conflict or a new push changes the head, so wait for fresh green.
Codex and the Opus reviewer found different real bugs on the same diff almost every round; each fix round introduced the next problem in the same area, so a Fable review of the WHOLE change (not just the last patch) after the third round with findings was worth it.

## Tried and ruled out
Trusting the executor's own test counts: several "full suite passed" claims were made before the last edit; CI on the exact head is the authority. Reusing monitoring incidents for new detectors without first scoping the upload engine: it would have auto-resolved and superseded them and sent "back to normal" messages. Deriving the exclusion of new_device from delivery metrics by joining the incident row: delivery rows carry no detector, so pruning the incident orphaned them; fix was to keep non-upload incidents until their delivery rows are gone.

## Watch out
In the code: sub-agents refuse to push branches unless the brief says they may; a coordinator relay does not count. Codex review often cannot finish the Python tests in its sandbox, so its "clean" is weak evidence. The Rust wrapper_shutdown pid_only_stop test is a known CI flake: rerun the failed job. Do not mount quadlet file names as podman volumes (the real names are vigie_standby_inv / _overrides); that created stray empty volumes on the pilot VM. ingest and pipeline on the pilot VM restarted once at 2026-11-15 00:34Z after healthchecks timed out; watch for a repeat before trusting the day-14 verdict. F5 S2b (the sweep that creates new_device incidents) has hard preconditions recorded in the F5 design addendum: opaque incident id, once-per-device-life guard, close-on-review, bounded allowlist backlog.
