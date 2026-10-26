---
title: "Vigie DHCP fix, last-IP and GUI PRs landed: review loop lessons"
author: Bearyjd
date: 2026-10-26
branch: main
cost: { minutes: 30, tokens: 440961 }
touches:
  - docs/gui-preview.md
  - server/tests/api/test_gui_preview_fixround6.py
  - server/tests/conftest.py
  - tools/gui/preview.py
  - server/src/vigie_api/ui/app.js
  - server/src/vigie_api/ui/views.js
  - server/tests/api/test_gui_preview_fixround1.py
  - server/tests/api/test_gui_preview_fixround4.py
  - server/tests/api/test_gui_preview_fixround5.py
  - server/tests/api/test_gui_preview_native.py
---

## Decided
- Merged 2026-10-26: #15 last observed IP, #16 DHCP option-order collector fix, #17 read-only GUI + guarded preview manager. Nothing was deployed; the collector change and the GUI/last-IP image rollout still need a separate, user-approved rollout (schema 10 is forward-only: API first, then pipeline).
- Merge gate used: independent Opus security review + Codex review per PR, test-first fix rounds, hosted CI green on the exact head, then merge.

## Tried and ruled out
- Codex refuses attacker-framed prompts (cyber-risk safeguard); plain "correctness and robustness review" wording works. Codex also times out on wide scopes: keep it to one file/delta and ~20 tool calls.
- Auto-approval rejects Codex scratch tests that could reach the fixed GUI preview port 18745: test functions directly with temp dirs.
- Counting ageing by total age (not inactivity) in the DHCP assembler lost 62% of split-poll packets; the permanent split-replay property test (dhcp_split_prop*.rs) now guards this.

## Watch out
- Every fix round introduced at least one regression the next review caught: always re-review the NEW code, not only the old findings.
- DHCP parser residual risks: post-ACK stall truncation, TCP-DNS child pids, synthetic fixture only (needs a live read-only capture before deploy).
- GUI preview: the native end-to-end lane skips loudly in CI when the runner interpreter fails the trust chain; port 18745 browser QA and a real managed start were never run (the user's live preview holds the port).
