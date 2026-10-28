---
title: Claude owns DHCP option-order parser fix (fix/dhcp-option-order)
author: Bearyjd
date: 2026-10-25
branch: main
cost: { minutes: 11, tokens: 35412 }
touches:
  - collector/agent/src/dnsmasq.rs
  - ".omc/STATE.md"
---

## Decided
- Claude owns the DHCP option-order fix in worktree ~/.cache/vigie-wt-dhcp, branch fix/dhcp-option-order from main 721e586. User approved scope and Codex's design candidate on 2026-10-25.
- Files owned: collector/agent/src/dnsmasq.rs, collector/agent/tests/ (dhcp_*), docs touching the parser. Not touching the GUI worktree, tools/gui, or .omc/STATE.md and RESUME.md.
- Nothing is pushed, merged or deployed. The soak is untouched; merge and deploy wait until after 2026-10-27 13:00:47Z.

## Tried and ruled out
- The old fix/dhcp-tags worktree is stale and not a base.

## Watch out
- Parser guards must stay: MAC mismatch/taint, 256 pending, 4096-byte lines, 64 option entries, no association by transaction ID alone.
- Mandatory Opus security review plus Codex adversarial pass before any merge.
