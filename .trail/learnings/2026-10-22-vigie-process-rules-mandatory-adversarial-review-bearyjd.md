---
title: "Vigie process rules: mandatory adversarial review"
author: Bearyjd
date: 2026-10-22
branch: main
cost: { minutes: 1, tokens: 1216 }
touches:
  - server/src/vigie_pipeline/stitch.py
  - docs/stitching.md
---

PROCESS (owner rule, 2026-10-22): an ADVERSARIAL REVIEW is a mandatory step of every change, never optional. Author agent -> separate independent opus security-reviewer in a git-archive export under $HOME/.cache (assume author wrong; mutation-test every guard; PoCs in a separate scratch dir) AND a Codex adversarial pass (/codex challenge) -> fix round -> orchestrator re-runs suites from a clean export -> repeat until MERGE -> only then merge. Before any merge: `git diff --name-status main...branch | grep ^D` must be empty. Never review or test inside an agent worktree.
WHY it matters: stitching took 4 review/fix rounds; each round found real veto bypasses (sparse copy, bad timestamps, partial-match peers, tail-lead, budget starvation) that the author's own tests missed. Test-weakening in fix rounds (loosened assertions) must be checked by the reviewer.
TRUST BOUNDARY: a MAC attaches only under an active identity_rule (non-blank creator) into an explicit auto_inherit=1 group; heuristics only suggest; the pipeline never writes overrides.db and never detaches (rule_attach_suspect is event-only). Human-ness of rules is enforced ONLY by the API, which must be the sole writer of identity_rules and must reject non-human principals.
