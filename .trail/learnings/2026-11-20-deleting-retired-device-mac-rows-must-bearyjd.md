---
title: "Deleting retired-device MAC rows must fail closed, and what a safe prune has to guard against"
author: Bearyjd
date: 2026-11-20
branch: main
cost: { minutes: 1, tokens: 2185 }
id: l-77fef775
scope: repo
status: active
src: agent
touches:
  - server/src/vigie_pipeline/processor.py
  - server/src/vigie_pipeline/overrides.py
  - server/tests/pipeline/test_identity_links_single_module.py
---

## Decided
Retired-MAC pruning only runs when the owner-decisions database exists, opens read-only, is at exactly the supported schema version and has every table the protected-device query needs. Anything else skips the prune and logs it. Deletion is irreversible and the owner's names, merges and essential marks hang off those rows, so "cannot tell what is protected" must mean "prune nothing", never "protect nothing". Of two overlapping PRs for the same finding, the one with a batch cap, a counter and owner-decision protection was kept over the one that failed main's guard test.

## Tried and ruled out
Treating a missing or empty owner-decisions file as "nothing protected": three independent reviewers reproduced deletion of protected rows that way (missing file, zero bytes, older schema, newer schema, a dropped table). Trusting a clean GitHub merge status: a PR can merge cleanly while main's guard test (only the overrides module may name identity_links) fails on the merge result, so merge main in and run that test before pushing.

## Watch out
Any prune of per-device evidence has to answer these, and the first version of this one did not: the owner-decisions read lives in a different database from the delete, so re-check it inside the delete transaction or a decision committed in between loses its rows; the age cutoff must come from server time, because a collector timestamp is untrusted and a clock step expires rows early for good; a device that returns while a prune is pending should revive its old id, so process sightings before pruning; the new-device notice cursor stalls if the row it points at is pruned; incident decisions, merges and candidate decisions also reference devices and belong in the protected set; per-MAC side tables keep rows unless pruned with it. Judge a guard test by removing the guard: most of the first round's tests passed with their guard deleted.
In the code: server/src/vigie_pipeline/processor.py (prune step), server/src/vigie_pipeline/overrides.py (protected-device query), server/tests/pipeline/test_prune_guards.py (one test per guard), server/tests/pipeline/test_identity_links_single_module.py (the guard that failed on merge).
