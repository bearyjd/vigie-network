# Identity stitching: simplification design (branch `simplify/stitching`)

Replaces the machinery accreted over nine review rounds on `fix/stitching-review` (033298d) with a
smaller design whose bounds hold **by construction**. Behaviour (what attaches, what is vetoed,
what is suggested) is unchanged except where section 7 says so. `docs/stitching.md` is the user
facing description; this file is the design rationale and the deletion list.

## 1. Invariants (unchanged)

- **T1** A MAC gets `link_source='rule'` ONLY under an active `identity_rules` row of `overrides.db`
  (non-blank `created_by`, not revoked, not expired) whose target has an explicit group with
  `auto_inherit=1`, both devices `identity_state='ok'`; rule, expiry, revocation and group are
  re-read from `overrides.db` under the inventory write lock immediately before the write. Every
  fingerprint/heuristic path only produces a pending suggestion. Human-ness of a rule is only
  enforceable by the (future) rule API.
- **T2** The pipeline never writes `overrides.db`, never detaches or unlinks (`rule_attach_suspect`
  is an event only).
- Idempotent passes; one cursor-based pipeline; fail closed on an unreadable `overrides.db`;
  parameterized SQL; no secrets in events/logs (short hashes only).

## 2. Data flow: two phases per `run_once`

```
batches -> observations/devices (unchanged)        [BEGIN IMMEDIATE per batch, as on main]
        -> mac_activity, mac_first_received, evidence_gaps   (fold; bounded per MAC)
COMPUTE  read-only transaction (BEGIN ... COMMIT, WAL reader, never blocks writers)
         robin over <= MACS_PER_PASS self MACs  + robin over <= MACS_PER_PASS rule-attached MACs
         each subject -> bounded Neighbourhood -> Decision (frozen dataclass) or Deferral(reason)
PREPARE  resolve snapshot human-decision IDs through inventory primary keys to pair outcomes,
         outside the inventory write transaction (including decisions on expired suggestions)
APPLY    BEGIN IMMEDIATE, count-bounded (section 4), <~1 s:
         for each decision re-validate inventory-side preconditions with indexed point lookups;
         immediately before each attach write, PRAGMA data_version on the pipeline's overrides
         connection must equal the snapshot's (never cached); drop stale ones; write.
```

The pipeline is the ONLY writer of the tables the decisions read (`observations`, `devices`,
`mac_activity`, `identity_candidates`, `suggestions`, `rule_attachments`); ingest writes only
`batches`/`collectors`. So between COMPUTE and APPLY only `overrides.db` (the API) and a future
human `identity_candidates.state='dismissed'` can change: both are re-read under the lock.

### Neighbourhood (one per subject, read phase)
A fixed set of indexed lookups, each `LIMIT BUCKET_ROWS + 1` ordered by `last_seen DESC`
(`idx_obs_fp_host`, `idx_obs_fp_mdns`, `idx_obs_fp_first`, `idx_obs_device`):
own name keys (fp, vc, hostname | mdns), target component MACs, target known-name keys (<=
TARGET_KEYS), per rule view: name keys and the "first seen within one gap" range. A lookup that
returns `BUCKET_ROWS + 1` rows marks the neighbourhood **truncated**. Because every MAC with
activity in retention has `last_seen` within retention, a complete (not truncated) lookup contains
every peer that can overlap AND every older identity of that signature (there is no separate
"historic" lookup, no HISTORIC_MATCH_LIMIT). Activity for the neighbourhood MACs is read by primary
key (<= INTERVALS_PER_MAC rows each, enforced at write time, section 3).

### Decision kinds (COMPUTE output)
`Attach(mac, from_device, target, rule, score, evidence, views)`, `Candidate(from, into, score,
evidence, state, withdraw: bool)`, `Suggest(from, into, score, evidence, reason_code, reason_text,
signals)`, `Event(kind, device, token, summary, severity)`, `Widen(src, dst)`. Each carries the
preconditions APPLY re-checks (section 4).

### One uncertainty rule
Whenever evidence is incomplete the subject DEGRADES, never attaches, never gets a silent veto:

| cause | rule path | candidate path | recheck |
|---|---|---|---|
| neighbourhood truncated / target component > ALIAS_IDS / > TARGET_KEYS | `rule_hit_needs_confirm` suggestion with `reason_text=<reason>` | candidate `open`, no suggestion | `rule_attach_suspect` ("evidence incomplete") |
| evidence gap overlaps the MAC's window | same | (maturity only matters for a permanent veto: `open`) | n/a |
| malformed rule on the target | same (`malformed_target`) | n/a | n/a |
| young / sparse MAC (immature) | the rule path defers silently; the candidate path still runs exactly as without a rule (a `fingerprint_match` suggestion or an `open` row) | `open` if overlapping | n/a |
| name group / compatible pool flooded | nothing + `signature_flood` once per group per day | nothing | pool ignored |
| compute time budget hit | subjects not reached wait; robin cursor persists | same | same |
| row cap / suggestion cap hit | decision dropped, recomputed next cycle | same | n/a |

Every degrade except "immature" also writes one `stitch_deferred` event per reason per UTC day.

## 3. Bounds (all constants in `config.py`)

| constant | value | bounds |
|---|---|---|
| `MACS_PER_PASS` | 256 | subjects examined per robin per pass (self robin, recheck robin) |
| `STITCH_COMPUTE_BUDGET_S` | 5 | wall time of COMPUTE (read-only); stops between subjects |
| `RECHECK_BUDGET_SHARE` | 0.5 | the re-check robin's share of it (checked between subjects and per lookup inside one; overrun bounded by one lookup plus the cut subject's evaluation); the self robin gets the remainder |
| `BUCKET_ROWS` | 1024 | rows per indexed lookup; more = truncated = degrade |
| `TARGET_KEYS` | 16 | distinct (fp, vc, name) keys of a target identity; more = degrade |
| `INTERVALS_PER_MAC` | 64 | rows of `mac_activity` per MAC, enforced at fold time (closest pair coalesced) |
| `PRUNE_BATCH_ROWS` | 1000 | per retention pass: activity rows deleted, gap rows deleted, and old receipt anchors examined, each separately limited and transacted; remainder on later passes |
| `MAX_ALIAS_IDS` | 5000 | merge component expanded; more = degrade |
| `MAX_SIGNATURE_BUCKET` | 64 | live self MACs per name group / compatible pool before flood |
| `MAX_ROWS_PER_PASS` | 200 | candidate + suggestion rows written per APPLY |
| `MAX_ATTACHES_PER_PASS` | 20 | attaches per APPLY (each <= ~12 statements + orphan cleanup) |
| `MAX_OPEN_SUGGESTIONS_PER_DEVICE` | 64 | open merge suggestions INTO one device; limits pending suggestions |
| orphan cleanup | `CLEANUP_ROWS_SHARE` x `MAX_ROWS_PER_PASS` | suggestion expiries + candidate dismissals per pass (keyset cursors, decided ids skipped in Python); `Settle` decisions finish the rest |
| gaps | retention / gap_s (~2016) | gaps in the retention window, merged within `activity_gap_s` at write time; expired backlog drains in bounded batches |

Lock hold (APPLY) is therefore `<= MAX_ROWS_PER_PASS + MAX_ATTACHES_PER_PASS * (12 + 64 + 2) +
widen + events` point writes, about 2,000, with bounded index pages. Each orphan cleanup call
fetches at most the remaining write allowance + 1 rows per direction, at most `2 * (limit + 1)`
rows total, through direction/id expression indexes. Expired and decided rows are skipped in
Python; each direction's persistent id cursor advances past every examined row. Decided rows
remain untouched; accumulated history takes additional passes. This read bound is per orphan
call; cleanup writes share the pass's row cap. Interval coalescing is conservative: bridging a
MAC's own silence only ADDS presence (more overlap, never less), and maturity is anchored on the
server clock, so it cannot help an attacker.

Candidate dismissal and its remaining-work probe use partial indexes on both endpoints with
`WHERE state IN ('open','suggested')`; dismissed history is absent from these indexes. Retention
pruning uses expiry indexes with count limits, and a received-time/MAC cursor bounds anchor
examination even when old anchors still have activity. Each retention transaction handles at most
`PRUNE_BATCH_ROWS` rows (plus cursor bookkeeping); later passes drain accumulated expired rows.
Suggestion-pair lookup checks prepared human outcomes in memory, otherwise seeks an unexpired
row by `(action, device_ids, expires_at)` with `LIMIT 1`; expired undecided rows add no scan work.
Preparing human outcomes costs one inventory primary-key probe per snapshot decision, outside
the writer lock; no overrides reads move inside that transaction.

## 4. APPLY preconditions (indexed point lookups)
- Every pair decision carries `expected`, the pair's candidate state at compute time; APPLY
  re-reads the row and drops the decision when it differs (a human dismissal in between).
- Attach: `observations.mac` still `('self', from_device)`; both `identity_state='ok'`; the
  rule unexpired at the clock read under the lock; the pair's candidate state unchanged; and
  overrides.db NOT written since the snapshot (`PRAGMA data_version` on the pipeline's connection,
  recorded in the snapshot, equal under the lock). Any write to overrides.db in between (a merge,
  a new, revoked or malformed rule, a regroup) drops every attach of the pass; they are recomputed
  against a fresh snapshot next pass. O(1) under the lock, whatever the size of overrides.db.
- Candidate: row re-read; identical or sticky (`dismissed`, `vetoed`) rows are not written.
- Settle: an orphan's remaining candidate rows are dismissed under the pass's row cap.
- Suggest: no open/decided suggestion for the pair; devices not linked; target below the cap.
- Event: `INSERT OR IGNORE` on `(kind, dedup)`.

### Intentional redundancy on the trust path
Two guards are kept although a mutation check cannot kill them in isolation: the APPLY phase
re-checks the snapshot's T1 facts for an attach (rule active, canonical target, explicit
`auto_inherit=1` group) although the decision was computed from that same snapshot and
`data_version` catches every change to it; and the compute phase caps `Widen` decisions at
`MAX_ROWS_PER_PASS` although APPLY reserves each under the same cap. Defence in depth on T1 and a
memory bound on the decision list; not candidates for removal.

## 5. Deleted (with the defect each removal closes)
- `mac_last_seen` + trigger, `active_macs` paging, `MAX_ACTIVE_MACS` newest-first cap (defect 1, 6).
- `mac_collectors`, per-collector gap scoping, `MAX_GAPS_PER_COLLECTOR` (defects 2, 3): one merged
  gap list for any collector. Availability cost: a late backlog from ANY collector defers rule
  attaches for every MAC whose window overlaps the gap (they become `rule_hit_needs_confirm`).
- Two-stage core/bulk loader, `STITCH_SETUP_MAX_SECONDS`, `partial`, per-phase `MAX_OVERLAP_OPS`
  and time-box slices, `BudgetExhaustedError`, `_charge` (defect 4, lock hold).
- `widen_linked_devices` unbounded UPDATE loop (defect 5): now `Widen` decisions under the row cap.
- `HISTORIC_MATCH_LIMIT`, `MAX_FLOOD_EVENTS_PER_PASS` + `signature_flood_summary`, the old
  `_settle_*` loop (a bounded `Settle` decision with the same `settle:<device>` key replaces it,
  fix round 1), `legacy` anchors, `evidence_gap`/`stitch_budget_exhausted`/
  `stitch_active_set_capped`/`alias_component_oversize` events (replaced by `stitch_deferred`).
- Migrations 4..11 squashed into ONE migration (#4). Main's pipeline schema (v3) has no stitching
  table and no anchor of any provenance, so no legacy heuristics are needed.

## 6. Migration plan
Pipeline migration 4 (additive, on top of main's v3): `mac_activity`, `mac_first_received`,
`evidence_gaps`, `rule_attachments`, `stitch_state`, `events.dedup` + unique index, candidate
indexes (including partial open/suggested endpoint indexes), the receipt-time/MAC anchor index,
suggestion indexes (`idx_suggestions_pair`, expiry index on
`json_extract(device_ids,'$[1]')`, and direction/id expression indexes
`idx_suggestions_from_id` / `idx_suggestions_into_id`), observation indexes (`idx_obs_fp_host`, `idx_obs_fp_mdns`,
`idx_obs_fp_first`, partial `idx_obs_rule`). Tests: upgrade from a populated main v3 database;
fresh install; reapply is a no-op.

## 7. Behaviour deliberately changed
1. A rule hit with incomplete evidence (gap, truncation, oversize component, malformed target) is
   a `rule_hit_needs_confirm` suggestion (reason_text names the cause) instead of a silent defer
   with a per-collector event. The human decides; nothing attaches.
2. Evidence gaps are not scoped per collector (section 5).
3. At most `MAX_OPEN_SUGGESTIONS_PER_DEVICE` open merge suggestions into one device; more wait
   (daily `stitch_deferred suggestion_cap`). Limits pending suggestions; historical cleanup uses
   bounded index pages and persistent cursors.
4. Recheck with incomplete evidence flags the attachment (`rule_attach_suspect`, once) instead of
   silently skipping: a spray of look-alikes around a rule-attached MAC is itself suspicious.
5. `mac_activity` keeps at most 64 intervals per MAC (coalescing, conservative).
6. Subjects are examined round-robin, `MACS_PER_PASS` per pass; on a flooded network a legitimate
   roll may wait several passes for its attach (visible as `stitch_deferred budget`).

## 8. Threat table (attacker action -> bound/defence -> test)
| attacker action | defence | test |
|---|---|---|
| copy fingerprint+name while victim present | union overlap veto, tail, lead, widening | veto_overlap: `test_sustained_overlap_is_vetoed_once_with_no_suggestion`, `test_tail_lead_attacker_is_vetoed_not_attached` |
| back-dated / future / sparse stamps to mature | stamp window, server anchor, clipping, covered time | maturity_activity: `test_backdated_first_batch_cannot_mature_a_mac_beside_the_present_device` |
| rename / change fingerprint after attach | attach-time evidence + per-rule views | evidence_recheck: `test_renaming_an_attached_copy_cannot_hide_a_later_overlap` |
| merge the vetoed target away | alias resolution through full chain, cycle-safe | veto_overlap: `test_a_permanent_veto_survives_its_target_being_merged` |
| extra names on the applicant | rule views only | veto_overlap: `test_an_extra_applicant_name_cannot_exclude_the_real_device_from_the_veto` |
| nameless/junk MAC veto or flood | compatible pool rules, retired excluded | veto_overlap: `test_a_nameless_mac_is_a_peer_only_within_a_gap_of_the_candidate` |
| 1000+ look-alikes to hide the victim | truncation -> degrade, never attach | bounds_perf: `test_a_spray_beyond_the_bucket_bound_degrades_to_a_suggestion_never_attaches` |
| spray to switch off the recheck | recheck robin over attached MACs only; truncation flags | bounds_perf: `test_a_spray_of_self_macs_does_not_delay_the_recheck`; evidence_recheck: `test_a_recheck_that_cannot_gather_complete_evidence_flags_the_attachment` |
| hold the write lock | APPLY count-bounded, reads outside the lock | bounds_perf: `test_apply_holds_the_lock_under_a_second_with_a_full_action_list` |
| dismissed history on either candidate endpoint | partial open/suggested endpoint indexes also serve remaining-work probes | bounds_perf: `test_candidate_cleanup_ignores_settled_endpoint_history`, `test_candidate_cleanup_production_queries_use_partial_endpoint_indexes` |
| expired suggestion history on a repeatedly suggested pair | expiry range seek with `LIMIT 1`; resolve historical human decisions before APPLY's write transaction | bounds_perf: `test_merge_pair_lookup_ignores_expired_undecided_history`, `test_apply_pair_history_and_unrelated_decisions_stay_outside_writer_lock` |
| accumulated expired activity, gaps and receipt anchors | count-limited indexed batches, separate transactions, anchor cursor advances past retained rows | maturity_activity: `test_purge_large_backlog_uses_bounded_transactions_and_eventually_finishes` |
| different fold/Unicode version after interrupted backfill | cursor target is persisted; mismatch/missing target restarts all rows before publishing completion | migrations: `test_interrupted_fold_recompute_restarts_when_target_version_changes` |
| unbounded memory/CPU | BUCKET_ROWS, INTERVALS_PER_MAC, MACS_PER_PASS, compute budget | bounds_perf: `test_compute_budget_stops_between_subjects_and_the_cursor_persists` |
| late-collector gap restores maturity | one gap list, retention-pruned, all loaded | maturity_activity: `test_a_mac_whose_window_overlaps_a_gap_is_not_mature` |
| human merges 100k devices | links read outside the lock; widen under the row cap | bounds_perf: `test_widening_is_count_bounded_per_pass` |
| malformed rule on the target | target becomes suggestion-only; an unreadable target makes every hit suggestion-only | attach_rules: `test_a_malformed_rule_on_a_target_turns_a_valid_attach_into_a_suggestion`, `test_a_malformed_rule_whose_target_cannot_be_read_makes_every_rule_hit_a_suggestion` |
| 65 compatible junk MACs around an attached copy | flooded pool = incomplete evidence: flag / confirm | evidence_recheck: `test_a_flooded_compatible_pool_cannot_suppress_the_suspect_flag` |
| dismiss a pair between COMPUTE and APPLY | candidate-state preconditions | attach_rules: `test_a_dismissal_between_compute_and_apply_cancels_the_attach` |
| 1000 candidate rows on an attaching orphan | cleanup under the row cap + `Settle` | attach_rules: `test_the_cleanup_of_an_orphans_candidate_rows_is_budgeted_and_finishes_later` |
| grow overrides.db to lengthen the lock | point lookups only under the lock | attach_rules: `test_the_lock_time_revalidation_does_not_depend_on_the_size_of_overrides` |
| 30k old attachments to switch the re-check off | recheck robin with persisted cursor | evidence_recheck: `test_the_recheck_robin_cycles_through_every_attached_mac` |

## 9. Tests: deleted or replaced (by file)
`test_stitching.py`, `test_stitch_rules.py`, `test_stitch_perf.py` and `test_stitch_review.py`
.. `test_stitch_review7.py` are replaced by six topic files (`test_stitch_attach_rules.py`,
`test_stitch_veto_overlap.py`, `test_stitch_evidence_recheck.py`,
`test_stitch_maturity_activity.py`, `test_stitch_bounds_perf.py`, `test_stitch_migrations.py`)
sharing `stitch_helpers.py`. Every behavioural assertion was carried over; the tests below were
dropped because the machinery they pinned no longer exists:
- per-phase work budgets, time-box slices and the setup cap (`MAX_OVERLAP_OPS_PER_PASS`,
  `STITCH_MAX_TXN_SECONDS`, `STITCH_SETUP_MAX_SECONDS`, `BudgetExhaustedError`, `_charge`,
  `FakeTime`/`Ticking` clocks, `partial` setups, "only the re-check ran", "budget event names the
  phase", "withdrawals charged before the first update", "lookups charged to the budget");
- the active-set cap and the trigger-kept summary (`MAX_ACTIVE_MACS`, `mac_last_seen`,
  `active_macs` paging, "newest first", "enumeration never touches stale rows");
- per-collector gaps and `mac_collectors` ("a gap of a collector that saw neither side does not
  block" is the one behaviour deliberately given up; `MAX_GAPS_PER_COLLECTOR`, the per-collector
  `evidence_gap` event: replaced by `stitch_deferred (evidence_gap)`);
- legacy anchors and the migration 6..11 shapes (there is one migration; main has no anchors);
- the old settle loop's tests (the cleanup is now a `Settle` decision under `CLEANUP_ROWS_SHARE`
  of the row cap, with its own tests);
- `HISTORIC_MATCH_LIMIT` ("historical matches are limited oldest first": a complete bucket holds
  every older identity, a truncated one degrades);
- the per-pass flood event cap and `signature_flood_summary`;
- the read-time interval cap ("keeps the newest intervals", "cap cannot launder a veto": the cap is
  now at fold time and only adds presence; sticky vetoes keep their own tests);
- in-memory map bookkeeping after an attach (`_moved`, cache resets, "undecided MACs first");
- the legacy re-check fallbacks for attachments without a `rule_attachments` row or without stored
  views (a missing row is now itself flagged).
`tools/trafficgen/tests/test_stitching.py` is kept verbatim and passes unchanged.

## 10. Behaviour deliberately changed (addendum)
7. A candidate subject whose neighbourhood is truncated writes nothing (the oldest identity may
   be hidden) and raises the daily `stitch_deferred (truncated)` event.
8. A rule-attached MAC without a `rule_attachments` row is flagged `rule_attach_suspect` (evidence
   missing) rather than re-checked against guessed names.
9. (fix round 1) A compatible pool over `MAX_SIGNATURE_BUCKET` degrades the rule hit to a
   `rule_hit_needs_confirm (compatible_flood)` suggestion instead of attaching nothing silently, and
   flags a re-checked attachment as incomplete evidence.
10. (fix round 1) A decision whose pair's candidate row changed between COMPUTE and APPLY is
    dropped (`stats.stale`), not applied.
11. (fix round 1) Any commit to overrides.db between the snapshot and APPLY drops every attach of
    that pass (`PRAGMA data_version`), closing merge/veto laundering, late second rules and late
    malformed rules at once. The point lookups of the first fix commit were replaced by this O(1)
    check.
16. (round 4) `fold` is a fixpoint (NFKC, casefold, NFKC; property-tested over the BMP and all
    special x combining pairs); `Hood.add_name` takes an already-folded key and never folds again;
    stored folds carry a version marker (`pipeline_meta.fold_version` = `FOLD_VERSION/unidata`)
    and are recomputed, chunked and resumable, when it changes. The cursor's target version is
    persisted separately; a missing/different target restarts at the beginning, and only a full
    traversal publishes that target as complete. The orphan cleanup pages by keyset
    and skips decided ids in Python (cost independent of the number of decisions).
15. (round 3) The known-name clause folds with `fold` (a lint test bans every other fold); a
    re-check cut by the budget is judged on everything gathered and flagged with its own reason;
    the fold back-fill skips empty names; the clock is re-read before each attach write; flood
    tokens hash a JSON key; decided suggestions were excluded in SQL from the orphan cleanup window
    (superseded by round 4's Python filtering and bounded direction/id pages).
    Mutation survivors kept as equivalent pairs: the `target_keys` flag is set both by
    `Hood.add_target` and `Hood.known_names` (either alone degrades the hit), beside the two
    intentional redundancies above.
14. (fix round 2, opus) Names are compared through ONE fold (NFKC + Unicode casefold) stored in
    `observations.hostname_fold`/`mdns_fold` (pipeline-written, back-filled at upgrade); the compute
    budget ticks per lookup inside a subject (a cut subject is deferred or flagged, the cursor
    moves past it); the re-check always evaluates the overlap it can see; any malformed rule makes
    every rule hit suggestion-only; the orphan cleanup keeps `CLEANUP_ROWS_SHARE` of the row cap and
    also settles rows where the orphan is the target; flood tokens use the 128-bit hash.
13. (fix round 2) `data_version` is re-read immediately before every attach write; the orphan's
    suggestion expiry is under the row cap (`Settle` finishes it); the re-check also flags an
    attachment whose rule is no longer active or whose device left its `auto_inherit=1` group
    ("rule or group no longer authorises this attach", event only).
12. (fix round 1) A re-checked attachment is flagged once per REASON (`evidence incomplete`,
    `sustained overlap`, `evidence missing`); a later different reason raises a fresh flag. Dedup
    tokens carry a 128-bit hash of the MAC.
