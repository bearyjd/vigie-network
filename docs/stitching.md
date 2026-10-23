# Identity stitching (P2, pipeline only)

Implements PRP-001 section 8 in `server/src/vigie_pipeline/` (`stitch.py`, `stitch_compute.py`,
`stitch_apply.py`, `stitch_hood.py`, `stitch_types.py`, `stitch_db.py`, `activity.py`,
`snapshot.py`). It runs at the end of every `run_once`. The design rationale, the deletion list and
the migration plan are in [`stitching-design.md`](stitching-design.md); this file describes what
the code does today.

The rule is unchanged: the pipeline can **continue** an identity only under an active rule read
from `overrides.db`; everything else is a **suggestion** a human decides. The pipeline never writes
`overrides.db`, never creates a group or a trust level, never detaches, and never produces an
attachment without a matching active, non-blank-creator rule.

**Trust boundary.** The pipeline enforces exactly: "the rule is an active row of `overrides.db`
(not revoked, not expired) with a non-blank `created_by`, re-read under the inventory write lock
immediately before the attach". Whether the creator is a *human* is **not** checkable here
(`created_by` is only a principal name). That is enforced by the API alone: the rule-creation API
(not yet built) MUST be the sole writer of `identity_rules` and MUST reject non-human principals.

## 1. Two phases per pass

```
COMPUTE  one read-only transaction (a WAL reader; never blocks ingest or the API)
         re-check robin: <= MACS_PER_PASS rule-attached MACs, from a persisted cursor
         self robin:     <= MACS_PER_PASS randomized self MACs, from a persisted cursor
         each subject -> bounded neighbourhood -> one DECISION or a deferral
APPLY    one BEGIN IMMEDIATE, count-bounded, no scans: re-validates every decision with indexed
         point lookups (the pair's candidate state; for an attach the rule, link, override and
         group rows of overrides.db by primary key), drops the stale ones, writes.
```

The pipeline is the only writer of the tables the decisions read (ingest writes only
`batches`/`collectors`), so between the two phases only `overrides.db` (the API) and a future human
`identity_candidates.state='dismissed'` can change: both are re-read under the lock.

Bounds (constants in `config.py`; each holds by construction, not by a deadline):

| constant | value | what it bounds |
|---|---|---|
| `MACS_PER_PASS` | 256 | subjects per robin per pass; every MAC gets its turn as the cursor advances and wraps |
| `STITCH_COMPUTE_BUDGET_S` | 5 s | wall time of COMPUTE; stops between subjects, the cursor stays on the last finished one |
| `BUCKET_ROWS` | 1024 | rows per indexed lookup; one more = incomplete evidence |
| `TARGET_KEYS` | 16 | distinct (opt55, opt60, name) keys of a target identity; more = incomplete |
| `INTERVALS_PER_MAC` | 64 | `mac_activity` rows per MAC, coalesced at fold time |
| `MAX_ALIAS_IDS` | 5000 | merge component expanded; more = incomplete (a human decides) |
| `MAX_SIGNATURE_BUCKET` | 64 | live self MACs per name group / compatible pool before a flood |
| `MAX_ROWS_PER_PASS` | 200 | candidate + suggestion + widen + orphan-cleanup rows per APPLY (a decision fits whole or waits) |
| `MAX_ATTACHES_PER_PASS` | 20 | attaches per APPLY |
| `MAX_OPEN_SUGGESTIONS_PER_DEVICE` | 64 | open merge suggestions into one device (bounds the orphan cleanup) |
| evidence gaps | retention / `activity_gap_s` | rows of `evidence_gaps`: merged within one gap at write time, pruned at retention |

APPLY therefore executes at most about 200 + 20 x (12 + 64) point writes plus one event per subject,
and its reads of `overrides.db` are primary-key lookups whose cost does not depend on how many
overrides, rules or links exist: well under a second on the server
(`test_apply_holds_the_lock_under_a_second_with_a_full_action_list`,
`test_the_lock_time_revalidation_does_not_depend_on_the_size_of_overrides`). Every decision carries
the candidate state of its pair as computed; a human change in between (a `dismissed` row, for
instance) drops the decision, which is recomputed against the new state on the next pass.

## 2. Inputs

| Source | Used for |
|---|---|
| `observations` | per-MAC signature: `dhcp_fingerprint` (opt55), `vendor_class` (opt60), `hostname`, `mdns_name`, `link_source`, `first_seen`, `last_seen` |
| `mac_activity`, `mac_first_received`, `evidence_gaps` | activity intervals, the SERVER time each MAC was first received, spans of known-missing evidence |
| `rule_attachments` | what justified each rule attach (immutable evidence for the re-check) |
| `overrides.db` (read-only snapshot per run, re-read under the lock) | `identity_rules`, `groups.auto_inherit`, `device_overrides`, `identity_links`, `suggestion_decisions` |

### Activity
Every raw row timestamp of a MAC is folded into closed intervals `[start, end]` in `mac_activity`;
a silence longer than `VIGIE_ACTIVITY_GAP_S` (300 s) starts a new interval. Folding is idempotent and
order independent. Rows whose `end` is older than 7 days are purged after each run. A MAC never holds
more than `INTERVALS_PER_MAC` rows: when a fold would exceed it, the smallest silences are bridged.
Bridging a MAC's own silence only ADDS presence (more overlap, never less), so it cannot help an
attacker; maturity is anchored on the server clock, not on covered time alone.

Row timestamps are collector-supplied and untrusted. A stamp outside
`[batch received_at - ACTIVITY_MAX_REPORT_LAG_S (1 h), received_at + ACTIVITY_SKEW_S (300 s)]` is
ignored in every batch (epoch-near stamps from a router without an RTC, far-future stamps, back-fill
over a peer's absence). `mac_first_received` records the SERVER receipt of the first batch carrying
the MAC, set once; when intervals are loaded, activity earlier than `first received - 1 h` is clipped
away. Any interval shorter than the activity gap is widened symmetrically to that width (a stamp
means "present around then"), so a copy stamping once per 301 s still overlaps.

**Dropped stamps are missing evidence, not safe evidence.** The span of the stamps a batch dropped
for the report lag (inside retention) is recorded in `evidence_gaps (start, end)`, merged into any
gap within one activity gap of it, for ANY collector. A MAC whose activity window overlaps a gap
(within one activity gap) is **not mature** (section 4), so it is never rule-attached and never
permanently vetoed. Availability cost, stated plainly: a late backlog from a routine outage longer
than an hour on any collector turns rule attaches of the MACs active in that window into
`rule_hit_needs_confirm` suggestions until the gap leaves retention. A collector that is merely
silent delivers nothing and leaves no trace; that cannot be told from an idle network.

### Neighbourhoods (what one decision reads)
A subject's neighbourhood is a fixed set of indexed lookups, each `ORDER BY last_seen DESC LIMIT
BUCKET_ROWS + 1`: its own (opt55, opt60, hostname | mDNS) buckets, the target identity's whole merge
component and the buckets of its known names (at most `TARGET_KEYS`), and per rule view the "first
seen within one gap" range of the fingerprint. Because every MAC with activity in retention has
`last_seen` inside retention, a lookup that is not truncated contains every peer that can overlap AND
every older identity of that signature. A lookup that returns one row more than the bound marks the
neighbourhood **truncated**; the subject then degrades (section 7). Activity for the gathered MACs
is read by primary key.

## 3. Candidates
A candidate is a randomized MAC that is still its own device (`link_source='self'`, locally
administered bit set, activity in retention). A pair is a candidate **only if**: opt55 equal and
non-empty, opt60 equal and non-empty, and (hostname equal OR mDNS name equal; case-insensitive).
Hostname alone is never enough. The newer MAC (by `first_seen`; ties use MAC order) is proposed
into the oldest matching device (`from_device`, `into_device`).

`score = sum(weights of equal signals)` (`SIGNAL_WEIGHTS`: opt55 0.30, opt60 0.30, mDNS 0.20,
hostname 0.20); every structural candidate scores >= 0.80. `VIGIE_STITCH_THRESHOLD` (0.8) decides
which candidates become suggestions. States in `identity_candidates` (unique per `(device_a,
device_b)`): `open`, `suggested`, `ambiguous`, `vetoed`, `dismissed` (human; sticky). The
`evidence` column holds the full signature values and is the only place they are stored.

**Ambiguity.** If two matching devices were active together for longer than the grace window they
are provably different: every pair becomes `ambiguous`, one `identity_candidate_ambiguous` event,
no suggestion, never an attach. A roller that took MACs A, B, C sequentially is read as one chain.

## 4. Overlap veto and maturity
`sustained overlap = |candidate activity ∩ union of the activity of every MAC of every matching
device|`. Over the grace window (`VIGIE_OVERLAP_GRACE_S`, 600 s; equal is tolerated) the pair is
`vetoed`, one `identity_overlap_veto` event, no suggestion. An established peer interval (longer
than `PEER_TAIL_MIN_GRACE_MULT` = 2 grace windows) is extended one activity gap past its last stamp.
Below the grace the veto still fires when the overlap covers **all** of the candidate's covered time
or, for a MAC observed longer than the grace, leaves it **less than half a gap** of its own time
(`2 * lead < gap`): the "tail lead" bypass.

**Maturity.** A MAC is mature only when its covered time (widened, clipped) is strictly longer than
the grace AND the server first received it strictly more than the grace ago AND no evidence gap
overlaps its window. An immature MAC is never rule-attached (a young one is deferred silently and
resolves itself) and never permanently vetoed: a sustained overlap of an immature MAC is a
provisional `open` row (written once, never over a `suggested` row), no event, no suggestion.

**Vetoes are permanent with one human recovery.** A `vetoed` row is never rewritten by the
pipeline and is looked up through the COMPLETE merge chains of both endpoints (cycle-safe, from the
smaller side's index), so merging the vetoed target into another device does not launder it. The
recovery is `state='dismissed'` (to be exposed by the API as "clear this veto"); the overlap is
still evaluated afterwards and a real one still blocks the attach. When a pair becomes `vetoed` or
`ambiguous` its open suggestion is withdrawn (`expires_at` set to just before now).

## 5. Suggestions
A unique, non-vetoed candidate at or above the threshold gets one immutable `merge_identity`
suggestion: `device_ids=[from, into]`, `payload={from_device, into_device, score,
evidence_summary}` (signal names, candidate id, short hashes), `reason_code='fingerprint_match'`,
`basis={device: override version}` from `overrides.db` (0 when absent), `expires_at = created + 7 d`.
At most one open suggestion per pair; none if `suggestion_decisions` holds a decision (a rejection
also sets the candidate `dismissed`) or `identity_links` already joins the devices. At most
`MAX_OPEN_SUGGESTIONS_PER_DEVICE` open suggestions point into one device; beyond that the candidate
stays `open` and one `stitch_deferred (suggestion_cap)` event a day says so.

## 6. Standing rules
A rule is active when `created_by` is non-blank, `revoked_at` is NULL and it is not expired (blank
or unparseable `expires_at` = expired). The JSON signature must hold `opt55`, `opt60` and
`hostname` and/or `mdns_name`; every SUPPLIED field is validated and a wrong-typed one rejects the
WHOLE rule (daily `rule_malformed` event); a malformed rule makes its target (through merges)
suggestion-only. For a mature randomized self MAC whose signature matches:

1. Exactly one canonical target device (through `identity_links`); two or more: `ambiguous`.
2. No sticky veto between the two identities (through their full merge components).
3. No sustained overlap with the **safety peers** derived from the RULE and the TARGET, never from
   names the applicant adds: the target's MACs, every MAC sharing a fingerprint and a name with any
   of them, and per rule view (the applicant restricted to the rule's fields) its name peers and
   its *compatible peers*: live self MACs with the same fingerprint whose names do not contradict
   the view and that share a name with it, carry a name the target already used, or were first
   seen within one activity gap of the applicant. Retired MACs stay peers but do not count toward
   floods. A compatible pool over `MAX_SIGNATURE_BUCKET` is a flood AND incomplete evidence: the
   hit degrades to `rule_hit_needs_confirm (compatible_flood)` (section 7), never an attach.
4. Both devices `identity_state='ok'` and the target in an EXPLICIT `auto_inherit=1` group;
   otherwise a `rule_hit_needs_confirm` suggestion.

The APPLY phase re-reads, by primary key under the inventory lock, the rule row (still present,
active and byte-for-byte the same rule, unexpired at the clock read under the lock), the target's
`identity_links` chain (still the same canonical device; the candidate's own device not merged
away), its `device_overrides` row (same explicit group) and that group's `auto_inherit` (1); it
also re-checks that the MAC is still a self MAC of the same device, both states `ok`, and that the
pair's candidate row is as it was when computed and not `vetoed`. Otherwise nothing attaches that
pass. A rule row whose target cannot even be read (a malformed `device_id`) makes EVERY rule hit
of that snapshot a `rule_hit_needs_confirm` suggestion.

**Attach** sets `observations.device_id` to the target with `link_source='rule'`, `link_rule_id`,
`link_score`; widens the target's `first_seen`/`last_seen`; retires the orphaned self device
(never deleted); expires every undecided suggestion from or into the orphan at once (two indexed
statements, bounded by the suggestion cap); dismisses the orphan's open candidate rows under the
pass's remaining row cap and finishes the rest on later passes (`stitch_state` key
`settle:<device>`, at most `MAX_ATTACHES_PER_PASS` orphans per pass); records `rule_attachments (mac, rule_id,
target, hostname, mdns_name, opt55, opt60, views)` with the values and each matched rule's field
mask at that moment; writes `mac_attached` (8-hex hashes only). Revoking or expiring a rule never
detaches; a later group change does not re-gate an attachment.

## 7. One uncertainty rule
Whenever a subject's evidence is incomplete it DEGRADES; it never attaches and never gets a silent
veto. Every degrade except "immature" also writes one `stitch_deferred` event per reason per UTC day.

| cause | rule path | candidate path | re-check |
|---|---|---|---|
| neighbourhood truncated, target with > `TARGET_KEYS` signatures | overlap visible: provisional `open`; else `rule_hit_needs_confirm` with `reason_text` naming the cause | nothing written (the oldest device may be hidden) | `rule_attach_suspect` ("evidence incomplete") |
| merge component > `MAX_ALIAS_IDS` | provisional `open` (a veto row may be unreachable: no suggestion) | nothing | flag |
| evidence gap in the MAC's window | overlap visible: `open`; else `rule_hit_needs_confirm (evidence_gap)` | `open` if overlapping (maturity only matters for permanence) | n/a |
| malformed rule on the target | `rule_hit_needs_confirm (malformed_target)` | n/a | n/a |
| young / sparse MAC | silent defer | `open` if overlapping | n/a |
| name group flooded | nothing + `signature_flood` once per group per day | nothing | n/a |
| compatible pool flooded | `signature_flood` + `rule_hit_needs_confirm (compatible_flood)` | n/a | `rule_attach_suspect` ("evidence incomplete") |
| the pair's candidate row changed between COMPUTE and APPLY | decision dropped, recomputed next pass | same | n/a |
| compute budget spent | subjects not reached wait; the cursor persists | same | same (the re-check robin runs first) |
| row cap / attach cap / suggestion cap | the decision waits for a later pass | same | n/a |

## 8. Post-attach re-check
Every pass re-checks up to `MACS_PER_PASS` rule-attached MACs (its own robin, run before the self
robin so a spray of new MACs cannot delay it). The peers are derived from the attach-time evidence
in `rule_attachments` (each matched rule's view, the attach-time fingerprints), never from what the
MAC calls itself now, so renaming or re-fingerprinting an attached copy, or revoking its rule, cannot
hide a later overlap. On sustained overlap, on incomplete evidence, or on a missing evidence row the
attachment is FLAGGED once (`rule_attach_suspect`, warn, on the target device); the pipeline does
not detach and creates no suggestion. Detaching waits for the API (`mac_detached`).

## 9. Safety properties (each has a test)
- `overrides.db` is opened `mode=ro` + `query_only`; its bytes are identical before and after. A
  read-only open of a WAL database still touches `-wal`/`-shm` sidecars in that directory.
- The snapshot is one read transaction; anything unexpected fails closed (`OverridesUnreadable`):
  missing column, non-integer `auto_inherit`/`version`, live rules without `device_overrides`, a
  non-text id anywhere. Missing `overrides.db`: no rules, basis 0. Present but unreadable or
  malformed: `stitching_skipped` (log once, one event per UTC day), the batches are processed with
  no identity links, the cursor advances, nothing is stitched; the ranges of merged devices that
  could not be widened catch up later as `Widen` decisions under the row cap.
- No attachment without a matching active, non-blank-creator rule; no group or trust is created.
- Hostile names never appear in logs, events or payloads (hashes only); they live only in
  `identity_candidates.evidence`, which consumers must treat as untrusted text.
- Re-running on unchanged data writes nothing but the robin cursors.

## 10. Threat table (attacker action -> defence -> test)
| attacker action | defence | test |
|---|---|---|
| copy fingerprint+name while the victim is present | union overlap veto, peer tail, half-gap lead | `test_sustained_overlap_is_vetoed_once_with_no_suggestion`, `test_tail_lead_attacker_is_vetoed_not_attached_and_the_victim_is_not_locked_out` (veto_overlap) |
| sparse / back-dated / future stamps to look mature | stamp window per batch, server anchor, clipping, covered time | `test_backdated_first_batch_cannot_mature_a_mac_beside_the_present_device`, `test_sparse_two_stamp_copy_is_deferred_while_victim_is_present` (maturity_activity) |
| rename or re-fingerprint after attach, revoke the rule | immutable attach evidence, per-rule views | `test_renaming_an_attached_copy_cannot_hide_a_later_overlap`, `test_the_recheck_searches_the_attach_time_fingerprint_bucket` (evidence_recheck) |
| merge the vetoed target away | full-chain alias resolution, smaller-side veto lookup | `test_a_permanent_veto_survives_its_target_being_merged`, `test_a_veto_survives_a_merge_chain_longer_than_the_link_depth` (veto_overlap) |
| extra names on the applicant | peers from rule views and the target only | `test_an_extra_applicant_name_cannot_exclude_the_real_device_from_the_veto` (veto_overlap) |
| nameless / junk-named MACs to veto or flood | compatible peers need a reason; retired excluded | `test_a_nameless_mac_is_a_peer_only_within_a_gap_of_the_candidate`, `test_junk_hostname_macs_do_not_block_the_legit_device` |
| 1000+ look-alikes to hide the victim | truncation degrades to a suggestion, never an attach | `test_a_spray_beyond_the_bucket_bound_degrades_to_a_suggestion_never_attaches` (bounds_perf) |
| spray to switch off the re-check | own robin, runs first; truncation flags | `test_a_spray_of_self_macs_does_not_delay_the_recheck`, `test_a_recheck_that_cannot_gather_complete_evidence_flags_the_attachment` |
| hold the inventory write lock | reads outside the lock; APPLY count-bounded | `test_apply_holds_the_lock_under_a_second_with_a_full_action_list` |
| unbounded CPU / memory | `BUCKET_ROWS`, `INTERVALS_PER_MAC`, `MACS_PER_PASS`, compute budget | `test_compute_budget_stops_between_subjects_and_the_cursor_persists`, `test_a_mac_never_holds_more_than_the_interval_cap_however_many_bursts_it_sends` |
| late backlog restores maturity | one gap list, all loaded, retention-pruned | `test_every_gap_is_loaded_so_the_oldest_relevant_one_still_blocks`, `test_the_copy_beside_a_late_collectors_victim_becomes_a_human_decision` |
| a human merges thousands of devices | links read outside the lock; `Widen` under the row cap; oversize components defer | `test_widening_is_count_bounded_per_pass_and_writes_only_where_narrow`, `test_an_oversize_component_is_deferred_not_recorded_as_a_veto` |
| malformed rule on the target (even one whose id is a BLOB) | target becomes suggestion-only; an unreadable target makes every hit suggestion-only | `test_a_malformed_rule_on_a_target_turns_a_valid_attach_into_a_suggestion`, `test_a_malformed_rule_with_a_blob_id_still_names_its_target`, `test_a_malformed_rule_whose_target_cannot_be_read_makes_every_rule_hit_a_suggestion` |
| 65 compatible junk MACs around an attached copy | a flooded pool is incomplete evidence: flag / confirm, never silence | `test_a_flooded_compatible_pool_cannot_suppress_the_suspect_flag`, `test_a_flooded_compatible_pool_turns_the_rule_hit_into_a_confirm_suggestion` |
| dismiss or decide a pair between COMPUTE and APPLY | candidate-state preconditions drop the decision | `test_a_dismissal_between_compute_and_apply_cancels_the_attach`, `test_a_dismissal_between_compute_and_apply_cancels_the_suggestion` |
| 1000 accumulated candidate rows on an attaching orphan | cleanup under the row cap, finished by `Settle` later; suggestions expired at once | `test_the_cleanup_of_an_orphans_candidate_rows_is_budgeted_and_finishes_later` |
| grow overrides.db to lengthen the lock | point lookups only under the lock | `test_the_lock_time_revalidation_does_not_depend_on_the_size_of_overrides` |
| 30k old attachments to switch the re-check off | own robin, persisted cursor, silent MACs cost one probe | `test_the_recheck_robin_cycles_through_every_attached_mac`, `test_a_recheck_subject_without_activity_in_retention_is_skipped` |
| rule revoked / regrouped while the pass runs | fresh snapshot and clock under the lock | `test_the_attach_rereads_the_rule_and_group_under_the_lock`, `test_expiry_is_rechecked_with_the_clock_read_after_the_lock_is_held` |

## 11. Accepted residual risk (asserted in tests)
- **Fingerprint copy after the victim left** (`rolling_fingerprint_copy_away`): no overlap to veto.
  Without a rule it is a suggestion; with an approved rule in an `auto_inherit` group the copy **is
  attached**. Only behavioural demotion (not built) or the human can catch it. Owner mitigation:
  keep `trusted`/`kids` at `auto_inherit=0`.
- **Short-lived impostor** (under the grace) is never vetoed, only never attached and never
  suggested; a device that rolls more often than every grace window stays a human decision.
- **Post-attach squatting.** A MAC attached while the victim looked absent stays attached (the
  victim's later rolls are vetoed against it: a lockout only a human can undo); every pass flags it
  (`rule_attach_suspect`) once the overlap shows. Detection, not repair.
- **Denial of convenience.** 65 live look-alikes with the victim's exact signature block that
  victim's rule attach (flood); 1025 look-alikes in a bucket, or a late backlog, turn it into a human
  confirmation; a spray of randomized MACs makes a legitimate roll wait up to
  `active MACs / MACS_PER_PASS` passes for its turn. Every one of these is visible as an event.
- **Suggestion spam.** `MAX_ROWS_PER_PASS` and `MAX_OPEN_SUGGESTIONS_PER_DEVICE` rate-limit and cap
  suggestions per target, but an attacker with many signatures can still fill the suggestion list
  over days (200 rows a pass). Pruning of candidate rows is not done.
- **Compromised collector** (holds the ingest credential) is outside this threat model: it can
  withhold or invent stamps inside the accepted window.
- **iOS sends no opt60**: iOS devices can never be stitched or covered by a rule as specified; the
  ground-truth tests inject a constant opt60 to exercise the behaviour (decision for the owner).

## 12. Not done (explicitly)
Behavioural demotion; `identity_state='conflict'|'pending_confirm'` side effects; the API: accept,
reject, merge, undo, rule creation/revocation, `mac_detached`, clearing a veto (`dismissed`);
classification rules; a rate limit on attachments per hour beyond `MAX_ATTACHES_PER_PASS`; pruning
of candidate rows.

## 13. Tests
`server/tests/pipeline/test_stitch_attach_rules.py` (T1/T2, rule parsing, gating, the lock-time
re-read, orphan cleanup), `test_stitch_veto_overlap.py` (candidates, ambiguity, veto, peers, sticky
vetoes, suggestions), `test_stitch_evidence_recheck.py`, `test_stitch_maturity_activity.py`,
`test_stitch_bounds_perf.py` (every bound above, adversarial sprays, the lock hold, query plans),
`test_stitch_migrations.py` (fresh install and upgrade from main's v3), with the harness in
`stitch_helpers.py`; and `tools/trafficgen/tests/test_stitching.py` (every committed fixture through
the real ingest app and `run_once`).
