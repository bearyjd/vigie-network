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
APPLY    BEGIN IMMEDIATE, count-bounded (section 4), <~1 s:
         re-read overrides.db snapshot once; for each decision re-validate preconditions with
         indexed point lookups; drop stale ones; write.
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
| young / sparse MAC (immature) | silent defer (resolves itself) | `open` | n/a |
| name group / compatible pool flooded | nothing + `signature_flood` once per group per day | nothing | pool ignored |
| compute time budget hit | subjects not reached wait; robin cursor persists | same | same |
| row cap / suggestion cap hit | decision dropped, recomputed next cycle | same | n/a |

Every degrade except "immature" also writes one `stitch_deferred` event per reason per UTC day.

## 3. Bounds (all constants in `config.py`)

| constant | value | bounds |
|---|---|---|
| `MACS_PER_PASS` | 256 | subjects examined per robin per pass (self robin, recheck robin) |
| `STITCH_COMPUTE_BUDGET_S` | 5 | wall time of COMPUTE (read-only); stops between subjects |
| `BUCKET_ROWS` | 1024 | rows per indexed lookup; more = truncated = degrade |
| `TARGET_KEYS` | 16 | distinct (fp, vc, name) keys of a target identity; more = degrade |
| `INTERVALS_PER_MAC` | 64 | rows of `mac_activity` per MAC, enforced at fold time (closest pair coalesced) |
| `MAX_ALIAS_IDS` | 5000 | merge component expanded; more = degrade |
| `MAX_SIGNATURE_BUCKET` | 64 | live self MACs per name group / compatible pool before flood |
| `MAX_ROWS_PER_PASS` | 200 | candidate + suggestion rows written per APPLY |
| `MAX_ATTACHES_PER_PASS` | 20 | attaches per APPLY (each <= ~12 statements + orphan cleanup) |
| `MAX_OPEN_SUGGESTIONS_PER_DEVICE` | 64 | open merge suggestions INTO one device; bounds orphan cleanup |
| gaps | retention / gap_s (~2016) | `evidence_gaps` rows: merged within `activity_gap_s` at write time, pruned at retention |

Lock hold (APPLY) is therefore `<= MAX_ROWS_PER_PASS + MAX_ATTACHES_PER_PASS * (12 + 64 + 2) +
widen + events` point writes, about 2,000, no scan. Interval coalescing is conservative: bridging a
MAC's own silence only ADDS presence (more overlap, never less), and maturity is anchored on the
server clock, so it cannot help an attacker.

## 4. APPLY preconditions (indexed point lookups)
- Attach: `observations.mac` still `('self', from_device)`; both `identity_state='ok'`; target
  exists; fresh snapshot: rule present and unexpired at `clock()`, `canonical(rule.device_id) ==
  target`, target group unchanged and `auto_inherit=1`; pair not `vetoed`/`dismissed`.
- Candidate: row re-read; identical or sticky (`dismissed`, `vetoed`) rows are not written.
- Suggest: no open/decided suggestion for the pair; devices not linked; target below the cap.
- Event: `INSERT OR IGNORE` on `(kind, dedup)`.

## 5. Deleted (with the defect each removal closes)
- `mac_last_seen` + trigger, `active_macs` paging, `MAX_ACTIVE_MACS` newest-first cap (defect 1, 6).
- `mac_collectors`, per-collector gap scoping, `MAX_GAPS_PER_COLLECTOR` (defects 2, 3): one merged
  gap list for any collector. Availability cost: a late backlog from ANY collector defers rule
  attaches for every MAC whose window overlaps the gap (they become `rule_hit_needs_confirm`).
- Two-stage core/bulk loader, `STITCH_SETUP_MAX_SECONDS`, `partial`, per-phase `MAX_OVERLAP_OPS`
  and time-box slices, `BudgetExhaustedError`, `_charge` (defect 4, lock hold).
- `widen_linked_devices` unbounded UPDATE loop (defect 5): now `Widen` decisions under the row cap.
- `HISTORIC_MATCH_LIMIT`, `MAX_FLOOD_EVENTS_PER_PASS` + `signature_flood_summary`, `settle:` state
  keys and `_settle_*`, `legacy` anchors, `evidence_gap`/`stitch_budget_exhausted`/
  `stitch_active_set_capped`/`alias_component_oversize` events (replaced by `stitch_deferred`).
- Migrations 4..11 squashed into ONE migration (#4). Main's pipeline schema (v3) has no stitching
  table and no anchor of any provenance, so no legacy heuristics are needed.

## 6. Migration plan
Pipeline migration 4 (additive, on top of main's v3): `mac_activity`, `mac_first_received`,
`evidence_gaps`, `rule_attachments`, `stitch_state`, `events.dedup` + unique index, candidate
indexes, suggestion indexes (`idx_suggestions_pair`, expression index on
`json_extract(device_ids,'$[1]')`), observation indexes (`idx_obs_fp_host`, `idx_obs_fp_mdns`,
`idx_obs_fp_first`, partial `idx_obs_rule`). Tests: upgrade from a populated main v3 database;
fresh install; reapply is a no-op.

## 7. Behaviour deliberately changed
1. A rule hit with incomplete evidence (gap, truncation, oversize component, malformed target) is
   a `rule_hit_needs_confirm` suggestion (reason_text names the cause) instead of a silent defer
   with a per-collector event. The human decides; nothing attaches.
2. Evidence gaps are not scoped per collector (section 5).
3. At most `MAX_OPEN_SUGGESTIONS_PER_DEVICE` open merge suggestions into one device; more wait
   (daily `stitch_deferred suggestion_cap`). Bounds orphan cleanup at attach.
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
| spray to switch off the recheck | recheck robin over attached MACs only; truncation flags | bounds_perf: `test_a_spray_cannot_hide_an_overlapping_peer_from_the_recheck` |
| hold the write lock | APPLY count-bounded, reads outside the lock | bounds_perf: `test_apply_holds_the_lock_under_a_second_with_a_full_action_list` |
| unbounded memory/CPU | BUCKET_ROWS, INTERVALS_PER_MAC, MACS_PER_PASS, compute budget | bounds_perf: `test_compute_budget_stops_between_subjects_and_the_cursor_persists` |
| late-collector gap restores maturity | one gap list, retention-pruned, all loaded | maturity_activity: `test_a_mac_whose_window_overlaps_a_gap_is_not_mature` |
| human merges 100k devices | links read outside the lock; widen under the row cap | bounds_perf: `test_widening_is_count_bounded_per_pass` |
| malformed rule on the target | target becomes suggestion-only | attach_rules: `test_a_malformed_rule_on_a_target_turns_a_valid_attach_into_a_suggestion` |

## 9. Tests: deleted or replaced (by file)
- `test_stitch_perf.py`, `test_stitch_review*.py` (1..7): split by topic into the six files
  below; tests of removed machinery are dropped: per-phase budgets and time-box slices
  (`FakeTime`, `Ticking`, `_charge` assertions), setup cap / partial setup, `mac_last_seen`
  trigger/summary, `mac_collectors`, per-collector gap events, `MAX_GAPS_PER_COLLECTOR`,
  `signature_flood_summary`, `stitch_active_set_capped`, legacy anchors / migration 6..11
  shapes, `settle:` markers, HISTORIC_MATCH_LIMIT, interval-cap laundering (the cap is now at
  write time and conservative). Every behavioural assertion is kept.
- New files: `test_stitch_attach_rules.py`, `test_stitch_veto_overlap.py`,
  `test_stitch_evidence_recheck.py`, `test_stitch_maturity_activity.py`,
  `test_stitch_bounds_perf.py`, `test_stitch_migrations.py`; `test_stitching.py` and
  `test_stitch_rules.py` are folded into them. `tools/trafficgen/tests/test_stitching.py` is kept
  verbatim.
