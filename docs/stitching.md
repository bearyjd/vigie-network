# Identity stitching (P2, pipeline only)

Implements PRP-001 section 8 in `server/src/vigie_pipeline/` (`stitch.py`, `stitch_db.py`,
`activity.py`, `snapshot.py`). It runs at the end of every `run_once`, after observations are
updated, in a single `inventory.db` transaction. There are no API changes in this round.

The design rule is unchanged: the pipeline can **continue** an identity only under an active rule
read from `overrides.db`; everything else is a **suggestion** a human decides. The pipeline never writes
`overrides.db`, never creates a group or a trust level, and never produces an attachment without a
matching active, non-blank-creator rule.

**Trust boundary (what is and is not enforced here).** The pipeline enforces exactly: "the rule is
an active row of `overrides.db` (not revoked, not expired) with a non-blank `created_by`". Whether
the creator is a *human* is **not** checkable in the pipeline (`created_by` is only a principal
name). That is enforced by the API alone: the rule-creation API (not yet built) MUST be the sole
writer of `identity_rules` and MUST reject non-human principals (service tokens). Heuristics only
ever suggest; the pipeline never writes `overrides.db`.

## 1. Inputs

| Source | Used for |
|---|---|
| `observations` | per-MAC signature: `dhcp_fingerprint` (opt55), `vendor_class` (opt60), `hostname`, `mdns_name`, `link_source`, `first_seen` |
| `mac_activity` | per-MAC activity intervals (below) |
| `overrides.db` (read-only snapshot per run) | `identity_rules`, `groups.auto_inherit`, `device_overrides` (group, version), `identity_links`, `suggestion_decisions` |

### Activity intervals
Every raw row timestamp (leases, neighbours, mDNS sightings, DNS, flows) of a MAC is folded into
closed intervals `[start, end]` in `mac_activity (mac, start, "end")` (pipeline schema v4; `end`
is quoted because it is an SQL keyword). A silence **longer than** `VIGIE_ACTIVITY_GAP_S`
(default 300 s) starts a new interval. Folding is idempotent and order independent (late batches
coalesce with neighbours). Rows whose `end` is older than 7 days are purged at the end of each run.
The table is derived and can be dropped.

Row timestamps come from the collector and are untrusted. When a batch is folded, a stamp outside
`[batch received_at - 7 d (activity retention), batch received_at + 300 s]` is **ignored** (not
clamped, not stored): a router without an RTC emits epoch-near stamps and a hostile or broken
collector could send far-future ones, either of which would fake observed history and mature a MAC
instantly. The 300 s allows for ordinary clock skew (`ACTIVITY_SKEW_S`). The ingest wire contract is
unchanged.

When the intervals are loaded for a pass, any interval shorter than `VIGIE_ACTIVITY_GAP_S` is widened
symmetrically to that width (a stamp means "present around then"). A single stamp, or a burst of
a few stamps, therefore still has width and overlaps a continuously present device; otherwise a copy
that sent one stamp per 301 s would have zero overlap and dodge the veto. Stored intervals are not
changed.

## 2. Candidates

A candidate is a randomized MAC that is still its own device (`link_source='self'`, locally
administered bit set, activity recorded). It is compared with every other MAC of another device.

A pair is a candidate **only if** all hold: opt55 equal and non-empty, opt60 equal and non-empty,
and (hostname equal OR mDNS name equal; case-insensitive). Anything weaker is not a candidate:
hostname/mDNS alone, a fingerprint without a name, or only one of opt55/opt60.

Direction: the newer MAC (by `observations.first_seen`; on a tie only one direction is used) is
proposed to be merged **into** the oldest matching device (`from_device`, `into_device`).

### Score
`score = sum(weights of equal signals)`, rounded to 6 places. Weights (`SIGNAL_WEIGHTS`,
`config.py`): opt55 0.30, opt60 0.30, mDNS name 0.20, hostname 0.20. Because opt55, opt60 and at
least one name are mandatory, every real candidate scores at least 0.80; the **suggest threshold**
(`VIGIE_STITCH_THRESHOLD`, default 0.8, range (0, 1]) decides which candidates become
suggestions. Raising it to 0.9 keeps hostname-only or mDNS-only name matches as `open`
candidates without a suggestion. Hostname alone can never reach a candidate because the opt55 and
opt60 requirement is structural, not part of the score.

Candidate states in `identity_candidates` (unique per `(device_a=from, device_b=into)`):
`open` (below threshold), `suggested`, `ambiguous`, `vetoed`, `dismissed` (a human rejected the
suggestion, or a rule settled the MAC; sticky). The `evidence` column holds the full signature
values and is the only place they are stored.

## 3. Ambiguity
Matching devices are everything that matches the candidate's signature (older **and** newer).
If two of them were active together for longer than the grace window they are provably different
devices, so the signature names more than one: every pair becomes `ambiguous`, the event
`identity_candidate_ambiguous` is written once per candidate device, and there is no suggestion
and never an automatic attach.

Note the deliberate refinement of "matches two devices": a roller that took MACs A, B, C
sequentially leaves three orphan devices with one signature. They are never concurrent, so they
are read as one chain and the newest MAC is proposed into the oldest. Two identical phones that
are simultaneously online are ambiguous (or vetoed). Two identical phones that are never seen
together within retention cannot be told apart and are treated as a chain; a human still decides.

## 4. Overlap veto
`sustained overlap = total length of (candidate MAC activity ∩ union of activity of every MAC
of every matching device)`. If it exceeds the grace window (`VIGIE_OVERLAP_GRACE_S`, default 600 s;
exactly equal is tolerated) the pair is `vetoed`, event `identity_overlap_veto` is written once
per unordered pair, and there is no suggestion. A rolling device that briefly holds two MACs
(overlap well under the grace) is tolerated. The union (not a single MAC pair) is used because a
rolling device presents as a chain of MACs: an impostor beside it overlaps the chain, not one MAC.
A device linked by `identity_links` contributes all of its MACs.

**Peer presence tail and own-time lead.** A silent peer is not gone until a full activity gap
(`VIGIE_ACTIVITY_GAP_S`, 300 s) has passed, so an *established* peer interval (longer than
`PEER_TAIL_MIN_GRACE_MULT` = 2 grace windows) is extended by one gap past its last stamp before the
overlap is computed. Short bursts (the minutes-long MACs of a fast roller) get no tail, otherwise
every hand-over of the `rolling_mac` fixtures would count as concurrent. Even below the grace, the
veto fires when the overlap covers **all** of the candidate's covered time, or, for a MAC observed
longer than the grace, when it leaves **less than half a gap** (150 s) of the MAC's own time. This
closes the "tail lead" bypass (an attacker present for 610 s beside a victim that stamps sparsely,
whose last stamp is 10 s earlier, used to slip under the old ratio test). Half a gap, not a whole
one: a lone stamp is widened by that much on each side, so a legitimate roll that overlaps its
neighbour by a few minutes always has up to a gap less own time than it seems. A ratio of 0.5 was
tried and rejected (it vetoes the legitimate `rolling_mac` fixture); `OVERLAP_COVER_RATIO` is gone.

**Maturity.** The veto only works on observed history, so a MAC is not eligible for a rule attach
until its **covered time** (the sum of its activity intervals after widening, not the first-to-last
span) is **strictly longer than** the grace window. Sparse stamps therefore cannot mature a MAC
cheaply: two stamps 700 s apart cover only 2 x 300 s. Until then it is deferred silently (no attach,
no event; it may still get a fingerprint suggestion, which is withdrawn if the pair later becomes
vetoed). With covered time longer than the grace, a copy that is present the whole time overlaps by
at least its covered time and is vetoed; with `>=` an overlap of exactly the grace would slip
through. Consequence: a device that rolls its MAC more often than every grace window (default
10 min) is not covered by rule attach and stays a human decision.

When a pair becomes `vetoed` or `ambiguous`, its open (undecided, unexpired) suggestion is
withdrawn: `suggestions.expires_at` is set to just before now, so every consumer sees it as
expired. Decided suggestions are never touched and `overrides.db` is not involved.

## 5. Suggestions
For a unique, non-vetoed candidate with `score >= threshold` the pipeline inserts one row in
`suggestions`. Suggestions are immutable, with one exception: withdrawal (section 4) rewrites
`expires_at` of an undecided suggestion to just before now; nothing else is ever updated:

| Field | Value |
|---|---|
| `action` | `merge_identity` |
| `device_ids` | `[from_device, into_device]` |
| `payload` | `{from_device, into_device, score, evidence_summary}`; the summary has signal names, the candidate id and short hashes only |
| `reason_code` / `reason_text` | `fingerprint_match` / `NULL` |
| `basis` | `{device_id: override version}` for both devices, read from `overrides.db` (0 when there is no row, or when the file does not exist) |
| `expires_at` | created + 7 days |

At most one open (undecided, unexpired) suggestion per `(from, into)` pair; none if
`suggestion_decisions` holds a decision for any earlier suggestion of the pair (a rejection also
sets the candidate to `dismissed`) or if `identity_links` already joins the devices. Once a
suggestion has expired undecided a new one may be created. The event `identity_candidate` is
written once per pair.

## 6. Standing rules (pass 1, before candidates)
`identity_rules` rows are used when `created_by` is non-blank, `revoked_at` is NULL (any non-NULL
value, including an empty string, is a revocation) and the rule is not expired (a blank or
unparseable `expires_at` counts as expired; `expires_at <= now` is expired). `created_by` carries the
app principal name (`app:<token_id>`) and cannot tell a human from a token, so service/token
principals cannot be rejected here; that distinction has to come from the rule-creation API. The JSON signature must contain `opt55`, `opt60` and `hostname` and/or `mdns_name`
(opt55 as a `"1,2,3"` string or a list of ints); every field the rule names must equal the MAC's.
For a randomized self MAC:

0. The MAC is mature (section 4) and its name group is not flooded (section 12).
1. The set of **distinct canonical devices** (following `identity_links`) whose active rules match
   must have exactly one member. Two or more devices: nothing attaches, the candidate is
   `ambiguous`, one `identity_candidate_ambiguous` event. Several rules for one device are fine.
2. No sustained overlap (as section 4) between the MAC and the rule device's MACs plus **every other
   MAC with the same opt55, opt60 and an agreeing hostname or mDNS name** (candidate-style match, not
   the rule's stricter one: the victim's own new MAC, e.g. before its mDNS name is seen, is a peer
   too); otherwise `vetoed`. The veto is evaluated before the attach, in the same pass.
3. Group gate: both the rule device and the MAC's own device must have `identity_state='ok'`
   (`conflict` / `pending_confirm` go to the confirm suggestion). Then the rule device must have an
   explicit group (`device_overrides.group_id` set) whose group has `auto_inherit=1` (defaults:
   `iot`, `guest`) -> **attach**. A device with **no group** (unassigned, no `device_overrides`
   row or a NULL group), an `auto_inherit=0` group, or a group row that cannot be found -> no
   attach; a `merge_identity` suggestion with `reason_code='rule_hit_needs_confirm'` is created
   instead and the MAC stays unassigned until a human accepts it. If a `fingerprint_match`
   suggestion for the pair is already open it is kept (one open suggestion per pair).

**Attach** sets `observations.device_id` to the canonical rule device with `link_source='rule'`,
`link_rule_id`, `link_score` (the rule's score), widens that device's `first_seen`/`last_seen`,
sets the orphaned self device to `status='retired'` (devices are never deleted; its earlier
candidates become `dismissed`; an already open suggestion for it simply expires), and writes
`mac_attached` on the target device. The event summary carries 8-hex hashes of the previous and
new MAC only.

**Peers.** The overlap veto compares the MAC with the union of: the target device's MACs, its
name peers (same opt55, opt60 and an agreeing hostname or mDNS name) and its *compatible peers*:
live self MACs with the same opt55 and opt60 whose hostname and mDNS name do not contradict its
own (a missing name is not a contradiction). The last set catches the victim's new MAC that has
shown only an mDNS name, or no hostname yet, beside a twin that copied the hostname. A device with
a different name never counts. Rule-attached MACs are re-checked every pass (section 8).

Revoking or expiring a rule **never detaches** an existing attachment in this round (no
`mac_detached` yet). **Attachments are also not re-gated when the group changes**: a MAC attached
while the device was in an `auto_inherit=1` group stays attached after the device is
moved to an `auto_inherit=0` group, and a later group change does not re-run the gate. Applying a
rule twice changes nothing. After each attach the canonical map is refreshed for the next MAC.

## 7. Safety properties (each has a test)
- `overrides.db` is opened `mode=ro` + `query_only`; its bytes are identical before and after.
  Sidecars: a read-only open of a WAL database still creates or touches `overrides.db-wal` and
  `overrides.db-shm` in the same directory (SQLite bookkeeping, not data). The pipeline's uid must
  therefore be able to write that directory (or a writer connection keeps the sidecars alive on a
  read-only mount). Not redesigned this round.
- The snapshot is read in one `BEGIN`/`COMMIT` read transaction. Anything unexpected fails closed
  (`OverridesUnreadable`, run goes on without stitching): a missing column, a non-integer
  `auto_inherit` or `version`, or live rules while the `device_overrides` table is missing (that
  would read as "unassigned", which now only suggests; still fail closed).
- Missing `overrides.db`: no rules, basis 0. Present but unreadable: stitching is skipped for the
  run and logged (`stitching_skipped`, ERROR); nothing is created. Other missing tables are read as empty.
- No attachment without a matching active, non-blank-creator rule (human-ness is the API's job,
  see the trust boundary above); no group or trust is created.
- Hostile hostnames/mDNS names never appear in logs, events or suggestion payloads (hashes only;
  values are already control-character-stripped at ingest). They are present in the `evidence`
  column of `identity_candidates`, which consumers must treat as untrusted text.
- Whole stage is one transaction; re-running on unchanged data writes nothing new.

## 8. Accepted residual risk (asserted in tests)
- **Fingerprint copy after the victim left** (`rolling_fingerprint_copy_away`): there is no overlap
  to veto. Without a rule it is a suggestion the human sees; with an approved rule in an
  `auto_inherit` group the copy **is attached**. Only behavioural demotion (not built) or the
  human can catch it. Owner mitigation: keep `trusted`/`kids` at `auto_inherit=0`.
- **Fingerprint copy while the victim is present** is vetoed once the overlap exceeds the grace,
  or sooner when it leaves less than half a gap of own time (section 4). A short-lived impostor
  (under the grace) is not vetoed.
- **Post-attach squatting and lockout.** The veto sees only activity observed so far. A MAC that
  was attached while the victim looked absent (stamps are sparse, or the victim's new MAC had not
  yet shown a name) stays attached even if the victim then turns out to have been present. The
  attacker then owns a rule-attached MAC in the victim's device and the victim's later rolls
  overlap it, so they are vetoed (a lockout that only a human can undo). Detection, not repair:
  every pass re-checks each rule-attached MAC against its device's peers (the device's other
  MACs, its name peers and the compatible peers of section 6) and, on sustained overlap, emits one
  `rule_attach_suspect` event (warn, on the target device, once per MAC). The pipeline does **not**
  detach (it must not rewrite trust) and creates **no suggestion**: the suggestion kinds
  (`label`, `move_group`, `quarantine`, `merge_identity`) have no "review this attachment"
  action, `merge_identity` points the wrong way and `quarantine` would quarantine the victim's
  whole device. The event is the human's cue; detaching waits for the API (`mac_detached`).
- **Short fixtures:** `hostname_spoof_full_fingerprint` has only 300 s of concurrency, inside the
  default 600 s grace, but the copy is wholly inside the victim's presence, so it is vetoed.

## 9. Fixture limitation: iOS sends no opt60
The committed iPhone archetype (and real iOS) sends no DHCP option 60. Since a candidate requires
opt55 AND opt60, **iOS devices can never be stitched or covered by a rule** as specified. The
ground-truth tests therefore assert (a) that the fixtures as committed produce no candidate, and
(b) the behaviours on the same traffic with a constant opt60 injected into iPhone leases. If iOS
must be supported, the signature needs a different second factor (decision for the owner).

## 10. Not done (explicitly)
- Behavioural demotion (compare first hours with the baseline; needs the features stage) and the
  `identity_state='conflict'|'pending_confirm'` side effects.
- API: accept, reject, merge, undo, rule creation/revocation, `mac_detached`.
- Classification rules (OUI, fingerprint database) and a rate limit on attachments per hour.
- Pruning of candidate rows.

## 11. Tests
`server/tests/pipeline/test_stitching.py`, `test_stitch_rules.py`, `test_stitch_review.py`, `test_stitch_review3.py`, `test_stitch_perf.py` (unit and rule harness; the
seeded `overrides.db` is built with the API's own migrations in `stitch_helpers.py`) and
`tools/trafficgen/tests/test_stitching.py` (every relevant committed fixture through the real
ingest app and `run_once`).

## 12. Flood bounds
All matching is done inside **name groups**: MACs with the same opt55, opt60 and one agreeing
hostname (or mDNS name), never against every observation.
- A name group with more than `MAX_SIGNATURE_BUCKET` (64) **live** MACs is **flooded**. Live = still
  `link_source='self'` AND active inside the 7 d activity retention window, so MACs that were
  attached by a rule, retired or have gone silent do not count (a device that legitimately rolls
  once per pass never floods itself). MACs with other names never share the group, so a swarm of
  junk-hostname MACs does not touch the victim's group. A MAC with any flooded group is neither
  rule-attached nor compared. One `signature_flood` event (warn, short hash of the group and the
  count) is written per group per **UTC day** (`events.dedup` token), not per pass. Fail closed, and
  deliberately **without a suggestion**: a flooded group creates no attach and no candidate.
  Residual: an attacker who sends 65 live MACs with the victim's exact opt55, opt60 and hostname
  blocks that victim's rule attach until those MACs go silent; this is a denial of service on
  convenience, never an attach, and is visible as the flood event.
- At most `MAX_ROWS_PER_PASS` (200) new or changed `identity_candidates` plus created `suggestions` rows
  are written per pass; the rest wait for later passes (existing rows are unaffected).
- Once-only events (`identity_overlap_veto`, `identity_candidate_ambiguous`, `identity_candidate`) use
  the indexed column `events.dedup` with a unique index on `(kind, dedup)` (pipeline schema v5)
  instead of an `instr()` scan over all summaries.

### CPU bounds (review 3)
Everything below runs inside `BEGIN IMMEDIATE`, so CPU is bounded as well:
- Live group sizes are computed once per reload, not per member. Concurrent device pairs of a name
  group are found by one sweep per pass (cached), not pairwise per candidate.
- Only each MAC's `MAX_INTERVALS_PER_MAC` (64) most recent activity intervals are compared.
- A global budget of `MAX_OVERLAP_OPS_PER_PASS` (20000 units, about 64 interval comparisons each)
  applies per pass. When it runs out the pass stops stitching new candidates (the decision in
  flight is abandoned before any write, so nothing is half-decided) and emits one
  `stitch_budget_exhausted` event per UTC day. Candidates without a candidate row are processed
  first, so repeated exhaustion still makes progress. The measured worst cases (16 groups x 64 MACs
  x 50 intervals, 1 x 64 x 200) finish in well under a second.
- The candidate loop stops as soon as `MAX_ROWS_PER_PASS` is reached.
- At most `MAX_FLOOD_EVENTS_PER_PASS` (20) new `signature_flood` events are written per pass; any
  further flooded groups that pass are counted in one `signature_flood_summary` event per UTC day
  and reported by their own events on later passes.
- Activity lower bound: stamps of a MAC with no stored activity older than 24 h
  (`ACTIVITY_NEW_MAC_LOOKBACK_S`) before the batch receipt are ignored, so a brand-new MAC cannot
  back-fill days of history; a known MAC keeps the 7 d retention window.
