# Identity stitching (P2, pipeline only)

Implements PRP-001 section 8 in `server/src/vigie_pipeline/` (`stitch.py`, `stitch_db.py`,
`activity.py`, `snapshot.py`). It runs at the end of every `run_once`, after observations are
updated, in a single `inventory.db` transaction. There are no API changes in this round.

The design rule is unchanged: the pipeline can **continue** an identity only under a rule a human
approved; everything else is a **suggestion** a human decides. The pipeline never writes
`overrides.db`, never creates a group or a trust level, and never produces an attachment without a
matching active human rule.

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

## 5. Suggestions
For a unique, non-vetoed candidate with `score >= threshold` the pipeline inserts one row in
`suggestions` (never updated afterwards):

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
`identity_rules` rows are used when not revoked and not expired (an unparseable `expires_at` counts
as expired). The JSON signature must contain `opt55`, `opt60` and `hostname` and/or `mdns_name`
(opt55 as a `"1,2,3"` string or a list of ints); every field the rule names must equal the MAC's.
For a randomized self MAC:

1. The set of **distinct canonical devices** (following `identity_links`) whose active rules match
   must have exactly one member. Two or more devices: nothing attaches, the candidate is
   `ambiguous`, one `identity_candidate_ambiguous` event. Several rules for one device are fine.
2. No sustained overlap (as section 4) between the MAC and the rule device's MACs plus every other
   MAC that matches the rule; otherwise `vetoed`.
3. Group gate: the rule device's `device_overrides.group_id` is NULL or absent (unassigned) or its
   group has `auto_inherit=1` (defaults: `iot`, `guest`) -> **attach**. An `auto_inherit=0` group,
   or a group row that cannot be found, -> no attach; a `merge_identity` suggestion with
   `reason_code='rule_hit_needs_confirm'` is created instead and the MAC stays unassigned until a
   human accepts it. If a `fingerprint_match` suggestion for the pair is already open it is kept
   (one open suggestion per pair).

**Attach** sets `observations.device_id` to the canonical rule device with `link_source='rule'`,
`link_rule_id`, `link_score` (the rule's score), widens that device's `first_seen`/`last_seen`,
sets the orphaned self device to `status='retired'` (devices are never deleted; its earlier
candidates become `dismissed`; an already open suggestion for it simply expires), and writes
`mac_attached` on the target device. The event summary carries 8-hex hashes of the previous and
new MAC only.

Revoking or expiring a rule **never detaches** an existing attachment in this round (no
`mac_detached` yet). Applying a rule twice changes nothing.

## 7. Safety properties (each has a test)
- `overrides.db` is opened `mode=ro` + `query_only`; its bytes are identical before and after.
- Missing `overrides.db`: no rules, basis 0. Present but unreadable: stitching is skipped for the
  run and logged (`stitching_skipped`, ERROR); nothing is created. Missing tables are read as empty.
- No attachment without a matching active human rule; no group or trust is created.
- Hostile hostnames/mDNS names never appear in logs, events or suggestion payloads (hashes only;
  values are already control-character-stripped at ingest). They are present in the `evidence`
  column of `identity_candidates`, which consumers must treat as untrusted text.
- Whole stage is one transaction; re-running on unchanged data writes nothing new.

## 8. Accepted residual risk (asserted in tests)
- **Fingerprint copy after the victim left** (`rolling_fingerprint_copy_away`): there is no overlap
  to veto. Without a rule it is a suggestion the human sees; with an approved rule in an
  `auto_inherit` group the copy **is attached**. Only behavioural demotion (not built) or the
  human can catch it. Owner mitigation: keep `trusted`/`kids` at `auto_inherit=0`.
- **Fingerprint copy while the victim is present** is vetoed once the overlap exceeds the grace.
  A short-lived impostor (under the grace) is not vetoed.
- **Short fixtures:** `hostname_spoof_full_fingerprint` has only 300 s of concurrency, inside the
  default 600 s grace, so by default it is a suggestion; a grace of 240 s vetoes it.

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
- Withdrawing a suggestion (suggestions are immutable; stale ones expire).
- Pruning of candidate rows.

## 11. Tests
`server/tests/pipeline/test_stitching.py`, `test_stitch_rules.py` (unit and rule harness; the
seeded `overrides.db` is built with the API's own migrations in `stitch_helpers.py`) and
`tools/trafficgen/tests/test_stitching.py` (every relevant committed fixture through the real
ingest app and `run_once`).
