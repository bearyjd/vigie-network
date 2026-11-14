# Monitoring v1 contract

This slice derives collector-scoped hourly activity, a frozen pooled-median upload reference,
read-only incidents, and conservative service-based device hints. It does not establish malicious
activity, identity trust, enforcement, calibrated classification accuracy, or production readiness.
A baseline cannot mature before real qualifying history exists; synthetic fixtures prove arithmetic,
not detection accuracy. A read-only local monitoring GUI and opt-in, off-by-default notification
senders are merged; GUI writes and live notification acceptance remain open.

Source is merged through the reviewed DNS-probe fixes. The
[2026-10-25 field status](monitoring-field-status-2026-10-25.md) records healthy server deployment
and actual router logging/parsed-DNS and collector privilege evidence. A LAN correction produced
fresh source flags 0; flagged history is retained and controlled drain reached backlog0.
PR12 processing-age API is deployed and verified. Bounded outage, drop-in repair and reconciled
helper respawn passed; natural rotation and cold boot remain pending. Real-router 48-hour soaks
1-3 have run since; soak 4 was running on 2026-11-09 (no outcome claimed). #86-#92 (merged
2026-11-08/09) are not deployed; the deployment state of earlier merges is not recorded here. No
fourteen-date mature field reference is claimed.

## Rollout and ownership

Deploy the new server before new collectors: the new optional top-level `observation_kind` is
accepted by this server, but older strict servers reject it. Ordinary collector windows emit
`observation`; clock probes and partial identity pushes emit `probe`. Existing signed fixtures
and legacy collectors remain accepted. Missing kind/bounds is unknown coverage, never proof
of a complete observation window.

Ingest owns durable event-window bounds, receipt time, kind, DNS-row count and health metadata
(ingest migrations4–5). The pipeline owns measurements, profiles, reference models, incidents and
service-only characterization evidence (pipeline migrations6–9). API owns only human overrides,
including monotonic link generations (overrides migration6). No monitoring job writes human
intent, grants trust, changes a group, approves an identity or invokes enforcement.

## Measurements and coverage

Each batch receipt is applied atomically with the pipeline cursor. `(collector_id,batch_id)`
deduplicates derived contributions. Measurements are keyed by collector, canonical observed MAC,
and closed UTC hour. Two batches with uploads100 and250 produce350; replay remains350.
Sensors are never summed across collectors.

An interval `[start,end)` contributes only when wholly inside one UTC hour. An interval ending
exactly at the boundary belongs to the preceding hour. Crossing intervals, partial probes,
o duration and overlaps are excluded rather than divided uniformly. Legacy unknown-kind windows
may carry measurements, but never qualified training coverage. No data is represented as null,
not zero. DNS rows count observed queries, not contacted domains; no qname is copied into aggregates. Reads include all UTC shards touched by the accepted window
and DNS clock slack; persisted expected DNS-row counts detect a retired query-day shard. Missing
raw data degrades coverage and makes API counters null rather than asserting zero.

Qualification requires at least3420 observed qualified seconds (95%) and no quality reasons.
Missing health, CT source gaps/truncation, dropped batches and counter overflow disqualify
the hour (`flow_degraded`). The informational truncation keys are `ct_unmapped_bytes`,
`ct_unmapped_flows` and `ct_lan_unmapped_flows`; they never degrade coverage. The two pairs mean
different things: `ct_unmapped_*` is only expected exclusions (the global remainder and the
router's own addresses, present in every batch on a normal LAN), while `ct_lan_unmapped_*` is
LAN-prefix sources that have no MAC, a genuine attribution failure (unattributed traffic of known
devices would otherwise look like a quiet hour). `ct_lan_unmapped_bytes` is governed by a
threshold, not presence: the hour is disqualified only when it is above `LAN_UNMAPPED_MIN_BYTES`
(262144, 256 KiB per window, so a few KB cannot disqualify a quiet hour) AND above
`LAN_UNMAPPED_MAX_SHARE_PCT` (5) percent of `mapped_bytes + ct_lan_unmapped_bytes`, where
`mapped_bytes` is the up + down bytes the batch attributes to MACs. Exactly at either bound
qualifies. A read-only router snapshot showed unmapped-but-LAN traffic at about 0.02% of bytes,
so 5% leaves a 250x margin; both numbers are policy to be tuned on real data.

A threshold trip is recorded under its own reason, `lan_unmapped_share`, instead of
`flow_degraded`, so an operator can tell attribution trouble from a collector fault. It
disqualifies the hour exactly like any other reason (qualified seconds 0; the API reports the hour
as `partial` with that reason; the monitoring engine does not use the hour as a sample). If a
collector fault is also present the hour lists both reasons, sorted. A malformed, non-integer,
boolean or negative `ct_lan_unmapped_bytes`, or per-MAC totals that cannot be computed (counter
overflow), is a data fault and stays `flow_degraded`. A batch from an older collector without
`ct_lan_*` keys behaves as before.

Limits of this gate, stated plainly:

- The floor and the share are PER WINDOW, not per hour. Up to about 15 MiB per hour of
  unattributed traffic (256 KiB in each of roughly 60 windows) can pass while the hour qualifies.
- The denominator is collector-wide. Busy mapped traffic from other hosts dilutes the share of one
  host's unattributed traffic, and no per-device gate is possible because unattributed traffic has
  no device.
- Therefore this gate protects baseline quality; it is not a detector and must not be read as
  one.
- A LAN host sourcing unattributed traffic above both the floor and the share can deny baselines
  for the whole collector. Operators see it as the `lan_unmapped_share` reason and in
  `ct_lan_unmapped_bytes_in_retained_detail` / `ct_lan_unmapped_flows_in_retained_detail` in the
  API collector summary.

The generic loss rule matches the `ct_` and `conntrack` prefixes case-insensitively (fail closed),
while the informational set is an exact, case-sensitive match: an upper-cased informational key is
not informational. Every other nonzero `ct_*`/`conntrack*` key, including any future one, still
degrades the hour, as do `source_flags` (other than bit 8 alone) and `dropped_batches`. A non-zero
`truncated_other` always degrades: the collector only produces it when more than 16 counters were
non-zero (severe degradation). It folds `ct_unmapped_flows` first, then the smallest counters (a collector
that emits the `ct_lan_*` pair keeps it ahead of the others when it folds), so it can hide `ct_errors`, `ct_dropped_keys` or
`conntrack_lost`. Unmapped conntrack stays visible in the API collector summary
(`ct_unmapped_*_in_retained_detail` and `ct_lan_unmapped_*_in_retained_detail`) and in the soak
note (`unmapped_conntrack`, `lan_unmapped_conntrack`). Hours ingested before this change
keep their stored `flow_degraded` reason and stay disqualified; they are not recomputed.

A distinct overlapping batch degrades the existing hour without adding its bytes or duration,
unless it is a tolerated edge overlap. Independent whole-second truncation of the collector's wall
and monotonic clocks can overlap consecutive 60 s windows by 1 s, so an overlap is tolerated only
when it is at most 2 s (`OVERLAP_TOLERANCE_S`), at most a tenth of the shorter window, neither
window contains the other, and both windows are at least 30 s long (`MIN_TOLERANT_WINDOW_S`; the
collector's nominal window is 60 s). Windows shorter than 30 s get no tolerance at all. Anything
else disqualifies: overlaps over 2 s, nested or duplicate windows under a new batch id, short
windows, and a window intersecting more than two others. Batches that never contribute coverage
(clock probes and windows crossing an hour boundary) are not neighbours. A tolerated batch is
credited only for the seconds no earlier credited batch already covered, so a chain of windows
adds up to its union, never its sum, and an hour's observed and qualified seconds are capped at
3600. Counters of the tolerated sliver may be counted twice, bounded by at most 2 s of deltas
per boundary. A chain window has two boundaries, so a chain of windows of length L inflates its
counters by at most 2/(L-2) of the union: about 7.1% at 30 s windows, 3.4% at 60 s. An identical
receipt replay does neither (it is rejected by `batch_id`). Hours already marked
`overlapping_window` stay disqualified. A healthy endpoint or a clock probe is never observation coverage. DNS-specific source
quietness is reported separately; it does not establish traffic completeness.

### Collector window and attribution behaviour

- **Window continuity.** The collector remembers the previous window's end and starts the next
  window exactly there (`start_n == end_{n-1}`), so consecutive windows neither overlap nor leave
  a gap. When the remembered end disagrees with the monotonic clock by more than 2 s (first
  window, a held flush, a wall-clock jump) it falls back to monotonic arithmetic, never longer
  than 24 h; a fallback never starts before the previous end. If the wall clock steps back
  behind the previous end, the flush is deferred (data kept, retried each loop step) until the
  clock catches up, for at most 600 s of monotonic time, after which the monotonic arithmetic is
  used so a permanent step cannot stall uploads. DNS rows read during a deferral carry the
  stepped-back clock; the deferred window raises those below its start up to the start (the
  server rejects rows outside the window), while a row stamped before the deferral began, or
  outside any deferral, is still dropped and counted when it is out of the window. A deferred batch
  shares one window's caps (the per-window sightings admission and the batch size cap) across up to
  about eight windows of data, so more counted drops are possible. A Hold during a deferral drops
  the whole accumulated window but counts it as one dropped window. A spooled or retried batch keeps
  its original window.
- **Sticky IP to MAC.** An IPv6 conntrack source whose neighbor entry expired while its flow
  lives on is still attributed from a bounded memory (4096 pairings, 2 h of monotonic time since
  the neighbor table last held the address). IPv4 is never remembered (DHCP reuses addresses),
  and an address the current table reports FAILED or INCOMPLETE is never served from memory. A
  current table entry always wins, so a reassigned address is billed to its new owner; nothing is
  attributed from memory after the 2 h. Residual risk: another device taking over the same IPv6
  address inside the 2 h while the table has no entry for it would be billed to the previous
  owner; for privacy/temporary and per-device ULA addresses this is negligible.
- **Split unmapped counters.** `ct_unmapped_bytes` / `ct_unmapped_flows` count only EXPECTED
  exclusions: the helper's global remainder and the router's own addresses (read from
  `/proc/net/fib_trie`, `/proc/net/if_inet6` and the configured LAN address, every 5 minutes; a
  read failure treats nothing as own). `ct_lan_unmapped_bytes` / `ct_lan_unmapped_flows` count
  any other source still without a MAC, a genuine attribution failure. Collectors that predate
  the new pair send everything in the legacy pair. When the `truncated` map exceeds 16 keys the
  `ct_lan_unmapped_*` pair is kept ahead of all other counts and `ct_unmapped_flows` is merged first.
  Accepted, bounded risk: a source equal to one of the router's own addresses is treated as
  expected even though conntrack tuples cannot prove the packet came from the router. It only
  affects whether an hour qualifies (the traffic is not hidden from the totals), and needs spoofed
  packets to reach conntrack despite source validation. A source that currently has a MAC mapping
  is never classified as own. The procfs reads are bounded (1 MiB for `fib_trie`, 64 KiB for
  `if_inet6`); a file over its bound counts as a read failure.

Deployment order: the server must learn a share-of-bytes threshold for `ct_lan_unmapped_*`
before this collector is deployed; until then any hour with a non-zero `ct_lan_unmapped_*` count
degrades under the fail-closed unmapped rule above.

Each stored per-MAC hourly counter saturates at `(2**63-1)//64`; saturation marks the entire hour
`counter_overflow`. At most64 MACs may contribute to one identity, so SQLite sums remain integer
and cannot overflow. Values remain capped displays, not training samples. Identity components
beyond supported bounds fail unavailable instead of returning a favorable partial aggregate.

## Frozen references and incidents

Algorithm `pooled-median-v1` freezes the first chronological eligible cohort containing at least
20 hours on14 distinct UTC dates. A stored `median_twice` preserves exact half-byte medians.
Known suspicious and fixed-large-upload hours are excluded. This is an explainable pooled baseline,
not an hour-of-week model or a malware verdict. It is deliberately not continually refit from
new unusual traffic, which limits one form of baseline contamination; slow adversarial drift and
unrecognized contamination still require real-data evaluation and feedback design.

The learned detector requires TWO consecutive eligible post-reference hours each strictly above
`max(50MiB,4*median)`. Equality does not fire. A missing or degraded intervening hour breaks the
pair. The cold-start fixed detector fires at or above1GiB upload/hour. Configure the fixed threshold
with `VIGIE_MONITORING_LARGE_UPLOAD_BYTES` (default1073741824; integer1..2**50). Select the
learned baseline family with `VIGIE_MONITORING_BASELINE` (`pooled` default, or `tod`; see below). Algorithm and full
policy are hashed into a version. A changed configuration rebuilds rather than silently reusing
an incompatible reference.

Open-hour work retains its closing deadline, so a time-only pipeline pass can evaluate an hour even if no further batch arrives. Only the latest closed hour is evaluated for new incidents. Historical backfill can supply allowed
learning history but cannot emit a historical alert flood. An episode uses a deterministic ID;
repeated processing updates it. A consecutive episode remains one incident. A later eligible quiet
hour resolves it; missing coverage does not claim recovery. Evidence includes observed bytes,
threshold, reference/config IDs, lineage, coverage floor and `unusual_is_not_malicious=true`.

Lineage hashes the canonical MAC set, attachment assignment generations and human link generations.
Merge, undo and attachment round-trips cannot resurrect a prior lineage by returning to the same
MAC set. Changes restart learning from the next UTC-hour boundary; initial rule-attached devices
also wait for future history. They can mature after probation, without requiring an unavailable
confirmation UI. Name-only edits do not reset learning. Old immutable references remain attributable
to their original lineage; stale open incidents are superseded. API labels stale profiles rebuilding.
If a retained training hour later loses quality, the active reference is withheld immediately by the API. The pipeline supersedes its open incidents and restarts future learning in `rebuilding_quality`; the historical immutable reference stays attributable. Collector-hour invalidations fan out through a durable cursor in batches of1000 MACs, and incomplete identities back off60 seconds so independent scopes progress. New entities may learn qualified history already recorded since feature activation; newly attached
MACs cannot immediately redefine an old reference.

### Time-of-day baseline (tod-median-v1, opt-in)

`vigie_pipeline/baselines_tod.py` is a pure module (no I/O, clock or database). The engine runs it
only when `VIGIE_MONITORING_BASELINE=tod`; the default `pooled` keeps `pooled-median-v1` unchanged.
The selector is pipeline-only, exact-match (`pooled` or `tod`, anything else fails at startup) and
is also the `monitoring_baseline` key of the persistent renderer. No schema or migration changed.
Switching it changes the policy version, so every profile restarts in `learning` from the next UTC
hour and open incidents are superseded (expected; flip it deliberately).

- **Cohorts.** `(is_weekend, hour_of_day // bucket_hours)` read from the sample's epoch hour in
  UTC. `bucket_hours` divides 24 (1, 2, 3, 4, 6, 8, 12 or 24; default 4), so adjacent hours pool and
  there are `2 * 24 / bucket_hours` cohorts. Local time and DST are deferred: a DST change never
  moves a sample between cohorts, it only means the bucket is not the household's wall-clock hour.
- **Maturity.** A cohort needs at least 20 valid samples AND 7 distinct UTC days, else it ABSTAINS
  (`immature_samples`, then `immature_days`). With four-hour buckets a weekday cohort matures after
  about 7 weekdays of history and a weekend cohort after about 7 weekend days (the fourth Saturday).
- **Valid samples.** Ineligible (missing) hours are skipped, never counted as zero. Suspicious hours
  and hours at or above the fixed large-upload line are excluded as contamination. At most 4368
  samples (26 weeks) are accepted; hours and byte counts must be exact integers.
- **Threshold.** Twice the cohort median is kept exactly; the line is
  `min(large_upload_bytes, max(minimum_bytes, median * multiplier))`: the same constants as
  `pooled-median-v1`, plus a cap at the fixed large-upload line. `pooled-median-v1` is not capped.
- **The caller freezes the baseline.** `fit_tod(samples, config, trained_until)` learns only from
  hours up to `trained_until` and records it, plus each cohort's last trained hour. `findings_tod`
  scores an hour only if it is strictly after both; otherwise it abstains with
  `leaks_evaluated_hours`. Appending later history never redefines normality, so slow drift is
  judged against the frozen window.
- **Engine freeze rule.** `trained_until` is the first qualified hour at which EVERY cohort is mature
  (so a weekday-only history never freezes; a device with no eligible data in some bucket stays in
  `learning` and only the fixed large-upload detector runs). It is then fixed and never advances.
  Any quality reset (a used hour became ineligible, suspicious or large) drops the reference and the
  profile goes `rebuilding_quality`, as for pooled.
- **Reason code and threshold.** A tod deviation reports `reason_code=two_qualified_upload_hours_in_cohort`
  (the read API and `api/openapi.yaml` accept it). When an incident continues into a cohort with a
  different line, its `threshold_bytes` follows the latest observation, as `observed_bytes` does.
- **API label.** `baseline.algorithm` in the activity view is now null whenever there is no stored
  baseline (learning, rebuilding or after a lineage change), under the default `pooled` mode too; it
  used to read `pooled-median-v1` in those states. For tod, `median_upload_bytes` is null (thresholds
  are per cohort), and the UI says so.
- **Intermittent devices and incidents.** Because the freeze needs every cohort mature, a device with
  intermittent data stays in `learning` and only the fixed detector runs. A fixed `large_upload` and an
  `upload_deviation` can both open for the same hours; duplicate incidents are by design. tod evidence
  also carries `bucket_hours`, the cohort and `cap_applied` (the read API's allowlist drops them today).
- **Persistence, no schema change.** The baseline row stores `algorithm=tod-median-v1`,
  `trained_until`, the used `training_hours`, and in `config_json` the policy (including
  `bucket_hours`) plus `training_bytes` (the byte value of each used hour). Every pass refits
  deterministically from those stored inputs, so pruning of raw measurements after 90 days or a
  rewritten `bytes_up` cannot move a frozen reference. Unreadable or inconsistent stored inputs are
  treated as a quality reset. `median_twice`, `sample_hours` and `distinct_days` hold OVERALL figures
  over the used hours (median of all used values, their count, their distinct UTC days) to satisfy the
  table and the API; thresholds never use them, only the per-cohort refit. Incident evidence keeps the
  pooled key set: `baseline_median_upload_bytes`, `sample_hours` and `distinct_days` describe the
  cohort of the evaluated hour (null when it has no fitted cohort).
- **One threshold, two sites.** The suspicious-hour marker in the engine and the deviation detector
  use the same `deviation_threshold`, so an hour is marked only when its own cohort is mature and
  leak-free.
- **Detection.** The fixed large-upload candidate is always evaluated first, even in cold start or
  with an immature cohort. The learned deviation needs TWO consecutive eligible hours, each strictly
  above the line of its OWN mature cohort. An immature current cohort abstains with its reason; an
  immature previous cohort abstains with `previous_<reason>`. A nightly backup that is high every
  night is learned, not flagged.
- **Known blind band.** A baseline poisoned by sustained high traffic before `trained_until` raises
  a cohort line up to `multiplier` times its median. The cap bounds the learned line at the fixed
  large-upload line (1 GiB/h by default), so sustained upload above that now also yields an
  `upload_deviation` candidate. It does NOT detect sustained traffic just below the fixed line: such a
  cohort is learned as normal and only the fixed detector remains as the backstop. `pooled-median-v1`
  has the uncapped limit.
- **Versioning.** `TodConfig.version` hashes the algorithm id and every parameter, including
  `bucket_hours`. Results are deterministic for any input order, and backfilled history fits by its
  own cohort.

## Bounded read API

All routes require the existing bearer read token, preserve collector scope and return typed envelopes.

- `GET /coverage?collector_id=...`: hourly coverage and collector receipt/window/backlog/resource
  summaries, including `latest_dns_observation_window_end` and its receipt time only from a
  positive DNS-row observation window. Probes never refresh these values.
- `GET /devices/{id}/activity?collector_id=...`: per-identity activity, lineage and model state;
  unknown devices return404. Human aliases resolve through existing identity links.
- `GET /incidents?collector_id=...&device_id=...` and `GET /incidents/{id}?collector_id=...`:
  bounded incident list/detail, with current-lineage attribution.

Hour ranges use `from_hour`/`to_hour`, UTC boundaries, a maximum90 days and at most200 hours/page.
Opaque cursors are bound to route, collector, device and exact range. Missing migrations yield503.
Collector detail summaries inspect at most10000 recent batches and expose capped indicators.
The device-list type filter examines at most `max(32,limit+1)` candidate rows per request and advances its opaque cursor by scanned position. A filtered page may be empty with a next cursor; following it does not skip later matches. Coverage also returns up to20 unavailable monitoring scopes with reason and retry time. Agent RSS/uptime are reported observations; absent router/helper/RAM/tmpfs/CPU metrics stay unknown.
These endpoints alone cannot certify a48-hour resource or DNS soak.

Soak ingest-address precheck: the soak runner config may carry an optional literal IPv4 `ingest_address` (the address the ingest container is published on, for example `<ingest-lan-ip>`). When set, the runner checks that the address is assigned to a local interface before the first sample and again before every later sample. If it is not, the run stops with status `fail` and reason `ingest_address_unbound` (exit code 1) instead of sampling a dead endpoint for hours. At start nothing is written to the journal. Mid-run the journal keeps its samples and only the printed report gains the reason. The early-abort report at start carries only `status`, `evidence_mode` and `reasons`. An unreadable interface table counts as unbound. The key must be a concrete unicast IPv4 string (loopback, link-local, multicast, reserved and unspecified are rejected, as is `null`). The failure is sticky: when the check aborts a run (non-preflight), the runner creates `<journal>.ingest_address_unbound` (exclusive, 0600, holding only the reason and a timestamp). While that file (or a symlink at that path) exists, every start, whether or not `ingest_address` is still configured, fails immediately with `ingest_address_unbound` without sampling, so resuming after the address returns cannot turn the failure into a pass. Delete the file deliberately, or begin a new journal, to clear it. If the marker cannot be written the fail report is still printed and a warning goes to stderr. `soak.py` does not read the marker. Omitting the key keeps the previous behavior. Existing reason names and verdict rules are unchanged.

Soak dropped-batch gate: the soak requires that no batch drops were received since the run started. The runner takes the run start from the first sample of the journal (its wall time, floored to the second) and sends it, 300 seconds earlier, on every coverage fetch of the run (the margin means runner/server clock skew can only cause a false fail, never hide a drop; the stored run start is unchanged) as the optional `dropped_since` query parameter, a strict UTC instant such as `2026-01-01T00:00:00Z` (the format the ingest stores in `received_at`; anything else, or an instant more than a day ahead of the server clock, is a 422). The collector coverage response then carries `dropped_batches_since`: one SQL sum of `dropped_batches` over the collector's batches received at or after that instant (a row exactly at the instant counts), or `null` when the parameter is absent or SQLite reports any operational error (overflow included). It is not subject to the 10000-batch summary cap, and the capped `dropped_batches_in_retained_detail` keeps its meaning but is no longer used by the soak. The gate is `dropped_batches == 0` as an integer on every sample, with the existing `dropped_batches_limit` reason. A null, absent, boolean, negative or non-integer total is an unknown metric, never a favorable zero. Drops received before the run start are irrelevant, however many there are. The 7-day batch purge cannot hide an in-run drop because retention exceeds the 48-hour run. A resumed run reuses the journal's first sample as the run start, never the current time; a first sample without a usable wall time counts every retained drop. A preflight has no journal and uses its own sample time. Drops reported in a batch that the collector delivers after the final sample are not counted; the verdict covers batches received up to the last sample. The server must be deployed with the `dropped_since` parameter and `dropped_batches_since` field before a soak starts: against an older build the total is absent, which fails closed as a missing metric. The runner needs Python 3.11 or later, because API timestamps ending in `Z` are parsed with `datetime.fromisoformat`.

## Characterization

The pure rule contract is [characterization.md](characterization.md). The pipeline retains only
MAC, protocol, service and timestamp, at most256 distinct services/MAC; overflow blocks a favorable
partial classification for24 hours. Each rule's supporting pair must be on the SAME MAC. A TV pair
split across two MACs cannot combine, even within one human identity. Conflicting qualified roles
produce unknown. Evidence is unauthenticated, spoofable LAN metadata, never identity proof.

`GET /devices/{id}` adds `explanation.characterization`: type/role, qualitative strength, rule IDs,
canonical service evidence, model version and expiry; numeric confidence remains null. Human type
choices take priority. Supporting evidence expires at the oldest required service's24-hour deadline;
API withholds expired or stale-lineage hints, without waiting for the next pipeline refresh. A
bounded20-device refresh processes new/expired hints and round-robin work. No raw hostname, vendor
class, UA or randomized-MAC OUI is turned into an asserted manufacturer or numeric probability.

### Incident delivery

Delivery is **off by default** and the local inbox works without any publisher. The pipeline (not
the API) owns the planner and the outbox and reads decisions read-only from `overrides.db`. While
delivery is disabled the runner is not called, so nothing is created and nothing expires. The
real network adapter (topic, ownership: D5) is not in the pipeline: the standalone ntfy and Home
Assistant senders (#49, #71; see below) ship the delivery file and are off by default. No pipeline
code names a topic or opens a socket.

**What is wired (unit 4b).** After `analyze_monitoring`, when `VIGIE_DELIVERY_ENABLED` is set,
each pipeline pass (`--loop` and `--once` alike) calls `delivery_runner.run_delivery`:

1. *Planner pass*: one `BEGIN IMMEDIATE`; `now` is read after it; the complete incident set, all
   delivery rows and the decisions are read; `plan()` runs and every action is applied through
   `delivery_sql`. A statement that does not affect exactly one row rolls the whole pass back
   (`PassError`, logged as `delivery_stage_failed`; the rest of the pipeline pass is unaffected).
   If `overrides.db` is absent, unreadable or locked the whole run is skipped (nothing is planned
   and nothing is sent; `delivery_decisions_unavailable` is logged once per run).
2. *Drain*: up to `VIGIE_DELIVERY_MAX_PER_RUN` due `pending` rows, oldest first. Per row: CLAIM in
   its own short transaction, `may_transmit` right before the publisher (past the deadline: no
   transmit, a failed attempt is recorded), the publish OUTSIDE any transaction under a hard wall
   timeout of `VIGIE_DELIVERY_TRANSMIT_DEADLINE_S` enforced by the runner (a daemon worker thread
   abandoned at the deadline), then COMPLETE with the claim token. A hung publisher ends the drain
   for that run, so a pass is delayed by at most one deadline plus the normal drain work. Every
   abandoned worker is tracked process-wide; once `VIGIE_DELIVERY_MAX_ABANDONED` of them are still
   running the runner stops before CLAIMing (no attempt is burned, `delivery_transport_wedged` is
   logged on the first such run and every 20th) until they return. A late worker's result is
   discarded and never completes a row. Capacity is reserved atomically before the CLAIM, and a
   delivery whose abandoned worker is still running is excluded from the candidate query and never published twice at once.
3. *Watermark*: the first enabled run stores `pipeline_meta.delivery_eligible_since` (the floor of
   `now`) with `INSERT OR IGNORE`; later runs, and disable/enable cycles, never move it.
   Incidents detected before it are never announced.

A runner exception is caught and logged (first occurrence and every 20th), never raised into the
pass. A message is built from fixed
templates, the relative link `/ui/#incident=<id>` and a device ALIAS (`Device <6 letters>`, a hash
of the device id): by default NO free text from the database is included, and the device name is
not even read. The owner opens the link to see the device name locally. This is the safe default
for any future network publisher, because free text cannot be proven safe. It narrows the earlier
"device label" payload decision; the owner can flip it with `VIGIE_DELIVERY_INCLUDE_LABEL=1`,
meant for local-only publishers such as the FilePublisher. In that mode the name
(`device_overrides.name`) goes through a strict acceptor (`delivery_publish.scrub_label`) that
validates the RAW string, with no truncation, trimming, whitespace collapsing or NFKC folding
first (each can hide content): at most 48 characters, no leading, trailing or doubled space, only
ASCII letters and digits, space, `'`, `’`, `-` and the Latin-1 letters U+00C0-U+00FF (without
x and division), already NFKC-stable, at most 3 digits, a letter, fewer than 12 hex-looking
characters (no MAC), no word of 20 or more characters. The name is then sent verbatim; anything
else, or a missing name or failed lookup, gives the alias (never the raw device id). This
over-redacts on purpose: names with a dot, underscore, emoji, more than 3 digits, other
punctuation or a non-Latin script show as an alias. Incident ids reach the relative link by
design; delivery ids are hashes.

**Settings** (all in `deploy/.env.example`; invalid values stop the pipeline at startup):
`VIGIE_DELIVERY_ENABLED` (only `1`/`true`/`yes` enable; `0`/`false`/`no`/`off`/empty disable; any
other value is an error), `VIGIE_DELIVERY_FILE` (required when enabled), `_LEASE_S` (300),
`_TRANSMIT_DEADLINE_S` (30), `_MAX_ATTEMPTS` (6), `_BACKOFF_BASE_S` (60), `_BACKOFF_CAP_S`
(3600), `_TTL_S` (86400), `_RETENTION_S` (2592000), `_MAX_PER_RUN` (20), `_MAX_ABANDONED` (2, at least 1: at most this many publishes are in flight or abandoned-and-still-running at any moment across the process, so it also bounds concurrent publishes), `VIGIE_DELIVERY_INCLUDE_LABEL` (off, see above), `_DRAIN_BUDGET_S` (60, at least the transmit deadline: once a drain has run this long (measured on a monotonic clock, checked before every claim attempt) it claims nothing more, so a transport that fails just under its deadline cannot hold the pass for `MAX_PER_RUN` x deadline).

**FilePublisher format.** The only publisher today appends one JSON object per line to
`VIGIE_DELIVERY_FILE`: `{"delivery_id","kind","title","body","link"}`, ASCII-only. The file is
created 0600 with `O_APPEND|O_NOFOLLOW`, only a regular file is accepted (a symlink, FIFO or
device is refused), each message is one `write` followed by `fsync`, every append holds an exclusive `flock` across the size check and the write, a failed or short
write is cut back to the previous size, and a message that would push
the file past 10 MiB is refused (the delivery then fails and retries; rotate or truncate the
file). The file must live under a mount the pipeline can write. The stock compose adds no volume for it
(the least-privilege mount matrix is unchanged), so use the pipeline's existing writable inventory
volume, e.g. `/inv/delivery-messages.jsonl`. The API container mounts that volume read-only, so it
can read the file but not modify it. Messages hold only a device alias (or, if opted in, a strictly validated name) and a relative link.

A failure of `fsync` (or of the cut-back itself) can leave a line that was already written while
the delivery is retried, so the retry duplicates it: delivery is at least once. Every line carries
`delivery_id`; consumers should dedupe on it.

**Enabling safely.** Set `VIGIE_DELIVERY_FILE=/inv/delivery-messages.jsonl`, then
`VIGIE_DELIVERY_ENABLED=1`, restart the pipeline and watch the file. Only incidents detected after
the first enabled pass are announced. To stop, set `VIGIE_DELIVERY_ENABLED=0`: pending rows then
wait (nothing expires) until it is switched back on.

**Residual windows.** A publisher that ignores its deadline can still finish after the runner
abandoned it, which may produce a duplicate (the row is retried); a completion that arrives after
its lease lapsed is lost by design; the runner and the planner must share one clock; a daemon
worker abandoned on a hang lives until its call returns (at most `MAX_ABANDONED` at a time), and
it may still have delivered its message after the row was retried: delivery is at least once.

Pipeline schema v11 adds `incident_deliveries`: one row per incident and kind (`open` or
`recover`; `UNIQUE(incident_id, kind)`), integer epoch-second `created_at`, `updated_at` and
`next_attempt_at` (required while `pending` or `sending`), `attempts >= 0`, a `version` (a plain
counter: 0 at creation, +1 per change) and `last_error` capped at 200 characters. `row_id` is an
`INTEGER PRIMARY KEY AUTOINCREMENT`, the incarnation token; `delivery_id` (unique) is the first 32
hex chars of `sha256(incident_id + "\n" + kind)`. External payloads carry a device label and an
incident link only. States:

| state | meaning |
| --- | --- |
| `pending` | waiting for `next_attempt_at`, then for a sender to claim it |
| `sending` | claimed: a sender holds a lease until `next_attempt_at`; the planner leaves it alone |
| `sent`, `failed`, `expired` | terminal |
| `suppressed` | held back by an acknowledged/expected decision; re-checked every pass |
| `withdrawn` | a `recover` taken back because its incident is not resolved; revived by the next resolution |

**Contract.** Unit 4b reads the complete incident set and the delivery rows, runs `plan()` and
applies every action inside one `BEGIN IMMEDIATE` transaction; it skips the pass if the incident
read fails (a partial list would expire pending rows as `incident_missing`). Each action is exactly
one of the statements below (`vigie_pipeline.delivery_sql`; the tests run them against a table built
by the production migration, and another test keeps this block identical to the code) and carries
the row it was planned against (`expected`: state, attempts, version, row_id) as an assertion. Every UPDATE
sets `updated_at=:now` and `version=version+1`. Each statement must affect exactly one row;
anything else is a planner bug, so roll the whole pass back (`delivery_sql.apply_actions` raises
`PassError` naming `delivery_id` and `row_id`). To investigate, run `SELECT * FROM
incident_deliveries WHERE delivery_id = '<id from the message>'`; a corrupt row may be removed by
hand with `DELETE FROM incident_deliveries WHERE row_id = <row_id>` (the next pass then plans the
incident afresh, so an open that was already sent may be announced again).

**Sender contract (a lease).** The sender works in short separate transactions: CLAIM a due
`pending` row (the only way to transmit; attempts are counted at claim, and a transmit aborted by
`may_transmit` still uses one); transmit outside any transaction; then COMPLETE with the claim token `(row_id, version)` (`sent`;
back to `pending` with a backoff, or `failed` past `max_attempts`, via
`delivery_sql.failure_statement`). The database allows only one live CLAIM per delivery
(`sending`, lease end in `next_attempt_at`) and fences every write by `row_id` and `version`, but
it cannot see a network call. Overlapping transmissions are prevented by the sender contract:

- a hard timeout covering connect, send and response, no longer than `transmit_deadline_seconds`
  (default 30);
- call `may_transmit(claimed_at, now, config)` right before the network call and abort without
  transmitting (recording a failed attempt) if it is false, i.e. `deadline` seconds or more after
  the claim;

Recording the result before the lease lapses is what avoids a duplicate send; a completion that
arrives later is harmless to the table, because it is fenced by `row_id` and `version`.

`lease_seconds` (default 300, at least 60) must be at least twice the deadline, so a sender that
honours the contract has finished transmitting before the earliest possible Reclaim, and the next
claim can only follow later. The lease is half-open, `[claim, claim + lease)`: at `next_attempt_at
== now` it has lapsed, the planner's Reclaim wins, and a completion arriving in that same second
finds a new version and is lost. Sender and planner must read one clock (the same pipeline process
or host) for the lease timing: clock skew between hosts, or a forward clock jump, can break the
no-overlap guarantee. Incarnation fencing does not depend on the clock at all. Residual: a
sender that violates its timeout (a hung network call) can cause a duplicate that the receiver
cannot detect; publisher idempotency keys are a later concern (4c).

The planner never touches a live `sending` row (no expiry, suppress, reschedule, withdraw or
forget). Whatever changed during the send (an ack, a snooze, a resolve or a reopen) is applied on
the next pass, once the row is `sent` or `pending` again.

**Time.** Compare with floor, stamp with ceil: we never act early and never promise early. The
shell derives two integers from `now` (`delivery_types.tick_floor` and `tick_ceil`, re-exported by
`delivery_sql`). Every eligibility test (CLAIM's `next_attempt_at <= :due_now`, a lapsed lease,
`may_transmit`) uses the floor; `updated_at` and every new deadline (lease end, backoff, snooze) use
the ceil, so `updated_at + backoff(attempts)` can never undershoot a stored deadline.

**Incarnations.** A statement keyed by a row matches `row_id = :row_id AND version = :version`.
`row_id` is AUTOINCREMENT, so SQLite never reuses one, even after a Forget: a recreated delivery
(same `delivery_id`) is a different row, and a claim token taken from an earlier incarnation can
never complete it, whatever the clock, the retention or the number of updates. `version` is a plain
counter with no ceiling. Backoffs are whole seconds (`backoff_base_seconds` and
`backoff_cap_seconds` must be integers) and every computed time is rounded up, so no statement ever
binds a fractional time.

```sql
-- planner: Enqueue (version 0; SQLite assigns a fresh row_id)
INSERT OR IGNORE INTO incident_deliveries
  (delivery_id, incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at,
   version)
VALUES (:id, :incident_id, :kind, 'pending', 0, :not_before, :now, :now, 0)

-- planner: Suppress, incident without a row
INSERT OR IGNORE INTO incident_deliveries
  (delivery_id, incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at,
   version)
VALUES (:id, :incident_id, :kind, 'suppressed', 0, NULL, :now, :now, 0)

-- planner: Suppress (pending, or a lapsed sending open, which keeps its retry deadline)
UPDATE incident_deliveries SET state='suppressed',
  next_attempt_at=COALESCE(:next_attempt_at, next_attempt_at), updated_at=:now,
  version=version+1
WHERE row_id=:row_id AND state=:state AND attempts=:attempts AND version=:version

-- planner: Reschedule
UPDATE incident_deliveries SET next_attempt_at=:next_attempt_at, updated_at=:now, version=version+1
WHERE row_id=:row_id AND state='pending' AND attempts=:attempts AND version=:version

-- planner: Requeue (suppressed -> pending)
UPDATE incident_deliveries SET state='pending', next_attempt_at=:not_before, updated_at=:now,
  version=version+1
WHERE row_id=:row_id AND state='suppressed' AND attempts=:attempts AND version=:version

-- planner: Revive (withdrawn -> pending; attempts and created_at are kept)
UPDATE incident_deliveries SET state='pending', next_attempt_at=:not_before, updated_at=:now,
  version=version+1
WHERE row_id=:row_id AND state='withdrawn' AND attempts=:attempts AND version=:version

-- planner: Expire (state is pending, suppressed, withdrawn or sending)
UPDATE incident_deliveries SET state='expired', updated_at=:now, version=version+1
WHERE row_id=:row_id AND state=:state AND attempts=:attempts AND version=:version

-- planner: Fail (pending, suppressed, withdrawn or sending)
UPDATE incident_deliveries SET state='failed', updated_at=:now, version=version+1
WHERE row_id=:row_id AND state=:state AND attempts=:attempts AND version=:version

-- planner: Withdraw (a recover, pending or lapsed sending, whose incident is not resolved)
UPDATE incident_deliveries SET state='withdrawn', updated_at=:now, version=version+1
WHERE row_id=:row_id AND state=:state AND attempts=:attempts AND version=:version

-- planner: Forget a recover row (or any row without the sibling guard)
DELETE FROM incident_deliveries
WHERE row_id=:row_id AND state=:state AND attempts=:attempts AND version=:version

-- planner: Forget an open row (refuses while a recover is pending or sending)
DELETE FROM incident_deliveries
WHERE row_id=:row_id AND state=:state AND attempts=:attempts AND version=:version
  AND NOT EXISTS (SELECT 1 FROM incident_deliveries r
                  WHERE r.incident_id=:incident_id AND r.kind='recover'
                    AND r.state IN ('pending', 'sending'))

-- planner: Reclaim a lapsed sending row that is still deliverable
UPDATE incident_deliveries SET state='pending', next_attempt_at=:next_attempt_at, updated_at=:now,
  version=version+1
WHERE row_id=:row_id AND state='sending' AND attempts=:attempts AND version=:version

-- sender: claim a due pending row (the only way to transmit); the lease end is next_attempt_at
UPDATE incident_deliveries SET state='sending', attempts=attempts+1,
  next_attempt_at=:now+:lease_seconds, updated_at=:now, version=version+1
WHERE row_id=:row_id AND state='pending' AND next_attempt_at<=:due_now
  AND attempts<:max_attempts AND version=:version

-- sender: the send succeeded (claim token: row_id and version)
UPDATE incident_deliveries SET state='sent', updated_at=:now, version=version+1
WHERE row_id=:row_id AND state='sending' AND version=:version

-- sender: the send failed, retry later (next_attempt_at from the claimed row)
UPDATE incident_deliveries SET state='pending', next_attempt_at=:next_attempt_at,
  updated_at=:now, version=version+1
WHERE row_id=:row_id AND state='sending' AND version=:version

-- sender: the send failed and the budget is spent
UPDATE incident_deliveries SET state='failed', updated_at=:now, version=version+1
WHERE row_id=:row_id AND state='sending' AND version=:version
```

**Maintenance.** A future migration that rebuilds `incident_deliveries` by copy, drop and rename
must carry the `sqlite_sequence` counter over (or run with no claim in flight), or `row_id`s would
restart and an old claim token could match a new row. Restoring an older database backup while a
sender holds a claim has the same effect: stop the senders first.

**Sender checklist (unit 4b).** Acceptance test: a fake transport with a HUNG transport.

1. One planner pass = one `BEGIN IMMEDIATE` transaction; read `now` AFTER the transaction has begun
   (so a CLAIM committed in the gap cannot leave the pass with stale time), then read the COMPLETE
   incident set and all rows, `plan()`, and apply the actions with `delivery_sql.apply_actions`;
   on `PassError` roll the whole pass back.
2. CLAIM (`delivery_sql.CLAIM` with `claim_params`) in its own short transaction; it must affect 1
   row. Re-read the row: its `(row_id, version)` is the claim token.
3. Call `may_transmit(claimed_at, now, config)` with `claimed_at` = the CLAIM's `:now`, which is the
   row's `updated_at`; abort without transmitting, and record a failure, if it is false.
4. Transmit outside any transaction with a hard timeout covering connect, send and response, at
   most `transmit_deadline_seconds`.
5. Record the result in a short transaction: `COMPLETE_SENT`, or `failure_statement(claimed, now,
   config)`, both with `completion_params` (the claim token).
6. Sender and planner read one clock (same process or host) for the lease timing.

If the sender crashes after transmitting, the row stays `sending` until the lease lapses. The
planner then judges the lapsed claim by the normal rules first: it expires it if its lifetime ended,
its incident is missing, or (for an `open`) its incident has since resolved or been superseded, and
withdraws a `recover` whose incident is no longer resolved. It fails it past the budget. An `open`
then meets the current decision as a pending row would: acknowledged or expected is suppressed, a
snooze moves it back to `pending` no earlier than the snooze end; only otherwise it Reclaims it
(back to `pending` after a backoff, `attempts` not counted again). A lapsed
lease means we cannot know whether the transmit happened. Delivery is therefore at least once, and
the cancellation rules deliberately favour a lost announcement over a stale one: a crash after a
successful send can cause one retransmission per reclaim (bounded by `max_attempts` for the whole
life of the delivery), and an `open` that did go out but whose claim lapsed and whose incident then
resolved (or was acknowledged) is expired or suppressed, so that user sees the open and never gets a
recover for it. We do not send a recovery for an announcement we cannot prove was delivered. Another
accepted window, bounded by one send duration: a `recover` claimed before its incident reopened is
delivered, so the user may see one stale recovery notice. A pending row already at `max_attempts`
is failed by the planner rather than left for the ttl, because CLAIM refuses it.

Rules (`vigie_pipeline.delivery_plan.plan()`; no I/O, `now` injected, a non-finite `now` raises
`ValueError`, action times are integer seconds):

- A loud open incident gets one `open` delivery. Acknowledged or expected incidents are suppressed
  (a row is inserted as `suppressed`, so history exists). Suppressed rows are re-checked every
  pass, so a cleared decision (or a cleared `NULL`-status row) requeues the delivery.
- A snooze defers delivery to `snooze_until` (strictly before is quiet, as in the inbox). A pending
  row is due at the verdict, but never before its cumulative backoff (after a failure, that is
  `attempts > 0`: `updated_at` plus the backoff for its attempts) and never later: a cleared or
  shortened snooze pulls it in, even if it
  was parked at the old snooze end by a Reclaim, while a longer snooze pushes it out. A lapsed
  claim that is acknowledged keeps the retry deadline a Reclaim would have used, so an ack followed
  by a clear cannot skip the backoff.
- An un-ack never silently drops an announcement. A pending row expires 24 hours after
  `max(created_at, next_attempt_at)`; a requeue sets `next_attempt_at` to its target, so an ack
  that lasted longer than the ttl does not expire a still-open loud incident. Spam is bounded by
  the attempt budget (a requeue keeps `attempts`; past `max_attempts` the row fails) and by a hard
  lifetime: a row more than 30 days past `created_at` expires as `lifetime` and is never revived,
  so an acknowledgement older than that never notifies after it is cleared. Failures back off 60 s
  doubling to 1 h, six attempts.
- An incident that closes before its `open` delivery went out expires it and gets no `recover`.
  Exactly one `recover` is created, only for a `resolved` incident whose `open` was `sent`, on the
  first pass after resolution however old the open row is. A pending `recover` for an incident that
  is no longer `resolved` (open again, or superseded) is withdrawn, and the next resolution revives
  that row, keeping its attempts and `created_at` (the retry budget and the lifetime are cumulative);
  a recover that was already sent is not repeated. Accepted windows are listed with the SQL above.
  Known limit: superseded
  incidents, and incidents that stay open because the device went silent
  (`monitoring_unavailable` covers silence), get no recovery notice.
- Retention is all or nothing. An incident's rows are forgotten together, in one pass (one
  transaction), and only when the incident is closed or missing, no recover is owed, and every row
  is terminal (`withdrawn` counts) and more than 30 days past `updated_at`. Rows of a still-open
  incident are never forgotten, so an old incident never re-announces, and a row is never forgotten
  alone: a half-forgotten incident would announce again when it reopens. Pending rows of a missing
  incident expire first. An incident id that is pruned and later reappears after all its delivery
  rows have been forgotten is treated as new, and so is a closed incident that reopens after its
  rows were forgotten (real incidents get a new id).
- Watermark: an incident detected before `eligible_since` that has no delivery rows is ignored
  completely. An incident that already has any row is managed normally, so raising the watermark
  never drops an owed recover or forgets state, and lowering it only admits incidents that were
  never announced.
- Unknown states, statuses and non-finite or non-numeric values fail closed (`unrecognised_state`).

### Incident delivery to ntfy

`deploy/persistent/ntfy_sender.py` ships the delivery file (the FilePublisher output above) to the
public ntfy server. It is **off by default**, standalone (Python standard library, no dependency)
and **not wired into the pipeline**: the pipeline keeps `Network=none` and has no network adapter,
no new `VIGIE_DELIVERY_*` setting and no code change. The sender is a separate process (a oneshot
user unit fired by a timer, run inside `podman unshare`) that only reads the file.

```
pipeline (Network=none) --FilePublisher--> delivery-messages.jsonl --read-only--> ntfy_sender.py --HTTPS--> ntfy.sh
```

**Why `podman unshare`.** The pipeline container writes the delivery file as its own uid (10001
inside the container, a host subuid outside) and FilePublisher forces mode 0600, inside a 0700
volume directory. A process running as the plain host user gets `EACCES` on it every minute and no
alert would ever be sent. `podman unshare` enters the rootless user namespace as its root, which
can read files owned by the mapped uids. Trust boundary: the same host user who owns the rootless
containers can already enter that namespace and read these files, so nothing is widened. Inside the
namespace the process is uid 0 and the host user's own files (config, topic, token, cursor) appear
as owned by uid 0; the sender's secret-file check compares the owner with the EFFECTIVE uid of the
process, so it holds both under `podman unshare` (0) and on a plain host (your uid). The check
assumes that no container of the stack runs as container uid 0: files written by such a container
would map to the host user and pass the owner check. Check read
access once by hand (replace the placeholder):

```sh
podman unshare test -r /ABSOLUTE/PATH/TO/delivery-messages.jsonl && echo ok
```

`delivery_file` in the config is the HOST path of the file inside the inventory volume, that is the
volume mountpoint plus the file name. Look the mountpoint up with
`podman volume inspect NAMESPACE_inv --format '{{.Mountpoint}}'` (placeholder namespace) and append
`/delivery-messages.jsonl` (the name you gave `VIGIE_DELIVERY_FILE`, below `/inv`).

**Privacy.** The public service sees the message title and body (the device ALIAS, or the
validated name if you opted in with `VIGIE_DELIVERY_INCLUDE_LABEL`), the relative incident link or,
if you configure `click_base`, the full click URL, the timing of each notification, your
household's public IP address and the client User-Agent. The topic is the only access control on
ntfy.sh: anyone who learns it can read the notifications, so use 32 or more random characters (the
sender requires at least 24; ntfy.sh limits topic names to 64). ntfy.sh keeps messages for a
limited time (about 12 hours by default; check the ntfy docs) during which anyone holding the topic
can fetch them with `since=`. Delivery to phones may go through third-party push services: the
Android build from the Play store is documented to relay through Google FCM (title and body would
be visible to Google), and iOS relies on Apple push through the ntfy.sh server; check the ntfy
docs for the current behaviour. Options to reduce that exposure, to be verified against the ntfy
docs before relying on them: the F-Droid build with UnifiedPush or its own foreground connection,
or a self-hosted server (set `server` and `allowed_hosts`). An optional bearer token is only
useful with a reserved topic or a self-hosted server. Without `click_base` no `Click` header is sent and
the link stays relative (it is already in the body). Only the five validated fields are ever read;
unknown keys in a record are dropped.

**Config** (JSON, mode 0600, owned by the running user; unknown keys are rejected). Paths are
placeholders:

```json
{
  "delivery_file": "/ABSOLUTE/PATH/TO/delivery-messages.jsonl",
  "cursor_file": "/ABSOLUTE/PATH/TO/CURSOR_DIRECTORY/ntfy-cursor.json",
  "topic_file": "/ABSOLUTE/PATH/TO/private/ntfy-topic",
  "token_file": "/ABSOLUTE/PATH/TO/private/ntfy-token",
  "server": "https://ntfy.sh",
  "allowed_hosts": ["ntfy.sh"],
  "click_base": "https://vigie.example.invalid",
  "timeout_seconds": 8,
  "max_batch": 50
}
```

Required: `delivery_file`, `cursor_file`, `topic_file` (absolute paths). Optional: `token_file`;
`server` (https only, no userinfo, query, fragment or path, host must be in `allowed_hosts`,
default `["ntfy.sh"]`); `click_base` (https, no userinfo, query or fragment; the message link
`/ui/#incident=<id>` is appended); `timeout_seconds` (default 8, at most 20); `max_batch` (lines
per run, default 50). The topic file holds one topic of 24 to 64 characters `A-Za-z0-9_-`; the token
file one bearer token of 1 to 512 characters `A-Za-z0-9._~+/=-`. Secret files must be regular
files (symlinks refused), owned by the effective user of the process, mode 0600 or 0400, at most
1 KiB, without control characters; one trailing newline is stripped. `server` and `click_base`
must be ASCII. Create them without leaking through the process list or shell history:

```sh
umask 077
head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > ntfy-topic   # 32 characters
```

Subscribe to that topic in the ntfy app yourself; nothing in the repository names it.

**Behaviour.** One run reads at most `max_batch` (at least 2, default 50) complete lines after the
cursor; while a rejected record waits for its probe (below) it keeps reading past that limit until
it finds the next valid line or reaches the end of the file. A partial trailing line waits for its
newline. A truncated or replaced file (other inode, shorter than the cursor, other first line)
restarts from the beginning with a warning, which can repeat old notifications. The device number
is ignored. Limits of this detection: an in-place truncate-and-rewrite that keeps the same first
line and ends up at least as long as the old cursor offset is undetectable and the new lines
before the offset are skipped; and FilePublisher's cut-back after a failed `fsync`, followed by a
longer line, can leave the cursor in the middle of a line so that one alert is lost. Nothing but
FilePublisher should rewrite the delivery file. A line that is over 8 KiB, not valid JSON, not an object or
fails the schema is skipped with a counted warning (no record text in the log) and never sent. The
schema is strict: `kind` open or recover, `link` exactly `/ui/#incident=` plus 1 to 186 characters
of `A-Za-z0-9%._~-`, and `title` and `body` must equal the writer's message templates with one
label (the writer's label charset, at most 48 characters) and the record's own link; a copy of the
templates in the sender is checked against `delivery_publish.py` by a test. Titles are folded to
ASCII for the header (the typographic apostrophe becomes `'`, accents are dropped); the body is
UTF-8. Runs are serialised by a lock (`<cursor_file>.lock`): a second run that finds it held exits 0
with "another run active". The cursor (offset, device, inode and a hash of the first line) is written atomically
(unique `O_EXCL` temp file, fsync, rename, mode 0600) after each successful send and after each skipped line, so
delivery is **at least once**: a crash between a send and its cursor write repeats that one
notification on the next run. ntfy has no publisher idempotency key, so the sender cannot prevent
this and does not invent one. (ntfy's sequence ID, `POST /<topic>/<sequence-id>`, updates or
replaces an earlier notification; it is not a dedupe guarantee and is not used.) The sender does
not rotate the delivery file. At the 10 MiB cap FilePublisher refuses further writes and the
pipeline's deliveries run out their attempts, so the file needs attention before then:

1. The file belongs to the container's subuid, so truncate it inside the namespace
   (`podman unshare`), and stop the timer first (`systemctl --user stop ntfy-sender.timer`).
   Stopping a timer does not stop a run already in progress: wait until the sender service is
   inactive (`systemctl --user is-active ntfy-sender.service` must not print `active`). Also
   stop the pipeline (the process that appends to the delivery file) BEFORE the check in step 2,
   or a record can arrive between the check and the truncate and be lost.
2. Truncate ONLY when the cursor offset equals the file size, that is when the sender has
   delivered everything. Check with the read-only helper (it reads each sender config only for
   `cursor_file` and `delivery_file`, writes nothing and prints no path). Run it from the
   repository root (or give the absolute script path), as `python3 -I`:
   `podman unshare python3 -I deploy/persistent/senders_caught_up.py --ntfy-config /ABSOLUTE/PATH/TO/private/ntfy-sender.json`
   prints `ntfy: offset=N size=M caught_up|behind`; exit 0 means caught up, 1 behind, 2 an
   unreadable or invalid config, cursor or delivery file. Truncate only on exit 0.
   If the HA sender is also enabled, add `--ha-config` and follow "Two senders, one delivery
   file" in the Home Assistant section instead. The helper only proves the state at the moment
   it ran. Truncating while the sender is behind (for example after exit 3) drops the pending
   alerts.
3. Run the helper again right before the truncate, and only on exit 0 run
   `podman unshare truncate -s 0 /ABSOLUTE/PATH/TO/delivery-messages.jsonl`. Start the timer
   (and the pipeline) again; the sender notices the shorter file and restarts from the beginning.

Requests are verified TLS (system trust store), proxy environment variables are ignored, redirects
are never followed, the response is read up to 4 KiB and discarded, and only HTTP 200 counts as
success. A run has a total wall-clock budget of 120 s: every call gets the smaller of
`timeout_seconds` and what is left, and backoff never sleeps past it. The budget is checked
between operations: one socket operation can still take up to `timeout_seconds`, so
`TimeoutStartSec` in the unit is the hard stop. Headers: `Title`, `Tags` (`warning` for open, `white_check_mark` for recover), `Priority:
default`, `Click` (only with `click_base`) and `Authorization: Bearer` (only with `token_file`).

**Exit codes.**

| Code | Meaning |
| --- | --- |
| 0 | Caught up, the delivery file does not exist yet, or another run holds the lock |
| 1 | Unexpected internal error (exception class logged, nothing else) |
| 2 | Configuration, secret file, lock or cursor error (a corrupt cursor is never guessed at) |
| 3 | Permanent failure: 401, 403, 404, other unexpected statuses, a redirect, or two rejected records in a row (or a rejected last record with no successor yet). Logged once, the cursor is NOT advanced past the record, so a wrong topic or token is neither retried in a loop nor silently skipped |
| 4 | Retryable failure (408, 425, 429, 5xx, network error, timeout, TLS failure) after up to 4 attempts with backoff of 1, 2 and 4 s (`Retry-After` honoured up to 60 s), or the 120 s run budget ran out; the cursor is unchanged |
| 5 | Caught up, but the server REJECTED a record (400, 413, 414, 422) and it was skipped: the next record was delivered, proving the channel works, so the rejected one is a poisoned record. An ERROR is logged with the file offset only |

Logs never contain the URL, topic, token, response body or record text. A rejected record is held
back until the next one is delivered, so one bad record cannot block the queue forever but a
broken channel never skips anything. Exit 3 needs the owner: fix the topic, token or server. Runs
are serialised by the lock, so starting the sender by hand while the timer is active is safe (the
stuck record is retried first).

**A stalled channel must not be silent.** The sender is the alert channel, so its own failure needs
a second path. A non-zero exit marks the unit failed, and the next successful run clears that
state, so do not rely on polling `systemctl --user is-failed ntfy-sender.service` alone. Set
`OnFailure=` in the service (a commented placeholder is in the template) to a local unit, for
example one that writes a marker or sends a desktop notification, and/or watch the journal
(`journalctl --user -u ntfy-sender.service -p err`). A run that ends with exit code 5 fires `OnFailure` too.

**Enabling (owner actions, nothing here is installed for you).**

1. Enable the pipeline side separately: `VIGIE_DELIVERY_FILE` and `VIGIE_DELIVERY_ENABLED=1`
   (see above). The sender does nothing useful until the pipeline writes the file, and the
   pipeline does not need the sender.
2. Create the topic (and token) files and the config; put the cursor in a directory the sender
   owns with mode 0700 (the sender refuses a cursor directory that is foreign-owned, a symlink or
   group/world-writable, and a lock file that is not a regular single-link file we own). The cursor
   directory must NOT be inside any volume the pipeline mounts; the sender cannot detect that.
   Leftover cursor temp files of the sender (`<cursor>.<pid>.<8 hex>.tmp`, older than 1 hour, our
   own regular files only) are removed at startup.
3. Dry run by hand: `podman unshare python3 -I deploy/persistent/ntfy_sender.py /ABSOLUTE/PATH/TO/private/ntfy-sender.json --once`
   prints `ntfy_sender sent=N skipped=M exit=C`.
4. Copy `deploy/persistent/ntfy-sender.service` and `ntfy-sender.timer` to `~/.config/systemd/user/`,
   replace every `/ABSOLUTE/PATH/...` placeholder, then `systemctl --user daemon-reload` and
   `systemctl --user enable --now ntfy-sender.timer`. The timer fires every 60 s with
   `Persistent=no`.

   **Why the unit is not mount-sandboxed (measured on the host).** `podman unshare` fails with
   "unable to create a new pause process: cannot re-exec process to join the existing user
   namespace" whenever the unit sets ANY mount-namespace directive: `PrivateTmp`,
   `ProtectSystem`, `ProtectHome`, `ReadWritePaths`, `ProtectKernelModules`, `ProtectKernelLogs`,
   `ProtectControlGroups`, `ProtectClock` or `ProtectHostname` (each tested alone). Joining the
   rootless user namespace is incompatible with a systemd mount namespace. These work, each alone
   and all together: `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictRealtime`,
   `RestrictSUIDSGID`, `LockPersonality` and `SystemCallArchitectures=native`; the unit sets
   exactly those plus `UMask=0077`. `NoNewPrivileges`, `RestrictNamespaces`, a capability bounding
   set and `SystemCallFilter` are also left out (they can break the setuid
   `newuidmap`/`newgidmap` helpers). Compensating controls: the sender validates every input
   itself, secrets must be 0600 and owned by the effective user, it has no inbound surface, uses
   only the standard library, and is off by default. A test fails if a mount-namespace directive
   is added to the service file.
5. To stop: `systemctl --user disable --now ntfy-sender.timer`. Pending lines stay in the file and
   are sent when the timer is enabled again.

### Home Assistant delivery

`deploy/persistent/ha_sender.py` ships the same delivery file to a Home Assistant (HA) webhook, as
designed in [PRP-004](prp/004-home-assistant-integration.md). It is **off by default**, standalone
(Python standard library), **not wired into the pipeline** (no code change, no new
`VIGIE_DELIVERY_*` setting, the pipeline keeps `Network=none`) and independent of the ntfy sender:
own config, own cursor, own units. **ntfy remains the counted alert channel.** An HTTP 2xx from an
HA webhook does not prove that an automation ran (HA likely answers 2xx for a wrong id or a
disabled automation, per HA docs, unverified), so HA delivery is best-effort convenience. Keep an
end-to-end canary on the HA side: let the automation stamp an `input_datetime` helper on every
message and watch for it going stale.

```
pipeline (Network=none) --FilePublisher--> delivery-messages.jsonl --read-only--> ha_sender.py --HTTP(S) POST--> HA webhook
```

Why `podman unshare`, the unit hardening limits and the "stalled channel" advice are the same as
for ntfy above; the units are `ha-sender.service` and `ha-sender.timer` (templates, not installed
by anything here). Set `OnFailure=` to a local unit so that a failed run is visible.

**Payload.** One JSON object per record (`Content-Type: application/json`), built only from the
validated record fields:

| Field | Content |
| --- | --- |
| `delivery_id` | The record's id, exactly 32 lowercase hex characters. The automation's dedupe key; `open` and `recover` of one incident differ |
| `sent_at` | The sender's UTC time when it sends (ISO 8601). Helps spot a replayed capture; it cannot flag a stale backlog |
| `kind` | `open` or `recover` |
| `title`, `body` | The validated text from the delivery file |
| `link` | Relative `/ui/#incident=<id>`. Not a dedupe key (`open` and `recover` share it) |
| `url` | Only with `vigie_base_url`: that base plus `link` |

The automation must treat the payload as untrusted display text and never as a command. HA may keep
it in its logbook, recorder and traces. Only the alias form is sent: a record whose label is not
exactly `Device` plus six lowercase letters (for example when `VIGIE_DELIVERY_INCLUDE_LABEL` is on
for another reason) is skipped with a counted warning and never sent.

**Secret webhook URL.** The full URL `https://ha.example.invalid:8123/api/webhook/WEBHOOK_ID` is the
only access control, so it lives in `url_file` (mode 0600 or 0400, owned by the effective user,
regular file, no symlink, at most 1 KiB, outside git) and is never printed or logged. The sender
validates it before use: scheme `https` (or `http` only for a host in `http_hosts`), host in
`allowed_hosts`, no userinfo, query or fragment, path exactly `/api/webhook/<id>` with `<id>` of 1
to 128 characters `A-Za-z0-9_-`. An error names only the failed rule (for example
`webhook URL invalid: path`). Rotate by changing the id in the HA automation and the file.

**Config** (JSON, mode 0600, unknown keys rejected and only names of lower-case letters and underscores are echoed, paths are placeholders):

```json
{
  "delivery_file": "/ABSOLUTE/PATH/TO/delivery-messages.jsonl",
  "cursor_file": "/ABSOLUTE/PATH/TO/HA_CURSOR_DIRECTORY/ha-cursor.json",
  "url_file": "/ABSOLUTE/PATH/TO/private/ha-webhook-url",
  "allowed_hosts": ["ha.example.invalid"],
  "http_hosts": [],
  "ca_file": "/ABSOLUTE/PATH/TO/private/ha-ca.pem",
  "start_at_end": true,
  "vigie_base_url": "https://vigie.example.invalid",
  "timeout_seconds": 8,
  "max_batch": 50
}
```

Required: `delivery_file`, `cursor_file`, `url_file`, `allowed_hosts` (host names, IPv4 or IPv6
literals; the NAME in the URL is pinned, not what it resolves to). Optional: `http_hosts` (default
empty; must be a subset of `allowed_hosts`, otherwise exit 2; a host listed here may be reached over
plain HTTP, every other host requires HTTPS. List only an RFC 1918 IPv4, an IPv6 ULA or a name you
trust DNS for: the sender does not classify addresses (it logs a warning, without the host, for an
entry that is not an RFC 1918, loopback or ULA literal), and plain HTTP exposes the secret URL and
payload to a LAN observer who can replay them); `ca_file` (a PEM bundle with an additional trusted CA, or
the CA or self-signed certificate of your HA, as a private file like the others; it is added to
the system trust store, and verification and host-name checking are never disabled); `start_at_end` (boolean, default
`true`, see "First run"); `vigie_base_url` (https, no userinfo, query or fragment); `timeout_seconds`
(default 8, at most 20); `max_batch` (lines per run, default 50, at least 1). The only command-line
flags are the config path, `--once` and `--seed-at-end`.

**First run.** A new cursor would replay every old message into HA, so with `start_at_end: true`
the first run seeds the cursor just after the last complete line of the delivery file and sends
nothing (a partial trailing line stays unread and is sent when it completes; the warning logs the
skipped byte count). Whatever was written before the first enable is dropped: an incident already
open appears in HA only as an orphan `recover`. Seeding happens only when no run ever established a
cursor there: the directory is new or holds nothing but the sender's lock file, and that lock is
not yet marked (the sender writes one byte into the lock once a cursor exists, and the run that
wins the lock decides, so two first runs never both seed and a failed first run leaves nothing
behind: configuration is validated before the directory or lock is created). The sender creates the
directory with mode 0700 if its parent exists. If the directory holds anything else (a temp file)
or a marked lock but no cursor, the cursor was probably deleted: the sender exits 2 instead of silently
dropping the backlog. Confirm once with the one-shot flag
`podman unshare python3 -I deploy/persistent/ha_sender.py /ABSOLUTE/PATH/TO/private/ha-sender.json --once --seed-at-end`,
which seeds and proceeds. The flag is not a config key and must never be written into the unit; it
is ignored when a cursor exists. `start_at_end: false` is the owner's explicit choice to replay the
whole file. Keep the cursor directory dedicated to this sender.

**Oversized lines.** A line longer than the read window (8 KiB per line of `max_batch`) is
skipped, and the rest of that physical line is discarded through its newline, never parsed as a
record: the cursor file carries a `discard` flag across runs for this, and the discarded bytes
are saved as progress (each discarded read window counts against `max_batch`), so a long line is
worked off over several runs and the cursor ends at the file size. If every line read in a run
was invalid, the run logs one ERROR line (no record text) and still exits 0, so `OnFailure=` does
not fire for it; watch the journal at error level.

**Behaviour.** Everything else mirrors the ntfy sender: strict per-line validation against the
writer's templates (invalid lines are skipped with a counted warning and never sent), atomic
0600 cursor, a lock beside the cursor (a second run exits 0), restart from the beginning with a
warning on a truncated or replaced file, at most `max_batch` lines per run, **at-least-once**
delivery (a crash between a send and the cursor write can repeat one message; dedupe on
`delivery_id`), a 120 s run budget, no proxy use, redirects never followed, the response read up to
4 KiB and discarded. Differences: any 2xx is success; 408, 425, 429, 5xx, timeouts and connection
or TLS errors are retryable (up to 4 attempts, 1, 2 and 4 s backoff, `Retry-After` honoured up to
60 s); every other status, including every other 4xx and any redirect, is permanent and stops the
run with the cursor before that record. A 2xx counts as success even if reading the response body
then fails. There is no "rejected record" probe (PRP-004 D6
recommendation), so exit 5 does not exist.

**Exit codes.**

| Code | Meaning |
| --- | --- |
| 0 | Caught up, the delivery file does not exist yet, or another run holds the lock |
| 1 | Unexpected internal error (exception class logged, nothing else) |
| 2 | Configuration, secret URL, CA file, lock or cursor error, including a missing cursor in a non-empty cursor directory without `--seed-at-end` |
| 3 | Permanent failure (4xx other than 408/425/429, redirect, unexpected status, or a TLS certificate verification failure); cursor NOT advanced |
| 4 | Retryable failure after retries, or the run budget ran out; cursor unchanged |

**TLS notes.** A certificate that fails verification (unknown CA, wrong host name) is
permanent (exit 3), not retried. "Not yet valid" and "expired" are retryable (exit 4): they are
usually clock skew right after boot. Python 3.13 and later also enable strict X.509 checking in the
default context (`VERIFY_X509_STRICT`), which rejects some older self-signed or private-CA
certificates (for example without a Subject Key Identifier, or a CA certificate without
`basicConstraints CA:TRUE`) even when `ca_file` names them. The sender never relaxes verification:
issue a new certificate with current tooling. Part of the H0 measurement before enabling: run one
request by hand over the real HTTPS path and confirm it verifies.

Logs and the summary line (`ha_sender sent=N skipped=M exit=C`) never contain the URL, the
webhook id, the host, the response body or record text.

**Two senders, one delivery file.** With ntfy and HA both enabled, the truncate procedure in the
ntfy section changes: stop BOTH timers, wait until BOTH sender services are inactive (a stopped
timer does not stop a run in progress), stop the pipeline (the process that appends to the
delivery file), and truncate only when the cursor `offset` of EVERY enabled sender equals the delivery file
size; truncating while either is behind drops its pending messages. Check both at once with the
read-only helper (exit 0 only when every named sender is caught up; any other exit means do not
truncate). Run it from the repository root (or give the absolute script path), as `python3 -I`,
after the pipeline is stopped, and run it again right before the `truncate`; it only proves the
state at the moment it ran:

```
podman unshare python3 -I deploy/persistent/senders_caught_up.py \
  --ntfy-config /ABSOLUTE/PATH/TO/private/ntfy-sender.json \
  --ha-config /ABSOLUTE/PATH/TO/private/ha-sender.json
```

It prints one `<name>: offset=N size=M caught_up|behind` line per sender. A cursor whose inode or
first-line hash no longer matches the file counts as behind, because the sender would restart
from the beginning.

**Enabling (owner actions, nothing here is installed for you).** Create the URL file with
`umask 077`, write the config and the dedicated cursor directory, dry-run by hand with the command
above (without `--seed-at-end` the first run seeds a new directory by itself), then copy
`ha-sender.service` and `ha-sender.timer` to `~/.config/systemd/user/`, replace every
`/ABSOLUTE/PATH/...` placeholder, run `systemctl --user daemon-reload` and
`systemctl --user enable --now ha-sender.timer`. Stop with
`systemctl --user disable --now ha-sender.timer`.

**H0 check.** `deploy/persistent/ha_h0_check.py` automates the by-hand request above. It reuses the
sender's config, URL validation, TLS context and status classification, sends ONE dummy POST
(`kind` `h0check`, no link) and prints only the host and a status class, never the URL, id or body:

```
python3 deploy/persistent/ha_h0_check.py /ABSOLUTE/PATH/TO/private/ha-sender.json \
  --url-file /ABSOLUTE/PATH/TO/private/other-webhook-url

# or, without a file (the URL, for example https://ha.example.invalid/api/webhook/ID, is
# typed at the prompt, so it stays out of the command line and shell history):
read -rs u; HA_H0_WEBHOOK_URL="$u" python3 deploy/persistent/ha_h0_check.py /ABSOLUTE/PATH/TO/private/ha-sender.json; unset u
```

Precedence: `--url-file`, then `HA_H0_WEBHOOK_URL`, then the config's `url_file`. The environment
variable is readable by the same user in `/proc/PID/environ` and skips the 0600/0400 file-mode
check; unset it afterwards. Run the check from the machine and path the sender will use. The dummy
payload can fire the real automation. Exit codes (also in `--help`): 0 any 2xx (not proof an
automation ran); 2 configuration or URL rule failed, nothing sent; 3 4xx other than 408/425/429 or
a redirect (auth or webhook-id problem, never retry); 4 retry class (5xx, 408, 425, 429, timeout,
connection error); 5 TLS verification failed (including not yet valid or expired, which the sender
would retry); 6 DNS failure. Record the codes for a wrong id, a disabled automation and so on in
the PRP-004 H0 table.

## Probes (built, off by default, not deployed)

Bounded DNS and TCP reachability probes run in a separate host unit, never in the pipeline (which
stays `Network=none`). Data flow: the runner opens only its config and state files and sends only the probe queries and
connects; no inventory, raw shard, override or device name is read into probe traffic or probe
logs. It is not isolated from other Vigie volumes: a host process under `podman unshare` can reach
all of the user's volumes, so that rests on the runner's code and config, not on a mount boundary.

- **Runner.** `deploy/persistent/probe_runner.py` (standard library only) reads a private JSON
  config and does one locked pass per timer tick (`probe.service` and `probe.timer` templates,
  every 60 s). Targets are at most 10 literal private addresses (RFC 1918 or ULA), never
  hostnames: nothing is resolved. Kinds are `dns_local`, `dns_upstream` (at most one) and
  `tcp_lan`. A DNS probe is one UDP query on a connected socket, so only the configured resolver
  can answer, with a 2 s timeout, no retry and a 4096-byte reply cap. A TCP probe is a connect with
  no payload. A result is `ok`, a latency and a fixed error class, never response content. Logs
  carry the target id and error class only, never an address, name or port.
- **Hysteresis.** An outage opens after 3 consecutive failed attempts and recovers after 3
  successes. At most 3 outage episodes per target per UTC day are reported; after that the target
  is `flapping` and its further episodes emit no open or recover event.
- **Outbound statement.** `dns_upstream` queries the household resolver for an owner-chosen
  canary name. On a resolver cache miss that one query is forwarded to the upstream the household
  already uses, about once a minute. While the name is cached an upstream outage is masked for up
  to its TTL. It is off unless the owner configures it.
- **Pipeline side.** Set `VIGIE_PROBE_FILE` (render does this when `probes_enabled` is set) and the
  pipeline reads the runner's state file read-only on every pass and writes only
  `pipeline_meta['probe_status']` plus events of kind `probe_outage`, `probe_recovered`,
  `probe_flapping` and `probe_stale` (no device, one event per episode). The file is untrusted
  input: over 64 KiB, malformed ids or enum values, out-of-range numbers, an `episode_start` more
  than a day after `written_at`, a future `written_at`, or older than `VIGIE_PROBE_STALE_S`
  (default 300 s) all mean "probes unavailable" and never "ok" or an outage. The reader has no id
  allowlist, so the spec's unknown-target-id acceptance test is intentionally not implemented.
  Probes are not an incident and are not delivered.
- **Status fails safe.** `probe_status` carries `valid_until` (`written_at` plus the stale limit):
  a consumer such as S3 `/probes` must treat the status as unavailable once now passes it,
  because a stopped pipeline cannot rewrite a status that says ok. A fold that fails marks the
  status unavailable (`reason` `error`) instead of leaving the old one. Turning the flag off
  writes one `disabled` unavailable status, once, if a status had been stored; with none stored
  nothing is written. A target not probed within the stale limit of `written_at` (or never) is
  `unknown`, and nothing is derived from it.
- **Event bounds** (the reader does not trust the writer's caps). Per target, at most 3
  `probe_outage` events per UTC day of the episode (derived from `episode_start`), at most 6 per
  target per day the pipeline inserts them, and at most 30 in total per episode day and per insert
  day; at most 10 `probe_flapping` events per day. An episode older than 7 days is never
  reported, so at most 7 days of buckets can be filled. A drop is logged once per kind and day
  (`probe_event_capped`). `probe_stale` is at most one event per UTC day for any cause: a start-up
  race can use that day's warning, and the status still shows the failure. An episode first seen
  already recovered (within 7 days) is announced as an outage then a recovery. An open outage is
  closed with a `probe_recovered` event (`removed` or `superseded`) when its target is gone or its
  current `episode_start` is a different one (newer, older after a clock step, or none after a
  fresh runner start); the scan covers 30 days and 100 rows per pass. A backward clock step is
  tolerated up to a day (`episode_start` may exceed `written_at` by at most that); the runner
  repairs a larger one itself.
- **Freeze.** Probe settings are their own `ProbeSettings`, outside the monitoring policy version,
  the detectors, `/coverage` and every existing table. Disabled, the rendered units and the
  pipeline's tables are byte-identical to a build without probes (`server/tests/pipeline/test_probe_freeze.py`,
  `deploy/tests/test_probe_render.py`).
- **Render.** Optional `probes_enabled` (default false) and `probe_allow` (the target addresses)
  add the probe volume, a read-only pipeline mount, the env var and the probe service/timer units.
  `IPAddressDeny=any` with `IPAddressAllow=` for the targets is defense in depth and best-effort:
  a systemd user manager may not be allowed to load the cgroup BPF programs it needs.
- **Self-contamination.** The server's own probe queries pass through the household resolver and
  can be attributed to the server host as DNS volume (about 1 to 2 per minute); keep the rate
  fixed and account for it before any DNS-volume detector.

Operating notes. `probe_allow` in the render config must list exactly the addresses of the probe
config's targets: a target missing from it is blocked by `IPAddressAllow` and shows up as a
timeout outage. The probe config's `state_file` must end in `probe-state.json` to match the
pipeline's `VIGIE_PROBE_FILE`, and `render.py` writes a `<namespace>-probe-config.json` skeleton
with `state_world_readable` already true (the runner's own default, 0600, cannot be read by the
pipeline uid). Pick a common, widely used canary name for `dns_upstream`: an unusual name is
visible upstream on every cache miss. Adding a target `kind` to the state document in S3 needs a
runner and pipeline upgrade together, or a state version bump.

Config fields (all values are placeholders): `enabled`, `state_file` (absolute path inside the
probe volume), optional `state_world_readable` (mode 0644 so the pipeline's uid can read it; the
document holds ids, error classes and counters only) and `targets`, each with `id`, `kind`,
`resolver` plus `qname` (DNS) or `address` plus `port` (TCP), and an optional `timeout_s` up to 2.

## Retention and verification limits

Raw shards and ingest batch detail retain the existing7-day policy. Derived receipt detail is
pruned after7 days only once the original ingest batch is gone, preserving replay deduplication.
Hourly measurements/coverage/suspicion and incidents retain90 days. Each pass deletes at most1000
rows/table, so backlog catch-up can temporarily retain older records; immutable reference metadata
retains its training-hour lineage while referenced by a current profile or retained incident.
No long-term DNS names are stored. Service evidence has a24-hour eligibility TTL and bounded prune.

Tests cover independent worked sums/replays, hour boundaries, atomic crash recovery, missing data,
19/20 hours and13/14 dates, exact10MiB median/50vs51MiB learned thresholds, missing-pair breaks,
lineage round-trips/name-only edits, cold-start fixed incidents and service expiry/same-MAC limits.
Full CI and independent review remain release evidence recorded in the PR, not an accuracy claim.
The [field report](monitoring-field-status-2026-10-25.md) separates completed installation and logfs
capacity, parsed-DNS, scoped persistence and bounded-outage recovery proof, deployed processing-age API and controlled repair/reconciled helper recovery from pending natural rotation, reboot behavior and
long-duration learning. D1–D6 owner decisions remain unchanged.
