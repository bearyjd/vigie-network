# Monitoring v1 contract

This slice derives collector-scoped hourly activity, a frozen pooled-median upload reference,
read-only incidents, and conservative service-based device hints. It does not establish malicious
activity, identity trust, enforcement, calibrated classification accuracy, or production readiness.
A baseline cannot mature before real qualifying history exists; synthetic fixtures prove arithmetic,
not detection accuracy. A local monitoring UI and notifications remain subsequent product work.

Source is merged through the reviewed DNS-probe fixes. The
[2026-10-25 field status](monitoring-field-status-2026-10-25.md) records healthy server deployment
and actual router logging/parsed-DNS and collector privilege evidence. A LAN correction produced
fresh source flags 0; flagged history is retained and controlled drain reached backlog0.
PR12 processing-age API is deployed and verified. Bounded outage, drop-in repair and reconciled
helper respawn passed; natural rotation and cold boot remain pending. The
48-hour run has not started. No fourteen-date mature
field reference is claimed.

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
Missing health, CT source gaps/unmapped/truncation, dropped batches and counter overflow disqualify
the hour. A distinct overlapping batch also degrades the existing hour without adding its bytes or duration; an identical receipt replay does neither. A healthy endpoint or a clock probe is never observation coverage. DNS-specific source
quietness is reported separately; it does not establish traffic completeness.

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
with `VIGIE_MONITORING_LARGE_UPLOAD_BYTES` (default1073741824; integer1..2**50). Algorithm and full
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

### Time-of-day baseline (tod-median-v1, not wired)

`vigie_pipeline/baselines_tod.py` is a pure module (no I/O, clock or database) that is NOT used by
the engine yet: monitoring still runs `pooled-median-v1`, and no schema, migration or environment
variable changed.

- **Cohorts.** `(is_weekend, hour_of_day // bucket_hours)` read from the sample's epoch hour in
  UTC. `bucket_hours` divides 24 (1, 2, 3, 4, 6, 8, 12 or 24; default 4), so adjacent hours pool and
  there are `2 * 24 / bucket_hours` cohorts. Local time and DST are deferred: a DST change never
  moves a sample between cohorts, it only means the bucket is not the household's wall-clock hour.
- **Maturity.** A cohort needs at least 20 valid samples AND 7 distinct UTC days, else it ABSTAINS
  (`immature_samples`, then `immature_days`). With four-hour buckets a weekday cohort matures after
  about 7 weekdays of history and a weekend cohort after about 4 weekends (8 weekend days).
- **Valid samples.** Ineligible (missing) hours are skipped, never counted as zero. Suspicious hours
  and hours at or above the fixed large-upload line are excluded as contamination. At most 4368
  samples (26 weeks) are accepted; hours and byte counts must be exact integers.
- **Threshold.** Twice the cohort median is kept exactly; the line is
  `max(minimum_bytes, median * multiplier)`, the same constants as `pooled-median-v1`.
- **The caller freezes the baseline.** `fit_tod(samples, config, trained_until)` learns only from
  hours up to `trained_until` and records it, plus each cohort's last trained hour. `findings_tod`
  scores an hour only if it is strictly after both; otherwise it abstains with
  `leaks_evaluated_hours`. The engine wiring unit will choose and persist `trained_until`; appending
  later history never redefines normality, so slow drift is judged against the frozen window.
- **Detection.** The fixed large-upload candidate is always evaluated first, even in cold start or
  with an immature cohort. The learned deviation needs TWO consecutive eligible hours, each strictly
  above the line of its OWN mature cohort. An immature current cohort abstains with its reason; an
  immature previous cohort abstains with `previous_<reason>`. A nightly backup that is high every
  night is learned, not flagged.
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
