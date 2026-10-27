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
  about 7 weekdays of history and a weekend cohort after about 7 weekend days (the fourth Saturday).
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
- **Known blind band.** A baseline poisoned by sustained high traffic before `trained_until` can
  raise a cohort threshold up to `multiplier` times its median-twice, so sustained exfiltration just
  under the fixed large-upload line (1 GiB/h) may not yield an `upload_deviation` candidate. The
  fixed detector remains the backstop; the engine wiring unit must freeze `trained_until` before
  suspected incidents and may cap the threshold. This is the same limit as `pooled-median-v1`.
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

### Incident delivery

Delivery is **off by default** and the local inbox works without any publisher. The pipeline (not
the API) owns the planner and the outbox and reads decisions read-only from `overrides.db`. While
delivery is disabled the runner is not called, so nothing is created and nothing expires. The
real network adapter (topic, ownership: D5) is a later unit; no code here names a topic or opens a
socket.

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
   delivery whose abandoned worker is still running is skipped, never published twice at once.
3. *Watermark*: the first enabled run stores `pipeline_meta.delivery_eligible_since` (the floor of
   `now`) with `INSERT OR IGNORE`; later runs, and disable/enable cycles, never move it.
   Incidents detected before it are never announced.

A runner exception is caught and logged (first occurrence and every 20th), never raised into the
pass. A message holds the device label (the `device_overrides.name`, else the device id) and a
relative link `/ui/#incident=<id>`, nothing else: the label is scrubbed of anything that looks
like an IP, MAC, domain or byte count, stripped of control characters and cut to 64 characters.

**Settings** (all in `deploy/.env.example`; invalid values stop the pipeline at startup):
`VIGIE_DELIVERY_ENABLED` (only `1`/`true`/`yes` enable; `0`/`false`/`no`/`off`/empty disable; any
other value is an error), `VIGIE_DELIVERY_FILE` (required when enabled), `_LEASE_S` (300),
`_TRANSMIT_DEADLINE_S` (30), `_MAX_ATTEMPTS` (6), `_BACKOFF_BASE_S` (60), `_BACKOFF_CAP_S`
(3600), `_TTL_S` (86400), `_RETENTION_S` (2592000), `_MAX_PER_RUN` (20), `_MAX_ABANDONED` (2, at least 1: at most this many publishes are in flight or abandoned-and-still-running at any moment across the process, so it also bounds concurrent publishes), `_DRAIN_BUDGET_S` (60, at least the transmit deadline: once a drain has run this long it claims nothing more, so a transport that fails just under its deadline cannot hold the pass for `MAX_PER_RUN` x deadline).

**FilePublisher format.** The only publisher today appends one JSON object per line to
`VIGIE_DELIVERY_FILE`: `{"delivery_id","kind","title","body","link"}`, ASCII-only. The file is
created 0600 with `O_APPEND|O_NOFOLLOW`, only a regular file is accepted (a symlink, FIFO or
device is refused), each message is one `write` followed by `fsync`, every append holds an exclusive `flock` across the size check and the write, a failed or short
write is cut back to the previous size, and a message that would push
the file past 10 MiB is refused (the delivery then fails and retries; rotate or truncate the
file). In compose the file lives on the `vigie-delivery` volume (`/delivery/messages.jsonl`).

A failure of `fsync` (or of the cut-back itself) can leave a line that was already written while
the delivery is retried, so the retry duplicates it: delivery is at least once. Every line carries
`delivery_id`; consumers should dedupe on it.

**Enabling safely.** Set `VIGIE_DELIVERY_FILE=/delivery/messages.jsonl`, then
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
