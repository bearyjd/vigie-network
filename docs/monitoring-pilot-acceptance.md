# Learned-detector field acceptance

The first field trial is on hold until a selected device has a usable reference for its detector.
See the [dated standby readout and field decisions](roadmap.md#next-field-decisions).

## Choose the cohort and device

Record the owner's decision on whether observations before and after the November 22 collector
redeploy are comparable. Compare coverage, address attribution and source quality on both sides.
The recorded cutover was 2026-11-22 03:31:43 UTC. The first full post-redeploy hour began at
2026-11-22 04:00 UTC.

The unchanged policy automatically freezes the earliest eligible cohort for each device and detector
as soon as both qualification floors are met. An owner decision does not postpone that freeze.
Record the choice before the selected profile reaches both floors if a reset must precede its first
freeze. If the owner accepts combining both periods, verify and use the current policy's frozen
reference after it matures. For a post-redeploy-only choice, require every training hour in the
reference to start at or after 2026-11-22 04:00 UTC. When exposed metadata cannot establish the
cohort, open the inventory database read-only and use a bounded query to look up `training_hours` by
reference ID in `monitoring_baselines` for upload or `monitoring_dns_baselines` for DNS.

If the existing lineage includes eligible pre-redeploy hours, its first reference can freeze with
a mixed cohort. Filtering a report to post-redeploy hours leaves the reference intact. If the
reference incorporates earlier hours or its cohort is unverifiable, hold the post-redeploy-only
trial and preserve the reference. To start fresh while the current lineage includes eligible
pre-redeploy hours, get separate approval for a policy or lineage reset. Each affected profile
starts at the next UTC hour boundary and must again accumulate 20 eligible hours on 14 distinct
UTC dates. Check which profiles the proposed reset would affect and use their recorded progress
to schedule the trial.

Choose one owner-confirmed device and detector. Record a local alias, canonical device identifier,
collector provenance, the UTC test window, and the policy and reference versions. Check the
selected device's complete hourly records and require a `mature` reference with current lineage
and policy. Collector-wide observed dates, uptime and a calendar estimate cannot establish
per-device eligibility. Confirm the pooled algorithm before using this upload test. The pooled
upload and DNS references each require at least 20 eligible hours across 14 distinct UTC dates.
Both detectors require at least 3,420 seconds of qualified observations and no coverage reasons
for an hour to qualify on the recorded standby build.
Each detector excludes hours marked suspicious by its engine from training. Upload also excludes
fixed-large-upload hours, and DNS excludes saturated hours from training and scoring. A mature
reference for one detector can coexist with learning or abstention for the other.

## Verify the deployed build

Record the ingest, pipeline and API image revision or digest and verify the trial's behavior
against that release. On the recorded standby revision `b1d385c`, verify the selected detector's
coverage and freeze rules, the activity and incident evidence fields, and the report sections
and retention in use. Check the running policy, DNS enablement and floor (for DNS), and the active
delivery allowlist and retention (for a delivery review). Hold the affected case if a required
behavior or configuration cannot be confirmed on the deployed build.

## Record the test before generating traffic

| Case | Activity and evidence | Expected result |
| --- | --- | --- |
| Benign control | Observe owner-labeled routine activity on the selected device during a qualified closed hour. For upload, include a consecutive eligible post-reference predecessor so the detector can judge the pair. Predeclare the expected volume and outcome. | The reference applies, and no learned incident opens for the declared control. |
| Learned upload positive | Use an owner-approved transfer to an endpoint the owner controls. Plan two consecutive qualified closed hours strictly above the greater of 50 MiB and four times the frozen median. Keep each below the configured fixed large-upload threshold so the learned rule can be judged on its own. Check both hours' recorded bytes and window overlap evidence. | One `upload_deviation` episode opens after the second qualifying hour. A follow-up qualified hour below or at the learned threshold should resolve it. |
| Learned DNS positive | With DNS monitoring enabled and the selected device's median at or above the configured floor, use owner-approved DNS activity through the observed local resolver. Record one qualified closed hour strictly above four times the reference median. | One `dns_deviation` episode is visible in the inbox with observed and reference counts. Success is based on the incident, independent of external delivery. |
| Coverage guard | For upload, find two otherwise triggering qualified hours separated by a degraded or missing hour, or use the offline upload replay (`python -m vigie_pipeline.replay --series SERIES.json --labels LABELS.json`) to demonstrate that case. For DNS, find an observed above-threshold count in an unqualified hour. If the counter or evaluation evidence is unavailable, record the coverage loss and hold the DNS guard judgment. | The coverage reason remains visible in field evidence. The upload gap prevents a two-hour trigger and the DNS hour cannot trigger. |

Use only the cases for the detector that is ready. For a stronger upload control, if approved
traffic and ordinary activity can produce it, record two consecutive eligible post-reference
hours. The first is at or below the learned threshold and the second is strictly above it. Keep
both below the fixed threshold and expect neither hour to open a learned upload incident.

For upload, hold the isolated positive if the
learned threshold reaches or exceeds the configured fixed threshold (1 GiB at the default) or no
approved byte count fits strictly between the thresholds. Check the contributing collector
windows in both scoring hours for overlaps or duplicate accounting. Use the stored start and
end times and quality reasons from `measurement_batches` for the selected collector and hours.
An hour can qualify even when the pipeline tolerates a small edge overlap and sums counters
from both windows. Hold the case if the check leaves either hour's byte total uncertain.

For DNS, hold the positive if safe traffic cannot cross the learned threshold within the approved
budget. Log intended activity separately from the queries that reached the collector because
caching and resolver bypass can make the counts differ. Expect the DNS coverage guard and full
DNS acceptance to remain on hold until a naturally unqualified hour supplies an observed
above-threshold count and evidence that the engine abstained. Keep the deployed floor in force
for the trial. See [detector rules and coverage](monitoring.md).

Every scoring hour, including both upload hours, must be strictly after `trained_until`. Check
for an existing open episode and choose a fresh case if the expectation is a new incident. The
upload engine evaluates the latest closed hour. For an upload pair, verify that it evaluated the
second hour for the selected collector and device while that hour was the latest closed hour.
Confirm that the eligible, consecutive first hour was present in the recorded series available to
that evaluation. For DNS, verify evaluation of the scoring hour, either on the normal latest
closed hour pass or on a recorded retry of that hour. Correlate the profile's `updated_hour` in
`monitoring_profiles` or `monitoring_dns_profiles` with the relevant activity evidence and
reference. Hold a missing incident if evaluation timing or scope cannot be established.

Recheck scoring-hour coverage, batch overlaps and the current reference after the pipeline processes
any pending quality work, and again before accepting or reusing the result. A late overlapping
window can invalidate earlier coverage or cause a reset if it affects a training hour. Reopen a
previous judgment if later evidence changes either the scoring hours or the reference. Hold the
affected case until it can be judged on valid evidence.

Capture each observation privately using this schema:

| Field | What to record |
| --- | --- |
| Context | Run UTC, owner cohort decision, device alias and canonical identifier, collector and service revisions or image digests, verified deployed behavior, detector and policy version |
| Reference | Algorithm, training hours and dates, cohort bounds, median and any relevant floor |
| Ground truth | Predeclared label and expected outcome, activity actually observed, UTC hours, approved traffic bounds |
| Evidence | Qualified seconds and reasons for each hour, observed bytes or DNS counts, collector-window overlaps and duplicate-accounting check for upload, incident ID and explanation if present, optional delivery result |
| Result | Pass, fail or hold, with the reason and any missing evidence |

Use the [monitoring API](api.md), device history and incident inbox for the hourly observations and
incident evidence. Check `baseline` or `dns_baseline` on the selected device's activity endpoint,
coverage for the chosen collector, and the incident's detector and reference evidence. DNS
incident values carry the `queries` unit even in the legacy `*_bytes` fields.

For the seven-day normal-LAN review, run `vigie-api pilot-report --since START_UTC --json` at
the designated end, as the database owner with the existing service data paths. Use the recorded
ISO UTC start. Record the report's `since` and `generated_at` as the actual bounds and verify that
they cover the designated seven days of normal activity. The report ends at its generation time.
Verify the pipeline's delivery retention (default 30 days). Pass `--delivery-retention SECONDS`
if it differs from the default and check `assumed_delivery_retention_s` in the report.
The delivery and unwanted-notification sections
return `unknown` when the report starts before its generation time minus delivery retention.
If the seven-day window exceeds retention, hold the seven-day delivery verdict. Run a separate
report with an ISO UTC `--since` start for longer collector-wide training context. Check report
freshness and section completeness even on exit zero. Use the DNS incident record to judge DNS
detection. Record delivery only for the approved detectors, which on the recorded standby are
`large_upload` and `upload_deviation`.
A pipeline `sent` result records a durable append. Verify phone receipt separately if the trial
includes external delivery.

### Daily digest for owner labelling (L2)

`vigie-api pilot-digest` prints one UTC day of the pilot so the owner can label it quickly. It
reuses the pilot report's definitions and is read-only, offline and deterministic: the clock is
`--now`, so the same copy and arguments always print the same output. Run it on a copy that
`vigie-backup verify` accepted (see "Backups" in [deploy](deploy.md)), never on the live files. It
opens each file `immutable=1`, creates no sidecar and refuses a symlink, a hardlink or a non-empty
`-wal`/`-journal`, a file that is not regular (a FIFO or directory) or one that changes or is
replaced while it is read (exit 2: checkpoint or use a verified backup copy). Malformed rows exit 3.
Pass as `--now` the time the copy was taken (the UTC time in the backup's `manifest.json`), not the
current time: a copy holding coverage or engine hours later than `--now` makes the day unknown.
Run it as a one-shot container against the backup directory:

```sh
podman run --rm --user 10001:10001 --memory 512m --network none -v <backup-dir>:/in:ro \
  <server-image> vigie-api pilot-digest --inventory /in/inventory.db --overrides /in/overrides.db \
  --day 2026-11-20 --now 2026-11-23T00:00:00Z
# add --format json for the full digest, or --labels-template csv (or json) for the label sheet
```

For the day it shows each network's (collector's) qualified hours out of 24 with counted reason
codes, and every incident detected that day or whose open notification was sent that day. Each
incident line gives its detector, open/resolved state, the owner's current decision, its open
delivery (`appended_locally`, `pending`, `suppressed`, `not_delivered`, `not_eligible` before the
delivery watermark, or `no_open_row`) and `receipt`. Then it prints the unlabeled count and the
budget per network: sent open notifications of the upload detectors that day, unwanted ones (the
current decision is `expected`) and undecided ones, against at most one unwanted open per network
per UTC day. Non-upload opens such as `new_device` are listed but not budgeted, as in the report.
It prints only incident, device, lineage and collector ids: no MAC, IP, hostname, device name,
incident evidence or delivery error. An id that is not a plain token is printed as `invalid-id#`;
collector ids of that kind stay separate networks, `invalid-id#1`, `invalid-id#2` and so on (`#`
never appears in a real id, so a masked label cannot collide with a real collector).
Revoked collectors without data that day are left out of the network table and counted in one line,
`N revoked collectors hidden` (`revoked_hidden` in JSON); one with data that day stays listed.

**Receipt.** `appended_locally` means the pipeline wrote the notification to its delivery file.
Nothing in the databases proves that it reached a phone, so every sent item is `receipt
unverified`. The budget counts opens RECORDED as sent on that UTC day, which is not the same as
received: if the pipeline stops after the append but before it records `sent`, the owner may
already have the notification while its row is still `pending` or `sending` (it then counts on the
day it is recorded). Such a row is listed as `delivery pending` and makes its network unknown.
An open is attributed to the network of the owner's decision when there is one (as the pilot
report does), else to the incident's collector. Record actual receipt yourself in
`owner_received`.

**Unknown.** `unknown` means the evidence is incomplete or unreviewed, never "nothing happened".
The digest lists every unknown day, network and item with its reasons. A day is unknown when it is
not yet over by `LIVE_LAG_S` (7200 s) as of `--now`, when delivery was not enabled for the
whole day (no delivery watermark, or one later than the day start), when it lies beyond delivery, incident or
coverage retention, when there is no coverage or engine evidence or the engine or ingest stopped
before the day ended, when the copy holds data newer than `--now`, when the output was truncated,
when an item has no network or when no overrides copy was given. A network is unknown when it has fewer than 24 qualified hours, when a budgeted
open is undecided, or when an upload item's delivery evidence is incomplete (`no open delivery row`,
`delivery pending`, `unrecognised delivery state` or `incident row missing`). An item is unknown
when it is unreviewed, has one of those delivery reasons, or was sent with receipt unverified. A
`snoozed` decision counts as reviewed, as in pilot_report.
A network-day verdict is `over` as soon as two unwanted opens are proven, even with unknowns.
`within` needs complete, reviewed evidence. Everything else is `unknown`. A quiet day (no open
sent) is `within` only under the same condition, with delivery enabled for the whole day: unlike
the report's seven-day verdict, which calls a window without notifications vacuous, one complete
day with no unwanted open meets the daily budget.

**Labels.** `--labels-template` prints one row per item with `owner_label` and `owner_received`
left empty. The labels are yours: the tool never fills or infers them, and it does not read a
filled sheet back.

## Accept the result and sequence the next work

- **Pass** when the mature reference matches the selected cohort, evidence covers the scoring
  hours, the benign control and positive produce their expected results, the coverage guard is
  evidenced, and the owner can explain the incident. Record field and replay results with their
  own provenance. Hold full acceptance if the guard remains unevidenced, including for DNS where
  the upload replay command does not apply.
- **Fail** when all prerequisites are met and the detector or explanation disagrees with the
  predeclared test. Preserve the evidence for replay or defect diagnosis.
- **Hold** when identity, cohort provenance, maturity, evidence quality or traffic limits prevent
  a fair test. A hold records the missing fact and the next readout that can resolve it.

Run the seven-day normal-LAN labeling and delivery review before claiming full monitoring MVP
field acceptance. Keep the controlled incidents' predeclared labels and actual owner judgments in
the private trial record. Start the normal-LAN window after the controlled activity, its incident
episodes and all associated delivery work have finished. If a controlled open is delivered in the
designated window, choose a clean seven-day window.

For each sent open during normal activity, record the owner's judgment. When the owner confirms
that a naturally occurring alert was unwanted because the underlying activity was routine, apply
the incident inbox's **Mark expected** action (`mark-expected` in the API). The report counts
sent opens with the current `expected` decision as unwanted. Acknowledging or snoozing those
opens leaves them out of the unwanted count, and a sent open with no decision makes the verdict
`unknown`. Preserve the owner's judgment and any phone receipt evidence separately from later
decision edits.

Compare sent opens with the proposed budget of at most one unwanted open per network per UTC day,
grouped by delivery completion day. Use `within_target` only when the report section status is
`ok`. A quiet week with complete evidence and zero sent opens is a valid observation. Record it
and mark the delivery component **Hold** because the report has no unwanted-notification verdict.
Keep observing normal activity without producing alerts for the report. Keep active collection,
detector policy and the delivery allowlist fixed during the trial. New activation or profile
choices require a separate decision.

[NextDNS](nextdns.md) has independent live lab evidence for its manual report. Provider verdicts
do not train local baselines or establish a learned incident. Destination/port novelty (F8) is
optional upload-incident detail. Its first field check should use an already-explainable upload
incident after the upload trial, resolution of the [F8 source gate](roadmap.md#f8-source-gate)
and a separate owner decision on the F8 slice. Other design work can
proceed using fixtures while baseline history accumulates.
