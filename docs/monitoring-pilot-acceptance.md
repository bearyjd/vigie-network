# Learned-detector field acceptance

The first field trial is on hold until a selected device has a usable reference for its detector.
See the [dated standby readout and field decisions](roadmap.md#next-field-decisions).

## Choose the cohort and device

Record the owner's decision on whether observations before and after the November 22 collector
redeploy are comparable. Compare coverage, address attribution and source quality on both sides.
If the owner accepts both periods, use the current policy's existing frozen reference after
it matures. If the owner selects post-redeploy only, require the selected device's actual frozen
reference to use eligible post-redeploy hours. A report filtered to that period cannot change
a reference already frozen from mixed data. If its cohort cannot be verified or does not meet the
owner's choice, hold that trial and record the missing prerequisite.
When the exposed reference metadata cannot establish the cohort, read `training_hours` by the
reference ID from `monitoring_baselines` for upload or `monitoring_dns_baselines` for DNS. Use a
bounded read-only inventory query. For a post-redeploy cohort, all entries must be on or after
the first full UTC hour following the cutover. Preserve the existing reference while the owner
considers any separate retraining decision.

Choose one owner-confirmed device and detector. Record a local alias, canonical device identifier,
collector provenance, the UTC test window, and the policy and reference versions. Check the
selected device's complete hourly records and require a `mature` reference with current lineage
and policy. Collector-wide observed dates, uptime and a calendar estimate cannot establish
per-device eligibility. Confirm the pooled algorithm before using this upload test. The pooled
upload and DNS references each require at least 20 eligible hours across 14 distinct UTC dates.
A qualifying hour has at least 3,420 seconds of qualified observations and no coverage reasons.
Both exclude suspicious training hours. Upload also excludes fixed-large-upload hours, and DNS
excludes saturated hours from training and scoring. A mature reference for one detector can
coexist with learning or abstention for the other.

## Record the test before generating traffic

| Case | Activity and evidence | Expected result |
| --- | --- | --- |
| Benign control | Observe owner-labeled routine activity on the selected device during a qualified closed hour. For upload, include a consecutive eligible post-reference predecessor so the detector can judge the pair. Predeclare the expected volume and outcome. | The reference applies, and no learned incident opens for an activity below the threshold. |
| Learned upload positive | Use an owner-approved transfer to an endpoint the owner controls. Plan two consecutive qualified closed hours strictly above the greater of 50 MiB and four times the frozen median. Keep each below the configured fixed large-upload threshold so the learned rule can be judged on its own. Check both hours' recorded bytes. | One `upload_deviation` episode opens after the second qualifying hour. A follow-up qualified hour below or at the learned threshold should resolve it. |
| Learned DNS positive | With DNS monitoring enabled and the selected device's median at or above the configured floor, use owner-approved DNS activity through the observed local resolver. Record one qualified closed hour strictly above four times the reference median. | One `dns_deviation` episode is visible in the inbox with observed and reference counts. Success is based on the incident, independent of external delivery. |
| Coverage guard | For upload, find two otherwise triggering qualified hours separated by a degraded or missing hour, or use the upload replay command to demonstrate that case. For DNS, find an observed above-threshold count in an unqualified hour. If the counter is unavailable, record the coverage loss and hold the detector guard judgment. | The coverage reason remains visible in field evidence. The upload gap prevents a two-hour trigger and the DNS hour cannot trigger. |

Use only the case for the detector that is ready. If safe traffic cannot cross the learned threshold
within the approved budget, hold the positive case. For DNS, log intended activity separately
from the queries that actually reached the collector. Caching and resolver bypass can make those
counts differ. See [detector rules and coverage](monitoring.md).

Every scoring hour, including both upload hours, must be strictly after `trained_until`. Check
for an existing open episode and choose a fresh case if the expectation is a new incident. The
engine normally evaluates the latest closed hour. Verify that it processed each test hour for
the selected collector and device while the hour was current. Correlate the profile's `updated_hour`
in `monitoring_profiles` or `monitoring_dns_profiles` with the relevant activity evidence and
reference. Hold a missing incident if evaluation timing or scope cannot be established.

Capture each observation privately using this schema:

| Field | What to record |
| --- | --- |
| Context | Run UTC, owner cohort decision, device alias and canonical identifier, collector and service versions, detector and policy version |
| Reference | Algorithm, training hours and dates, cohort bounds, median and any relevant floor |
| Ground truth | Predeclared label and expected outcome, activity actually observed, UTC hours, approved traffic bounds |
| Evidence | Qualified seconds and reasons for each hour, observed bytes or DNS counts, incident ID and explanation if present, optional delivery result |
| Result | Pass, fail or hold, with the reason and any missing evidence |

Use the [monitoring API](api.md), device history and incident inbox for the hourly observations and
incident evidence. Check `baseline` or `dns_baseline` on the selected device's activity endpoint,
coverage for the chosen collector, and the incident's detector and reference evidence. DNS
incident values carry the `queries` unit even in the legacy `*_bytes` fields.

Run `vigie-api pilot-report --since 7d --json` as the database owner with the existing service
data paths for upload delivery and owner-decision review. For longer collector-wide context, use
a UTC start that spans the training interval. Check freshness and section completeness even on exit
zero. Use the DNS incident record to judge DNS detection. Record delivery only for the approved
detectors, which on the recorded standby are `large_upload` and `upload_deviation`.
A pipeline `sent` result records a durable append. Verify phone receipt separately if the trial
includes external delivery.

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
field acceptance. Compare evaluated upload deliveries with the proposed budget of at most one
unwanted open per network per UTC day, grouped by completion day. Use `within_target` only when
the report section status is `ok`. A window with zero sent opens has an unknown verdict. The report
uses the incident's current `expected` decision, so retain the predeclared labels and phone receipt
evidence separately from later edits. Keep the active collection, detector policy and delivery allowlist fixed during
the trial. New activation or profile choices require a separate decision.

[NextDNS](nextdns.md) has independent live lab evidence for its manual report. Provider verdicts
do not train local baselines or establish a learned incident. Destination/port novelty (F8) is
optional upload-incident detail. Its first field check should use an already-explainable upload
incident after the upload trial and a separate decision on the F8 slice. Other design work can
proceed using fixtures while baseline history accumulates.
