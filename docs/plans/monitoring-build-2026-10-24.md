# Autonomous monitoring build — 2026-10-24

Execution authorized by the user's instruction to stage the whole roadmap and implement device
fingerprinting, DNS coverage, persistent deployment, long-duration testing, and baseline/anomaly
features now. The existing identity trust boundary remains in force. This plan does not claim
production readiness, measured classification accuracy, or a completed long-duration test.

Status on 2026-10-25: the five source foundations and follow-up shutdown/DNS-probe fixes are
merged after review and CI. The [dated field report](../monitoring-field-status-2026-10-25.md)
records actual server/router activation, corrected LAN scope, controlled drain and stop/restart
evidence, scoped boot-link/cron installation and bounded ingest-outage recovery. PR12 processing-age
source is merged; candidate-image deployment and remaining repair/rotation gates are pending. Flagged history is retained,
not reset to make acceptance pass; the runtime metrics key still requires owner approval.
The real 48-hour run has not started; later UI/feedback work and mature field baselines remain
separate roadmap stages.

## Delivery sequence

1. **DNS deployment recovery:** reproduce reload failure being reported as success; make failed
   and interrupted application retryable, with root-safe state and honest checks. Review and merge
   this focused prerequisite before enabling real logging.
2. **Coverage and measurements:** preserve original batch windows, distinguish clock probes from
   observation windows, expose collection freshness/coverage and attribution gaps, and build
   idempotent bounded hourly per-MAC measurements scoped to each collector.
3. **Device characterization:** add versioned deterministic rules over observed DHCP/multicast
   evidence. Return provenance, evidence strength, conflicts and abstention. Human labels and
   overrides retain precedence; type inference never grants trust or changes enforcement.
4. **Baseline and incident path:** store immutable baseline versions, expose learning/degraded
   status, evaluate fixed upload and qualified learned upload deviations, and provide bounded
   authenticated activity/incident APIs with observed/expected values and evidence.
5. **Persistent operation:** prepare and independently review exact router and Tower host changes,
   rollback, ownership, startup dependencies, credentials and recovery. Test the rollback path
   before enrollment; deploy only owned Vigie services and preserve unrelated workloads.
6. **Long-duration acceptance:** run controlled service/transport/log-rotation recovery tests, then
   a durable 48-hour resource/freshness monitor. Its report must distinguish elapsed test time,
   missing observations, restarts, faults and measured limits. Starting it is not passing it.

Use focused PRs where the dependency boundary is independently reviewable. For each: failing
test first, minimal implementation, full relevant local checks, draft PR, independent adversarial
review, verify/fix findings, re-review, hosted CI on the exact reviewed head, then guarded merge.
Never override protections or merge red checks.

## Initial implementation contracts

- Preserve event-window start/end independently of receipt time. Legacy batches lacking proven
  metadata remain unknown; never invent intervals from their ingestion timestamps.
- Scope traffic to a collector. Do not blindly add overlapping sensors or claim all-LAN visibility.
  Keep unassigned traffic visible rather than attributing it to an arbitrary device.
- Missing data is not zero traffic. Initial clock-sync probes are not observation coverage.
  Expose stale collectors, DNS silence/configuration uncertainty, accounting/truncation failures,
  unmapped flows, backlog and exclusions. A healthy process is not proof of healthy collection.
- Initial hourly qualification accepts only windows fully contained in one half-open UTC hour.
  Cross-hour/oversized windows remain visible as excluded evidence; no invented uniform split.
- Initial learned eligibility: closed hours with at least 95% qualified coverage; at least 20
  eligible hours across 14 distinct days. These are configurable conservative starting settings,
  not measured statistical guarantees. Ineligible history returns an explicit learning reason.
- Freeze the reference baseline before evaluating later data. Initial learned threshold is a
  strict upload excess over `max(50 MiB, 4 × median)` for two consecutive eligible hours. A
  separate configurable fixed rule starts at 1 GiB per hour and can operate during learning.
- Record algorithm/configuration version, training interval, scope, lineage and evidence with
  every baseline/incident. Unresolved suspicious windows cannot update the reference. Backfill
  can repair history without generating a retrospective notification flood.
- Keep per-MAC contributions independent of mutable device IDs. Attachment, merge and undo
  invalidate/rebuild affected derived state; newly attached MACs cannot immediately redefine an
  established device's normal behavior. Ordinary human name changes do not invalidate history.
- Use bounded retention: existing seven-day raw window and up to 90 days of hourly aggregates,
  with documented cardinality/storage limits. Long-term aggregates do not retain DNS names.
- Type confidence is explicitly heuristic evidence strength until calibrated. Random/private
  MAC prefixes are not manufacturer facts. Conflicting/stale/insufficient evidence stays unknown.
- DNS collection covers queries actually visible to the router's resolver. DoH/DoT, caching,
  offload, same-bridge traffic and unknown VLAN/IPv6 scope remain explicit limitations.

## Approved TDD seams

| Seam / boundary class | Catches | Does not establish |
|---|---|---|
| Root scripts / locally substitutable filesystem and reload executable | Failed reload, retry, crash state, unsafe paths, preservation and rollback | Actual firmware behavior without a separate live test |
| Signed ingest → pipeline → authenticated API / in-process owned components | Schema compatibility, event windows, atomic receipts, duplicate counts, coverage visibility | Real router log/packet visibility |
| Hourly aggregation / in-process | Hand-computed 100+250=350 bytes; replay remains350; hour boundaries, resets, missing and cross-hour data | Unobserved traffic or overlapping sensor equivalence |
| Characterization pipeline / in-process | Independent documented rule fixtures, conflicts, expiry, override precedence and unknown fallback | Physical identity, trust, calibrated probabilities |
| Baseline/detector / in-process with injected clock | 19/20 hours and13/14 days; known median; strict50/51MiB thresholds; missing-hour persistence break; contamination | Field false-positive rate without labeled observations |
| Identity changes → measurements/baseline / owned integration | Merge/undo conservation, assignment lineage, rebuild and alert suppression | Automatically trustworthy newly attached MACs |
| Persistent units / locally substitutable manager plus owned real router/server | Restart, bounded retries, tmpfs recreation, rotation, outage and exact rollback | Reboot or48h acceptance until actually observed |
| Soak runner / injected monitor for unit tests, owned real targets for acceptance | Durable state, missing samples, counter resets, threshold failure and truthful elapsed duration |48h passage from a fake clock or short smoke run |

Expected values come from these contracts and hand-worked fixtures, never from implementation
output. Test substitutions stay outside the behavior exercised by each seam.

## Operational assumptions and boundaries

Tower is the current deployment target because its rootless Podman runtime has been exercised.
Do not create/modify unrelated LXC guests, containers or firewall rules. Permanent service units,
DNS changes and rollback must be concrete and reviewed before applying them. Do not force client
DHCP renewals, reboot the household router unexpectedly, or rewrite Couvre-feu enforcement.
Keep keys, DNS history, household identifiers and raw captures private. Retain existing evidence
and named data volumes; no deletion/prune/force-push is part of this build.

## Whole roadmap staging

This build supplies the five requested foundations. The existing roadmap also retains the local
dashboard/device charts/incident inbox, notification lifecycle, richer temporal/destination
detectors, optional multi-network/Zeek/Suricata adapters, and measured ML. Stage those dependent
features explicitly after their data and operational prerequisites; do not label them implemented
because the backend contracts or this plan exist. The monitoring MVP's eventual UI and labeled
seven-day alert pilot remain separate acceptance evidence.
