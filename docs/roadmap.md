# Vigie roadmap — discovery, baselines and unusual behavior

Draft recommendation, 2026-10-24. This roadmap extends the identity MVP; it does not claim that the current
build detects network anomalies. The user wants an app that discovers and characterizes devices AND the
network, learns normal activity, and makes strange behavior understandable. Implementation beyond the
approved current build requires its own reviewed scope. [Research and primary sources](research/network-monitoring-features-2026-10-24.md).

## Execution stages

The user authorized the five-area autonomous build on 2026-10-24. Its
[implementation plan](plans/monitoring-build-2026-10-24.md) defines the TDD seams, initial settings,
deployment boundaries and PR/review/CI/merge gates. This table stages the whole roadmap; queued
features remain unimplemented until their own acceptance evidence exists.

| Stage | Scope | State / prerequisite |
|---|---|---|
| M0 | Inventory, reversible identity decisions and rules, API, bounded real-router pilot | Foundation merged; ten-minute field evidence recorded separately from production readiness |
| M1a — current build | Device fingerprinting; real DNS/source coverage; persistent router/Tower deployment; durable48h testing; hourly baselines and explainable upload incidents | Authorized and in progress; do not infer completion from this plan or an open PR |
| M1b | Local overview, device charts/history, coverage panel and incident inbox | Queued after M1a API/data contracts; necessary for the eventual monitoring MVP |
| M1c | Incident feedback, acknowledgment/snooze/expected lifecycle, optional deduplicated notifications and labeled seven-day field pilot | Queued after persisted incident state; external delivery needs a configured owner-controlled destination |
| M2 | Time-of-day patterns, destination/port novelty, essential-device absence, network-wide shifts, incident correlation and calibrated characterization | Queued after sufficient qualified history and owner-labeled evaluation |
| M3 | Multiple network/VLAN scopes and optional external Zeek/Suricata metadata adapters | Queued after approved sensor placement and measured traffic visibility |
| M4 | Drift models and optional AI explanations/classifiers | Conditional on demonstrated benefit over deterministic rules and an explicit privacy/resource review |

M1a uses local authenticated APIs as its initial review surface. It does not replace the queued UI,
claim full-MVP completion, or make a48h observation satisfy fourteen-day baseline eligibility.
The real soak must reach its endpoint; synthetic clock tests verify the runner, not elapsed field time.

## Intended daily experience

Open Vigie locally and see what is connected, which device/network behaviors changed, whether internet/DNS
or an important local service is unhealthy, and how complete the evidence is. Open an incident to see
observed versus expected activity, affected devices, the time window, collection gaps and likely benign
explanations. Mark it expected, investigate, acknowledge or snooze it. Keep this history for later comparison.
A quiet inbox with broken collection must look unhealthy, not reassuring.

A small local monitoring UI is essential proposed product scope: overview, device history, incident inbox
and coverage/health. It does not replace the separate control app, which retains enforcement authority.
A type inference or anomaly never grants trust, changes a group, blocks traffic or rewrites router configuration.

## Sequence and proposed exit criteria

Effort bands indicate engineering size, not delivery dates: S = focused change with a narrow contract;
M = multiple components plus fixtures; L = a subsystem/UI or operational integration. Sensor access and
real-data observation time are separate dependencies and can dominate elapsed time. Metrics below are
proposed acceptance targets to calibrate with owner-labeled data, not demonstrated performance.

| Milestone | Deliverable / dependency | Proposed exit evidence | Effort |
|---|---|---|---|
| M0 — identity foundation | Inventory, reversible human identity decisions/rules, bounded stitching, API workflow, CI and honest deployment docs | Foundation merged after independent review and CI. Real deployment acceptance remains explicitly separate. | M, completed foundation |
| M1 — monitoring MVP, next | Real collection validation; coverage panel; hourly device/network aggregates; cold-start baseline status; fixed large-upload and qualified upload-deviation alerts; bounded DNS/reachability probes; minimal local UI/inbox and notification lifecycle | Deterministic replay without duplicate counts/alerts; injected collection failure visible within two configured collection windows; injected sustained upload and probe outage visible within two detector windows. Seven-day normal-LAN pilot reports alert volume and owner judgments, target ≤1 unwanted external notification/network/day. | L |
| M2 — richer behavior/context | Day/time patterns, destination/port novelty, network-wide shifts, measured type rules, incident correlation and feedback | ≥14 valid observation days before evaluating initial learned deviations; chronological held-out replay includes backups/updates, sleeping devices, restarts, IPv6 and gaps. Report precision/recall per detector, abstentions and coverage, never a single unsupported accuracy score. | L |
| M3 — richer optional visibility | Approved multi-network adapters and external Zeek/Suricata metadata sensor on a capable host, with suitable TAP/SPAN placement | Fixture/replay contracts; malformed/flooded inputs bounded; missing sensor flagged; duplicate overlapping observations do not inflate totals. Demonstrate exactly which traffic is observable before enabling scan/beacon claims. | L |
| M4 — measured learning | Robust per-device drift first; optional classifier/AI explanations only if rules leave a useful residual | Compare against deterministic baseline on owner-labeled chronological holdout; predeclare false-alert budget; no regression in explainability, privacy or resource bounds. Cancel models that add no measurable value. | M–L, conditional |

The [bounded real-router field pilot](router-validation-2026-10-24.md) found inventory identities still typed `unknown`, no DNS rows or DHCP option 55/60 observations, and conntrack attribution gaps. Prioritize visible source coverage and characterization backed by measured confidence before learned baseline alerts. This field evidence informs M1; it does not establish M1 as implemented.

M1 includes network health, not only identity. Passive DNS error-rate/latency analysis is outside M1's existing
batch contract; start with explicitly labeled probes, or approve a separate response-telemetry extension.
Critical new-device or fixed-volume alerts may run during cold start; learned alerts must disclose insufficient history.

## Baselines and explainable detectors

Build bounded hourly features: upload/download bytes, flow counts, destination/port diversity, query counts,
active minutes and data-quality coverage, grouped by stable device and observed network/sensor scope.
Missing buckets are missing, never zero. Handle restart/counter reset, duplicated batches, backfill and clock skew
before training. Keep event time and processing time separately; backfill can revise history without spamming users.

Start with robust medians/quantiles or EWMA, minimum absolute volume and persistence/hysteresis thresholds.
A first rule might flag a large absolute upload; a separate learned rule compares sustained upload to that device's
valid history. Display both thresholds and the contributing windows. Avoid “compromised” verdicts.
Use pooled hour-of-day / weekday-weekend cohorts until enough observations exist. Suggested initial learned
eligibility: ≥14 valid days overall and ≥20 valid hourly samples across ≥7 distinct days in the relevant pooled
cohort; otherwise remain learning. A literal hour-of-week has few samples even after several weeks: pool it,
show uncertainty, or wait for ≥8 valid occurrences before treating its comparison as mature.
These are starter settings to evaluate, not statistical guarantees.

Characterization separates observations (claimed vendor strings, services, fingerprints) from inferred device
role/type and human labels. A randomized/private MAC makes OUI manufacturer inference unreliable; show
unknown rather than treating its prefix as a vendor fact. Cross-check multiple independent hints and display
provenance/confidence without using inferred type to grant trust.

Track baseline version, source coverage and model parameters in every alert. Prevent easy contamination:
exclude invalid/gapped windows and unresolved suspicious intervals from automatic updates; preserve original
observations and allow an audited reset. After merge/undo, recompute attribution and baseline lineage; do not
blindly pool histories or let a newly attached MAC immediately redefine “normal.” Compare its behavior against
the frozen established baseline first. Limit baseline update rates, retain an older reference profile and test
gradual adversarial drift; unresolved suspicious intervals cannot teach the detector to accept the attack.
Source/coverage changes version the baseline or return it to learning. “Expected” feedback may annotate one event or a scoped exception;
it must not silently whitelist every future behavior or retrain all devices.

Prioritized detectors:

1. Large upload, sustained upload increase, long absence of a normally chatty essential device; separate benign
   backup/update patterns and sleeping devices through owner context and coverage gates.
2. New destination/port plus meaningful volume, changed activity hours, unusual DNS volume, shared outage or
   network-wide traffic shift. Novelty is contextual evidence, not a maliciousness score.
3. DNS periodicity candidates and scan-like destination fanout only where input granularity supports them;
   exact flow cadence, TCP SYN scans and east-west coverage wait for a richer validated source.
4. Threat feeds and drift/classifier models only after retention, license, false-positive and explainability reviews.

## Incidents, interface and notifications

Each incident carries device/network identity, event start/end and detection times, reason code, detector version,
observed/expected values, evidence references, coverage caveats, severity and lifecycle state. A local timeline
connects measurements, identity changes, baseline resets, sensor failures and human feedback.

Deduplicate by detector + entity + episode; use cooldowns and separate recovery notifications. Acknowledge,
snooze-until and mark-expected are distinct audited actions. A scoped exception has an expiry and remains
visible. Retry delivery with stable IDs and bounded backoff; test outage/restart without duplicate floods.
Default external notifications contain a device label and incident link, not raw DNS history/destination details.
ntfy delivery and topic ownership remain gated by D5; the local inbox works without a configured publisher.

## Privacy, coverage and operating budgets

Keep collection/analysis local by default; no remote LLM, reputation lookup or cloud reporting without a separate
explicit choice. Names, destination histories, presence and even keyed hashes can be sensitive. No payload capture
in the standard product. Retain detailed evidence only within a stated window and purge correlated indexes and
notification payloads too. Proposed starting policy follows PRP-001's seven-day raw window, with up to 90 days
of bounded hourly aggregates; inspect aggregate sensitivity and measure space before enabling this retention.

Retain the existing router target of <10 MB collector RSS and prove it in a 48-hour real-router soak, including
multicast/flood/transport outage cases. Tmpfs usage needs a separate cap because it also consumes RAM.
Proposed server pilot budget: ≤512 MB pipeline RSS and ≤1 GB/day raw growth at 60 devices; measure and revise
before general rollout. No raw-packet IDS runs on this small router. New probes are server-side, allowlisted,
rate-limited (start ≤1 per target/minute, at most ten targets), and off until explicitly configured.

Expose per-sensor freshness, backlog, dropped/unmapped records, truncation, time skew and known source scope.
Show IPv6/VLAN/DNS visibility as observed/unknown/degraded; do not infer full coverage from an empty count.
Same-bridge traffic can bypass router conntrack. DoH/DoT, offload and sampled/top-K summaries limit conclusions.
Network totals mean observed traffic for a declared scope, not necessarily all traffic on the LAN.
A DNS query is not proof a domain was contacted: caches, prefetch, shared CDN addresses and encrypted DNS
make domain-to-flow attribution incomplete. A network map may show confirmed controller/sensor links only;
label inferred relationships and never fabricate physical topology from address proximity.

Before importing OUI/fingerprint data, destination categories, rules, geolocation or threat feeds, record source,
version, license, update mechanism and redistribution compatibility with this AGPL project. Product documentation
is inspiration, not permission to copy proprietary rules, data or UI assets.

## Starter backlog and test seams

| Unit | First implementation contract | Meaningful verification |
|---|---|---|
| Coverage | Typed per-source quality windows and sensor/network scope | Missing/late/partial source, IPv6 absent, top-K overflow and clock skew fixtures; no healthy badge from silence |
| Aggregation | Idempotent hourly device/network features with bounded cardinality | Duplicate/reordered batches, counter resets, overflow, merge/undo and bounded query-plan checks |
| Baseline | Versioned deterministic fit/update/abstain with injected clock | Cold start, missing≠zero, time-zone/DST, weekly pooling, contamination and historical backfill |
| Detectors | Pure evaluate(features, baseline, quality, config) → structured candidates | Known benign updates/backups and injected sustained deviations; assert reason and abstention, not just score |
| Health probes | Allowlisted bounded source adapter with timeout/result contract | DNS/TCP/TLS timeout/recovery and partial outage; no arbitrary URL fetch or uncontrolled scanning |
| Incidents/delivery | Persisted episode state and stable delivery identifiers | Restart/retry dedup, ack/snooze/expiry, recovery and publisher outage |
| Local UI | Coverage banner, inventory, device chart and incident detail/feedback | Seeded API fixtures plus browser journeys; show learning/degraded status and survive absent notifications |
| Future sensor | Versioned metadata-only Zeek/EVE adapter | Malformed/flooded events, provenance, NAT/IPv6 mapping and overlapping-sensor dedup |

Use recorded owner-approved samples and synthetic replays; separate fixture performance from real-LAN results.
Review each unit independently, then run the whole chain and collect deployment evidence before calling its milestone done.

## Owner decisions and existing gates

D1 authoritative couvre-feu tree; D2 dnsmasq-change policy; D3 fixed-MAC policy for kid/adult devices;
D4 server placement; D5 notification topic/ownership; D6 person IDs remain unresolved owner gates.
This roadmap does not resolve them, approve PRP-002, authorize router commands or change enforcement policy.
A future lease-only collection mode avoids dnsmasq changes but loses fingerprint/DNS evidence; show that tradeoff
rather than promising identical coverage. Safe fixture-driven development can proceed while field-dependent
acceptance waits. UI framework, external sensor placement, final alert budget and retention beyond current
policy remain proposed choices to settle in each milestone's design review.
