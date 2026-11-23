# Vigie roadmap — discovery, baselines and unusual behavior

Execution status updated 2026-11-23. Source is on main at `7811822` (#131). The standby field readout comes from the deployed `b1d385c` baseline. This roadmap extends the identity MVP.
Initial deterministic characterization and upload-incident source is merged; field efficacy remains
unmeasured. The user wants an app that discovers and characterizes devices AND the
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
| M1a — current build | Device fingerprinting; real DNS/source coverage; persistent router/Tower deployment; durable48h testing; hourly baselines and explainable upload incidents | All five source foundations merged; live parsed DNS, privilege, corrected LAN scope, drain and stop/restart proofs passed. Real-router 48-hour soaks 1-4 have run (soak 4 passed on 2026-11-14) and the pilot runs on the standby VM. Natural rotation/boot gates, credential approval, real 48-hour acceptance and field baseline maturity remain pending. Coverage-qualification, LAN-unmapped threshold and collector window/attribution fixes (#86-#88) are merged; the router collector carrying #88 was redeployed at 03:31:43 UTC on 2026-11-22 (T0, operator-run), and the monitoring policy stayed unchanged. See the [November 23 standby readout](#2026-11-23-standby-readout). Retired-device MAC observations can be pruned after 90 days, opt-in only (`VIGIE_PRUNE_RETIRED_MACS`, default off; #114, #125). The [2026-10-25 field status](monitoring-field-status-2026-10-25.md) is historical |
| M1b | Local overview, device charts/history, coverage panel and incident inbox | The local GUI at `/ui/` includes passive coverage, active probe status, device history, an incident inbox, events and a device timeline. Field acceptance against a mature baseline is pending |
| M1c | Incident feedback, acknowledgment/snooze/expected lifecycle, optional deduplicated notifications and labeled seven-day field pilot | Per-incident acknowledgment, snooze, mark-expected and clear are available through the [API](api.md#incidents-and-review-lifecycle) and the [opt-in incident controls](gui-preview.md) in the local GUI. Opt-in delivery, a per-detector delivery allowlist (`VIGIE_DELIVERY_DETECTORS`, #109) and standalone ntfy and Home Assistant webhook senders are merged (off by default; #49, #71). Scoped exceptions are deferred. The synthetic [MVP acceptance tests](e2e.md#synthetic-monitoring-mvp-acceptance) cover the incident workflow. No labeled seven-day pilot is recorded, external delivery needs a configured owner-controlled destination, and phone alerts (ntfy) have been enabled on the pilot VM since 2026-11-21 (the recorded standby allowlist covers only `large_upload` and `upload_deviation`) |
| M2 | Time-of-day patterns, destination/port novelty, essential-device absence, DNS-volume deviation, network-wide shifts, incident correlation and calibrated characterization | Opt-in time-of-day baseline (`tod-median-v1`, `VIGIE_MONITORING_BASELINE=tod`, #37) is merged; `pooled` stays the default; its evidence keys are exposed in the read API (#105). A new-device notice (`new_device`, incident detector, open-only, `VIGIE_NEW_DEVICE_NOTICE`, off by default; #108-#112) and the owner-marking half of essential-device absence (API plus overrides migration v10, #110) are merged. The absence sweep (`VIGIE_ESSENTIAL_ABSENCE`, #113) is merged. The opt-in DNS-volume detector (`VIGIE_MONITORING_DNS`) has a separate baseline and runs on standby with a 200-query floor. Learned DNS field evaluation is pending. Opt-in F8 destination/port novelty remains behind the [source gate](#f8-source-gate). Network-wide shifts and correlation remain queued |
| M2b | Exposure and suspicious-traffic evidence: device-type known-issue notes from imported CVE data, local blocklist/reputation DNS matches, read-only provider DNS verdicts | The dataset-free evidence pack and the manual NextDNS report (#131) are merged. The report passed dedicated live lab cases and awaits a separate decision for standby or household use. [Offline dataset staging and decisions](datasets.md) are merged. Scheduled fetching, dataset readers, reputation matching and known-issue notes remain proposed |
| M2c — endpoint connection events (design proposal) | Observe-only evidence from an endpoint firewall (Snitchwatch/OpenSnitch) compared with router conntrack | Design doc only: [docs/prp/003-endpoint-events.md](prp/003-endpoint-events.md); nothing built; K1-K4 confirmed; E0 feasibility measurement next |
| M3 | Multiple network/VLAN scopes and optional external Zeek/Suricata metadata adapters | Queued after approved sensor placement and measured traffic visibility |
| M4 | Drift models and optional AI explanations/classifiers | Conditional on demonstrated benefit over deterministic rules and an explicit privacy/resource review |

M1a uses local authenticated APIs as its initial review surface. The local GUI reads the same APIs and can submit deliberate incident decisions in an explicit editing session. M1a does not
claim full-MVP completion, or make a48h observation satisfy fourteen-day baseline eligibility.
The real soak must reach its endpoint; synthetic clock tests verify the runner, not elapsed field time.

### 2026-11-23 standby readout

- **Collector-wide coverage through 12:00 UTC.** DNS observations were present in every hour.
  Coverage qualified in 23 of the previous 24 complete hours and 166 of the previous 168.
- **Device training.** Each detector family reached a maximum of 212 eligible hours and 10 of
  14 required UTC dates across its profiles. Zero references were mature. These maxima do not
  establish when a selected profile will next qualify.
- **Collector windows after the swap.** Overlap fell from 8–14/hour before the swap to zero in
  the first 11 complete hours. A later check counted three overlaps (36–60 seconds) and no gaps
  in 820 post-swap windows. That count alone does not establish the affected hours' qualification.
  Conntrack-unmapped flags still appeared in the checked batches.

### Next field decisions

1. Record the owner's choice on combining observations before and after the November 22 redeploy.
   The unchanged policy freezes each profile automatically when its earliest eligible cohort meets
   both floors. Make the choice before that freeze if the first reference must be post-redeploy-only.
   Verify every training hour starts at or after 2026-11-22 04:00 UTC for that choice. Profiles with
   earlier eligible hours need a separately approved policy or lineage reset to start fresh. Each
   affected profile restarts at the next UTC hour boundary and must earn 20 eligible hours on 14
   distinct UTC dates. Use the selected profiles' actual progress for scheduling. Follow the
   [learned-detector field acceptance design](monitoring-pilot-acceptance.md) to verify the deployed
   build and test evidence. Full DNS acceptance remains on hold pending an unqualified hour with an
   observed above-threshold count and engine abstention evidence.
2. Judge the monitoring MVP using the controlled learned-detector trial and a subsequent seven-day
   normal-LAN review. Start the seven-day window after controlled incidents and associated delivery
   work have finished.
3. While history accumulates, continue fixture-driven design for bounded evidence sources and
   endpoint measurement. Keep NextDNS manual and limited to explicitly approved report scope.
   Use the dedicated lab evidence when reviewing a future standby or household trial.

#### F8 source gate

F8 is a locally reviewed, opt-in, count-only upload-incident detail slice. The local adversarial
review reported that the hour-boundary filter suppresses context on normal collector cadence.
Resolve that source defect and establish an explainable learned upload incident before seeking
an owner decision on the separate F8 field exercise.

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
| M1 — monitoring MVP, next | Real collection validation; coverage panel; hourly device/network aggregates; cold-start baseline status; fixed large-upload and qualified upload-deviation alerts; bounded DNS/reachability probes (runner, pipeline fold, `GET /probes` and overview panel, off by default and pending live activation). An offline replay and evaluation harness (#104) and a pilot-report CLI (#94) are merged; minimal local UI/inbox and notification lifecycle | Deterministic replay without duplicate counts/alerts; injected collection failure visible within two configured collection windows; injected sustained upload and probe outage visible within two detector windows. Seven-day normal-LAN pilot reports alert volume and owner judgments, target ≤1 unwanted open notification per network per UTC day in the pilot report. | L |
| M2 — richer behavior/context | Read-only provider DNS context with provenance and explicit attribution; day/time patterns, destination/port novelty, network-wide shifts, measured type rules, incident correlation and feedback | ≥14 valid observation days before evaluating initial learned deviations; chronological held-out replay includes backups/updates, sleeping devices, restarts, IPv6 and gaps. Report precision/recall per detector, abstentions and coverage, never a single unsupported accuracy score. | L |
| M3 — richer optional visibility | Approved multi-network adapters and external Zeek/Suricata metadata sensor on a capable host, with suitable TAP/SPAN placement | Fixture/replay contracts; malformed/flooded inputs bounded; missing sensor flagged; duplicate overlapping observations do not inflate totals. Demonstrate exactly which traffic is observable before enabling scan/beacon claims. | L |
| M4 — measured learning | Robust per-device drift first; optional classifier/AI explanations only if rules leave a useful residual | Compare against deterministic baseline on owner-labeled chronological holdout; predeclare false-alert budget; no regression in explainability, privacy or resource bounds. Cancel models that add no measurable value. | M–L, conditional |

*Dated note, 2026-11-09: the paragraph below is the 2026-10-25 snapshot. Soaks 1-3 have run since; soak 4 was running on 2026-11-09 (no outcome claimed). The read-only GUI and the opt-in senders are now merged.*

The [bounded real-router field pilot](router-validation-2026-10-24.md) found inventory identities still typed `unknown`, no DNS rows or DHCP option 55/60 observations, and conntrack attribution gaps. This historical result motivated the merged coverage/characterization source. The [October 25 field snapshot](monitoring-field-status-2026-10-25.md) records actual parsed-DNS delivery and corrected LAN scope while retaining the earlier flagged windows and pending recovery, long-duration and accuracy gates; M1a source delivery does not complete the UI/feedback stages or the full monitoring MVP.

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

## Exposure and suspicious-traffic evidence (M2b proposal)

Goal: help the owner see which devices may be exposed to known vulnerabilities and which traffic looks like it
could be malicious, as **evidence with confidence labels**. Nothing here is a verdict. A match never blocks
traffic, never changes a group or trust, and never merges identities; enforcement stays with Couvre-feu. The
dataset-free evidence pack, manual dataset staging and acceptance, and bounded NextDNS report are implemented.
The remaining reader, scheduling, reputation and known-issue proposals retain their per-dataset source, license and false-positive review gates (D7, D8 and D9 are decided).

Phases, each shippable and reviewed on its own:
1. **Identity quality first.** CVE-style matching needs vendor/product (ideally version). Measure how many
   inventory devices have a usable vendor, product or service signal (DHCP fingerprint, mDNS/service
   characterization, OUI for non-randomized MACs) and show the unknowns honestly. Passive router-side data rarely
   gives firmware versions, so most matches will be type-level.
2. **Local DNS reputation match.** Match the router-local parsed DNS queries (already collected per device) against
   an imported, versioned blocklist/reputation list. Output: an explainable incident (`detector=dns_reputation`) with
   the device label, window, list name and version, match count, and likely benign explanations, using the existing
   incident lifecycle (acknowledge, snooze, mark expected). No query text leaves the LAN. Bounded lists, bounded
   scans, and a quality latch when DNS coverage is partial.
3. **Known-issue notes.** Import an offline CVE dataset (for example NVD data and a known-exploited list) with recorded
   source, date, license and checksum. Map a device's vendor/product signal to candidate advisories and show them as
   "device type may be affected" notes with a confidence level, never as "vulnerable". Prefer exploited-in-the-wild
   entries first to keep noise low. A human can mark a note expected or not applicable, with an audit entry.
4. **Provider verdict context.** The manual [NextDNS report](nextdns.md) counts attributable threat-feed blocks in a bounded
   query window. Separate roaming visibility remains a proposal and needs an explicit owner decision.
5. **Sensor evidence (M3).** Zeek/Suricata EVE metadata for protocol-level indicators, only after sensor placement is approved.

Constraints that apply to every phase:
- Imports are manual or explicitly scheduled, versioned, checksummed and reversible; the Tower keeps working with no
  network access. No telemetry, no cloud lookups of household data, no remote LLM.
- Before importing any dataset record its source, version, update mechanism, license and redistribution compatibility
  (the repository is AGPL-3.0; many blocklists are GPL or non-commercial), refresh date and false-positive notes
  (existing rule, stated in full).
- Incidents reuse the existing incident lifecycle; a per-detector alert budget must be set before enabling, and a
  cold-start disclosure applies. Adding `dns_reputation` extends the detector contract in `docs/api.md`.
- Known-issue notes are a separate entity with their own API write path, scopes and audit actions (the incident API has
  no free-text note and no "not applicable" state); they never raise attention or notify. A human can mark one expected
  or not applicable, with an audit entry.
- An OUI alone never qualifies a device for a known-issue note: it identifies the network-chip vendor, not the product.
  Require a product-level signal and show the signal used.
- Reputation lists: security categories only (malware, phishing, command-and-control), fetched from pinned HTTPS
  sources; reject an update whose size or entry churn exceeds a threshold without review; keep a local allowlist. A
  checksum proves integrity, not trustworthiness. A match means a query was made, not that the domain was contacted.
- Matched domains appear only in local incident detail, obey the seven-day raw window, and never appear in notifications.
- Provider block/category verdicts are labelled third-party opinion and never raise incident severity by themselves.
  Roaming (off-LAN) query history is opt-in under D8 and held to the same raw window. The provider API key is a secret:
  stored privately, never logged, and treated as having full account scope until proven otherwise.
- Acceptance: phase 1 exits with a measured share of devices that have a product-level signal; phase 2 passes a
  seven-day pilot report of `dns_reputation` volume against an owner-labelled precision target; phase 3 starts only if
  phase 1 coverage is useful. Proposed targets, to be calibrated with owner-labelled data.
- Tests: fixture-replayed lists with benign and malicious domains, list-update and rollback, partial-DNS-coverage
  abstention, duplicate/overlapping sources, and a negative suite proving a match never changes trust or groups.

### Device evidence pack (export for outside analysis)

Requirement: the owner can export what Vigie knows about one device as a single, bounded, redacted document to
take to an external analyst or assistant, without Vigie itself calling any network service. The pack carries
evidence with confidence labels and provenance, never a verdict. Contract, levels, audit and the injection
posture are in `docs/api.md` ("Evidence pack"). Phasing:
1. **Phase 1 (implemented).** `POST /devices/{id}/evidence-pack` and `vigie-api evidence export`: identity,
   DHCP/mDNS fingerprints, type determinations, incidents and coverage gaps, with `datasets: []`. No CVE, KEV,
   reputation or provider data. The GUI stays GET-only and read-only; an export button is future work.
2. **Phase 2.** A `known_issue_notes` section once D7 data exists (below). Every match cites a `dataset_id` with
   version, date and sha256 under `datasets[]`; this is an additive minor schema bump.
3. **Phase 3.** A `dns_reputation` section from the local parsed-DNS match, only after the incident detector exists.

Owner decisions recorded 2026-10-26:
- **D9 = A (type-level notes).** Known-issue notes may be type-level. Only the known-exploited (KEV) list qualifies,
  and only with a product-level signal (an OUI alone never does). Notes appear in device detail only: never as
  incidents, never in notifications. A human can mark a note "not applicable", with an audit entry.
- **D8 = keep NextDNS upstream.** The router's dnsmasq stays the single home DNS entry point, so Vigie attributes
  queries per device; NextDNS stays the upstream and roaming filter; provider logs are read-only context only.
- **D7 = confirmed by the owner, 2026-10-26.** A scheduled fetch of KEV and URLhaus into a staging area, a human
  accept step, and versioned, reversible imports; KEV and URLhaus first. Confirmation approves the plan, not an
  implementation: staging and the human accept/reject step exist as CLI only ([datasets.md](datasets.md)); no fetch, reader or applied dataset exists yet, and each dataset still needs its source, version, license
  and false-positive review before import.

### Resolver role: NextDNS, AdGuard Home and Vigie

Vigie's per-device DNS truth is the router-local dnsmasq log, which records which device asked. Whatever resolver
sits upstream (NextDNS, AdGuard Home, another) only answers. Keep these roles separate:
- **Local dnsmasq log (Vigie source).** Device attribution, coverage flags and baselines come from here.
- **Upstream filtering resolver.** NextDNS is a cloud resolver whose profiles follow the owner away from home on devices configured to use it, with
  blocklists/threat categories and configurable log retention and storage region; AdGuard Home is a self-hosted LAN resolver with local logs and filters that does not
  leave home unless the owner exposes it through a VPN. Either can be dnsmasq's upstream.
- **Couvre-feu boundary (checked against its docs, 2026-10-26).** Couvre-feu enforces by MAC on the router (fw3/iptables
  forwarding rules and schedules) and, for child devices only, redirects IPv4 port 53 to the router and blocks DoT/DoQ and
  known DoH addresses. It does no content or category filtering (that stays with the upstream resolver), it never changes
  dnsmasq configuration, adult and control devices are unaffected, and roaming/cellular/VPN are outside its coverage. So
  Vigie has guaranteed per-device DNS only for devices whose DNS is forced through the router; adult devices that use
  NextDNS directly or DoH are invisible to the dnsmasq log and must show as DNS-coverage `degraded`. Couvre-feu's own
  decision list (its D1-D6 build decisions) is unrelated to Vigie's owner gates D1-D6; do not conflate them.
- **Provider logs as optional context.** The [NextDNS operator report](nextdns.md) reads a bounded window of raw
  provider logs and correlates them with local queries when the owner can verify a dedicated provider device ID
  for queries forwarded from one LAN device. A shared router identifier cannot establish a device binding.
  Per-device names at the provider require a forwarder (for example
  the NextDNS CLI) that sends LAN device names to the provider: that is a cloud disclosure and a dnsmasq/router change
  gated by D2 and D8, not a default. Even then there is no automatic identity merge and no training of the router-local
  baseline on cloud history (existing rule).
- **D8 resolver strategy:** keep NextDNS for roaming and threat-category filtering, keep the router's
  dnsmasq as the single home DNS entry point so Vigie attributes queries per device, and add AdGuard Home only if the
  owner wants provider-independent local logs or a self-hosted filter. A hybrid (AdGuard Home at home, a NextDNS
  profile on roaming devices) avoids a hard choice only if those profiles are disabled on the home network: a phone
  or laptop with a NextDNS profile or Android Private DNS sends encrypted DNS straight to the provider even at home,
  bypasses dnsmasq, and must then show as DNS-coverage `degraded`, never as quiet. This changes no Vigie code; it
  changes which context sources exist. The owner has a paid NextDNS plan, so query limits are not a factor; log
  retention, storage region and the API key's scope are inputs to any separate activation decision.

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
New gates for M2b: D7 offline dataset import cadence and sources (decided: scheduled fetch into staging with human
accept, KEV and URLhaus first); D8 resolver strategy (decided: keep NextDNS upstream, router
dnsmasq as the single home entry point, provider logs read-only context); D9 known-issue notes (decided: type-level,
KEV only, product-level signal required, device detail only). See "Device evidence pack" above.
This roadmap does not resolve them, approve PRP-002, authorize router commands or change enforcement policy.
Endpoint connection events (M2c) are a separate design-only proposal in [PRP-003](prp/003-endpoint-events.md); it is not PRP-002.
A future lease-only collection mode avoids dnsmasq changes but loses fingerprint/DNS evidence; show that tradeoff
rather than promising identical coverage. Safe fixture-driven development can proceed while field-dependent
acceptance waits. UI framework, external sensor placement, final alert budget and retention beyond current
policy remain proposed choices to settle in each milestone's design review.

The [NextDNS operator report](nextdns.md) is the first M2 provider context adapter (#131). On November 23 the
dedicated Atlas lab verified live attribution for one threat-feed block and zero matches for the allowed control.
A November 23 live lab follow-up recorded withheld attribution for a simultaneous A/AAAA pair and a batch-end observation. It labels
provider coverage as unverified. Standby and household use remain separate approval decisions. Provider context adapters
have no enforcement, notification, or severity authority. Keep cloud history out of router-local baseline training
and automatic identity merging.
The local GUI is implemented, including the read-only M1b foundations in #17, #31 and #65.

M1c field hardening includes a transport-gap/sequence-reset quality latch: when a helper restarts
and cumulative counters re-prime, retain the interrupted interval as partial even if current source
flags are zero. TDD seams should cover restart, missing sequence, reconnect and reset without
replay/double counting; assert preserved gap provenance and abstention from confident baseline
training. This is proposed hardening, not implemented or evidence of malicious traffic.
