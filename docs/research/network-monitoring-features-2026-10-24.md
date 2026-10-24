# Network monitoring feature research — 2026-10-24

Status: product research and recommendations, not implemented functionality or deployment approval.
The requested vision covers discovery, device characterization, learned device/network habits,
and investigation of strange behavior. The identity/API build is one prerequisite, not this whole product.
Primary sources below were opened and read on this date. Product documentation describes capabilities;
it does not establish detection accuracy, resource suitability, or equivalence with Vigie's sensors.

## What the reference products demonstrate

| Reference | Documented behavior | Proposed lesson for Vigie |
|---|---|---|
| [Fing monitoring](https://www.fing.com/monitor/) | Continuous discovery, device connection/offline and internet-outage notifications, chronological event history; continuous monitoring requires a running monitoring unit. | Prioritize a durable timeline and collection continuity over another one-time scan view. |
| [NetAlertX features](https://docs.netalertx.com/FEATURES/) | Multiple discovery/import sources, presence/IP changes, device overview, change alerts, notification suppression/deduplication and extensible publishers. | Expose observation sources and coverage; build notification controls before adding many detectors. |
| [Firewalla abnormal uploads](https://help.firewalla.com/hc/en-us/articles/360020926913-Abnormal-Upload-Alarms-Tutorial) | Distinguishes unusual upload behavior from a fixed large-upload threshold. Its tutorial uses device/destination/time/transfer context and explains that retrospective computation can delay alarms. | Show measured deviation and event time separately from detection time; unusual does not establish maliciousness. |
| [ntopng alerts](https://www.ntop.org/guides/ntopng/basic_concepts/alerts.html) | Threshold and behavioral alerts can concern hosts, interfaces and whole networks. Threshold incidents have active/past periods; documented examples include SYN volume and packet drops. Smoothing-based behavioral alerts require an Enterprise L license. | Track incidents with start/recovery rather than endless independent messages; support network-level entities. Do not assume that paid product functionality can be copied or redistributed. |
| [Zeek connection logs](https://docs.zeek.org/en/master/reference/logs/conn.html) | Connection metadata includes endpoints, protocol, duration, directional bytes, state and missed bytes; logs can come from live traffic or stored captures. | Optional external telemetry can improve temporal and protocol evidence. A conntrack summary is not an equivalent connection log. |
| [Suricata EVE output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) | JSON events can include alerts, anomalies and protocol metadata; optional Community ID helps correlate flows across tools. Payload output is configurable. | Future adapter should accept bounded metadata/alerts, preserve sensor provenance and correlation IDs, and exclude payloads by default. |
| [Prometheus blackbox exporter](https://github.com/prometheus/blackbox_exporter#readme) | Supports endpoint probes including DNS, HTTP(S), TCP and ICMP; exposes probe success and timing. | Probe a few owner-approved targets to distinguish DNS/service reachability problems from an observation gap. Reusing a server-side prober may be simpler than extending the router. |

These are feature precedents. Detector thresholds, budgets and priorities below are our recommendations,
not claims about these products or measured results on the owner's LAN.

## Candidate features and feasibility

| Priority | Feature | Evidence needed / limitation |
|---|---|---|
| First | Device cards: owner label, inferred type with confidence (separate from observed vendor hints), MAC/IP history, current presence, evidence source | Existing inventory is a base; presence is observed activity, never proof that a person is home. Sleeping or silent devices need an unknown state. |
| First | Visibility panel: collector freshness, spool/dropped/unmapped counters, observed networks and IPv4/IPv6 | Leverage batch health/source flags. A green pipeline is not proof every VLAN or LAN conversation is visible. |
| First | Large uploads + sustained upload deviation | Directional byte aggregates, trustworthy accounting/attribution, valid baseline coverage; distinguish thresholds from learned anomalies. |
| First | Network availability, DNS probe duration/success and local service checks | Bounded explicit active probes; current DNS query records have no response code or response duration. Passive NXDOMAIN rates/latency require a schema/source extension. |
| Next | New destination/port or changed activity hours | Maintain bounded destination cohorts and time-aware summaries. “New” means absent from retained, sufficiently complete history, not a globally novel or dangerous address. |
| Next | Network-wide volume/connection/DNS shifts, shared outage correlation | Combine device and network windows; deduplicate related incidents. First show correlation, not a claimed root cause. |
| Later | Beaconing and scans | DNS timestamps permit coarse periodic-query candidates; conntrack summaries lack precise flow starts, source ports and TCP flags. Fine periodicity/SYN-scan claims require richer telemetry and measured recall. |
| Later | Rogue DHCP, service/port inventory and topology | New source or explicitly approved active discovery; rate-limit scans and label inferred topology. Do not turn on broad scans implicitly. |
| Conditional | Drift models, threat intelligence and AI summaries | Labeled evaluation, source licensing, local execution and explanation controls first; no model writes trust or router policy. |

## Sensor constraints that change the roadmap

[PRP-001 §2](../prp/001-vigie-architecture.md) records that same-bridge traffic bypasses conntrack,
its sampled summaries have coarse timing, neighbor attribution can be spoofed, and the router is resource constrained.
The [batch model](../../server/src/vigie_ingest/models.py) supplies directional summary bytes/flow counts,
DNS query timestamps and limited health; it does not currently provide passive DNS response status/latency,
packet-level scan flags, or explicit per-network identity in every observation.
Bounded/overflow buckets hide some destinations. A disappearing signal can be truncation or lost visibility.
Encrypted DNS and unobserved IPv6/VLAN paths reduce coverage; low DNS volume alone cannot establish DoH.
Offload and sampling behavior need real-router measurements before byte-volume claims are accepted.

## Product choices from the brainstorming pass

Considered three paths: a richer inventory first, an all-in-one IDS immediately, or a modest observability
product with an incident inbox. Recommend the third: finish safe identity decisions, then ship a monitoring
MVP with visible coverage, hourly aggregates, a few explainable detectors, a small local UI and controlled notifications.
This delivers useful daily answers without making packet visibility or anomaly-accuracy promises we cannot test.

The local monitoring UI is new proposed scope. The separate control app remains the authority for enforcement;
users should not need that app just to inspect Vigie's measurements. No automatic trust promotion, quarantine,
firewall or DNS changes follow from a monitoring alert.

Deferred ideas remain useful: owner-approved DNS/service probes, multi-network sensors, service inventory,
external Zeek/Suricata, topology and threat feeds. Prefer existing adapters/tools where provenance, license,
resource cost and failure semantics are acceptable. Feature research does not authorize installations.
See [the roadmap](../roadmap.md) for dependencies, proposed exits and starter tasks.
