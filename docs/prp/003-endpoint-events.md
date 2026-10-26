# PRP-003: Endpoint connection events (Snitchwatch/OpenSnitch) as an observe-only evidence source

Status: **Design proposal. Nothing is built.** Owner decisions K1-K4 (section 11) were confirmed by the owner on 2026-10-26; the feasibility measurement (phase E0, section 6) is next and must finish before any listener exists.
License: AGPL-3.0-or-later. Branch: `docs/prp-endpoint-events`.

Numbering: `docs/roadmap.md` already refers to a "PRP-002" for a different proposal; this document deliberately uses 003 and does not reuse that number.

Relationship to other docs: [PRP-001](001-vigie-architecture.md) is the architecture this extends (section references below are to it). The companion research note is PR #21 (`bearyjd/vigie-network`, open). The peer design is `bearyjd/snitchwatch#231`. The evidence-pack note in section 8 refers to PR #23 (`feat/evidence-pack`, not on `main` at the time of writing). The roadmap entry is stage M2c in [roadmap](../roadmap.md).

Labelling: every statement about the peer project (Snitchwatch, OpenSnitch v1.8.0 behaviour) is **per the peer spec (bearyjd/snitchwatch#231), not verified by Vigie**. Statements about this repository carry `file:line` references that were read and checked on `origin/main` 760edf1.

## 1. Goal and non-goals

**Goal.** An external check of an endpoint firewall. The router sees every packet from the host but not the program or the decision; the endpoint firewall knows the program and the decision but only for what it intercepts. Comparing the two shows traffic the endpoint guard did not report, and a guard that has gone quiet. Secondary: per-program attribution on the device page.

**Non-goals.** Vigie stays observe-only: no enforcement, nothing sent back to the endpoint, no raw packet or payload capture. Endpoint data never feeds stitching, type inference, baselines or merges (same rule as section 8). It never clears or suppresses a router-side detector.

**Peer contract (sender side; per the peer spec (bearyjd/snitchwatch#231), not verified by Vigie).**

| Item | Contract |
|---|---|
| Source | `opensnitchd` remote logger (JSON, TCP) to loopback rsyslog on the endpoint |
| Transport | rsyslog allowlists fields and forwards with `omfwd` over TCP+TLS, RFC 5425 octet-counted framing; server certificate verified against a pinned CA and peer name; mutual TLS |
| Message | one event per syslog message; MSG is a JSON object with ONLY `time`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `dst_host`, `process_path`, `user_id`, `Action`, `Rule`, `Type`, plus a configured `host_id` |
| Default decisions | `Action` and `Rule` are the string `"<nil>"` when the daemon's default action decided |
| Type | `0` = connection |
| Never present | `process_env`, `process_args`, `process_cwd`, `process_tree`, checksums |
| Loss | the daemon drops events when its queue is full or rsyslog is down, so absence is not proof |
| Not reported at all | DNS responses, the daemon's own traffic, rules marked `nolog`, unparsable packets, connections not intercepted when `InterceptUnknown` is false, inbound traffic |

## 2. Architecture (recommended)

A **new dedicated `endpoint-ingest` container** receives the TLS syslog stream itself, with mTLS **required**. It is not a relay into `/v1/batch`.

| Property | Value |
|---|---|
| Hardening | same `x-hardening` anchor as the other services (`deploy/compose.yaml:34-44`: uid 10001, read-only, `cap_drop: [ALL]`, no-new-privileges); the anchor's `mem_limit: 512m` / `cpus: 1.0` (lines 44-45) are overridden to `mem_limit: 128m`, `cpus: 0.25` |
| Runtime | Python asyncio + stdlib `ssl` |
| Port | `${VIGIE_LAN_ADDR}:6514`, bound like ingest (`deploy/compose.yaml:103-106`, `VIGIE_LAN_ADDR` has no default) |
| Storage | own volume `vigie-endpoint`; own server certificate (new `gen-certs.sh --role endpoint`, keeping the ingest/API certificate separation stated at `deploy/gen-certs.sh:2-3`) |
| Mounts | NEITHER `vigie-inv` nor `vigie-overrides`; the pipeline mounts `vigie-endpoint` read-only |

**Why not the alternatives.**

| Option | Verdict | Reason |
|---|---|---|
| Dedicated listener (recommended) | Chosen | Own writer and own volume; identity comes from the client certificate; no coupling to batch limits |
| Tower-side relay into signed batches | Rejected | Ingest runs a single worker and holds an exclusive `flock` on the raw directory (`deploy/compose.yaml:78-80` `--workers 1`; `server/src/vigie_ingest/lock.py:19-28`; PRP-001 section 4, line 100), so a second writer cannot share `/raw`. A relay still needs the same TLS listener, adds a second key on the same host and no new trust boundary, and couples endpoint traffic to batch limits (`api/batch.schema.json:363` `maxItems` 5000 for `conntrack`; body cap 512 KB, `server/src/vigie_ingest/config.py:9`). A relay on the endpoint breaks the peer contract (rsyslog `omfwd` only) |
| rsyslog `imtcp` on the Tower (steelman) | Rejected | Battle-tested framing, but it gives no per-message client-certificate identity (`host_id` would be whatever the sender claims), identity would need one port per host, and the files it writes are one more parser to harden |

**Framing.** The peer sends NO syslog header, so the frame body must be exactly one JSON object; any PRI or header is rejected and counted (`header_present`).

## 3. Trust boundaries and STRIDE

Boundaries: (1) LAN to listener (before auth, then after mTLS); (2) listener to `vigie-endpoint` shards; (3) shards to pipeline (read-only); (4) pipeline to incidents, API and evidence packs. **Every endpoint field is attacker-controlled text, `time` included.**

| STRIDE | Threat | Mitigation |
|---|---|---|
| S | Host claims another `host_id` | mTLS mandatory; client certificate SPKI must be in the registry; payload `host_id` must equal the host bound to that certificate, else reject and count `host_id_mismatch`; the source IP is never used for identity |
| S | Compromised host fabricates events to hide traffic | Endpoint events NEVER clear or suppress router detectors (DoH, volume); "no incident" is not shown as "clean" |
| T | Framing smuggling, partial frames | Octet count 1-5 digits, no leading zero, <= 8192, then exactly one space; any violation closes the connection; a frame must complete within 10 s of its first byte |
| R | Who sent what | Store per event the certificate SPKI id, server receive time and connection id |
| I | `process_path`/`dst_host` leak through incidents, notifications or packs | Never stored in incidents or notifications; packs use new Sensitive kinds (section 8); raw retention 7 d |
| D | Slowloris, connection or event floods, huge JSON numbers, disk fill | Limits in section 8; every drop has a counter; writes stop when the volume has < 5% free (counted as `disk_low`) |
| E | Listener compromise reaching inventory or overrides | Those mounts are absent; TLS 1.3 only (no renegotiation); no compression |

**JSON strictness (every rule rejects the event and increments a counter).**

- Duplicate keys rejected (`object_pairs_hook`); `NaN`/`Infinity` rejected; any integer literal longer than 10 digits rejected.
- The key set must EQUAL the allowlist plus `host_id`: an extra field (such as a leaked `process_args`) or a missing field rejects the event.
- `Type` must be 0 (other values are counted as `type_skip`); ports 0-65535; IPs must parse with `ipaddress`; `user_id` 0..2^32-1.
- `dst_host` <= 253 LDH/IDNA characters; `process_path` absolute and <= 4096 bytes.
- Any C0/C1 control, bidi-override or NUL character rejects the event. This is safe: a missing event becomes suspicion on the router side, never a clearance.
- `"<nil>"` in `Action`/`Rule` is stored as `decided_by='default'`, `action=NULL` (verdict unknown); the event still counts as "reported".

**Time.** Join windows use the server receive time. The endpoint `time` and the skew are stored. If |skew| > 5 min (the bound used in PRP-001 section 4), the event is marked `late` and joined using the endpoint time corrected by the host's median live skew, and only if it is no older than `VIGIE_MAX_SPOOL_AGE_S` (`server/src/vigie_ingest/config.py:72`, default 86400). Future-dated events are rejected (`future_ts`).

**Dedup.** Key `(host, time, proto, src_ip, src_port, dst_ip, dst_port)` in a bounded LRU of 50k entries / 10 min. TLS prevents network replay; rsyslog may resend after a reconnect.

## 4. Data model and provenance

Daily shard `endpoint-YYYYMMDD.db` in `vigie-endpoint`, written only by the listener:

| Table | Columns |
|---|---|
| `endpoint_event` | `host_id, cert_id, conn_id, recv_ts, event_ts, skew_s, late, proto, src_ip, src_port, dst_ip, dst_port, dst_host_id, process_path_id, user_id, action, rule_id, decided_by` |
| string dictionaries (per shard) | paths, hosts, rules |
| `endpoint_counters` | `host_id, minute, counter, n` |

Pipeline-owned (`inventory.db`):

| Table | Columns |
|---|---|
| `endpoint_hourly` | `host_id, device_id, hour, events, late, dropped, router_keys, matched_keys, unmatched_keys, excluded_keys, skew_p50` |
| `endpoint_presence` | `host_id, hour, tls_connected_s` |

Every derived row carries `source_kind='endpoint'` beside the router kinds. Endpoint data NEVER feeds stitching, type inference, baselines or merges.

## 5. Host identity

**Authentication is held by the listener.** `endpoint_hosts(host_id, spki1, spki2, revoked)` lives in the listener's own database, written by a new `provision-endpoint.sh HOST_ID` that mirrors `deploy/provision-collector.sh` and `server/src/vigie_ingest/admin.py`.

`gen-certs.sh` produces only self-signed server certificates today (`deploy/gen-certs.sh:128`, `openssl req -x509`), so it needs a new `--role endpoint-ca`: a private P-256 CA issuing client certificates with `CN=host_id`, valid 397 days. Two SPKI pins per host allow rotation; revocation is the registry flag (no CRL). The peer's rsyslog verifies the server against the CA file and the permitted peer name, which must be in the server certificate's SAN.

**Binding to a device (human-owned).** `endpoint_host_bindings(host_id, device_id, state proposed|approved|revoked, version)` in `overrides.db`, written ONLY by the API.

- The pipeline proposes a binding only after 24 h in which the event `src_ip`, mapped through `raw_neigh`/`raw_lease` (`server/src/vigie_ingest/db.py:20`), lands on MACs of a single device.
- The binding targets the `device_id`, never an IP, so a DHCP change has no effect. It covers every MAC of that device (`observations.device_id`) and follows stitching aliases (`merged_into`, `server/src/vigie_api/effective.py:130`).
- If the device is retired the binding is suspended.
- Per hour, if `src_ip` maps to a MAC outside the bound device set: `binding_mismatch`, shown as a status (not an incident), and detectors are suppressed for that hour.

## 6. Router-to-endpoint join (honest feasibility)

The router stores NO source port. What exists:

| Fact | Reference |
|---|---|
| `raw_flow` holds `(device_mac, dst_ip, dst_port, proto, bytes_up, bytes_down, flows)` | `server/src/vigie_ingest/db.py:94-97` |
| The helper aggregates per `(src_ip, dst_ip, dst_port, proto)` | `collector/conntrack-helper/src/agg.rs:1` |
| Sampling every 60 s | `collector/conntrack-helper/src/cli.rs:25` |
| `top_n` 512 with `other` quotas `k_lan` 192, `k_wan` 64 | `collector/conntrack-helper/src/agg.rs:13-16` |
| The agent folds anything beyond 20,000 rows into a per-MAC `other` row with dst and port NULL | `collector/agent/src/ctfold.rs:19-21` |
| `flows` is the MAX count of live flows across samples in a window | `collector/agent/src/ctfold.rs:9-12` |
| `new_flows` is computed by the helper but absent from `ConntrackSummary`, so it never reaches the batch | `collector/conntrack-helper/src/agg.rs:71`; `api/batch.schema.json:3-76` |

So the finest possible join key is **(device, dst_ip, dst_port, proto, window)**, and only on non-`other` rows.

**Match rule.** A router key counts as matched if the endpoint reported that key within +-120 s of the window. Until `new_flows` exists, a key reported in the last 24 h also counts (long-lived flows).

**Exclusions.** Protocols other than tcp/udp; ports 53, 853, 5353, 67, 68; destinations that are LAN, router, multicast, link-local or loopback; `other` and unmapped rows; endpoint events whose `src_ip` is off the LAN.

**Phase E0: measure first** (one desktop, 48 h, an offline script over shards plus an exported JSON log, no listener):

- share of bytes and flows in `other` rows;
- key match ratio;
- the remaining unmatched classes (VPN, container NAT, kernel traffic);
- events per day and bytes per event;
- what `raw_flow.ts` means and the window length (both **unverified**).

## 7. Incidents

Hourly, because `monitoring_incidents` uses `last_hour` and has `observed_bytes`/`threshold_bytes` `NOT NULL` (`server/src/vigie_pipeline/schema.py:228-233`). Either store counts in those columns with `detector` naming the unit, or migrate the schema.

| Incident | Fires when | Suppressed when |
|---|---|---|
| Likely unreported traffic (shadow mode first) | Two consecutive closed hours (15 min grace) with unmatched keys >= 3, unmatched flows >= 5 and unmatched/candidate >= 10% | no approved binding or a binding mismatch; any listener drop, rate-limit, late or queue counter for the host in that hour +-1; router `coverage_hourly` qualified < 90%; skew unknown or > 60 s; the host's trailing 7-day match ratio < 0.9; the host is marked "runs NAT'd VMs/containers" (detector off); destination in the host's declared VPN endpoints |
| Endpoint guard quiet | Device present (lease or neighbour) with >= 20 non-excluded router flows over >= 3 windows in the hour and zero events from the host in that hour | no events in the prior 24 h (setup problem: status, not incident); router coverage gap; listener uptime < 30 min or within `evidence_gaps`; evidence records "TLS disconnected" vs "connected but silent"; auto-resolves when events return |

Starting thresholds are calibrated in shadow mode against a false-alert budget set in advance (roadmap M2b).

**Wording.** "Likely unreported traffic: the router saw N connections from <device> to M destinations that its endpoint guard did not report between HH:00 and HH:59. Possible causes: dropped events, VMs or containers sharing the connection, or a program the guard does not see." It never says malware or bypass as a fact. If the guarded host is the Tower itself, container egress shows up as the pasta/slirp process: add a fixture.

## 8. Retention, privacy, limits

**Retention.** Raw shards: `VIGIE_ENDPOINT_RETENTION_DAYS`, default 7, hard max 30, `secure_delete` like raw shards (`docs/deploy.md:128` for the existing setting; `server/src/vigie_ingest/db.py:138`). `endpoint_hourly` holds counts only, 90 d.

**Privacy.** `process_path`, `dst_host`, `user_id` and `rule` are never in incidents, notifications or `search_queries`. Evidence packs (`feat/evidence-pack`, PR #23, not on `main` at the time of writing) need new Sensitive kinds with their own pseudonym namespaces (`proc`, `dsthost`; uid and rule omitted). Do not reuse `host`, or LAN hostnames and remote domains become linkable inside one pack. In `server/src/vigie_api/evidence_redact.py` on that branch (`_PSEUDONYM` at line 33, `_INDEXED` at line 44) a new kind falls through: raw at full level, omitted at pseudonymized/minimal unless added to `_PSEUDONYM` or `_INDEXED`. Add `proc`/`dsthost` to `_PSEUDONYM`; leave uid/rule omitted.

**API (read-only).** New scope `endpoint:read` (off by default) for event detail. A per-host health view (connected, last event, counters, skew, binding state) needs no special scope. Binding approval goes through the existing human-write path.

**Limits.**

| Limit | Value |
|---|---|
| Connections | 32 total, 4 per peer address (IPv6 grouped by /64) |
| TLS handshake | 5 s |
| Idle connection | 15 min |
| Max frame | 8 KiB |
| Event rate per host | 50/s, burst 500 |
| Events per host per day | 200k |
| In-memory queue | 10k; stop reading for <= 5 s, then drop and count |
| Commit | every 1 s or 500 events |
| Expected volume | 5-20k events per desktop per day (about 3-5 MB per host per day); to verify in E0 |

**Counters.** `tls_fail, unknown_cert, revoked, host_id_mismatch, frame_bad, frame_timeout, conn_limit, rate_drop, quota_drop, header_present, json_bad, dup_key, unexpected_field, missing_field, bad_value, type_skip, future_ts, too_old, duplicate, queue_full, disk_low`.

## 9. Test plan

| Area | Cases |
|---|---|
| Framing | Hypothesis fuzz: splits across TLS records, leading zeros, count 0 or 99999, EOF mid-frame, 1 byte/s slowloris, idle-connection exhaustion |
| TLS | no client cert, wrong CA, unregistered SPKI, revoked cert, TLS 1.2 client, `host_id` spoofing |
| JSON | duplicate `process_path`, 10^5-digit int, NaN, nested object, extra `process_args`, `"<nil>"`, bidi/ANSI/NUL characters, 1 MB `dst_host`, skew +-10 min, rsyslog resend dedup |
| Isolation | the listener cannot open inventory or overrides; the pipeline opens endpoint shards read-only |
| Join fixtures | long-lived flow, VPN, container NAT, IPv6 privacy address, DHCP change, laptop away then back with a late burst, coverage gap, drop counter > 0 must suppress |
| Adversarial | a fabricated event stream cannot clear router detectors; process paths never appear in notifications or pseudonymized/minimal packs; Markdown injection through `process_path` stays fenced |

## 10. Phasing

| Phase | Scope |
|---|---|
| E0 | Feasibility measurement (section 6); no listener yet |
| E1 (confirmed, K3; after E0, before E5) | Add `new_flows` to `ConntrackSummary` in the batch schema (collector + schema change) |
| E2 | Listener, storage, counters, registry, read-only health view |
| E3 | Binding approval, then the join running in SHADOW for 14 d |
| E4 | Endpoint guard quiet |
| E5 | Likely unreported traffic, only after the shadow false-alert budget is met |

Each phase gets a review log in the PRP-001 section 15/17 format.

## 11. Owner decisions

All four were confirmed by the owner on 2026-10-26; the recommendation text is kept as rationale.

| # | Decision | Recommendation (rationale) | State |
|---|---|---|---|
| K1 | mTLS mandatory, no fallback | Yes | Confirmed by the owner, 2026-10-26 |
| K2 | Dedicated listener rather than a relay or Tower-side rsyslog | The listener | Confirmed by the owner, 2026-10-26 |
| K3 | Carry `new_flows` in `ConntrackSummary` (collector and schema change) | Yes, before E5; without it long-lived flows force the 24 h carry-over | Confirmed by the owner, 2026-10-26 |
| K4 | Showing `process_path` | Raw only in full-level packs and under the `endpoint:read` scope, 7 d raw retention, never in notifications | Confirmed by the owner, 2026-10-26 |

## 12. Risks

| Risk | Mitigation / note |
|---|---|
| New attack surface on the Tower: a network listener | Dedicated container, no inventory/overrides mounts, mTLS required, TLS 1.3 only, strict parser, hard limits, counters, 128 MB / 0.25 CPU cap, LAN-address bind and host firewall to the endpoint addresses |
| Fabricated-event trust | Events never clear router detectors; absence of an incident is not shown as clean |
| Operational burden of client-certificate issuance | `provision-endpoint.sh`, 397-day certificates, two SPKI pins for rotation; one desktop first |
| Endpoint asleep vs guard quiet | Presence from router lease/neighbour; TLS connected vs silent recorded; setup-problem status instead of incident |
| Accuracy of the join | No source port on the router side; E0 measures it first; shadow mode and a false-alert budget before any incident is shown |

## 13. Review log

Not yet run. Slots to be filled in the PRP-001 section 15/17 format.

| Round | Reviewer | Findings and dispositions |
|---|---|---|
| 1 | Opus security review | to be filled when the review runs |
| 1 | Codex review | to be filled when the review runs |
