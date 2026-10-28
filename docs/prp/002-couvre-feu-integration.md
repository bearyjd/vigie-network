# PRP-002: Vigie and couvre-feu integration (rev 2)

Status: **DRAFT, awaiting owner review. No implementation until approved.**
Depends on: PRP-001 (rev 3, `001-vigie-architecture.md`). License AGPL-3.0-or-later.
Supersedes: rev 1 (2026-10-22), which was written against a stale snapshot of couvre-feu.
Facts about couvre-feu below were verified on 2026-10-28 against `main` of
`github.com/bearyjd/couvre-feu` at commit `906bfca`. Nothing in couvre-feu was modified and no router was touched.

Neither repository holds private household information. Examples here use placeholders
(`person-a`, `<router-lan-ip>`); real names, addresses and MACs stay out of both repos and out of this document.

## 1. Two peers

| | couvre-feu | Vigie |
|---|---|---|
| Job | Controls the network: per-person pause and schedule enforcement on the router, with a parent web app | Characterises the network: a stable `device_id` across many MACs, device type, anomaly events, suggestions |
| Authority | **Sole enforcer.** Owns who a MAC belongs to (`people[].macs`), pauses, schedules, protected MACs | **Sole device inventory.** Owns device identity, inferred type, MAC history |
| Humans | Parents and admins approve every policy change | Labels and merges are approved through couvre-feu's UI |

They should support each other and respect each other:

1. **Authority stays put.** Vigie never changes enforcement or couvre-feu's router objects, and never causes enforcement. couvre-feu never edits Vigie's identity data.
2. **Neither needs the other to do its own job.** If Vigie is down, enforcement is unchanged. If couvre-feu is down, Vigie keeps collecting, and its events stay available to pull once couvre-feu returns.
3. **Humans decide in one place.** Suggestions from Vigie are approved by a parent in couvre-feu, never applied automatically.
4. **Share the minimum.** Labels, MAC sets, device types and events only. No DNS names, no raw logs, no secrets.
5. **Nothing private lives in git**, in either repo.

## 2. What couvre-feu looks like today (changes since rev 1 marked)

| Topic | Current state |
|---|---|
| Code of record | `bearyjd/couvre-feu` `main`. Rev 1 treated a local doc snapshot as a candidate; it is not. |
| Router policy model | Still `people[{id, macs[]}]`, pauses, schedules, doh. A MAC in no person gets default allow. "Rotating identities remain a coverage limit" is still stated in `docs/enforcement-contract.md`. |
| Limits | Unchanged: 64 people, 32 MACs per person, 256 total, a MAC belongs to one person, protected adult MACs refused. |
| Receipts (**changed**) | The 128-receipt budget still exists, but the router now evicts the oldest receipt instead of failing at capacity (`docs/contracts/tier1-rpc.md`). Two older docs still say "fails closed". |
| Reconstruction (**changed**) | A guarded, staged-generation swap is built. It is explicitly not one atomic transaction, and production remains gated on it. |
| Scope (**changed**) | `scope-add` and `scope-remove` exist, but only as root, interactive, TTY-confirmed commands that the service cannot reach by design. Live rehearsal is pending. |
| Device inventory (**new**) | A read-only router verb `rpc-inventory` and a service inventory with flags `new`, `private`, `unassigned`, polled every 60 s, admin-only (`/admin/inventory`), with an admin "Devices on the network" panel in the web app. `GET /devices` is a demo stub. |
| Auth and network | WebAuthn passkeys, roles `admin` and `parent`. **No bearer or machine tokens and no outbound HTTP** (router access is SSH only). Loopback or private listener behind a TLS proxy. |
| Router co-tenancy | Unchanged: it owns the `cf_*` and `cf2_*` firewall objects and `cf_sched_*` UCI sections, and edits `/etc/config/firewall`, `/etc/sysupgrade.conf` and root's crontab. `AGENTS.md`: never change dnsmasq configuration or the WAN zone. |
| New, flagged off | Per-account flag gate, audit log, ask-for-time (service and parent card), reward time, a static DoH resolver list for kids. |
| Proven live | Nothing has run on a real router yet. The rehearsal phase is pending. |

## 3. What each side gives the other

**Vigie to couvre-feu** (read-only, advisory):
- Identity across MAC rotation: "these MACs are one device", so a `private` flag can be explained rather than just shown.
- Inferred device type, plus anomaly and incident events.
- Coverage-gap events (section 5).
- Evidence for a suggestion, so a parent sees why a merge or label is proposed.

**couvre-feu to Vigie** (read-only, with revision, digest and age):
- Person assignment of a device (the owner field).
- A coverage report: which MACs are currently enforced for each person.
- Protected-adult MAC context, so Vigie can warn about a mis-assignment.

**Neither does:** Vigie does not assign people, pause anything or edit the router. couvre-feu does not rewrite device identity or infer device types.

## 4. The inventory overlap

couvre-feu now has its own LAN inventory (who is on the bridge right now, flagged new, private, unassigned). Vigie also keeps a device list. Two device lists in two UIs would drift.

Proposal: couvre-feu's inventory stays the *ledger of who is on the LAN and who it is assigned to*, because it sits next to the enforcement decision. Vigie *enriches* its rows with `device_id`, inferred type and the rotation chain. Neither builds a second device-management UI. Open question D8 asks the owner to confirm.

## 5. Coverage-gap detection (the shared value)

Vigie compares couvre-feu's coverage report with its own inventory and emits events. ("Coverage" here means which MACs are enforced. It is unrelated to the existing `coverage` data in `api/openapi.yaml`, which describes collector data coverage.)

- `coverage_gap_new_mac`: a device assigned to person P shows a MAC outside P's enforced set (for example a private-address rotation). High severity for child-owned devices.
- `unassigned_device`: a device with no owner is active on the LAN.
- `protected_mac_conflict`: a MAC in a person's set also appears under a device owned by a protected adult.
- `coverage_report_stale`: no report within a bound (default 10 minutes). A stale report is shown, never trusted for decisions.

## 6. How data moves

Vigie already authenticates API callers with bearer tokens, including integration and read-only token types that cannot approve rules (`docs/api.md`), and ships an OpenAPI description (`api/openapi.yaml`). couvre-feu has no machine auth and no outbound HTTP. That asymmetry shapes the options:

| Option | How | Cost |
|---|---|---|
| **A. couvre-feu pulls and pushes** | A small outbound-only client in couvre-feu reads Vigie's devices and events, and posts the coverage report, using a Vigie token | Adds outbound HTTP and a secret to an enforcement service. Could sit behind a flag like its other new features. Vigie's `integration` and `read-only` tokens get `403` on writes today (`docs/api.md`), so the coverage endpoint also needs a new, narrowly scoped write permission on Vigie. |
| **B. Vigie pulls an export** | couvre-feu exposes a read-only, token-protected export of assignments and enforced MAC sets | Adds an inbound machine-auth endpoint to couvre-feu. Vigie then initiates calls, which rev 1 avoided. |
| **C. File handoff** | couvre-feu writes a read-only snapshot file that Vigie reads from a shared location | No new network surface, but needs a shared location and has no freshness guarantee beyond the file time. |

Recommendation: **A, behind a flag, starting read-only.** It keeps Vigie passive and keeps couvre-feu the only initiator, as rev 1 did. A Vigie outage cannot change enforcement. The decision belongs to couvre-feu's owner because it changes that service's security posture (D7).

## 7. Vigie-side conflicts with couvre-feu's router rules

Rev 1 listed these. Status today needs re-verifying in phase I1.

| # | Concern | Status |
|---|---|---|
| C1 | The collector's dnsmasq logging drop-in (`log-queries=extra`, `log-dhcp`) and the dnsmasq restart it implies, against couvre-feu's "never change dnsmasq" rule | **Still open.** The drop-in is still the collector's design. Decision D2. Until decided, do not enable it on the shared router. |
| C2 | Vigie docs suggesting force-DNS or DoH-block rules that couvre-feu already owns | Re-verify. Vigie should only detect DoH bypass, never enforce. |
| C3 | A cron watchdog editing root's crontab, which couvre-feu journals | **Still open.** The collector's init script and `vigie-log-watchdog.sh` document a root cron job (`collector/agent/deploy/vigie-collector.init:15`, `collector/agent/deploy/vigie-log-watchdog.sh:2`). Replace it with a supervised loop that touches no crontab, or agree an exception with couvre-feu's owner. |
| C4 | Naming collisions | Router objects use only `vigie_*`, `/etc/vigie`, `/tmp/vigie`; never `cf_`, `cf2_`, `cf:v1`, `cf_sched_`. Add a static check. |
| C5 | Operator SSH sessions and couvre-feu's SSH guard | Document: Vigie install commands do not invoke `cfctl`. |
| C6 | Vigie `groups` mistaken for enforcement | Document as advisory UI zones. |

## 8. Failure behaviour and privacy

- Vigie down or stale: enforcement unchanged; couvre-feu shows inventory age; no policy action derived from stale Vigie data.
- couvre-feu down: Vigie keeps collecting and its events stay available to pull; coverage reports stop and `coverage_report_stale` fires.
- Disagreement (Vigie says device X has MAC m, couvre-feu's policy lacks m): never auto-resolved; it becomes an event for a human.
- A wrong Vigie merge cannot cause enforcement, because assignment is a human action in couvre-feu, and its protected-adult and one-MAC-one-person rules remain the backstop.
- Both systems stay inside the household network; no cloud. Tokens, pins and real identifiers live in owner-only private config outside both source trees.
- Suggested hygiene check for both repos: a docs lint that fails on private-range IPs, MACs outside fixtures, absolute home paths and personal names.

## 9. Phases

| Phase | Where | Scope | Exit criteria |
|---|---|---|---|
| **I0** | Owner | Decisions D2 to D8 (section 11) | Written answers |
| **I1** | Vigie | Router coexistence: re-verify C1 to C6, a `dhcp_source = leases` collector mode with no dnsmasq change, the naming check | Tests, docs, review |
| **I2** | Vigie | A new narrowly scoped write permission for the coverage endpoint (integration tokens are read-only today), the endpoint, gap events, `owner`, `unassigned` and `updated_since` filters, contract tests against the OpenAPI client | Tests, independent review |
| **I3** | couvre-feu (its own PRP) | Flagged-off Vigie client, enrichment of the inventory rows, inbox, assignment action | Its acceptance process |
| **I4** | Both | End to end on the demo router: a rolling-MAC device owned by a child raises `coverage_gap_new_mac`, and a parent assigns the new MAC through the human path | Demo run and write-up |
| **I5** | Both | Assisted MAC-set maintenance for rolling devices | Blocked, see below |

I5 stays blocked, and its shape changes. Receipt eviction and `scope-add` now exist, but guarded reconstruction is still non-atomic, the rehearsal has not run, and `scope-add` is interactive and root-only by design. So I5 can only ever be *suggestions to a human*, not automation, unless couvre-feu's owner decides otherwise.

## 10. Risks

1. **A fixed-MAC household rule may shrink the enforcement value.** If child devices use a fixed per-network address, Vigie's main contribution becomes inventory, new-device and coverage-gap detection, and compliance monitoring. That is still the core of I1 to I4.
2. **Two approval systems.** Mitigated by routing every approval through couvre-feu.
3. **Mis-assignment.** Show evidence and `link_source` next to every suggestion.
4. **Adding outbound HTTP to an enforcer** is a security-posture change that is couvre-feu's to approve.
5. **Router load.** Both agents on one low-power router are unmeasured; I1 includes a measurement before enabling anything beyond leases mode.
6. **Scope creep into couvre-feu.** Its changes are listed here but designed in its own repo.

## 11. Decisions needed from the owner

- ~~D1. Authoritative couvre-feu tree.~~ Resolved: `main` of `bearyjd/couvre-feu`.
- **D2. dnsmasq.** (a) Keep "never change dnsmasq" and run Vigie in leases-only mode; (b) allow the logging drop-in after couvre-feu's DNS baseline is re-measured with it; (c) build a passive packet-capture helper later.
- **D3. Fixed-MAC rule.** Are child and adult devices set to a fixed per-network Wi-Fi address today? It decides how much weight I5 deserves.
- **D4. Where each runs** relative to the other, and which interface Vigie's API binds.
- **D5. Notifications.** Which channel and owner for gap alerts.
- **D6. Person identifiers.** Confirm couvre-feu person ids are what Vigie's `owner` field holds verbatim.
- **D7. Transport.** Option A, B or C in section 6, and whether couvre-feu may gain an outbound client.
- **D8. Inventory split.** Confirm couvre-feu's inventory is the ledger and Vigie enriches it (section 4).
