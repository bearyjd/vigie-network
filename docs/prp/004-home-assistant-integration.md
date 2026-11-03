# PRP-004: Home Assistant integration (outbound webhook sender)

Status: **Design proposal. Nothing is built.** No owner decision below is confirmed yet; the open decisions are listed in section 9.
License: AGPL-3.0-or-later. Branch: `docs/prp-004-home-assistant`.

Relationship to other docs: [PRP-001](001-vigie-architecture.md) is the architecture this extends. [PRP-003](003-endpoint-events.md) is the format model for this document (phases, threat table, owner decisions). The delivery design this reuses is the ntfy sender: [`deploy/persistent/ntfy_sender.py`](../../deploy/persistent/ntfy_sender.py) and "Incident delivery to ntfy" in [monitoring](../monitoring.md). The delivery file is written by [`delivery_publish.py`](../../server/src/vigie_pipeline/delivery_publish.py); the deployment note is in [deploy](../deploy.md).

Labelling: every statement about Home Assistant (HA) behaviour is **per HA docs, unverified** by Vigie; H0 exists to replace each with a measurement. Statements about this repository were read in the files linked above.

Placeholders: this document names no real URL, hostname, webhook id, token or address. Every value below such as `HA_BASE_URL`, `WEBHOOK_ID` or `/ABSOLUTE/PATH/...` is a placeholder the owner fills in on their own machine, never in git.

## 1. Goal and non-goals

**Goal.** Let an incident that Vigie already raises also trigger a Home Assistant automation (for example a light, a phone notification through the HA app, or a dashboard badge), without giving HA any access to Vigie.

**Non-goals.**

- Vigie stays observe-only: no enforcement, no command sent to the router or to any device, and HA never controls Vigie.
- No change to the pipeline. It keeps `Network=none`, gets no network adapter and no new `VIGIE_DELIVERY_*` setting for transport.
- No MQTT broker, no HA add-on, no custom HA component in H0 or H1.
- No raw DNS history, destination details, MAC or IP addresses in anything sent to HA.

## 2. Architecture (recommended)

The pipeline already writes validated incident messages to a JSON-lines delivery file (`FilePublisher`). A new standalone **`ha_sender`** reads that file and POSTs outward, exactly as the ntfy sender does.

```
pipeline (Network=none) --FilePublisher--> delivery-messages.jsonl --read-only--> ha_sender.py --HTTP(S) POST--> HA webhook
```

| Property | Value |
|---|---|
| Direction | Outbound only. The sender runs on the Vigie host and pushes to HA. HA needs no route to, account on or token for Vigie |
| Transport | HA webhook (an HTTP POST to `HA_BASE_URL/api/webhook/WEBHOOK_ID`), not MQTT |
| Process | Separate oneshot process fired by a timer, standard library only, off by default, not wired into the pipeline (same shape as the ntfy sender) |
| Reads | The delivery file, read-only. It never writes to the pipeline's volumes |
| State | Its own cursor file, separate from the ntfy cursor, so the two senders advance independently |
| Alerting channel | **ntfy remains the counted alert channel.** HA delivery is best-effort convenience: an HTTP 2xx from an HA webhook does not prove an automation ran (see H0 and the canary in H1) |

**Why a webhook and not MQTT.**

| Option | Verdict | Reason |
|---|---|---|
| Webhook (chosen) | Chosen | One secret-URL POST per message; no broker to install, secure or keep alive; webhook triggers are a built-in automation trigger (per HA docs, unverified); fits the existing sender pattern. Weakness: HA likely answers 2xx even when nothing ran (section 5, H0) |
| Token-authenticated HA events API (`/api/events`) | Alternative, not chosen | Per HA docs, unverified, returns real errors for a bad request, but needs a long-lived HA access token. Per HA docs, unverified, such a token is not scoped to one action, so a leak grants broad HA API access. Worse than a webhook id if leaked; choose it only if H0 shows webhooks cannot signal failures usefully |
| MQTT | Rejected for now | Needs a broker both sides trust, broker credentials on the Vigie host, and topic ACLs; adds a long-lived connection and a second secret. Reconsider only if the owner already runs a broker and wants retained state (see H2) |
| HA polling Vigie's API | Rejected as the primary path | Requires HA to reach Vigie and hold a Vigie credential, which inverts the direction this design is built on. Kept only as the optional H2 read path |

## 3. Trust boundaries and threat model

Boundaries: (1) delivery file to sender (local, read-only); (2) sender to HA over the LAN or the owner's chosen path; (3) HA automation to whatever the owner connects (phone, lights).

| Threat | Mitigation |
|---|---|
| Webhook URL leaks (the id in the path is the only access control; per HA docs, unverified, there is no other authentication on a webhook trigger) | The full URL is a secret. It lives in a file outside git, mode 0600, owned by the process uid, regular file, symlinks refused (same private-file rules as the ntfy secret files). It is never printed and never logged, including on error. The owner rotates it by changing the webhook id in the HA automation and the file |
| Secret-URL file is malformed or points somewhere unintended | The sender validates the file before use: scheme per D4, host must be in `allowed_hosts`, path exactly `/api/webhook/<id>` with the id restricted to a conservative charset and length, no userinfo, query or fragment. Errors say only which rule failed (for example "webhook URL invalid: path") and never echo the host, path or id |
| HA logs record unknown or remote webhook ids (per HA docs, unverified, a request to an unknown id may be logged) | Treat HA logs as a place the id can leak: a mistyped or rotated id is logged by HA and a scanner hitting HA may log its guesses. The owner restricts HA log access and rotates the id if it appears in shared logs or support bundles |
| Third-party path (Nabu Casa cloud URL or a tunnel) | The payload and the secret URL then pass through a third party, and a remote path needs `local_only` off (per HA docs, unverified), which widens who can post to the webhook. Not recommended; if chosen (D7) it is a documented, accepted risk and the id must be rotated on any suspicion |
| Replay or sniffing on plain HTTP by a LAN observer | The URL and payload are visible and replayable. Mitigated by HTTPS (D4). `sent_at` and `delivery_id` let the automation recognise a captured request replayed later (same `delivery_id`, old `sent_at`); they do not stop a first delivery. A replay still triggers the automation unless the automation checks them |
| Someone else posts to the webhook and spoofs an alert | Accepted and stated: a leaked URL allows spoofed or replayed triggers. The automation must treat the payload as untrusted display text, never as a command, and must not unlock, disarm or open anything based on it. Restrict the webhook to local sources in HA if the sender is on the LAN (the HA option `local_only`, per HA docs, unverified; confirm the default for the installed version) |
| Sensitive content reaches HA, its logs, history or companion apps | Content is alias plus a relative link only, the same default as ntfy. The label switch is NOT offered for HA (section 6, D3). No addresses, no DNS names, no raw evidence. HA may store the payload in its logbook, recorder database and automation traces (per HA docs, unverified; retention is the owner's HA configuration), so the owner should know the payload is retained there |
| Log leakage from the sender | Log lines never contain the URL, the webhook id, the token, the response body or record text. Errors report a class and an HTTP status only |
| Redirect, downgrade or wrong TLS peer | Redirects are never followed. `allowed_hosts` pins the host NAME, not what it resolves to. TLS verification is never disabled (section 5, H1 TLS). Plain HTTP follows D4 |
| Compromised or malicious HA | Out of scope for detection. HA receives only what Vigie would show in a notification, so the blast radius of a compromised HA is that text |
| Sender compromise | It holds one outbound secret and read access to one file. It has no Vigie credentials and no write access to Vigie state |
| Duplicate triggers after a crash or a pipeline retry | Delivery is at least once in the sender AND upstream: the pipeline's own delivery is at-least-once too. The automation dedupes on `delivery_id` (section 4) |
| A new cursor replays all history into HA | See the first-run rule in H1 |
| HA-side read token (H2 only) | See H2: a Vigie API token with the least scope that works, stored on the HA side, only if H2 is built. Not needed for H0, H1 or H3 |

## 4. Payload

One JSON object per message, built only from the validated fields of the delivery record. Field names are a proposal for H1 review.

| Field | Content |
|---|---|
| `delivery_id` | The record's own id: exactly 32 lowercase hex characters, the first 32 of a sha256 over the incident id, a newline and the kind (`delivery_plan.py:99`). The sender rejects any other shape. The dedupe key. The `open` and `recover` messages of one incident have different ids |
| `sent_at` | The sender's own wall-clock time in UTC, ISO 8601, taken when it sends. It cannot flag a stale backlog (a delayed message is stamped when it is finally sent). It only helps detect a captured HTTP request replayed later (D4). Incident age is not carried in the delivery record; adding it needs a pipeline change and is not proposed |
| `kind` | `open` or `recover` |
| `title` | The validated title, as in the delivery file |
| `body` | The validated body, as in the delivery file |
| `link` | Relative incident link of the form `/ui/#incident=<id>`. NOT a dedupe key: `open` and `recover` share one link. Use it only to replace or update an existing HA notification for the same incident |

The sender does not add a Vigie base URL by default; the owner can set an optional base in the private config so the HA notification opens the UI. That base is an owner-private value like the webhook URL and is never printed.

## 5. Phases

| Phase | Scope | Notes |
|---|---|---|
| H0 | Owner side only, no Vigie code | Measurement, below. Decide the open items in section 9. Output: a table of measured status codes recorded in this PRP |
| H1 | `ha_sender.py` | Modelled on `ntfy_sender.py`; details below |
| H2 | Optional read-only entities | HA shows state (open incident count, per-device status). Notes only here; no code. See below |
| H3 | Sidebar panel or ingress embedding of the Vigie UI | **Deferred** until the owner's HA installation type is known (open decision D1) |
| H4 | Hardening and docs | Review log; a "Home Assistant delivery" section in [monitoring](../monitoring.md); `ha-sender.service` and `ha-sender.timer` templates beside the ntfy ones (placeholders only, same `OnFailure=` placeholder, off by default); the secret-rotation procedure; the multi-sender truncate rule and its helper check (below) |

### H0: measurement before any code

HA's behaviour on a bad request is **per HA docs, unverified**, and the likely answer is that HA returns HTTP 200 and only logs the problem. Everything in H1 that depends on status codes is conditional on this table. Steps, each with a dummy payload only and recorded as status code plus whether anything appeared in the HA log:

1. POST to a correct webhook id with an enabled automation (baseline).
2. POST to a **wrong** id.
3. POST to the id of a **disabled** automation.
4. POST from a source `local_only` should refuse (if the owner has a second network to try from).
5. POST with a malformed body and with an oversized body.
6. If D4 allows plain HTTP, repeat step 1 over HTTP and confirm the sender's TLS rules do not break it.

**A 2xx does not prove delivery.** If steps 2 and 3 return 2xx, the sender cannot learn about a wrong id or a disabled automation from the status code at all, and its 4xx "permanent" class would almost never fire.

**End-to-end canary.** Because the status code may be blind, the automation stamps an `input_datetime` helper with the time of each received message (or of a periodic sender heartbeat message). The owner watches that value, for example on a dashboard card or an HA-side "stale for N hours" check. ntfy stays the counted alert channel; the canary only tells the owner that the HA path has gone quiet. Whether the canary needs an extra `kind` such as `heartbeat` is an H1 review item.

### H1: `ha_sender`

Modelled on the ntfy sender; each item below mirrors a property of [`ntfy_sender.py`](../../deploy/persistent/ntfy_sender.py).

| Aspect | Design |
|---|---|
| Input | The same delivery JSON-lines file; every line validated against the strict schema (kind, link pattern, title and body equal to the writer's templates). A line that fails validation is skipped with a counted warning and never sent |
| Cursor | Its own cursor file (offset, device, inode, hash of the first line), written atomically with mode 0600 after each successful send and each skipped line. Truncated or replaced file restarts from the beginning with a warning |
| Locking | A lock beside the cursor serialises runs of this sender; a second run exits 0. The lock does not coordinate with the ntfy sender, which is why the truncate rule below is needed |
| Delivery semantics | At least once. A crash between a send and the cursor write can repeat one message, and the pipeline's own delivery is at-least-once as well. The automation dedupes on `delivery_id`, never on `link` |
| Outcome classes | 2xx: success, advance the cursor (but see H0: not proof of delivery). 5xx, 408, 429, timeouts and connection errors: **retryable**, bounded backoff within a run budget, cursor unchanged. Other 4xx: **permanent** under the D6 recommendation (stop, cursor not advanced past the record, nonzero exit). If D6 is decided the other way, 400/413/414/422 become a per-record "rejected" class held for a probe |
| Exit codes | Same numbering as the ntfy sender for operator familiarity: 0, 1, 2, 3 (permanent), 4 (retryable or exhausted run budget). **Exit 5 (caught up but a rejected record was skipped) exists only if D6 keeps the probe rule**; under the recommendation it is unused. Final numbering is confirmed in H1 |
| First run | A new cursor starts at offset 0, which would replay every historical message into HA. The config has `start_at_end` (default true): on the first run the sender seeds the cursor at the offset just after the **last complete newline** of the delivery file (not the file size, because the writer may be mid-append; a partial trailing line stays unread and is sent later), with device, inode and first-line hash, and sends nothing. Setting it false is the owner's explicit choice to replay. **Default-true drops everything written before the first enable**: an incident already open then appears in HA only as an orphan `recover` message. That is acceptable because ntfy stays the counted alert channel. **Seeding only when the cursor directory is new:** a missing cursor file also happens when the cursor was deleted after a first run, which would silently drop the backlog. The sender therefore seeds only if the cursor directory did not exist or is empty of any cursor, lock or sender state; otherwise it exits 2 asking the owner to confirm (for example by passing the seed intent explicitly), and any seed logs a warning with the skipped byte count A truncated or replaced delivery file also restarts from the beginning and replays; the sender logs that (as ntfy does) and the owner expects it. Tests: new cursor directory plus an existing file sends nothing and creates the cursor at the last newline, including a file that ends with a partial line (the partial line is sent after it completes); an existing cursor directory without a cursor file exits 2; the seed warning carries the byte count and no record text |
| TLS | ntfy uses the system trust store only (`ntfy_sender.py:768`, `ssl.create_default_context()`), which is wrong for an HA instance with a private CA or a self-signed certificate. `ha_sender` adds an optional `ca_file` (a PEM CA bundle or a pinned server certificate, a private-file-checked path) used to build the SSL context. Verification and hostname checking are never disabled, and there is no "insecure" option. This is new code, not a reuse |
| Hosts and plain HTTP | `allowed_hosts` pins the NAME in the URL, not where it resolves. Plain HTTP is governed by a **separate** key `http_hosts`, empty by default, which must be a subset of `allowed_hosts`; a URL uses `http` only if its host is in `http_hosts`, every other host requires HTTPS. A host in `http_hosts` should be a literal RFC 1918 IPv4 or an IPv6 ULA address (`fc00::/7`), or a name the owner trusts DNS for; the sender does not resolve or classify addresses, so this is the owner's declaration, not a check. The ntfy code does not cover this: its `HOST_RE` (`ntfy_sender.py:63`) rejects IPv6 literals and `_https_url` refuses any non-https scheme, so literal addresses, bracketed IPv6 and an explicit `http` allowance are new validation code with their own tests |
| Redirects | Never followed; a redirect is a permanent failure |
| Logging | Never logs the URL, webhook id, token, response body or record text. The summary line reports counts and the exit code only |
| Config | A JSON file outside git, mode 0600, with absolute paths: delivery file, cursor file, a separate secret file holding the webhook URL. The full key set: `delivery_file`, `cursor_file`, `url_file`, `allowed_hosts`, `http_hosts` (default empty, subset of `allowed_hosts`), `ca_file` (optional), `start_at_end` (default true), `vigie_base_url` (optional, private), `timeout_seconds`, `max_batch`. Unknown keys are rejected, and `http_hosts` outside `allowed_hosts` is a config error (exit 2). Secret files must be regular files, mode 0600 or 0400, owned by the effective uid, symlinks refused, size bounded |
| Runtime | Standard library only; oneshot user unit plus timer, run through `podman unshare` for the same file-ownership reason as ntfy (see [monitoring](../monitoring.md)). Off by default; owner actions only |
| Tests | A unit test file modelled on `deploy/tests/test_ntfy_sender.py`: status classification, cursor behaviour including the first-run seed, secret-file permissions and URL validation, `ca_file` handling, `http_hosts` subset rule, label fail-closed, 425 parity, redirect refusal, and a log-capture test asserting that no URL, id, host or record text appears |

**Differences from the ntfy sender (explicit, so H1 is not assumed to be a copy).**

| Behaviour | ntfy sender | `ha_sender` |
|---|---|---|
| Success | Only HTTP 200 (`ntfy_sender.py:612`) | Any 2xx (webhooks may answer other 2xx codes; confirm in H0) |
| Retryable | 408, 425, 429, 5xx (`:61`, `:614`) | 408, 429, 5xx, plus 425 if H0 or review keeps parity |
| Held for a probe | 400, 413, 414, 422 (`:62`), using `MIN_BATCH = 2` | Not used under the D6 recommendation; every other 4xx is permanent |
| Trust | System store only | System store plus optional `ca_file` |
| Scheme | https only | https; http only by D4 |
| First run | Starts at offset 0 | Seeds at end of file by default |
| Auth | Optional bearer token | None; the URL is the secret |

**Two senders, one delivery file: the truncate rule.** The current instructions in [monitoring](../monitoring.md) (lines 627-635) assume one sender. With ntfy and `ha_sender` both enabled they must become: stop BOTH timers, and truncate only when EVERY enabled sender's cursor offset equals the delivery file size, because truncating while either sender is behind drops its pending alerts. H4 updates those lines and ships a helper check (a small read-only script that prints each sender's cursor offset against the file size and exits nonzero unless all enabled senders are caught up) so the owner does not compare numbers by hand.

### H2: read-only entities (notes, no code)

An optional second path gives HA state it can display, rather than events it can react to.

- **No such Vigie endpoint exists yet.** H2 would need a new, read-only integration entity list (open incident count, per-device status) designed and reviewed separately.
- Polling would use a Vigie API token. The token scopes in `server/src/vigie_api/tokens.py:15` include `integration` and `read-only`; which of them (or a new narrower one) fits is undecided and must be the least that works, never `app`, `app rules:write` or `service`. That token is stored **on the HA side**, not on the Vigie host. This is the only phase where HA holds a Vigie credential; it inverts the H1 direction and needs its own review.
- Per-device entities are **opt-in**, one device at a time, so that adding Vigie to HA does not publish the whole device inventory into the HA entity registry and recorder by default.
- Entity names and attributes follow the same content rule as section 4: alias by default, no addresses.
- No code is proposed here. The API endpoint, authentication scope and polling interval are undecided and belong in a separate review.

### H3: sidebar or ingress (deferred)

Embedding the Vigie UI in HA depends on the installation type (per HA docs, unverified: add-ons and ingress are available on some installation types and not on others). Because that is unknown, this phase is listed but not designed. See D1.

## 6. Data and privacy

| Data | Sent to HA by default | Opt-in |
|---|---|---|
| Device alias | Yes (in title and body, as in the delivery file) | |
| Validated device name | No | Not offered for HA (see below) |
| Relative incident link | Yes | |
| Vigie base URL | No | Optional private config value |
| IP, MAC, DNS names, ports, process paths, raw evidence | Never | Never |
| Per-device entities (H2) | No | Per device |

`VIGIE_DELIVERY_INCLUDE_LABEL` is a pipeline-wide switch: it changes what the pipeline writes to the delivery file, so it affects every sender that reads it. [monitoring](../monitoring.md) (lines 235-236) describes it as meant for local-only publishers such as the FilePublisher, so enabling it for a network sender is an accepted pipeline-wide risk, not an HA feature. This PRP therefore does not offer it as an HA option. If the owner enables it anyway for another reason, `ha_sender` fails closed: the record carries no device id, so it cannot rewrite a label to the alias, and the ntfy label charset accepts any ordinary name. The sender therefore skips (counted warning, never sent, no record text logged) any record whose label is not exactly the alias pattern `Device [A-Za-z]{6}`, with a test that a named-device record is skipped. A per-sender label policy would need a pipeline change and is not proposed.

## 7. Test plan

| Area | Check |
|---|---|
| Classification | 200-299 success; 400/401/403/404 permanent; 408/429/5xx retryable; 425 retryable if parity with ntfy is kept (a test pins whichever is decided); timeout and connection reset retryable; redirect permanent |
| First-run seed | New directory sends nothing and seeds at the last newline (partial trailing line case); existing directory without cursor exits 2; seed warning logs the byte count |
| `ca_file` and TLS | A private CA or pinned certificate verifies; a wrong certificate fails; no code path disables verification |
| URL validation | Scheme, host in `allowed_hosts`, `http` only for `http_hosts`, path `/api/webhook/<id>`, id charset; errors never echo host, path or id |
| Label | A record whose label is not `Device [A-Za-z]{6}` is skipped and counted; `delivery_id` not 32 lowercase hex is rejected |
| Cursor | Resume after a crash; truncated, replaced and partial-line files; independent from the ntfy cursor |
| Secrets | Permission, ownership, symlink and size checks on the URL file; a log-capture test proving the URL, id and record text never appear, including on exceptions |
| Content | Only validated fields are posted; an invalid record is skipped and never sent |
| End to end (H0/H1) | Against a test HA instance or a local stub server, with dummy payloads only |

## 8. Risks

| Risk | Mitigation / note |
|---|---|
| Webhook URL treated like a password but stored carelessly | 0600 file outside git, never printed, rotation procedure in H4 |
| HA recorder, logbook and traces keep incident text (per HA docs, unverified) | Minimal default content (alias and relative link); the owner decides HA retention |
| Two senders (ntfy and HA) double the operational surface | Independent cursors and units; each is off by default |
| Home network path to HA is plain HTTP | D4: HTTPS by default, plain HTTP only for hosts the owner lists in `http_hosts`; replay mitigated by `sent_at` and `delivery_id` |
| HA silently accepts and drops messages (2xx with no action) | H0 measurement; the canary; ntfy stays the counted alert channel |
| Two senders on one delivery file | Independent cursors; the all-senders truncate rule and helper check (H4) |
| HA type unknown | H3 deferred; H0 to H2 do not depend on it |

## 9. Open decisions

| # | Decision | Recommendation | State |
|---|---|---|---|
| D1 | Which HA installation type is in use (OS, supervised, container, core)? Drives H3 and whether add-ons or ingress are possible | None until known | **Open** |
| D2 | Transport: webhook rather than MQTT | Webhook | Proposed |
| D3 | Content: alias plus relative link only, the same default as ntfy. The label switch is pipeline-wide and meant for local-only publishers, so it is not an HA option | Same default as ntfy | Proposed |
| D4 | Plain HTTP allowed for a private LAN HA address (an RFC 1918 or ULA literal, or a name, listed in `http_hosts`), or HTTPS required, implemented as the separate `http_hosts` key (empty by default, subset of `allowed_hosts`). Plain HTTP exposes the secret URL and payload to a LAN observer, who can replay them | HTTPS required (with `ca_file` for a private CA) unless the owner lists the host in `http_hosts` | **Open** |
| D5 | Is H2 (read path, read-only token, per-device entities) wanted at all | Defer until H1 has run for a while | **Open** |
| D6 | On a 4xx, skip the record after a good probe (ntfy rule, exit 5) or stop on every other 4xx. H0 may show that HA returns 2xx for the wrong-id and disabled cases, which would make the 4xx class nearly unreachable | Stop on every other 4xx, unless H0 shows a per-record 4xx exists | **Open** (decided after H0 and in H1 review) |
| D7 | Does the sender reach HA directly on the LAN, or through a reverse proxy, tunnel or cloud URL (a third party sees the URL and payload, and `local_only` must be off) | Direct on the LAN; the owner states the path; no real hostnames go into the repository | **Open** |

## 10. Review log

| Round | Reviewer | Findings and dispositions |
|---|---|---|
| 1 | Opus critic | Verdict REVISE: 3 HIGH (webhook 4xx claim likely false, truncate rule with two senders, first-run replay), 4 MEDIUM (TLS trust and private-host definition, pipeline-wide label switch, H1 versus D6 contradiction and missing ntfy differences, missing threat rows, secret-URL validation), 4 LOW (replay and `sent_at`, dedupe key, unlabelled HA claims, H2 token scope); 3 + 4 + 4 = 11. All addressed in the second commit (sections 2, 3, 4, 5, 6, 8, 9) |
| 2 | Opus critic | Verdict REVISE: 1 MEDIUM on `http_hosts` and the full config key set; MEDIUM items on first-run seeding (orphan `recover`, deleted cursor, partial trailing line, `sent_at` limits); LOW items on label fail-closed, `delivery_id` shape and citation, test plan and unverified-claim labels, review-log counts. All addressed in the third commit |
| 2 | Codex challenge | Clean |
| 1 | Codex challenge | Found nothing |
| 2 | Opus security review | to be filled before merge |
