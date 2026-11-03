# PRP-004: Home Assistant integration (outbound webhook sender)

Status: **Design proposal. Nothing is built.** No owner decision below is confirmed yet; the open decisions are listed in section 9.
License: AGPL-3.0-or-later. Branch: `docs/prp-004-home-assistant`.

Relationship to other docs: [PRP-001](001-vigie-architecture.md) is the architecture this extends. [PRP-003](003-endpoint-events.md) is the format model for this document (phases, threat table, owner decisions). The delivery design this reuses is the ntfy sender: [`deploy/persistent/ntfy_sender.py`](../../deploy/persistent/ntfy_sender.py) and "Incident delivery to ntfy" in [monitoring](../monitoring.md). The delivery file is written by [`delivery_publish.py`](../../server/src/vigie_pipeline/delivery_publish.py); the deployment note is in [deploy](../deploy.md).

Labelling: statements about Home Assistant (HA) behaviour are **per the HA documentation, not verified by Vigie**. Statements about this repository were read in the files linked above.

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

**Why a webhook and not MQTT.**

| Option | Verdict | Reason |
|---|---|---|
| Webhook (chosen) | Chosen | One authenticated-by-secret POST per message; no broker to install, secure or keep alive; HA webhook triggers are a built-in automation trigger (per HA docs); fits the existing sender pattern and its retry classification |
| MQTT | Rejected for now | Needs a broker both sides trust, broker credentials on the Vigie host, and topic ACLs; adds a long-lived connection and a second secret. Reconsider only if the owner already runs a broker and wants retained state (see H2) |
| HA polling Vigie's API | Rejected as the primary path | Requires HA to reach Vigie and hold a Vigie credential, which inverts the direction this design is built on. Kept only as the optional H2 read path |

## 3. Trust boundaries and threat model

Boundaries: (1) delivery file to sender (local, read-only); (2) sender to HA over the LAN or the owner's chosen path; (3) HA automation to whatever the owner connects (phone, lights).

| Threat | Mitigation |
|---|---|
| Webhook URL leaks (the id in the path is the only access control; per HA docs there is no other authentication on a webhook trigger) | The full URL is a secret. It lives in a config file outside git, mode 0600, owned by the process uid, regular file, symlinks refused (same private-file rules as the ntfy secret files). It is never printed and never logged, including on error. The owner rotates it by changing the webhook id in the HA automation and the file |
| Someone else posts to the webhook and spoofs an alert | Accepted and stated: a leaked URL allows spoofed or replayed triggers. The automation must treat the payload as untrusted display text, never as a command, and must not unlock, disarm or open anything based on it. Restrict the webhook to local sources in HA if the sender is on the LAN (the HA option `local_only`, per HA docs; confirm the default for the installed version) |
| Sensitive content reaches HA, its logs, history or companion apps | Content is alias plus a relative link only, the same default as ntfy. A validated device name is sent only if the owner sets `VIGIE_DELIVERY_INCLUDE_LABEL` (opt-in, off by default; see [monitoring](../monitoring.md)). No addresses, no DNS names, no raw evidence. HA may store the payload in its logbook and recorder database, so the owner should know the payload is retained there |
| Log leakage from the sender | Log lines never contain the URL, the webhook id, the token, the response body or record text. Errors report a class and an HTTP status only |
| Redirect or downgrade to another host | Redirects are never followed. `allowed_hosts` pins the destination host. Plain HTTP is allowed only for an explicitly configured private host; the default is HTTPS (see decision D4) |
| Compromised or malicious HA | Out of scope for detection. HA receives only what Vigie would show in a notification, so the blast radius of a compromised HA is that text |
| Sender compromise | It holds one outbound secret and read access to one file. It has no Vigie credentials and no write access to Vigie state |
| Duplicate triggers after a crash | Delivery is at least once (see H1). The automation should be idempotent, for example a notification keyed by the incident link |
| HA read token (H2 only) | Read-only, long-lived token, stored like the webhook URL, only if H2 polling is built. Not needed for H0, H1 or H3 |

## 4. Payload

One JSON object per message, built only from the validated fields of the delivery record. Field names are a proposal for H1 review.

| Field | Content |
|---|---|
| `delivery_id` | The record's own id (supports automation-side dedupe) |
| `kind` | `open` or `recover` |
| `title` | The validated title, as in the delivery file |
| `body` | The validated body, as in the delivery file |
| `link` | Relative incident link of the form `/ui/#incident=<id>` |

The sender does not add a Vigie base URL by default; the owner can set an optional base in the private config so the HA notification opens the UI. That base is an owner-private value like the webhook URL and is never printed.

## 5. Phases

| Phase | Scope | Notes |
|---|---|---|
| H0 | Owner side only, no Vigie code | Create an HA automation with a webhook trigger. Test with a hand-sent POST of a fixed dummy payload. Decide the open items in section 9. Output: the payload shape accepted by the automation, recorded in this PRP |
| H1 | `ha_sender.py` | Modelled on `ntfy_sender.py`; details below |
| H2 | Optional read-only entities | HA shows state (open incident count, per-device status). Notes only here; no code. See below |
| H3 | Sidebar panel or ingress embedding of the Vigie UI | **Deferred** until the owner's HA installation type is known (open decision D1) |
| H4 | Hardening and docs | Review log, a "Home Assistant delivery" section in [monitoring](../monitoring.md), a unit and timer template, failure alerting via `OnFailure=`, and the secret-rotation procedure |

### H1: `ha_sender`

Modelled on the ntfy sender; each item below mirrors a property of [`ntfy_sender.py`](../../deploy/persistent/ntfy_sender.py).

| Aspect | Design |
|---|---|
| Input | The same delivery JSON-lines file; every line validated against the strict schema (kind, link pattern, title and body equal to the writer's templates). A line that fails validation is skipped with a counted warning and never sent |
| Cursor | Its own cursor file (offset, device, inode, hash of the first line), written atomically with mode 0600 after each successful send and each skipped line. Truncated or replaced file restarts from the beginning with a warning |
| Locking | A lock beside the cursor serialises runs; a second run exits 0 |
| Delivery semantics | At least once. A crash between a send and the cursor write can repeat one message. The `delivery_id` in the payload lets the automation dedupe |
| Outcome classes | 2xx: success, advance the cursor. 4xx: **permanent** (the URL, id or HA config is wrong), stop, cursor not advanced past the record, nonzero exit. 5xx, 408, 429, timeouts and connection errors: **retryable**, bounded backoff within a run budget, cursor unchanged |
| Per-record rejection | The ntfy sender skips a record the server rejects after a good probe of its successor. For HA, whether to reuse that rule or treat every 4xx as permanent is an open item for H1 review (decision D6) |
| Exit codes | Same numbering as the ntfy sender for operator familiarity: 0 caught up, 1 internal error, 2 config/cursor/secret-file error, 3 permanent failure, 4 retryable failure or exhausted run budget, 5 caught up but a rejected record was skipped. Final numbering is confirmed in H1 |
| Redirects | Never followed; a redirect is a permanent failure |
| Logging | Never logs the URL, webhook id, token, response body or record text. The summary line reports counts and the exit code only |
| Config | A JSON file outside git, mode 0600, with absolute paths: delivery file, cursor file, a separate secret file holding the webhook URL, `allowed_hosts`, timeout, batch size. Unknown keys rejected. Secret files must be regular files, mode 0600 or 0400, owned by the effective uid, symlinks refused, size bounded |
| Runtime | Standard library only; oneshot user unit plus timer, run through `podman unshare` for the same file-ownership reason as ntfy (see [monitoring](../monitoring.md)). Off by default; owner actions only |
| Tests | A unit test file modelled on `deploy/tests/test_ntfy_sender.py`: status classification, cursor behaviour, secret-file permissions, redirect refusal, and a log-capture test asserting that no URL, id or record text appears |

### H2: read-only entities (notes, no code)

An optional second path gives HA state it can display, rather than events it can react to.

- HA would poll a small read-only list: the integration entity list (open incident count, per-device status). Polling uses a **read-only** HA-side token for Vigie's API, which exists only if H2 is built. This is the only phase where HA holds a Vigie credential, and it inverts the H1 direction, so it needs its own review.
- Per-device entities are **opt-in**, one device at a time, so that adding Vigie to HA does not publish the whole device inventory into the HA entity registry and recorder by default.
- Entity names and attributes follow the same content rule as section 4: alias by default, no addresses.
- No code is proposed here. The API endpoint, authentication scope and polling interval are undecided and belong in a separate review.

### H3: sidebar or ingress (deferred)

Embedding the Vigie UI in HA depends on the installation type (for example a supervised or OS install can host add-ons and ingress, while a container install cannot). Because that is unknown, this phase is listed but not designed. See D1.

## 6. Data and privacy

| Data | Sent to HA by default | Opt-in |
|---|---|---|
| Device alias | Yes (in title and body, as in the delivery file) | |
| Validated device name | No | `VIGIE_DELIVERY_INCLUDE_LABEL` (pipeline setting, shared with ntfy) |
| Relative incident link | Yes | |
| Vigie base URL | No | Optional private config value |
| IP, MAC, DNS names, ports, process paths, raw evidence | Never | Never |
| Per-device entities (H2) | No | Per device |

`VIGIE_DELIVERY_INCLUDE_LABEL` is a pipeline-wide switch: it changes what the pipeline writes to the delivery file, so it affects ntfy and HA together. A per-sender label policy would need a pipeline change and is not proposed.

## 7. Test plan

| Area | Check |
|---|---|
| Classification | 200-299 success; 400/401/403/404 permanent; 408/429/5xx retryable; timeout and connection reset retryable; redirect permanent |
| Cursor | Resume after a crash; truncated, replaced and partial-line files; independent from the ntfy cursor |
| Secrets | Permission, ownership, symlink and size checks on the URL file; a log-capture test proving the URL, id and record text never appear, including on exceptions |
| Content | Only validated fields are posted; an invalid record is skipped and never sent |
| End to end (H0/H1) | Against a test HA instance or a local stub server, with dummy payloads only |

## 8. Risks

| Risk | Mitigation / note |
|---|---|
| Webhook URL treated like a password but stored carelessly | 0600 file outside git, never printed, rotation procedure in H4 |
| HA recorder keeps incident text indefinitely | Minimal default content (alias and relative link); owner decides HA retention |
| Two senders (ntfy and HA) double the operational surface | Independent cursors and units; each is off by default |
| Home network path to HA is plain HTTP | D4: HTTPS by default, plain HTTP only for an explicitly configured private host |
| HA type unknown | H3 deferred; H0 to H2 do not depend on it |

## 9. Open decisions

| # | Decision | Recommendation | State |
|---|---|---|---|
| D1 | Which HA installation type is in use (OS, supervised, container, core)? Drives H3 and whether add-ons or ingress are possible | None until known | **Open** |
| D2 | Transport: webhook rather than MQTT | Webhook | Proposed |
| D3 | Content: alias plus relative link only; `VIGIE_DELIVERY_INCLUDE_LABEL` opt-in | Same default as ntfy | Proposed |
| D4 | Plain HTTP allowed for a private LAN HA address, or HTTPS required | HTTPS required unless the owner lists a private host explicitly | **Open** |
| D5 | Is H2 (read path, read-only token, per-device entities) wanted at all | Defer until H1 has run for a while | **Open** |
| D6 | On a 4xx, skip the record after a good probe (ntfy rule) or stop on every 4xx | Stop on every 4xx, because for a webhook a 4xx almost always means a wrong id or a disabled automation, not one bad record | **Open** (decided in H1 review) |
| D7 | Does HA reach the sender's network path directly, or through a reverse proxy or tunnel the owner already runs | Owner states the path; no real hostnames go into the repository | **Open** |

## 10. Review log

| Round | Reviewer | Findings and dispositions |
|---|---|---|
| 1 | to be filled | An Opus review and a Codex challenge are required before merge per the project review loop |
