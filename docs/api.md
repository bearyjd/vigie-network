# Human identity decisions

The API is the sole writer of human intent in `overrides.db`. It opens `inventory.db`
read-only. The pipeline opens `overrides.db` read-only and writes derived inventory state.
These ownership boundaries also apply to accepting suggestions and clearing vetoes.

All endpoints use the existing response envelope and bearer authentication. The generated
[`api/openapi.yaml`](../api/openapi.yaml) describes request bodies and error responses.
No generated TypeScript client exists in `api/`.

| Method | Endpoint | Human action |
|---|---|---|
| POST | `/suggestions/{suggestion_id}/accept` | Apply a label/group decision or confirm a merge; `remember: true` also approves a rule |
| POST | `/suggestions/{suggestion_id}/reject` | Reject a suggestion |
| POST | `/identity/merges/{merge_id}/undo` | Revoke a confirmed merge |
| GET | `/identity/rules` | Page through rules, including expiration/revocation and active state |
| POST | `/identity/rules` | Approve a standing rule |
| DELETE | `/identity/rules/{rule_id}` | Revoke a standing rule |
| POST | `/identity/candidates/{candidate_id}/clear-veto` | Request one veto clearance |

Write bodies carry `expected_versions: {"device-id": 3, ...}` for exactly the involved devices.
For a single device, `expected_version: 3` is also accepted. Supply exactly one form. Versions
come from `GET /devices/{id}` detail's `identity_override_version`, keyed by its `requested_id`;
a device with no own override has version 0. This also exposes an alias's own version for merge
undo. The effective `override_version` and ETag continue to describe the canonical device and
are used for PATCH. Rule creation also requires `device_id` and `signature`, and accepts
`expires_at`. For example:

```json
{
  "device_id": "device-id",
  "expected_version": 0,
  "signature": {"opt55": "1,3,6", "opt60": "vendor", "hostname": "phone"}
}
```

Optional `X-Request-ID` is bounded plain ASCII. Reusing it for the same action, target, principal,
and body returns the recorded result; changing the body returns 409. Without a request id, the
body identifies retries. Accepted/rejected suggestions and completed undo operations also remain
idempotent across new request ids. Use the returned new device versions for a later action.

## Rules and human approval

Rule creation and revocation require the control app's explicit `rules:write` privilege.
Integration/service and read-only tokens cannot approve rules. The principal recorded in
`created_by` and the audit log remains `app:<token_id>`. The control app is responsible for
obtaining human approval: person identities and owner decision D6 remain unresolved.
Issue that control-app token with `python -m vigie_api tokens create --rules-write`.

A signature requires opt55 and opt60 and at least one hostname or mDNS name. Every supplied
field is validated; a malformed optional field rejects the whole rule. Names use the pipeline's
Unicode `fold()` before storage, and validation shares the pipeline rule parser. Rule expiration
uses `expires_at`, defaulting to 180 days; revocation records a timestamp and retains history.

`GET /identity/rules` uses keyset pagination ordered by `(created_at, id)`. `limit` defaults
to 50 and accepts 1–200; pass the opaque `page.next_cursor` back as `cursor`. A null cursor
means the history is exhausted. Revoked and expired rules remain in this paged history.
Malformed cursors return an enveloped 400; invalid limits return an enveloped 422.

Rules may be created for any group. Automatic rule attachment still requires the target to have
an explicit group whose `auto_inherit` is 1. In other groups the pipeline requests confirmation;
creating a rule does not bypass that gate. Revoking or expiring a rule does not detach a MAC
that was already attached.
After a merge, revoking an older rule uses the canonical target's current override version.
Retiring its target does not prevent revocation.

## Suggestions, merges, and undo

Acceptance checks both the caller's device versions and the suggestion's stored basis under
one overrides write transaction. Expired suggestions, retired/orphaned devices, aliases, and
merge candidates outside `open`/`suggested` cannot be accepted. Merge acceptance checks current
inventory activity and components in read transactions before acquiring the overrides writer
lock, then revalidates the exact links and device versions with indexed lookups under the lock.
Oversized components, observation/activity inputs, or alias flattening return 409
(`merge_too_large`, requiring an operator) before any mutation.
The defaults in API `config.py` are 256 combined component IDs (`MAX_MERGE_ALIASES`),
1024 observations (`MAX_MERGE_OBSERVATIONS`), 8192 activity rows
(`MAX_MERGE_ACTIVITY_ROWS`), and 256 link writes (`MAX_MERGE_FLATTEN_WRITES`).
Operators can set the corresponding `VIGIE_API_MAX_MERGE_*` environment variables.
Activity overlap is checked in both component directions, so a short interval fully contained
in its peer's activity cannot pass by choosing the merge direction. Canonical write lookups use
at most 33 primary-key link reads; cycles and chains beyond 32 links return 409 without mutation.

Merge acceptance records one identity link, merge history, the suggestion decision, version
increments, and an audit entry together. Repeating an accepted request returns its recorded
result without another decision or link. Rejection records a decision without changing device
classification or trust. Undo revokes the link and retains history; repeating an undo is a no-op.
Device versions protect undo against intervening human changes.
Remembered-rule approval includes the complete inserted rule in the same transaction's audit
entry, including signature, expiry, target group, and creator.
Undo also revokes a rule created by that merge's `remember: true` approval, so it requires
`rules:write` when it revokes that rule. Independently created rules remain separate approvals.

## Clearing a veto

Clearing records an audited `candidate_decisions` intent in `overrides.db`, keyed by candidate
id and its exact ordered device pair. It never updates inventory from the API. The next pipeline
pass consumes that intent once, marks the matching veto `cleared` in inventory, and performs
a fresh compute/apply cycle. A clearance alone never attaches a MAC, and current overlap still
blocks attachment and establishes a fresh sticky veto. That veto survives evidence retention;
another audited clearance is required. A consumed clearance cannot clear any later veto again.
An ordinary dismissed suggestion keeps its existing sticky semantics.

Sticky vetoes can name historical merged aliases. To clear one, `expected_versions` must cover
the union of its exact two endpoints and their current canonical devices (at most four distinct
IDs). Fetch `GET /devices/{id}` for each endpoint, follow `merged_into` when present, and read
each requested ID's `identity_override_version`. Canonical versions cannot replace an alias's
own version. Missing or retired canonical devices, missing historical endpoints, cycles and
overlong link chains fail closed. A retired historical alias is allowed when its canonical
device remains live. The intent retains the original ordered candidate pair; all supplied
device versions advance in the same audited transaction and return in `data.versions`.
The pipeline still checks current rules, groups, identity state and overlap before attachment.

## Write costs and safety

Each successful human mutation and its audit entry commit together. New writes use optimistic
device versions; stale versions return 409 without a write. Idempotent retries do not create
new audit rows. Request ids correlate audit entries without including bearer credentials.
The existing body-size cap and per-token rate limiter apply to every new write endpoint.

Reads, token verification, failed requests, and idempotent retries do not stamp tokens or update
counters in SQLite. `identity_version.version` advances in the same transaction as
attach-relevant changes: rules, links, candidate/clear-veto decisions, suggestion decisions,
device group changes, and group `auto_inherit` changes. The pipeline reads it in its snapshot
and compares it immediately before each attach. It also checks the schema version to fail
closed on concurrent schema changes. A relevant write drops remaining attaches for
that pass; the next pass recomputes. Repeated relevant writes can keep delaying attachment.
Token lifecycle, audit/receipt/history-only writes, and device `name`, `owner`, `type`, version
and update metadata alone are irrelevant to attach authorization and do not delay attaches.
Inventory `identity_state` is checked separately under the pipeline lock; the API exposes no
override for it. Old overrides schemas without the version table retain the conservative
`PRAGMA data_version` fallback, where any commit delays the pass's remaining attaches.

The write-path policy test enumerates every SQL mutation in `vigie_api/*writes*.py`.
Its explicit irrelevant-table allowlist is `audit_log` (audit history), `api_write_receipts`
(retry receipts), and `identity_merges` (undo history; live authorization resides in links,
rules, and decisions). Label-only `device_overrides` writes are excluded by column-sensitive
triggers. Token writes in `tokens.py` are also irrelevant. Changes to this policy require an
explicit classification in the test; table triggers ensure relevant bumps share the mutation's
transaction, including direct group and `auto_inherit` edits.

## Accepted residual risk

- **Cross-database acceptance race.** Inventory and overrides are separate databases. The API's
  read-only inventory mounts cannot take a cross-process lock spanning inventory checks and
  the overrides commit. A merge acceptance can therefore rest on inventory checks that the
  pipeline has since made stale. The pipeline revalidates on its next pass and flags conflicts;
  acceptance does not provide a cross-database atomic snapshot through commit.
- **Attach availability.** Relevant writes delay attaches by one pass; irrelevant writes do
  not. Sustained relevant changes can keep invalidating plans despite per-token rate limits.


## Last observed address

Device list and detail responses include nullable `last_observed_ip` and
`last_observed_ip_at`. They report the latest valid source-address association
from DHCP lease or neighbour evidence for the identity's MACs, including its
currently merged members. `last_observed_ip_at` is the collector batch window
end of the snapshot that most recently *reported* the pairing. The collector
sends lease and neighbour changes as deltas, so it is not "last seen at this
address", lease expiry, packet arrival time, or server receipt time. This
historical observation does not guarantee the device's current address. An
address never creates an identity link or changes a human label.

IPv4 and IPv6 are supported. IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are
normalised to IPv4 before filtering and storage. Excluded classes: unparseable
or scoped (`%zone`) spellings, unspecified (`0.0.0.0`, `::`), the IPv4 `0.0.0.0/8`
block, multicast, loopback, link-local (`169.254.0.0/16`, `fe80::/10`), and
the IPv4 reserved `240.0.0.0/4` block, which includes limited broadcast
`255.255.255.255`. Observations stamped more than 300 s after the batch was
received (collector clock skew) are excluded. Older stamps are accepted for
any spool age the ingest endpoint accepts, because the upsert is monotonic: a
late batch can never replace a newer observation. The newest sensor
stamp wins; equal stamps prefer lease evidence, then the lexically greatest
canonical address (and MAC for an otherwise equal identity-level tie). This is a
deterministic presentation choice, not proof of address ownership.

Caveats. The same address can be reported for several MACs after a DHCP
reassignment or a duplicate address; the previous holder keeps showing it until
newer evidence for that MAC arrives. A collector whose clock runs up to 300 s
fast can out-stamp a correct collector's newer pairing. Neither case is
resolved by the server.

Visibility. Every valid token scope (app, service, integration, read-only)
that can read `/devices` sees these fields; there is no per-field gating. No
IP addresses were exposed by the API before this field was added. Treat any
token that can read devices as allowed to see local and global addresses.

Incremental sync. `updated_at` and `updated_since` do not move when only a
merged member MAC's address changes (they follow the canonical device's own row
and overrides). Clients that need address changes should refresh the pages they
display rather than rely on `updated_since` alone.

Pipeline schema 10 retains one latest association per observed MAC. It does not
replay processed batches or backfill old raw data. Fields remain null until new
qualifying lease/neighbour evidence arrives; an API reading an older pipeline
schema also returns null. Merge and undo recompute the view from current member
MACs. Device filtering and pagination are unchanged, with one indexed address
query scoped to each returned page. Existing clients can ignore the additive
fields; terminal viewers should use `.get` for compatibility with older APIs.

## Incidents and review lifecycle

Monitoring incidents (`GET /incidents`, `GET /incidents/{id}?collector_id=`) carry two independent axes.
The pipeline alone owns `state` (`open`, `resolved`, `superseded`). Humans own `review`, an overlay kept
in `overrides.db`; the API never writes `inventory.db` and the pipeline never reads decisions.
`review` is `null` or `{status, snooze_until, version, decided_by, decided_at}` (`decided_by` is `app`;
the token id is not exposed). `attention` is derived: true only while `state` is `open` and no decision
covers it. `acknowledged` and `expected` cover it indefinitely; `snoozed` covers it strictly before
`snooze_until`, after which the incident returns to attention (the decision and its version are kept).
A snooze on an incident that later resolves stays as history with `attention` false. `GET /incidents`
also accepts `state=open|resolved|superseded`. There is no filter on review or attention.

Actions are `POST /incidents/{incident_id}/{action}?collector_id=...` with action `acknowledge`,
`snooze`, `mark-expected` or `clear` (removes the decision, which un-snoozes; a tombstone row keeps the version). Any status can move to
any other. The body is strict (unknown fields are 422; there is no free-text note):
`{"expected_version": n}`, plus `"until"` for snooze. `expected_version` is the incident's own decision
version: 0 when it has never had one, +1 on every write including `clear` (it never goes backwards). A stale value is
`409 version_conflict`, whose error body carries `current_version`. Every incident read (list and
detail) has `decision_version`: send it as `expected_version`. It stays above 0 after `clear`, when
`review` is null. It is unrelated to the device `identity_override_version`.

- `until`: RFC 3339 UTC (`Z` or `+00:00`, whole seconds), from 60 seconds to the cap after now. The cap
  is 7 days, configurable with `VIGIE_API_INCIDENT_SNOOZE_MAX_S` (at least 120). Anything else is
  `422 invalid_until`. The window is judged when a write is applied, so a replay of an accepted
  `X-Request-ID` request still succeeds after time has passed.
- Allowed on `open`, `resolved` and `superseded`: acknowledge, mark-expected, clear. Snooze needs an open
  incident (`409 incident_not_open`). `clear` with nothing to clear is `409 no_decision`.
- Scopes: `app` and `app rules:write` tokens only; `read-only`, `service` and `integration` get `403`.
  The usual per-token rate limit and body limit apply (`429`, `413`).
- Errors: `401`, `403 forbidden`, `404 incident_not_found` (also for another collector's incident),
  `409 version_conflict | idempotency_conflict | incident_not_open | no_decision`, `422`, `503`.
- Idempotency: only an explicit `X-Request-ID` replays: the first result for an identical body, and
  `409 idempotency_conflict` for a different one. Without it every call is applied or refused on its
  `expected_version` alone, so a stale retry is always `409 version_conflict`, never a replay. The
  incident must belong to `collector_id` (else 404) before any replay is served. The receipt key
  includes the action and incident, so reusing one request id for another action or incident is an
  independent request, not a conflict. A non-writer token gets 403 before the body is validated.
- Audit: `monitoring.incident.acknowledge | snooze | mark_expected | clear`, target the incident id,
  with the before/after review and the copied incident identity. `GET /events` shows these with
  `device_id: null` and the incident id in the summary.
- Retention: only the current decision is stored (history is in the audit log). A recurrence is a new
  incident with a new id, so a decision never carries over to it. Decision rows of incidents the pipeline
  has pruned are invisible, and (and cleared tombstones) are deleted (at most 100 per write, once older than 120 days).
- `expected` is a per-incident label, not a suppression. It does not touch baselines, the suspicious
  hours the detector tracks, or later incidents.

## Evidence pack

`POST /devices/{device_id}/evidence-pack` exports what Vigie knows about one device as a single document
for outside analysis. It is evidence with confidence, not a verdict. The response is the document itself (not the
`{ok, data}` envelope), sent as `Content-Disposition: attachment` with `Cache-Control: no-store`.

- Scopes: `app` and `app rules:write` only; `read-only`, `service` and `integration` get `403`, before the body is
  read (a malformed or non-UTF-8 body from such a token is still `403`; anonymous is `401`). The per-token rate
  limit and request body limit apply (`429`, `413`). The GUI stays read-only (GET only); an export button is future work.
- Body (strict, unknown fields are `422`; an absent body means the defaults):
  `{"redaction": "pseudonymized" | "minimal" | "full", "format": "json" | "markdown", "confirm_full": bool}`.
  `full` needs `confirm_full: true` (`422 confirmation_required`); an unknown level is `422 invalid_redaction`.
- Errors: `401`, `403 forbidden`, `404 not_found`, `413` (request body, or `pack_too_large` if a pack cannot be cut under
  256 KiB), `422`, `429`, `503 inventory_unavailable | audit_unavailable`. A merged alias resolves to the canonical
  device exactly like `GET /devices/{id}`; `subject.requested_ref` records the alias.
- Levels. `pseudonymized` (default): MACs become `mac-<8 hex>` (OUI kept only for non-randomized MACs), hostnames,
  mDNS names and the owner-set name/owner become `host-<8 hex>`, device/collector/incident ids `dev-`/`col-`/`inc-`,
  IP addresses only their class (`private-v4`, `ula`, `global-v6`, ...); DHCP option 55, bounded option 60,
  service kinds, rule ids and timestamps stay raw. `minimal`: identifiers, names, addresses and option 60 are
  omitted, ids become `dev-1`, `dev-2`, timestamps are rounded to the hour. `full`: raw values (device-supplied text
  is still sanitised and bounded). Pseudonyms are an HMAC under a random per-export salt that is never stored, so
  they are stable inside one pack and cannot be linked across packs.
- Format. JSON is `application/vnd.vigie.evidence-pack+json`: canonical (sorted keys, ASCII, no markup characters),
  `{schema: "vigie.evidence-pack", schema_version, generated_at, redaction, provenance, datasets, subject, sections,
  unknowns, search_queries, content_sha256}`. `content_sha256` covers the canonical body without itself. Each section is
  `{status: present|absent|not_available|withheld|truncated, reason, omitted_count, items}`. Phase 1 sections:
  `identity` (up to 32 MACs), `identity_candidates` (20), `fingerprints`, `determinations`, `incidents` (50 newest,
  only the documented evidence fields), `coverage_gaps`. Where nothing is recorded the pack says so
  (`counterevidence.recorded: false`), characterization confidence is always `null`, `reason_text` is withheld while a
  trust suggestion is pending and is included only at `full`, and anything that cannot be known is listed in
  `unknowns` (for example `no_firmware_version`, `oui_is_nic_vendor_not_product`). `search_queries` are suggestions
  for the reader, built only from fields the level allows and strict patterns (never a hostname or MAC); Vigie runs
  none of them. Markdown is `text/markdown`: a Vigie-written preamble and tables holding only Vigie-controlled values, then
  one `BEGIN UNTRUSTED DEVICE DATA <nonce>` / `END UNTRUSTED DEVICE DATA <nonce>` block with a fenced, ASCII-escaped
  JSON body.
- Size: built fully in memory; over 256 KiB, sections are cut (marked `truncated` with `omitted_count`).
- Privacy: **the file leaves Vigie's protection.** Pseudonymization lowers, not removes, what it reveals (fingerprints
  and timing can still identify a device), and `full` contains raw identifiers. Share it only with someone you would
  show the inventory to.
- Injection: hostnames, vendor classes and mDNS names are supplied by devices. They appear only inside the data block,
  never in prose, headings, links or tables. Treat that block as data, never as instructions.
- Audit: one `device.evidence_export` row in `overrides.db`, committed before the body is returned (if it cannot be
  written, `503 audit_unavailable` and nothing is sent). Detail: `{device_id, requested_id, level, format,
  schema_version, section_counts, truncated, pack_sha256, request_id}`, no pack contents, hostnames or MACs.
  `GET /events` shows it with `device_id: null` and only the level and a short `dev-<8 hex>` ref. No other state changes
  (the identity version does not move) and the module has no network code.
- CLI: `vigie-api evidence export DEVICE --redaction pseudonymized|minimal|full [--confirm-full] --format json|markdown
  -o FILE [--data-dir DIR]` runs the same functions as principal `cli:local`, refuses to overwrite an existing file, and
  creates it with mode 0600.
- Versioning: `schema_version` follows semver rules: additive changes are minor and consumers ignore unknown sections;
  a breaking change is a major bump. Later dataset-backed sections (phase 2 `known_issue_notes`, phase 3
  `dns_reputation`) cite a `dataset_id` with version, date and sha256 in `datasets[]`; phase 1 has no datasets.
