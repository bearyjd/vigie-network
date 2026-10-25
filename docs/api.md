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
currently merged members. The time is the collector batch window end attached
to that snapshot, not lease expiry, packet arrival time, or server receipt time.
This historical observation does not guarantee the device's current address.
An address never creates an identity link or changes a human label.

IPv4 and IPv6 are supported. Invalid, scoped, unspecified, multicast, loopback,
and limited-broadcast addresses are excluded. Observations outside the existing
one-hour report-lag / activity clock-skew limits are excluded. The newest sensor
stamp wins; equal stamps prefer lease evidence, then the lexically greatest
canonical address (and MAC for an otherwise equal identity-level tie). This is a
deterministic presentation choice, not proof of address ownership.

Pipeline schema 10 retains one latest association per observed MAC. It does not
replay processed batches or backfill old raw data. Fields remain null until new
qualifying lease/neighbour evidence arrives; an API reading an older pipeline
schema also returns null. Merge and undo recompute the view from current member
MACs. Device filtering and pagination are unchanged, with one indexed address
query scoped to each returned page. Existing clients can ignore the additive
fields; terminal viewers should use `.get` for compatibility with older APIs.
