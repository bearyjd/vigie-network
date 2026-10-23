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
| GET | `/identity/rules` | List rules, including expiration/revocation and active state |
| POST | `/identity/rules` | Approve a standing rule |
| DELETE | `/identity/rules/{rule_id}` | Revoke a standing rule |
| POST | `/identity/candidates/{candidate_id}/clear-veto` | Request one veto clearance |

Write bodies carry `expected_versions: {"device-id": 3, ...}` for exactly the involved devices.
For a single device, `expected_version: 3` is also accepted. Supply exactly one form. Versions
come from device reads (`override_version`, also returned as the device's ETag); a device with
no override has version 0. Rule creation also requires `device_id` and `signature`, and accepts
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
inventory activity as well. Inventory checks are read-only; there is no cross-database atomic
transaction with the pipeline's independently changing inventory.

Merge acceptance records one identity link, merge history, the suggestion decision, version
increments, and an audit entry together. Repeating an accepted request returns its recorded
result without another decision or link. Rejection records a decision without changing device
classification or trust. Undo revokes the link and retains history; repeating an undo is a no-op.
Device versions protect undo against intervening human changes.
Undo also revokes a rule created by that merge's `remember: true` approval, so it requires
`rules:write` when it revokes that rule. Independently created rules remain separate approvals.

## Clearing a veto

Clearing records an audited `candidate_decisions` intent in `overrides.db`, keyed by candidate
id and its exact ordered device pair. It never updates inventory from the API. The next pipeline
pass consumes that intent once, marks the matching veto `dismissed` in inventory, and performs
a fresh compute/apply cycle. A clearance alone never attaches a MAC, and current overlap still
blocks attachment. A consumed clearance cannot clear any later veto again.

## Write costs and safety

Each successful human mutation and its audit entry commit together. New writes use optimistic
device versions; stale versions return 409 without a write. Idempotent retries do not create
new audit rows. Request ids correlate audit entries without including bearer credentials.
The existing body-size cap and per-token rate limiter apply to every new write endpoint.

Reads, token verification, failed requests, and idempotent retries do not stamp tokens or update
counters in SQLite. Every actual overrides commit invalidates an in-flight pipeline attach plan
through `PRAGMA data_version`, delaying those attaches by one pass. Rate limiting bounds this
availability cost; it does not weaken the attach checks.
