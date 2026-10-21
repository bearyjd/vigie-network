# vigie-ingest

Collector-facing ingest service (PRP-001 section 4/5). Exposes only `POST /v1/batch`.
It never serves the app API and never runs the pipeline. Python 3.12, FastAPI, SQLite.

## Setup and tests

```sh
cd server
uv python install 3.12
uv sync
uv run pytest          # includes coverage, fails under 80%
uv run ruff check .
```

Regenerate the batch JSON schema after editing `src/vigie_ingest/models.py`
(a test fails on drift):

```sh
uv run python -m vigie_ingest.schema_export     # writes ../api/batch.schema.json
```

## Run

TLS is mandatory. The service refuses to start without `--tls-cert`/`--tls-key` unless
`--insecure-dev` (or `VIGIE_INSECURE_DEV=1`) is given; never use that outside development.

```sh
export VIGIE_DATA_DIR=/var/lib/vigie          # inventory.db + raw-YYYYMMDD.db
export VIGIE_SECRETS_DIR=/run/secrets         # collector_key_<key_id> files (podman secrets)
export VIGIE_SHARD_RETENTION_DAYS=7           # 1..30 (hard max 30)
uv run python -m vigie_ingest.admin provision rtr-1 k1   # register collector id + key id
uv run python -m vigie_ingest --host <LAN-IP> --port 8443 \
  --tls-cert /run/secrets/vigie_ingest_cert --tls-key /run/secrets/vigie_ingest_key
# uv run python -m vigie_ingest.admin revoke rtr-1
# re-provision a revoked collector (resets seq/boot state): admin provision --force rtr-1 k1
```

`python -m vigie_ingest` passes the cert and key to uvicorn (`--ssl-certfile`/`--ssl-keyfile`
equivalents) and sets `limit_concurrency=64` and `timeout_keep_alive=5` (tune with
`--limit-concurrency` / `--timeout-keep-alive`; the request body has a 10 s deadline,
`VIGIE_BODY_TIMEOUT_S`). If you run uvicorn yourself, pass `--ssl-certfile`, `--ssl-keyfile`,
`--limit-concurrency` and `--timeout-keep-alive` explicitly.

The service refuses to start unless every non-revoked collector has a valid key file.
Key file `collector_key_<key_id>`: hex text of at least 32 random bytes
(`openssl rand -hex 32`). Keys are read from the file on each request, never from the database.

**Collector SPKI pin** (the collector pins the server certificate's public key, not the cert):

```sh
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64
```

Configure two pins (current and next) on the collector to allow certificate rotation.

**Rate limiting and proxies.** The pre-auth limiter keys on the direct TCP peer (IPv6 by /64 by default) and
ignores `X-Forwarded-For`. If a reverse proxy is ever put in front, every client would share
the proxy's budget; then run uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy-ip>` so
only that trusted proxy may set the client address, and raise the limit accordingly.

## Wire contract

Request headers (the signed fields; the body cannot be parsed before authentication):
`X-Vigie-Collector-Id`, `X-Vigie-Key-Id`, `X-Vigie-Boot-Id`, `X-Vigie-Seq`, `X-Vigie-Sent-Ts`
(unix seconds), `X-Vigie-Batch-Id` (UUIDv7), `X-Vigie-Signature`.

```
signature = hex(HMAC-SHA256(key, collector_id|key_id|boot_id|seq|sent_ts|batch_id|hex(SHA256(raw_body))))
```

The JSON body repeats those fields and must match the headers (mismatch is a counted 422).
Schema: `../api/batch.schema.json`.

| Status | Meaning |
|---|---|
| 200 `{"duplicate":false}` | applied |
| 200 `{"duplicate":true}` | batch_id already applied (treat as success) |
| 401 `{"error":"unauthorized"}` | any auth failure (bad HMAC, unknown/revoked collector, bad headers); uniform |
| 400 | `sent_ts` more than 5 min from server time |
| 409 | `seq` not greater than last seq within the same `boot_id` |
| 408 | body not received within the deadline |
| 413 | body over 512 KB (rejected before it is read in full or parsed) |
| 422 | post-auth schema/envelope failure (including a batch touching more than `max_shard_days` shard days); counted in `collectors.parse_failures`, nothing applied |
| 429 | per-peer-address limit (before the body is read) or per-collector limit (after the HMAC verifies) |

Persistence: shards hold `raw_dns`, `raw_flow`, `raw_lease`, `raw_neigh`, `raw_sighting`,
`raw_health` (all with `collector_id` and `batch_id`). Each record is sharded by its own `ts`
clamped to the batch window (records without a ts use `window_end`). `window_end` must be within
24 h of `sent_ts`. `batches` also stores `truncated` and `dropped_batches`.

Crash safety: shards are committed first (delete-by-batch_id then insert, so re-applying is
idempotent), then the inventory transaction records the batch and advances `seq`. A crash in
between makes the retry apply normally rather than report `duplicate`. Exactly one process per
data dir: the entrypoint refuses `--workers` above 1 and takes an exclusive `flock` on
`<data_dir>/.ingest.lock` (it exits with an error if another instance holds it). Shard purge and
writes are serialised by an in-process lock, so the commit-time duplicate race (a second writer
applying the same `batch_id` between our shard and inventory commits) cannot occur in a supported
deployment; it is exercised in tests in-process only, not across real processes.

Time under that lock is bounded: a batch may touch at most `max_shard_days` shard days (default 3,
`VIGIE_MAX_SHARD_DAYS`, else 422), connections opened under the lock wait at most 1.5 s for
SQLite locks, and a retry of an already-applied batch is answered from a read-only check without
taking the lock (re-checked under the lock for the not-yet-applied case).

Raw-shard readers must join against `batches`: a crash between the shard commit and the
inventory commit can leave orphan shard rows (same `collector_id`/`batch_id`, no `batches` row).
The collector's retry replaces them, but until then they are not part of an applied batch.

Upgrade note: migration v3 sets `last_sent_ts = 0` for existing collectors, so the first batch
after the upgrade skips the boot_id-rollback guard (the 5-minute `sent_ts` skew check still
applies).

Rate limiting has two stages. Before authentication the bucket is the peer address only
(`VIGIE_RATE_LIMIT_PREAUTH_PER_MIN`, default 120/min), a generous CPU guard. IPv6 peers are
grouped by /64 by default (`VIGIE_RATE_LIMIT_IPV6_PREFIX`, default 64; `0` or `none` uses full
addresses). The claimed `X-Vigie-Collector-Id` is never used there, so a LAN host cannot spend a
victim's budget by claiming its id. After the HMAC verifies, a per-collector limiter
(`VIGIE_RATE_LIMIT_PER_MIN`, default 60/min) is charged; unauthenticated requests never create or
spend its entries.

The peer table is bounded (4096). When full, stale entries are swept, then the oldest entry is
evicted if idle for over 30 s; otherwise new addresses share one overflow bucket. Peers whose
request passed HMAC verification are remembered in a small allowlist (at most 4 per provisioned
collector, counted at startup, LRU, dropped after 1 hour without a verified request). An
allowlisted peer never uses the overflow bucket (it still counts against its own bucket), so a
host spraying thousands of source addresses cannot lock a known collector out.

Design limit: a host that shares the collector's NAT or peer address (or its /64) shares its
pre-auth budget and can exhaust it, because the peer address is the only identity before the HMAC
is checked. Give each collector its own address. The real defence is at the network level:
restrict the listener to the collector addresses with a firewall rule. Homelab examples (collector
at 192.168.8.2, listener on 8443):

```
# nftables
nft add rule inet filter input tcp dport 8443 ip saddr != { 192.168.8.2 } drop
# iptables
iptables -A INPUT -p tcp --dport 8443 -s 192.168.8.2 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP
```

Single instance: the process holds an exclusive flock on `<data dir>/.ingest.lock` (taken by the
CLI and, for `uvicorn --factory`/gunicorn, by the app lifespan). A second instance on the same
data dir fails to start; so does a filesystem without flock support (exit 2 from the CLI).

Revocation: a batch that was applied and is retried after its collector is revoked gets 401 over
HTTP (authentication runs first), not `200 duplicate`. Nothing is deleted: the stored rows and
the `batches` row stay.

Retention: raw shards deleted after `VIGIE_SHARD_RETENTION_DAYS` (default 7, max 30); `batches`
rows older than 7 days purged. Maintenance runs at startup and hourly.

## App API (`vigie_api`)

The app principal's HTTP surface (PRP section 6), separate process and port from ingest.
Contract: `../api/openapi.yaml` (OpenAPI 3.1, emitted as JSON, which is valid YAML; a test fails
on drift). Regenerate with `uv run python -m vigie_api.openapi_export`.

```sh
export VIGIE_DATA_DIR=/var/lib/vigie      # inventory.db (opened read-only) + overrides.db (rw)
uv run python -m vigie_api tokens create --id control-app   # prints the token once, stores SHA-256
uv run python -m vigie_api tokens revoke control-app
uv run python -m vigie_api --host <LAN-IP> --port 8444 --tls-cert ... --tls-key ...
```

TLS is required (`--insecure-dev` / `VIGIE_INSECURE_DEV=1` for development only). No CORS.
`Authorization: Bearer vgt_<id>.<secret>`; every auth failure is the same 401. Limits:
`VIGIE_API_RATE_LIMIT` per `VIGIE_API_RATE_WINDOW_S` per token (failed auth is limited per source
address), `VIGIE_API_MAX_BODY_BYTES` (default 16 KiB, 413).

Envelope: `{ok, data, error:{code,message}|null, page:{next_cursor}|null}`. Implemented:
`GET /devices` (filters `type`, `group` (`unassigned` for none), `identity_state`, `status`,
`updated_since`; transient hidden unless `include_transient=1` or `status=transient`),
`GET /devices/{id}`, `GET /macs/{mac}`, `PATCH /devices/{id}`, `GET /events`, `GET /suggestions`,
`GET /healthz`. Not yet: accept/reject/merge/undo, identity rules, SSE, metrics.

`PATCH` needs `If-Match: "<override version>"` (428 if absent, 412 on mismatch with the current
`ETag`); a device with no override has version 0 and the first write creates version 1. Only the
fields present in the body change; `null` clears one. Aliases (merged devices) return the
canonical device with `merged_into` on reads and 409 on PATCH. `group_id` comes only from
`device_overrides`; inferred data never assigns a group. `/events` is oldest-first and
`page.next_cursor` is the resume point (pass it as `since`).

**Event cursors are rowids.** `GET /events` pages on `events.rowid` (inventory.db) and
`audit_log.rowid` (overrides.db). `audit_log` is `AUTOINCREMENT`, so its rowids are never reused.
The pipeline `events` table is NOT yet `INTEGER PRIMARY KEY AUTOINCREMENT`: until it is, never
`VACUUM` inventory.db and never delete the newest `events` rows (a reused rowid lands behind a
client's cursor and the event is silently skipped). An xfail test
(`tests/api/test_api_rowid_review.py`) records the requirement; fixing it is a pipeline schema
migration.

**Text safety.** Every free-text field returned (hostnames, event summaries, names, reason text,
suggestion payload strings) is sanitised on output: control, format/bidi, line/paragraph
separator and tag characters are stripped and the length is bounded; stored values are untouched.
`name`/`owner` writes additionally reject those characters (NFKC-normalised first).

**Failed-auth limiter.** Counts failed authentications only, per source (IPv6 by /64, IPv4-mapped
addresses as their IPv4). A valid token is never blocked by it. A blocked source presenting no
token-shaped credential costs no database work; one presenting a well-formed token costs one
indexed lookup (needed so that a valid token still works from a shared address).

Overrides are loaded whole per list request (home-scale: hundreds of devices); revisit before
use on a large network.
