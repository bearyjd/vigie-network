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

**Rate limiting and proxies.** The limiter keys on the direct TCP peer (IPv6 by /64) and
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
| 422 | post-auth schema/envelope failure; counted in `collectors.parse_failures`, nothing applied |
| 429 | per-source-IP rate limit (before the body is read) |

Persistence: shards hold `raw_dns`, `raw_flow`, `raw_lease`, `raw_neigh`, `raw_sighting`,
`raw_health` (all with `collector_id` and `batch_id`). Each record is sharded by its own `ts`
clamped to the batch window (records without a ts use `window_end`). `window_end` must be within
24 h of `sent_ts`. `batches` also stores `truncated` and `dropped_batches`.

Crash safety: shards are committed first (delete-by-batch_id then insert, so re-applying is
idempotent), then the inventory transaction records the batch and advances `seq`. A crash in
between makes the retry apply normally rather than report `duplicate`. Single process per data
dir is assumed (shard purge and writes are serialised by an in-process lock).

Retention: raw shards deleted after `VIGIE_SHARD_RETENTION_DAYS` (default 7, max 30); `batches`
rows older than 7 days purged. Maintenance runs at startup and hourly.
