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

```sh
export VIGIE_DATA_DIR=/var/lib/vigie          # inventory.db + raw-YYYYMMDD.db
export VIGIE_SECRETS_DIR=/run/secrets         # collector_key_<key_id> files
export VIGIE_SHARD_RETENTION_DAYS=7           # 1..30 (hard max 30)
uv run python -m vigie_ingest.admin provision rtr-1 k1   # register collector id + key id
uv run uvicorn vigie_ingest.app:create_app --factory --host <LAN-IP> --port 8443
# uv run python -m vigie_ingest.admin revoke rtr-1
```

Key file `collector_key_<key_id>`: hex text of at least 32 random bytes
(`openssl rand -hex 32`). Keys are read from the file on each request, never from the database.

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
| 413 | body over 512 KB (rejected before it is read in full or parsed) |
| 422 | post-auth schema/envelope failure; counted in `collectors.parse_failures`, nothing applied |
| 429 | per-source-IP rate limit (before the body is read) |

Retention: raw shards deleted after `VIGIE_SHARD_RETENTION_DAYS` (default 7, max 30); `batches`
rows older than 7 days purged. Maintenance runs at startup and hourly.
