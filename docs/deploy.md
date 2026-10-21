# Operations guide

Short guide for running the server stack in `deploy/`. Setup is in the top-level
[`README.md`](../README.md). Nothing here has been run against a started stack yet (the image has
not been built); commands marked *unverified* are written from the code and podman documentation.

## Permission model: three processes, one writer per file

| Process | `inventory.db` | raw shards | `overrides.db` | Secrets |
|---|---|---|---|---|
| `ingest` (collector principal) | writes `collectors`, `batches` | writes | **not mounted** | TLS cert and key, `collector_key_<key_id>` |
| `pipeline` | writes derived tables (devices, observations, events) | reads | reads | none |
| `api` (app principal) | reads | not used | writes (labels, tokens, audit log) | TLS cert and key |

How it is enforced, honestly:

- **Structural**: ingest never mounts the overrides volume, the pipeline has no secrets, and only
  ingest can read collector keys. Containers run `read_only: true`, `cap_drop: [ALL]`,
  `no-new-privileges`, `/tmp` as tmpfs, rootless.
- **In code, not by mount flags**: api opens `inventory.db`, and the pipeline opens `overrides.db`,
  with SQLite `mode=ro` plus `PRAGMA query_only=ON` (`server/src/vigie_api/schema.py`,
  `server/src/vigie_pipeline/overrides.py`). The compose file mounts those volumes read-write
  because a read-only mount breaks SQLite WAL readers (they cannot create or attach `-shm`; reproduced
  with a stand-in test: a cleanly closed WAL database in a read-only directory fails with "attempt to
  write a readonly database"). Do not add `:ro` to those mounts without testing against a running
  stack.
- **No uid separation**: all three containers run as uid 10001, because files are created 0600 and
  rootless volumes have one owner.
- **`overrides.db` lives on its own volume**, linked into the data directory as
  `/var/lib/vigie/overrides.db -> /overrides/overrides.db` by `deploy/entrypoint.sh` (api and
  pipeline derive the path from `VIGIE_DATA_DIR`; there is no separate setting). The entrypoint never
  replaces an existing file: a regular `overrides.db` in the data volume makes the container refuse to
  start (exit 70).
- **Ingest is a single worker.** It takes an exclusive `flock` on `<data dir>/.ingest.lock`. Never run
  two ingest containers on one data volume and never put the data volume on NFS/SMB.

## Backups

Back up **`overrides.db` only**, plus optionally the aggregate tables of `inventory.db`. **Never back
up the raw shards** (`raw-YYYYMMDD.db`): they hold per-client DNS history and are meant to expire.
Losing `overrides.db` loses human labels, group intents and API tokens; the control app keeps its own
enforcement state.

Use SQLite's online backup, not a file copy (the database is in WAL mode). The slim image has no
`sqlite3` CLI, so run it from the host against the volume (*unverified*):

```sh
podman volume ls | grep vigie_overrides                     # project prefix depends on the directory name
V=$(podman volume inspect deploy_vigie_overrides --format '{{.Mountpoint}}')
sqlite3 "$V/overrides.db" ".backup '/safe/place/overrides-$(date +%F).db'"
```

Rootless volume paths are under your home directory and usually readable by your user; if not, use
`podman unshare`. Alternative from inside the stack with Python's `Connection.backup`, mounting a
backup directory with `run -v` (*unverified*).

Encrypt backups at rest (for example `age` or `gpg`); they contain token hashes and your labels.
Restore: stop `api` and `pipeline`, copy the backup over `overrides.db` in the volume (as uid 10001,
mode 0600), start them.

## Retention

Set in `deploy/.env` (read at container start, so recreate the service after editing:
`podman-compose up -d --force-recreate ingest`):

- `VIGIE_SHARD_RETENTION_DAYS` - raw shards (default 7, range 1-30, hard max 30). Purged at ingest
  startup and hourly.
- `batches` rows (dedupe records) are purged after 7 days; not configurable.
- `VIGIE_MAX_SPOOL_AGE_S` - how old a collector window may be (default 24 h).
- Event and hostname retention (PRP section 9, 90 days) is **not implemented**: no setting exists, so
  `events` and hostnames in `inventory.db` are kept. Until it exists, never `VACUUM` `inventory.db` and never
  delete the newest `events` rows (see "Event cursors" in `server/README.md`).

Retention shortens how long raw data sits on disk; it is not a substitute for encrypting the volume.
Put the data directory on an encrypted filesystem (PRP section 9).

## Upgrades and migrations

1. `git pull`, then `podman build -f deploy/Containerfile -t localhost/vigie-server:dev .` (or a new
   `VIGIE_IMAGE_TAG`).
2. `podman-compose up -d` recreates changed services.
3. **Schema ownership**: ingest owns `devices`, `observations`, `collectors`, `batches`. The pipeline
   **refuses to migrate ingest-owned tables** unless started with `--migrate`. After an upgrade that
   changes ingest's schema, start ingest first (it migrates on open), or run the pipeline once with
   migration:
   `podman-compose run --rm --no-deps pipeline python -m vigie_pipeline run --once --migrate`.
   The pipeline refuses a **newer** schema than it understands (`SchemaVersionError`); that is how a
   downgrade is caught.
4. In `--loop` mode a `SchemaVersionError` ends the process; compose restarts the pipeline
   (`restart: on-failure`) until the schema matches. On a fresh stack the pipeline therefore
   restarts a few times until `provision-collector.sh` has created `inventory.db`; that is expected.
5. `overrides.db` is migrated by the api at startup (it creates and migrates the file).
6. Roll back by restoring the previous image tag. A schema that moved forward cannot be moved back:
   keep a copy of the data volume before an upgrade that bumps a schema version
   (`podman volume export`, *unverified*).

## Rotating the server certificate (SPKI pin)

The collector pins the certificate's public key and takes **two** pins (`pin1`, `pin2`, 64 lowercase hex
characters, different from each other), so a rotation never has a moment where the router rejects the
server.

1. Generate the next certificate somewhere else:
   `VIGIE_CERT_SAN=... ./gen-certs.sh --out ./certs-next` and note its hex pin.
2. On the router edit `/etc/vigie/collector.conf`: keep the current pin as `pin1`, set the **next** pin as
   `pin2`, restart the collector. Confirm it still connects.
3. On the server replace the secrets and recreate the services:
   `podman secret rm vigie_tls_cert vigie_tls_key`, `podman secret create vigie_tls_cert certs-next/server.crt`,
   `podman secret create vigie_tls_key certs-next/server.key`, then
   `podman-compose up -d --force-recreate ingest api`. (`gen-certs.sh --force --create-secrets` does the
   same for a certificate you generate in place.)
4. Once the collector connects with the new certificate, put the new pin in `pin1`, choose another
   spare for `pin2`, and restart the collector.
5. Update the control app's trust anchor (`--cacert` / pinned certificate) as well: the API uses the same
   certificate.

Skipping step 2 means the collector rejects the server and spools (RAM only, bounded) until you
fix the router config.

## Rotating a collector key

1. `deploy/provision-collector.sh rtr-1 k2` creates the key `collector_key_k2`, prints the router
   config and the `scp -O` line. The key file is `collector-rtr-1/key-k2`; the old one is untouched.
2. Add `collector_key_k2` to `compose.yaml` (ingest `secrets:` and top-level `secrets:`) as the script prints,
   register the collector (the script does it when the secret is listed): the row's `key_id` becomes `k2`.
3. `podman-compose up -d --force-recreate ingest`.
4. Copy the new key to the router (`scp -O`), set `key_id=k2` in `collector.conf`, restart the collector.
   Batches signed with the old key fail with a uniform 401 from the moment the row switches, so do steps
   2-4 together; the collector spools meanwhile.
5. Remove `collector_key_k1` from compose and `podman secret rm collector_key_k1` when done.

Revoking a collector: `podman-compose run --rm --no-deps ingest python -m vigie_ingest.admin revoke rtr-1`.
A revoked collector is rejected with 401 even for batches it already delivered. Re-provisioning a revoked
collector needs `admin provision --force` (it resets the sequence state).

## API tokens

`podman-compose run --rm --no-deps api python -m vigie_api tokens create --id control-app` prints the
token once (stdout) and stores only its SHA-256. `tokens revoke control-app` revokes it. Rotate by creating
a second token, switching the control app, then revoking the first.

## Health and logs

`podman-compose ps` shows the healthchecks: ingest and api probe their own TLS listener (any HTTP answer
for ingest, `GET /healthz` for api); the pipeline check is **liveness only** (PID 1 is the pipeline).
`podman-compose logs -f pipeline` shows `run_complete` and `run_failed` records. Ingest's pre-auth limiter
keys on the peer address, so check the rootless network mode keeps the real source address
(`podman info --format '{{.Host.RootlessNetworkCmd}}'`).
