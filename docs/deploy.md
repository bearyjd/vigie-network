# Operations guide

Short guide for running the server stack in `deploy/`. Setup is in the top-level
[`README.md`](../README.md). Nothing here has been run against a started stack yet (the image has
not been built); commands marked *unverified* are written from the code and podman documentation.

## Permission model: three processes, three volumes

Ownership follows the PRP section 5 table. Nothing in this file has been run against a started
stack (no image build, no real podman); the read-only-mount behavior below was tested with
bubblewrap bind mounts (`server/tests/test_ro_mount_wal.py`), not with containers.

| Process | `inventory.db` | raw shards | `overrides.db` | Secrets |
|---|---|---|---|---|
| `ingest` (collector principal) | writes `collectors`, `batches`; no overrides | writes | **not mounted** | ingest TLS cert and key, `collector_key_<key_id>` |
| `pipeline` | writes derived tables (devices, observations, events) | reads | reads | none |
| `api` (app principal) | reads | **not mounted** | writes (labels, links, tokens, audit log) | its own TLS cert and key |

Mounts and writable paths, exactly as in `deploy/compose.yaml` (`deploy/tests/check_refs.py` fails if
this table and the compose file disagree):

| Volume | ingest | pipeline | api |
|---|---|---|---|
| vigie-raw | rw | ro | - |
| vigie-inv | rw | rw | ro |
| vigie-overrides | - | ro | rw |

Container paths: `vigie-raw` is `/raw` (`raw-YYYYMMDD.db` shards and the ingest `flock`),
`vigie-inv` is `/inv` (`inventory.db`), `vigie-overrides` is `/overrides` (`overrides.db`).
Writable paths per service, everything else is a read-only root filesystem:

- `ingest`: `/raw`, `/inv`, and the `/tmp` tmpfs (64 MB).
- `pipeline`: `/inv`, and `/tmp` (holds the heartbeat file).
- `api`: `/overrides`, and `/tmp`.

**Every consumer mount above is `:ro` where it was shown to work, and none is left `rw` for
convenience.** Specifically, the pipeline cannot write shards or `overrides.db`, and the api cannot
write `inventory.db` or see any shard.

How it is enforced, honestly:

- **Structural**: ingest never mounts the overrides volume, so it cannot forge tokens, links or
  rules. The api and the pipeline address `overrides.db` directly as `/overrides/overrides.db`
  (`VIGIE_OVERRIDES_PATH`); there is no symlink inside a volume ingest can write. Their entrypoint
  (`deploy/entrypoint.sh`) refuses to start (exit 70) if `VIGIE_OVERRIDES_PATH` is unset, lies inside
  the raw or inventory directory, or if a file or link named `overrides.db` exists anywhere in those
  directories (stale layout, or something planted by ingest). Nothing is deleted for you.
- **Keepers make the `:ro` mounts work.** A SQLite WAL database nobody has open loses its `-wal` and
  `-shm` files, and a reader on a read-only mount cannot recreate them: it fails with
  "unable to open database file" (tested). So each writer keeps ONE connection open for its
  lifetime: ingest holds `inventory.db` and every raw shard (new shards as they appear, released
  before retention deletes them), the pipeline loop holds `inventory.db`, the api holds
  `overrides.db`. Tested with a real read-only bind mount: readers succeed while the keeper runs, 300
  open/read/close cycles against a continuously committing writer produced no errors, and a reader
  after the writer was SIGKILLed saw a consistent snapshot. Single-use `--once` runs and
  `compose run` helpers hold nothing.
- **When a keeper is down, readers fail closed.** The api answers 500 on inventory reads. The
  pipeline logs `overrides_unreadable` and runs with NO identity links and NO rules from
  `overrides.db` (it never treats an unreadable file as trust or as a grant), and a shard it cannot
  read leaves its batch pending for the next pass. Consequence worth knowing: while the api is down
  and its keeper gone, the pipeline can create separate devices for MACs a human had linked; the
  links apply again when the api is back, but already-created devices are not merged back by itself.
- In code as well: the api opens `inventory.db`, and the pipeline opens `overrides.db` and shards,
  with SQLite `mode=ro` plus `PRAGMA query_only=ON`. Containers run `read_only: true`,
  `cap_drop: [ALL]`, `no-new-privileges`, an explicit `user: 10001:10001`, a 64 MB `/tmp` tmpfs,
  512 MB memory and 1 CPU each, rootless.
- **No uid separation**: all three containers run as uid 10001, because files are created 0600 and
  rootless volumes have one owner. Separation is by mount and code, not by uid.
- **Ingest is a single worker.** It takes an exclusive `flock` on `/raw/.ingest.lock`. Never run two
  ingest containers on one raw volume and never put the volumes on NFS/SMB.
- **Layout change.** Earlier drafts used one `vigie_data` volume. There is no migration: move
  `inventory.db` and `raw-*.db` into the new volumes by hand, or start fresh.

## Backups

Back up **`overrides.db` only**, plus optionally the aggregate tables of `inventory.db`. **Never back
up the raw shards** (`raw-YYYYMMDD.db`): they hold per-client DNS history and are meant to expire.
Losing `overrides.db` loses human labels, group intents and API tokens; the control app keeps its own
enforcement state.

Use SQLite's online backup, not a file copy (the database is in WAL mode). The slim image has no
`sqlite3` CLI, so run it from the host against the volume (*unverified*):

```sh
podman volume ls | grep vigie-overrides                     # project prefix depends on the directory name
V=$(podman volume inspect deploy_vigie-overrides --format '{{.Mountpoint}}')
sqlite3 "$V/overrides.db" ".backup '/safe/place/overrides-$(date +%F).db'"
```

Rootless volume paths are under your home directory and usually readable by your user; if not, use
`podman unshare`. Alternative from inside the stack with Python's `Connection.backup`, mounting a
backup directory with `run -v` (*unverified*).

Encrypt backups at rest (for example `age` or `gpg`); they contain token hashes and your labels.
Restore: stop `api` and `pipeline`, copy the backup over `overrides.db` in the volume (as uid 10001,
mode 0600), start them. Never `podman-compose down -v` without a backup: it deletes this volume.

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

## Rotating the server certificates (SPKI pin)

Ingest and the api have separate certificates. Only the **ingest** certificate is pinned by the
collector, which takes **two** pins (`pin1`, `pin2`, 64 lowercase hex characters, different from each
other), so a rotation never has a moment where the router rejects the server. The order matters:
the router must learn the next pin BEFORE the server switches.

1. Generate the next ingest certificate somewhere else:
   `VIGIE_CERT_SAN=... ./gen-certs.sh --out ./certs-next` (default role `ingest`) and note its hex pin.
2. On the router edit `/etc/vigie/collector.conf`: keep the current pin as `pin1`, set the **next** pin as
   `pin2`, restart the collector. Confirm it still connects.
3. Only then switch the server: `podman secret rm vigie_tls_cert vigie_tls_key`,
   `podman secret create vigie_tls_cert certs-next/server.crt`,
   `podman secret create vigie_tls_key certs-next/server.key`, then
   `podman-compose up -d --force-recreate ingest`. `gen-certs.sh --force` regenerates in place without
   publishing the new pin first, so it is for first setup and broken installs, not for rotation.
4. Once the collector connects with the new certificate, put the new pin in `pin1`, choose another
   spare for `pin2`, and restart the collector.
5. The api certificate rotates independently: `./gen-certs.sh --role api --out ./certs-api-next`,
   replace `vigie_api_tls_cert` / `vigie_api_tls_key`, `podman-compose up -d --force-recreate api`,
   and update the control app's trust anchor (`--cacert` / pinned certificate).

Skipping step 2 means the collector rejects the server and spools (RAM only, bounded) until you
fix the router config.

## Rotating a collector key

1. `deploy/provision-collector.sh rtr-1 k2` creates the key `collector_key_k2`, prints the router
   config and the `scp -O` line. The key file is `collector-rtr-1/key-k2`; the old one is untouched.
2. Add `collector_key_k2` to `compose.yaml` (ingest `secrets:` and top-level `secrets:`) as the script prints,
   register the collector (the script does it when the secret is listed): the row's `key_id` becomes `k2`
   **immediately**; re-running the script for an already registered collector does the same.
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

For a control app that obtains human approval of standing identity rules, issue its token with
`tokens create --id control-app --rules-write`. This grants `rules:write` in addition to ordinary
app access. Existing app tokens keep ordinary write access but cannot create or revoke rules.
Service/integration and read-only tokens cannot approve rules. Vigie records the app token id;
the control app is responsible for obtaining the human's approval (D6 remains pending).
See [the API contract](api.md) for identity decisions and version guards.

## Health and logs

`podman-compose ps` shows the healthchecks (`deploy/healthcheck.py`):

- ingest: a TLS request to `/v1/batch`; a 4xx answer (it has no GET route, so 405) means up, **a 5xx
  never counts as healthy**.
- api: `GET /healthz` must return 200.
- pipeline: a heartbeat file in `/tmp` that the loop touches after every **successful** pass. It is
  unhealthy once the last good pass is older than 3 x `VIGIE_PIPELINE_INTERVAL_S` (default 30, so 90
  seconds), so a failing, stuck, or schema-less loop shows up; plain liveness would not. It starts
  with a 120 s grace period, and on a fresh stack stays unhealthy until a collector exists (the
  pipeline restarts until ingest has created the schema).

Healthy on a fresh stack therefore takes a couple of minutes, not seconds.
`podman-compose logs -f pipeline` shows `run_complete` and `run_failed` records. Ingest's pre-auth
limiter keys on the peer address, so check the rootless network mode keeps the real source address
(`podman info --format '{{.Host.RootlessNetworkCmd}}'`).

## Reboots

Containers use `restart: unless-stopped`, but nothing restarts rootless containers after a reboot by
itself. Both of these are needed (*unverified on this host*):

1. `sudo loginctl enable-linger $USER`: lets your user services run without a login session.
2. `systemctl --user enable --now podman-restart.service`: starts containers whose restart policy
   matches at boot. Read `systemctl --user cat podman-restart.service` first: older podman versions
   start only `--restart=always` containers and would skip these (`unless-stopped`); newer ones also
   include `unless-stopped`. If yours does not, generate Quadlet or `podman generate systemd` units
   instead. Then reboot once and check `podman-compose ps`.

## Server-side rollback

Everything the server side created, undone (run in `deploy/`; the router side is in the README):

```sh
podman-compose down            # removes the containers, KEEPS the volumes (data survives)
podman-compose down -v         # ALSO deletes vigie-raw, vigie-inv and vigie-overrides:
                               # raw history, the inventory, labels and API tokens. Back up first.
podman secret ls               # then remove what you created:
podman secret rm vigie_tls_cert vigie_tls_key vigie_api_tls_cert vigie_api_tls_key collector_key_k1
rm -rf certs certs-api collector-rtr-1 .env            # local key material and config
# firewall: undo each rich rule you added (README has the exact commands), then
sudo firewall-cmd --reload
```

## Supply chain

The base image and the uv image are pinned by `@sha256` digest in `deploy/Containerfile`, and the
build backend (hatchling and its dependencies) by `deploy/build-constraints.txt`. The digests were
looked up through the registries' HTTP APIs, not by pulling or building, and the first real build
may show they need a refresh. `python3 -I deploy/tests/check_refs.py --release` fails when either
image is unpinned. The runtime stage has pip, setuptools and wheel removed. Not covered: pinning
build dependencies by hash, scanning the image, signing it.
