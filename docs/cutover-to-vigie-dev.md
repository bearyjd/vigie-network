# Cutover runbook: moving the Vigie server from Tower to the Atlas VM

Status: rehearsed on 2026-11-02 against the standby (router untouched, Tower only read).
Placeholders: `<tower-ingest-addr>` and `<standby-addr>` (LAN address and published port of each
ingest), `<standby-api-addr>`, `<collector-id>`, `<key-id>` (the collector row's `key_id`; the
HMAC secret is `collector_key_<key-id>`), `<standby-uid>` (numeric uid of the standby's service
account). No real address, name or secret belongs in this file.

## 1. Purpose and the one rule that shapes the order

Move ingest, pipeline and api from the Tower rootless stack to the standby quadlets, keeping the
inventory, overrides (labels, links, API tokens) and the collector identity, with the router
losing as little data as possible.

**The collector cannot reload its config.** It has no SIGHUP handler (`collector/agent/src/main.rs:10`,
default SIGTERM action). Any edit of `/etc/vigie/collector.conf` needs
`/etc/init.d/vigie-collector restart`. A restart discards the RAM spool and the unreported
`dropped_batches` counter (`spool.rs:1`, `sender.rs`), picks a new random `boot_id` and restarts `seq`
at 1 (`main.rs:321-340`). So the order "stop Tower, back up, restore, start standby, change router
URL" silently throws away every batch spooled during the downtime. The order below flips the
router FIRST, while the standby is still up but not yet holding the data: the collector then
spools into a fresh queue (the standby answers 401, which the collector treats as retryable,
`sender.rs:185`), and the queue is drained into the standby once the restore is done.

## 2. Decision: certificate and pin

The collector authenticates the server by SHA-256 of the certificate's SubjectPublicKeyInfo only.
Chain, host name, SAN and validity are not checked (`tls_pin.rs:1-8`, `verify_server_cert` ignores
the server name); the handshake signature must still verify, so the peer must hold the key. The URL
host is used only for connecting (and SNI when it is a DNS name). Config takes two pins
(`pin1`, `pin2`, must differ, `config.rs:209`).

| Option | Router fields that change | Tower key leaves Tower | Rollback |
|---|---|---|---|
| 1. Reuse Tower cert+key on the standby | `server_url` | yes (copy of a TLS private key) | `server_url` |
| 2. New cert, replace `pin1` | `server_url`, `pin1` | no | `server_url` and `pin1` (Tower pin must be restored) |
| **3. New cert, keep `pin1`, set `pin2` = standby pin** | `server_url`, `pin2` | no | `server_url` only (`pin1` still Tower) |

Chosen: **option 3**. One edit and one collector restart, Tower's private key never moves, and a
rollback needs no pin change. Option 1 is the fallback if the router `pin2` slot cannot be used.
The standby pin is computed from the certificate the standby actually serves, so a typo is
impossible:

```sh
echo | openssl s_client -connect <standby-addr> 2>/dev/null | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1
```

(Rehearsal: the value equals the `pin_sha256_hex` that `gen-certs.sh` stored for the standby.)
The old `pin2` value on the router is overwritten; note it before the edit if it matters.

## 3. Prerequisites (all must hold; do not start otherwise)

1. The 48-hour soak is finished or abandoned. A router edit restarts the collector and invalidates
   a strict run; the soak monitor also fails with `ingest_address_unbound` once Tower stops
   publishing. Stop the soak unit on Tower first.
2. Standby is up and healthy, `delivery` off, sender timer disabled.
3. Standby images equal Tower's api/pipeline image. Note that Tower's ingest may run an older
   image than the standby's; the standby ingest then migrates the restored inventory on open.
   Rehearsal restored Tower's schema (user_version 5) onto the newer image without a problem.
4. Real HMAC key staged on the standby, BEFORE the window (it is moved through a pipe, never
   printed or written to disk outside the secret store). Tower side name is
   `<tower-namespace>_collector_key_<key-id>`:
   ```sh
   # run on Tower; stdin of the ssh command receives the key
   podman secret inspect --showsecret --format '{{.SecretData}}' <tower-namespace>_collector_key_<key-id> \
     | ssh <standby-ssh> 'sudo -n -u vigie env XDG_RUNTIME_DIR=/run/user/<standby-uid> HOME=/home/vigie \
         podman secret create vigie_standby_collector_key_<key-id> -'
   ```
   Check the byte count only (`... | wc -c`, rehearsal: 66 = 64 hex + newline). Then add to
   `vigie_standby-ingest.container`, next to the existing `Secret=` lines, and run
   `systemctl --user daemon-reload`:
   ```
   Secret=vigie_standby_collector_key_<key-id>,target=collector_key_<key-id>,uid=10001,gid=10001,mode=0400
   ```
   Do not restart ingest yet (a restart now would fail: see section 7).
5. Clocks: VM and router within the server's 300 s skew (`max_clock_skew_s`); VM reports NTP synced.
6. LAN reachability from a LAN host to `<standby-addr>` and the pin computed in section 2.
7. Data volume check on the standby (rehearsal: raw shards are NOT copied, section 6).
8. The control app (API consumer) knows the new API address and the standby API certificate.
9. Operator has the router credentials and the router config backup (`cp /etc/vigie/collector.conf
   /etc/vigie/collector.conf.pre-cutover`).

## 4. Spool budget (the maximum downtime)

Facts from code: spool is RAM only, `SPOOL_CAP` = 1 MiB, drop-oldest, a batch larger than the whole
spool is dropped (`spool.rs:8,28-36`). A window is 60 s (`main.rs` default), one batch per window.
Drops are counted and reported as `dropped_batches` in the next successful batch. Retry backoff is
5 s doubling to a 300 s cap with jitter in [half, full] (`backoff.rs`). The server also rejects a
batch whose window ended more than 24 h before `sent_ts` (not binding here).

Batch size is not logged. Estimate (re-serialising the stored rows of ~1400 recent batches as keyed
JSON, plus 700 bytes of envelope): mean about 51 KB, p95 about 83 KB, max about 191 KB. Treat these
as estimates, not wire sizes.

| Sizing | Batches in 1 MiB | Minutes of data |
|---|---|---|
| mean 51 KB | about 20 | about 20 |
| p95 83 KB | about 12 | about 12 |

After the standby comes up the collector may still be sleeping in a backoff of up to 300 s. Budget:
**the standby must accept batches within about 7 minutes of the router restart (p95), 5 minutes as
the go/no-go limit.** Beyond that, the oldest windows are dropped (counted, not silent), and the
soak-style "fresh dropped batches" gate would fail. The measured technical path is under 30 s
(section 8); the rest is operator time.

## 5. Sequence

Run Tower commands on Tower, standby commands as the service account:
`S='sudo -n -u vigie env XDG_RUNTIME_DIR=/run/user/<standby-uid> HOME=/home/vigie'`.

**Step 1: pre-flight (T-10 min).**
- Tower: `podman ps` shows ingest/pipeline/api healthy; ingest log shows ~1 POST per minute.
- Standby: `$S podman ps` healthy; `curl -sk -o /dev/null -w '%{http_code}\n' https://<standby-addr>/v1/batch` prints 405.
- Latest batch `health.spool_batches` is 0 (router queue empty).
- Tower's ntfy sender has caught up: its cursor offset equals the delivery file size.
- Check: all of the above. Stop here if any fails.

**Step 2: flip the router (T0).** On the router (edit as documented in `docs/deploy.md`,
"Rotating the server certificates"; copy files with `scp -O`, no sftp on OpenWrt):
```sh
cp /etc/vigie/collector.conf /etc/vigie/collector.conf.pre-cutover
# edit /etc/vigie/collector.conf: server_url=https://<standby-addr>/v1/batch
#                                 pin2=<standby pin from section 2>   (pin1 stays Tower's)
vigie-collector --config /etc/vigie/collector.conf --check    # syntax+credentials (unverified on this router)
/etc/init.d/vigie-collector restart
```
`collector_id`, `key_id` and `/etc/vigie/key` do not change. Record the time.
- Check: standby ingest journal shows `POST /v1/batch 401` about once a minute (TLS and pin
  work, no data accepted yet); Tower ingest journal shows no new POST. No `200`, no TLS error. If
  the router logs TLS/pin failures instead, fix `pin2` or roll back now (section 9).

**Step 3: drain Tower, then freeze it.** The restored inventory only carries correct pipeline
state if Tower's pipeline has processed every received batch, because the standby has no raw shards
(section 6). Wait until pending is 0:
```sh
podman run --rm --network none --user 0:0 --entrypoint python \
  -v <tower-namespace>_inv:/inv:ro localhost/vigie-server:<tag> -c '
import sqlite3; c=sqlite3.connect("file:/inv/inventory.db?mode=ro",uri=True)
print(c.execute("select last_batch_rowid from pipeline_cursor").fetchone()[0],
      c.execute("select max(rowid) from batches").fetchone()[0])'
```
Both numbers equal (pipeline cycle is ~60 s). Then stop, in this order:
```sh
systemctl --user stop vigie-ntfy-sender.timer
systemctl --user stop <tower-namespace>-ingest.service
systemctl --user stop <tower-namespace>-pipeline.service <tower-namespace>-api.service
```
Check: `podman ps` on Tower shows none of the three; ingest log silent. (Tower volumes and secrets
stay untouched; do not remove anything.)

**Step 4: final backup (read-only on Tower) and ship.**
```sh
mkdir -m 700 <scratch>
podman run --rm --network none --user 0:0 --entrypoint python \
  -v <tower-namespace>_inv:/inv:ro -v <tower-namespace>_overrides:/ov:ro \
  -v <scratch>:/out:rw,Z localhost/vigie-server:<tag> -c '
import sqlite3, os
for s, d in (("/inv/inventory.db","/out/inventory.db"), ("/ov/overrides.db","/out/overrides.db")):
    a = sqlite3.connect(f"file:{s}?mode=ro", uri=True); b = sqlite3.connect(d); a.backup(b); b.close(); a.close()
    os.chmod(d, 0o600)'
for f in inventory.db overrides.db; do
  cat <scratch>/$f | ssh <standby-ssh> "$S bash -c 'umask 077; cat > /home/vigie/deploy/restore/$f'"
done
```
Use the SQLite online backup (WAL database; never copy the file). Check: sizes plausible
(rehearsal: about 8.0 MB and 0.18 MB, 0.5 s and 1.6 s).

**Step 5: restore on the standby and start (the data critical path).**
```sh
$S systemctl --user stop vigie_standby-pipeline.service vigie_standby-api.service vigie_standby-ingest.service
$S podman unshare bash -c '
V=/home/vigie/.local/share/containers/storage/volumes; set -e
cd $V/vigie_standby_inv/_data;       rm -f inventory.db inventory.db-wal inventory.db-shm delivery-messages.jsonl
cp /home/vigie/deploy/restore/inventory.db .; chown 10001:10001 inventory.db; chmod 600 inventory.db
cd $V/vigie_standby_overrides/_data; rm -f overrides.db overrides.db-wal overrides.db-shm
cp /home/vigie/deploy/restore/overrides.db .; chown 10001:10001 overrides.db; chmod 600 overrides.db
cd $V/vigie_standby_raw/_data;       rm -f raw-*.db raw-*.db-wal raw-*.db-shm .ingest.lock'
$S systemctl --user start vigie_standby-ingest.service        # accepting about 1 s later
$S systemctl --user start vigie_standby-api.service           # wait for /healthz 200, then:
$S systemctl --user start vigie_standby-pipeline.service
```
Delete stale `-wal`/`-shm` sidecars: a stale WAL would replay onto the new file. The restored
collector row is active with Tower's `last_seq`/`boot_id`: do NOT run `admin provision --force`
(it zeroes `last_seq`, `boot_id` and `last_sent_ts`, section 7). Start the api before the
pipeline: the pipeline's first pass can log `overrides_unreadable` if the api's overrides keeper is
not open yet (harmless, one pass, but it also skips stitching once).
- Check: ingest TLS answers 405 within seconds; within the collector's next retry (<= 5 min) the
  ingest journal shows `POST ... 200`.

**Step 6: verify (checklist in section 10).** Then remove the transfer copies:
`rm -f /home/vigie/deploy/restore/*` and `<scratch>/*` (household data), keep nothing.

**Step 7: after the bake-in.** Tower stays stopped but intact (units not removed) until you decide
to retire it. Do not start Tower ingest again while the router points at the standby (two ingests
on one collector fork the sequence state).

## 6. Raw shards: copy or not

Tested. The pipeline needs no historical shards: with the restored inventory and an EMPTY raw
volume the pipeline ran clean passes, stitching included (`overrides` readable), and `/coverage`
reported `backlog_batches` 0. Shard reads happen only for batches past the pipeline cursor
(`processor.py:157`, `measurements.py`). **But**: a batch that is still pending at backup time
and whose shard file is missing is consumed with zero MACs and the cursor advances
(`sources.py:read_batch` skips a missing file). Test: cursor rewound by 2 in a scratch copy, empty
raw: `batches 2, macs 0`, cursor advanced, no error. So draining Tower's pipeline (Step 3) is
mandatory, not cosmetic. Not copying raw also respects "never back up raw shards"
(`docs/deploy.md`, Backups): per-client DNS history stays on Tower and expires by retention.

## 7. Collector identity on the standby

- Ingest refuses to start if any NON-revoked collector row has no key file
  (`app.py _require_keys`). Rehearsal: restore without the key secret gives
  `RuntimeError: no valid key file ... for collectors: [<collector-id>]`. This is why the key
  secret and `Secret=` line are staged in prerequisites.
- The idle standby is kept safe by revoking the collector row after each restore
  (`python -m vigie_ingest.admin revoke <collector-id>` in a one-shot container with the inventory
  volume rw, `--network none`, `VIGIE_DATA_DIR=/tmp/vd`, tmpfs `/tmp`). A revoked row answers 401
  and needs no key. For the real cutover skip the revoke.
- `admin provision <collector-id> <key-id>` without `--force` on a revoked row fails
  (`collector ... is revoked; re-provisioning needs force`). With `--force` the row becomes
  `last_seq=0`, `boot_id=NULL`, `revoked=0` (measured). Use it only for a new collector, never to
  continue Tower's.
- Sequence behaviour with the real row restored (measured with the trafficgen signer library, a
  TEST key under the real collector and key ids, standby only):

| Post | Result |
|---|---|
| old boot id, `seq = last_seq + 1` (router not restarted) | 200 `duplicate:false` |
| same `batch_id` again (lost ACK) | 200 `duplicate:true` |
| new boot id, `seq = 1` (router restarted, the real case) | 200 `duplicate:false` |
| new boot id, `seq = 2` | 200 |
| revoked row | 401 |

`check_state` (`store.py`): duplicate by `batch_id` first, then `|sent_ts - now|` <= 300 s, then
`seq > last_seq` if the boot id matches; a different boot id is accepted if `sent_ts >=
last_sent_ts`. The collector re-stamps `sent_ts` on every attempt (`sender.rs:119`), so spooled
batches are accepted late. Because Tower's ingest is idle before the backup, nothing the router got
ACKed is missing from the restored `batches` table.

## 8. Rehearsal timings (standby only; one full pass, wall clock per stage)

| Stage | Seconds | Note |
|---|---|---|
| S1 final backup of Tower inventory+overrides (read-only) | 0.5 | no lock on Tower |
| S2 ship both files to the standby (pipes) | 1.6 | LAN |
| S3 stop pipeline + api + ingest | 11.7 | pipeline 10.6 (ignores SIGTERM, section 12), api 0.5, ingest 0.5 |
| S4 replace volume contents (`podman unshare`) | 0.3 | ownership 10001, no sidecars, raw emptied |
| S5 revoke collector (rehearsal only, not in the real cutover) | 0.5 | |
| Start ingest -> TLS answering | 0.9 | ON the critical path |
| Start api -> `/healthz` 200 | 0.9 | |
| Start pipeline -> container healthy | 31.6 | podman health interval; NOT on the critical path |
| Whole rehearsal T0 -> all healthy | 48.2 | includes 1 s of test cleanup |

Data critical path (S1+S2+S4+start ingest): about 3.3 s, plus 1.2 s of stop when the SIGTERM fix
is in place. Add the Tower drain wait (<= about 60 s) and operator time. A second full pass (after
the identity tests) reproduced stop and replace within 0.2 s. Taking the backup does not touch
Tower's live stack.

## 9. Rollback

Decision point: if the standby has not accepted a `200` within 5 minutes of Step 2, roll back.

Cost, stated plainly: the router restarts again, so the RAM spool is discarded a second time
(up to about 12-20 batches), and anything the standby accepted after Step 5 is not on Tower. No
Tower data is ever modified by the cutover, so Tower is exactly as it was at Step 3.

1. Tower, start in this order and check each:
   ```sh
   systemctl --user start <tower-namespace>-ingest.service
   systemctl --user start <tower-namespace>-api.service <tower-namespace>-pipeline.service
   systemctl --user start vigie-ntfy-sender.timer
   ```
   Verify: `podman ps` healthy x3; `curl -sk -o /dev/null -w '%{http_code}\n' https://<tower-ingest-addr>/v1/batch` = 405.
2. Router: restore `/etc/vigie/collector.conf.pre-cutover` (only `server_url` and `pin2` differ; `pin1`
   was never changed) and `/etc/init.d/vigie-collector restart`.
3. Verify on Tower: ingest journal shows `POST ... 200` within 5 minutes; the collector row has a
   new `boot_id`, small `last_seq`, `revoked=0`, rising `last_sent_ts` (the new boot is accepted
   because `sent_ts` is newer); pipeline cursor equals max batch rowid after two cycles; delivery
   file unchanged by the rollback; `/coverage` backlog 0.
4. Standby: make it a stale standby again: `admin revoke <collector-id>` on its inventory (or
   restore a fresh copy later); `delivery` stays off, timer disabled. Standby data accepted during
   the attempt is discarded by the next restore.

Rehearsed: the standby side of "return to stale standby" (revoke, services healthy). The Tower
and router steps were not run (hard rule); they are plain starts of existing units.

## 10. Verification checklist

After Step 2: router accepted the config; standby shows 401s, Tower shows none.
After Step 3: Tower pipeline cursor == max rowid; Tower units stopped.
After Step 5, on the standby:
- `podman ps`: ingest, api, pipeline healthy.
- `curl -sk -o /dev/null -w '%{http_code}\n' https://<standby-api-addr>/ui/` = 200 and `/healthz` = 200.
- Inventory (read-only one-shot container): `pragma quick_check` = ok, `user_version` = 5,
  collector row active with Tower's final `last_seq` and `key_id`, `batches` count and `devices`
  count equal to Tower's at the backup (the standby ingest's startup retention may purge `batches`
  rows older than 7 days: counts can be lower by that amount, rowids are unchanged).
- `delivery_eligible_since` equals Tower's (rehearsal: equal, from the same backup).
- `GET /coverage?collector_id=<collector-id>` with a temporary API token
  (`python -m vigie_api tokens create --id cutover-check`, revoke afterwards): `ok:true`,
  `backlog_batches` 0, `last_seq` rising, `dropped_batches_since` accounting as expected. Note
  that `coverage` requires `collector_id`.
- Pipeline journal: `run_complete` every 30 s, no `overrides_unreadable` after the first pass.
- Collector-side: new `boot_id` in the collector row, `seq` counting from 1, spool depth falling
  to 0 in `health.spool_batches`, no further 401.
- The control app works against the standby API with its existing token (tokens come with the
  restored `overrides.db`).

## 11. ntfy on the standby (after verification, in this order)

Tower's sender timer and Tower's pipeline must already be stopped (Step 3) so no message is sent
twice. Incident delivery state lives in `inventory.db` (`incident_deliveries`) and the permanent
`delivery_eligible_since` watermark came with the backup, so incidents Tower already delivered are
not resent and older ones stay unannounced. The sender cursor file identifies the delivery file by
inode, first line and size and restarts at 0 on a replaced file (`ntfy_sender.py read_chunk`), so a
new `delivery-messages.jsonl` needs no cursor reset; delete a stale cursor only if the sender
reports it corrupt.

1. Pipeline delivery env: add to `vigie_standby-pipeline.container`
   `Environment=VIGIE_DELIVERY_ENABLED=1` and `Environment=VIGIE_DELIVERY_FILE=/inv/delivery-messages.jsonl`,
   then `systemctl --user daemon-reload && systemctl --user restart vigie_standby-pipeline.service`.
2. Wait two pipeline passes; check the file exists in the inventory volume
   (`podman unshare test -r <path> && echo ok`) and `wc -l` is small (only post-watermark
   incidents). A large count means stop and investigate before step 3.
3. Sender: `systemctl --user enable --now vigie-ntfy-sender.timer`. The timer unit, config and the 0600
   topic file are already installed; the config's `delivery_file` is the host path of the file in step 2.
4. Verify one `systemctl --user start vigie-ntfy-sender.service` pass exits 0 or 5 (caught up).

To turn it off again: disable the timer first, then remove the two env lines and restart the pipeline.

## 12. Boot survival and graceful stop

Boot: the quadlets have `WantedBy=default.target`; confirm user linger for the service account
(`loginctl show-user vigie -p Linger`) and reboot once in a quiet window; it is not rehearsed here.

SIGTERM: PID 1 is the Python process (`deploy/entrypoint.sh:40` ends in `exec "$@"`, so the shell is
not the problem). The kernel does not deliver a signal with default disposition to PID 1, and the
pipeline loop handles only `KeyboardInterrupt` (`vigie_pipeline/cli.py:98`); ingest and api run
under uvicorn, which installs its own handlers (they stop in 0.5 s). Result: `podman stop` waits
the 10 s timeout, SIGKILL, exit 137, the unit ends `failed`. Measured with throwaway containers:

| Variant | Stop time | Exit |
|---|---|---|
| default (SIGTERM) | 10.08 s | 137 |
| `--stop-signal=SIGINT` | 0.08 s | 0, log `stopped`, `held.close()` ran |
| `--init` | 0.07 s | 143 (killed, unit would show failed) |

Proposed fix (not applied to any live unit): in the pipeline quadlet add
`PodmanArgs=--stop-signal=SIGINT`. The generator of Podman 4.9.3 accepted it in a dry run; the
`StopSignal=` key is NOT supported there. A code change (a SIGTERM handler in `cli.py` that raises
`KeyboardInterrupt`) is the durable alternative.

## 13. Risks and unknowns

- Router edit is not rehearsed (hard rule). The `--check` invocation and the init path are from the
  repo templates, unverified on the device. A typo costs one rollback.
- Router restart costs: the in-progress window and the first-minute probe batch are lost.
  After a restart, `dropped_batches` history is reset to 0 on the router.
- Batch size is an estimate (section 4); check the router's reported `spool_batches` in health
  during the window for the real depth.
- The standby ingest image is newer than Tower's ingest; behaviour on live traffic is verified
  only with synthetic traffic and the signer-library tests above.
- Control app trust anchor changes (standby API certificate differs); API clients that pin it fail
  until updated.
- Two ingests must never run for one collector. Keep Tower's ingest stopped after the cutover.
- `/coverage` and the GUI show the data only from the restored backup onward for raw-derived detail
  (no shard history on the standby).
- Rehearsed the cutover once with a fresh Tower backup and twice for the restore itself. Human time
  per step is not measured.
- Fixed wall-clock figures come from a LAN-local VM with a warm image; a cold disk or a loaded
  host would be slower.
