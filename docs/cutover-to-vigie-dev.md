# Cutover runbook: moving the Vigie server from <old-host> to the <new-host>

Status: rehearsed on 2026-11-02 (UTC) against the standby (router untouched, <old-host> only read).
Placeholders: `<tower-ingest-addr>` and `<standby-addr>` (LAN address and published port of each
ingest), `<standby-api-addr>`, `<collector-id>`, `<key-id>` (the collector row's `key_id`; the
HMAC secret is `collector_key_<key-id>`), `<standby-uid>` (numeric uid of the standby's service
account). No real address, name or secret belongs in this file.

## 1. Purpose and the one rule that shapes the order

Move ingest, pipeline and api from the <old-host> rootless stack to the standby quadlets, keeping the
inventory, overrides (labels, links, API tokens) and the collector identity, with the router
losing as little data as possible.

**The collector cannot reload its config.** It has no SIGHUP handler (`collector/agent/src/main.rs:10`,
default SIGTERM action). Any edit of `/etc/vigie/collector.conf` needs
`/etc/init.d/vigie-collector restart`. A restart discards the RAM spool and the unreported
`dropped_batches` counter (`spool.rs:1`, `sender.rs`), picks a new random `boot_id` and restarts `seq`
at 1 (`main.rs:321-340`). So the order "stop <old-host>, back up, restore, start standby, change router
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

| Option | Router fields that change | <old-host> key leaves <old-host> | Rollback |
|---|---|---|---|
| 1. Reuse <old-host> cert+key on the standby | `server_url` | yes (copy of a TLS private key) | `server_url` |
| 2. New cert, replace `pin1` | `server_url`, `pin1` | no | `server_url` and `pin1` (<old-host> pin must be restored) |
| **3. New cert, keep `pin1`, set `pin2` = standby pin** | `server_url`, `pin2` | no | `server_url` only (`pin1` still <old-host>) |

Chosen: **option 3**. One edit and one collector restart, the old host's private key never moves, and a
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
   a strict run; the soak monitor also fails with `ingest_address_unbound` once <old-host> stops
   publishing. Stop the soak unit on <old-host> first.
2. Standby is up and healthy, `delivery` off, sender timer disabled.
3. Standby images equal the old host's api/pipeline image. Note that the old host's ingest may run an older
   image than the standby's; the standby ingest then migrates the restored inventory on open.
   Rehearsal restored the old host's schema (user_version 5) onto the newer image without a problem.
4. Real HMAC key staged on the standby, BEFORE the window (it is moved through a pipe, never
   printed or written to disk outside the secret store). <old-host> side name is
   `<old-namespace>_collector_key_<key-id>`:
   ```sh
   # run on <old-host>; stdin of the ssh command receives the key
   podman secret inspect --showsecret --format '{{.SecretData}}' <old-namespace>_collector_key_<key-id> \
     | ssh <standby-ssh> 'sudo -n -u <service-user> env XDG_RUNTIME_DIR=/run/user/<standby-uid> HOME=/home/<service-user> \
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
**the standby must be ready (restored, ingest healthy) within about 7 minutes of the router restart
(p95); plan on 5.** The first `200` can come later than readiness: retries are 5, 10, 20, 40, 80, 160 s
(jittered, each between half and full), then 150-300 s apart, so a perfect restore may see its first
`200` at T0+5.3 min or up to about T0+10 min. Beyond that, the oldest windows are dropped (counted, not silent), and the
soak-style "fresh dropped batches" gate would fail. The measured technical path is under 30 s
(section 8); the rest is operator time.

## 5. Sequence

Run <old-host> commands on <old-host>, standby commands as the service account:
`S='sudo -n -u <service-user> env XDG_RUNTIME_DIR=/run/user/<standby-uid> HOME=/home/<service-user>'`.

**Step 1: pre-flight (T-10 min).**
- Old host: `podman ps` shows ingest/pipeline/api healthy; ingest log shows ~1 POST per minute.
- Standby: `$S podman ps` healthy; `curl -sk -o /dev/null -w '%{http_code}\n' https://<standby-addr>/v1/batch` prints 405.
- Standby must be INERT: its collector row has `revoked=1` (query `select revoked from collectors`
  with a read-only one-shot container) AND a signed post for `<collector-id>` currently returns 401.
  Why both: an idle standby answers 401 because the HMAC fails with no key (`app.py:126-127`); the
  revoked flag only matters once a key is mounted. Ingest has `Restart=on-failure`
  (`deploy/persistent/render.py:159-161`): if the key is mounted and the row is active, it starts
  accepting real batches BEFORE the restore, and the Step 5 wipe would destroy batches the router
  already had ACKed. So mount the key only in Step 5 (move the `Secret=` line and the
  `daemon-reload` from prerequisite 4 into Step 5), or keep the row revoked until the restore.
- Old host's ntfy sender has caught up (cursor offset equals delivery file size).
- Stop here if any check fails.

**Step 2: flip the router (T0).** Immediately before the edit, re-check that the router queue is
empty (latest batch `health.spool_batches` == 0 in the old host's inventory): anything in the spool at
restart is discarded. On the router (edit as documented in `docs/deploy.md`, "Rotating the server
certificates"; copy files with `scp -O`, no sftp on OpenWrt):
```sh
cp /etc/vigie/collector.conf /etc/vigie/collector.conf.pre-cutover
# edit /etc/vigie/collector.conf: server_url=https://<standby-addr>/v1/batch
#                                 pin2=<standby pin from section 2>   (pin1 stays the old host's)
# --check must NOT run as root (exit 77 before --check is handled, main.rs:301-315). Run it as the
# dedicated account through the audited helper, exactly as the init script does (vigie-collector.init:52):
/usr/bin/vigie-privdrop "$(id -u vigie)" "$(id -g vigie)" /usr/bin/vigie-collector --config /etc/vigie/collector.conf --check
# prints "config and key ok"; unverified on the device (the key file is 0600 owned by that account)
/etc/init.d/vigie-collector restart
```
`collector_id`, `key_id` and `/etc/vigie/key` do not change. Record the time.
- Check: the old host's ingest journal shows no new POST; the standby journal shows `401` responses,
  sparse because of the backoff (a few in the first minutes, then one every 2.5-5 min). No `200`, no
  TLS error. If the router logs TLS/pin failures instead, fix `pin2` or roll back now (section 9).

**Step 3: drain and freeze the old host.** Order matters. A delivery is only a file append plus a
`sent` mark in `inventory.db` (`delivery_runner.py:253-262`, `delivery_publish.py:163-181`); the mark
is restored onto the standby, and Step 5 deletes the delivery file. Any line appended after the
sender's last run would be marked sent and never delivered. The pipeline sets its cursor before the
monitoring and delivery stages run (`processor.py:64-75`), so cursor == max rowid is NOT a full drain.
1. Stop the old host's INGEST first (the router already moved):
   `systemctl --user stop <old-namespace>-ingest.service`.
2. Wait until the pipeline cursor equals max rowid AND at least one complete `run_complete` log line
   appeared AFTER that point (pipeline interval is 30 s, so allow about 60 s):
   ```sh
   podman run --rm --network none --user 0:0 --entrypoint python \
     -v <old-namespace>_inv:/inv:ro localhost/vigie-server:<tag> -c '
   import sqlite3; c=sqlite3.connect("file:/inv/inventory.db?mode=ro",uri=True)
   print(c.execute("select last_batch_rowid from pipeline_cursor").fetchone()[0],
         c.execute("select max(rowid) from batches").fetchone()[0])'
   # container names use an underscore (<old-namespace>_pipeline); service names a hyphen
   podman logs --since 2m <old-namespace>_pipeline | grep -c run_complete
   ```
3. Stop the pipeline, SIGINT ONLY during its idle wait. The images running on the old host predate
   the graceful-shutdown work: the pipeline ignores SIGTERM (PID 1, section 12), and a SIGINT that
   arrives while a pass is running raises `KeyboardInterrupt` out of the worker join, which can
   leave a delivery in `sending` for its 300 s lease (the standby would re-send it). So:
   - Watch `podman logs -f --since 1m <old-namespace>_pipeline` for a fresh `run_complete` line
     (loop interval 30 s). Right after it, the loop sleeps: send
     `podman kill --signal SIGINT <old-namespace>_pipeline` then
     `systemctl --user stop <old-namespace>-pipeline.service`.
   - If a pass is in progress (no `run_complete` yet since the last start of work), wait for the next
     `run_complete`; never signal mid-pass.
   - Verify the log shows `stopped` (clean exit 0) and that no `sending` rows remain (query in
     item 7). Never rely on the 10 s SIGKILL: it can also leave a partial JSONL line at the end of
     the old delivery file.
   - Once `stopped` is confirmed: if `podman logs <old-namespace>_pipeline` (no `--since`, so the
     whole container life) contains any `delivery_publish_timeout`, an abandoned publisher thread
     can have left a partial JSONL line. The file is 0600 in a 0700 dir owned by a host subuid, so
     read it through `podman unshare`: `podman unshare tail -c1 <delivery-file> | od -An -tx1` must
     print `0a`; if not, stop and investigate.
   - Do NOT rely on a plain `systemctl --user stop` to drain. `podman stop` defaults to 10 s and
     `TimeoutStopSec=45` does not lengthen it, while a drain can need about 90 s. A plain stop drains
     only once the pipeline runs with `--stop-timeout` >= 120 (`PIPELINE_STOP_TIMEOUT_S = 120`,
     branch `fix/stopsignal-sigint`, NOT yet merged). Until then use the SIGINT-in-idle-window
     procedure above only.
4. Run the old sender ONCE and confirm it caught up. First record the cursor offset (the `offset` in the
   JSON file named by `cursor_file` in the sender config; needed for invalid-record recovery, section 11)
   and set the journal window: `start=$(date '+%Y-%m-%d %H:%M:%S')`. Then
   `systemctl --user start vigie-ntfy-sender.service`, then read the exit code with
   `systemctl --user show vigie-ntfy-sender.service -p ExecMainStatus` (the unit has no
   `SuccessExitStatus`, so exit 5 shows the unit as failed). Decide per the exit-code table in
   section 11 (exit 0 also needs no `skipping invalid record` / `records skipped` line in the sender
   journal for this run: `journalctl --user -u vigie-ntfy-sender.service --since "$start"`; timer-fired runs in the same window also appear until the timer is disabled), and the cursor offset must equal the delivery file size (`cursor.json` offset vs
   `podman unshare stat -c %s <delivery-file>`; a plain host `stat` is denied).
5. Then `systemctl --user disable --now vigie-ntfy-sender.timer` and
   `systemctl --user stop <old-namespace>-api.service`.
6. Keep the old units from coming back on a reboot (`WantedBy=default.target` is in the `[Install]`
   section of each quadlet SOURCE, `render.py:166`; `deploy/persistent/README.md:24`). The services
   are GENERATED by the quadlet generator, so `systemctl --user disable` does not apply to them
   (it printed nothing and changes no link on the standby; the generator creates the
   `default.target.wants` link from the source). Instead, for each of ingest, pipeline, api, in
   `~/.config/containers/systemd/`:
   ```sh
   cp -p <old-namespace>-ingest.container <backup-dir>/            # keep the original for rollback
   sed -i '/^\[Install\]/,$d' <old-namespace>-ingest.container    # [Install] is the last section
   # same for -pipeline.container and -api.container, then:
   systemctl --user daemon-reload
   ```
   Verified on the standby (its api unit, restored afterwards): after removing `[Install]` and
   `daemon-reload`, `systemctl --user list-dependencies default.target` no longer lists the unit
   and the generator's `default.target.wants` no longer links it; a running unit keeps running.
   The sender's timer and service are PLAIN unit files (not generated), so
   `systemctl --user disable --now vigie-ntfy-sender.timer` is correct for them (verified on the
   standby: enable creates and disable removes the `timers.target.wants` link). Rollback restores
   the saved sources (section 9).
7. Check no delivery row is in flight (must print 0; add to the section 10 checklist). Every
   database is now closed cleanly and its `-wal`/`-shm` sidecars are gone, so a plain `mode=ro`
   open FAILS on the read-only mount (`unable to open database file`; reproduced on the standby for
   both databases; same cause as `server/tests/test_ro_mount_wal.py:34-43`). Use `immutable=1`,
   which skips locking and WAL handling. That is safe ONLY because the writers are confirmed
   stopped and no non-empty `-wal` exists (an immutable open ignores a WAL, so any left-over WAL
   would silently lose data; the helper below refuses if one is present):
   ```sh
   podman run --rm --network none --user 0:0 --entrypoint python \
     -v <old-namespace>_inv:/inv:ro localhost/vigie-server:<tag> -c '
   import sqlite3, os
   w = "/inv/inventory.db-wal"
   assert not (os.path.exists(w) and os.path.getsize(w)), "non-empty WAL: a writer is still running or crashed"
   c = sqlite3.connect("file:/inv/inventory.db?mode=ro&immutable=1", uri=True)
   print(c.execute("select count(*) from incident_deliveries where state=\"sending\"").fetchone()[0])'
   ```
   (`state` is a column of `incident_deliveries` with values including `pending` and `sending`,
   `schema.py:269-283`; the query ran on the standby and returned 0.)
Take the final backup only after all of this. Volumes and secrets stay untouched; remove nothing.

**Step 4: final backup (read-only on <old-host>) and ship.** Same rule as above: the databases are
cleanly closed, so open them with `immutable=1` (chosen over mounting the volumes rw: it needs no write
access to the live volumes, and the helper refuses a non-empty WAL). The SQLite backup API still
produces a consistent single-file copy.
```sh
mkdir -m 700 <scratch>
podman run --rm --network none --user 0:0 --entrypoint python \
  -v <old-namespace>_inv:/inv:ro -v <old-namespace>_overrides:/ov:ro \
  -v <scratch>:/out:rw,Z localhost/vigie-server:<tag> -c '
import sqlite3, os
for s, d in (("/inv/inventory.db","/out/inventory.db"), ("/ov/overrides.db","/out/overrides.db")):
    w = s + "-wal"
    assert not (os.path.exists(w) and os.path.getsize(w)), "non-empty WAL: " + s
    a = sqlite3.connect(f"file:{s}?mode=ro&immutable=1", uri=True); b = sqlite3.connect(d); a.backup(b); b.close(); a.close()
    os.chmod(d, 0o600)
    c = sqlite3.connect(d); print(s, c.execute("pragma quick_check").fetchone()[0], c.execute("pragma user_version").fetchone()[0])'
```
Expect `ok` and the schema versions (rehearsal on the stopped standby: inventory `ok` 5, overrides `ok` 9).
Then ship both files through a pipe:
```sh
# run on the old host; the local shell expands $f, the remote command runs as the service user
for f in inventory.db overrides.db; do
  cat <scratch>/$f | ssh <standby-ssh> "sudo -n -u <service-user> env XDG_RUNTIME_DIR=/run/user/<standby-uid> HOME=/home/<service-user> bash -c 'umask 077; cat > /home/<service-user>/deploy/restore/$f'"
done
```
Use the SQLite online backup (WAL database; never copy the file). Check: sizes plausible
(rehearsal: about 8.0 MB and 0.18 MB, 0.5 s and 1.6 s).

**Step 5: restore on the standby and start (the data critical path).** First mount the real key
(prerequisite 4: `Secret=` line plus `daemon-reload`) while the services are stopped, so ingest never
runs with an active row and a key before the restore.
```sh
$S systemctl --user stop vigie_standby-pipeline.service vigie_standby-api.service vigie_standby-ingest.service
$S podman unshare bash -c '
V=/home/<service-user>/.local/share/containers/storage/volumes; set -e
cd $V/vigie_standby_inv/_data;       rm -f inventory.db inventory.db-wal inventory.db-shm delivery-messages.jsonl
cp /home/<service-user>/deploy/restore/inventory.db .; chown 10001:10001 inventory.db; chmod 600 inventory.db
cd $V/vigie_standby_overrides/_data; rm -f overrides.db overrides.db-wal overrides.db-shm
cp /home/<service-user>/deploy/restore/overrides.db .; chown 10001:10001 overrides.db; chmod 600 overrides.db
cd $V/vigie_standby_raw/_data;       rm -f raw-*.db raw-*.db-wal raw-*.db-shm .ingest.lock'
$S systemctl --user start vigie_standby-ingest.service        # accepting about 1 s later
$S systemctl --user start vigie_standby-api.service           # wait for /healthz 200, then:
$S systemctl --user start vigie_standby-pipeline.service
```
Delete stale `-wal`/`-shm` sidecars: a stale WAL would replay onto the new file. The restored
collector row is active with the old host's `last_seq`/`boot_id`: do NOT run `admin provision --force`
(it zeroes `last_seq`, `boot_id` and `last_sent_ts`, section 7). Start the api before the
pipeline: the pipeline's first pass can log `overrides_unreadable` if the api's overrides keeper is
not open yet (harmless, one pass, but it also skips stitching once).
- Check: ingest TLS answers 405 within seconds; within the collector's next retry (<= 5 min) the
  ingest journal shows `POST ... 200`.

**Step 6: verify (checklist in section 10).** Then remove the transfer copies:
`rm -f /home/<service-user>/deploy/restore/*` and `<scratch>/*` (household data), keep nothing.

**Step 7: after the bake-in.** <old-host> stays stopped but intact (units not removed) until you decide
to retire it. Do not start <old-host> ingest again while the router points at the standby (two ingests
on one collector fork the sequence state).

## 6. Raw shards: copy or not

Tested. The pipeline needs no historical shards: with the restored inventory and an EMPTY raw
volume the pipeline ran clean passes, stitching included (`overrides` readable), and `/coverage`
reported `backlog_batches` 0. Shard reads happen only for batches past the pipeline cursor
(`processor.py:157`, `measurements.py`). **But**: a batch that is still pending at backup time
and whose shard file is missing is consumed with zero MACs and the cursor advances
(`sources.py:read_batch` skips a missing file). Test: cursor rewound by 2 in a scratch copy, empty
raw: `batches 2, macs 0`, cursor advanced, no error. So draining the old host's pipeline (Step 3) is
mandatory, not cosmetic. Not copying raw also respects "never back up raw shards"
(`docs/deploy.md`, Backups): per-client DNS history stays on <old-host> and expires by retention.

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
  continue the old host's.
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
batches are accepted late. Because the old host's ingest is idle before the backup, nothing the router got
ACKed is missing from the restored `batches` table.

## 8. Rehearsal timings (standby only; one full pass, wall clock per stage)

| Stage | Seconds | Note |
|---|---|---|
| S1 final backup of <old-host> inventory+overrides (read-only) | 0.5 | no lock on <old-host> |
| S2 ship both files to the standby (pipes) | 1.6 | LAN |
| S3 stop pipeline + api + ingest | 11.7 | pipeline 10.6 (ignores SIGTERM, section 12), api 0.5, ingest 0.5 |
| S4 replace volume contents (`podman unshare`) | 0.3 | ownership 10001, no sidecars, raw emptied |
| S5 revoke collector (rehearsal only, not in the real cutover) | 0.5 | |
| Start ingest -> TLS answering | 0.9 | ON the critical path |
| Start api -> `/healthz` 200 | 0.9 | |
| Start pipeline -> container healthy | 31.6 | podman health interval; NOT on the critical path |
| Whole rehearsal T0 -> all healthy | 48.2 | includes 1 s of test cleanup |

Data critical path (S1+S2+S4+start ingest): about 3.3 s, plus a short stop once a graceful-stop fix
is deployed. Add the <old-host> drain wait (<= about 60 s) and operator time. A second full pass (after
the identity tests) reproduced stop and replace within 0.2 s. Taking the backup does not touch
the old host's live stack.

## 9. Rollback

Decision point: do NOT wait for a first `200` (see section 4: it can legitimately arrive up to about
T0+10 min). Decide at Step 5 completion + 300 s + margin, and check readiness instead: key mounted,
collector row active (`revoked=0`), ingest healthy, TLS answering 405. If ready but no `200` after
that, look at the router log before rolling back.

Cost, stated plainly: the router restarts again, so the RAM spool is discarded a second time (up to
about 12-20 batches). **Data accepted only by the standby is lost on rollback; there is no merge.**
The old host's data is untouched by the cutover, so it is exactly as at Step 3.

1. Standby first, in this order:
   (a) Check the standby `incident_deliveries` table (read-only container, section 11) for
   `sending`=0 and `pending`=0 while the pipeline is still running. Any `pending` (including backoff) or
   `sending` row is NOT shipped by the rollback: it is lost with the standby, like all standby-only
   data. Wait until both are 0, or accept and record the loss in writing before continuing. This result
   is provisional: a row can still be planned between (a) and (b), and delivery runs only inside the
   pipeline (`processor.py:71-74`), so it is lost after the stop.
   (b) Stop the pipeline so nothing can append after the sender reaches EOF: use the idle-window SIGINT
   procedure of section 3 (watch for `run_complete`, then `podman kill --signal SIGINT` and
   `systemctl --user stop`) and confirm the log shows `stopped`. Then REPEAT the (a) query: this second result is the one that
   counts. If `pending` or `sending` is not 0, write the loss down. A plain stop is a 10 s SIGKILL until
   `fix/stopsignal-sigint` is merged (section 3, item on stopping) and can leave a `sending` row and a
   partial JSONL line. Removing the two `VIGIE_DELIVERY_*` env lines is optional once it is stopped.
   (c) Partial-line check before the final sender run: `podman unshare tail -c1 <delivery-file> | od -An -tx1`
   must print `0a`; if not, stop and investigate. Skip it when the delivery file is absent (the publisher
   creates it only on the first publish, section 11) and the repeated (a) query shows no deliveries to drain.
   File absent and rows still pending: the loss is already recorded in (b), skip.
   (d) Run the standby sender once (`systemctl --user start vigie-ntfy-sender.service`) against the
   now-stable file: cursor == file size, exit per the section 11 table. Record the cursor `offset` and set
   `start=$(date '+%Y-%m-%d %H:%M:%S')` just before the start and check the journal for this run only
   (`journalctl --user -u vigie-ntfy-sender.service --since "$start"`; timer-fired runs in the same window
   also appear until the timer is disabled).
   (e) Then stop the sender timer (plain unit: `systemctl --user disable --now vigie-ntfy-sender.timer`),
   so no duplicate alerts; then `admin revoke <collector-id>` and remove the key `Secret=` line.
2. Old host: restore the saved quadlet sources (the generated units cannot be `enable`d), then start
   in this order, checking each. `reset-failed` clears a start-limit hit (5 starts per hour, which
   repeated starts trip):
   ```sh
   cp -p <backup-dir>/<old-namespace>-{ingest,pipeline,api}.container ~/.config/containers/systemd/
   systemctl --user daemon-reload && systemctl --user reset-failed '<old-namespace>-*'
   systemctl --user enable --now vigie-ntfy-sender.timer      # plain unit
   systemctl --user start <old-namespace>-ingest.service
   systemctl --user start <old-namespace>-api.service <old-namespace>-pipeline.service
   ```
   Verify: `podman ps` healthy x3; `curl -sk -o /dev/null -w '%{http_code}\n' https://<tower-ingest-addr>/v1/batch` = 405.
3. Router: restore `/etc/vigie/collector.conf.pre-cutover` (only `server_url` and `pin2` differ; `pin1`
   was never changed) and `/etc/init.d/vigie-collector restart`.
4. Verify on the old host: ingest journal shows `POST ... 200` (allow up to about 10 min for the first
   one); the collector row has a new `boot_id`, small `last_seq`, `revoked=0`, rising `last_sent_ts`;
   pipeline cursor equals max batch rowid after two cycles; `/coverage` backlog 0.

Rehearsed: the standby side (revoke, services healthy). The old-host and router steps were not run
(hard rule); they are source restores, `daemon-reload` and starts of existing units.

## 10. Verification checklist

After Step 2: router accepted the config; standby shows 401s, <old-host> shows none.
After Step 3: <old-host> pipeline cursor == max rowid; <old-host> units stopped.
After Step 5, on the standby:
- `podman ps`: ingest, api, pipeline healthy.
- `curl -sk -o /dev/null -w '%{http_code}\n' https://<standby-api-addr>/ui/` = 200 and `/healthz` = 200.
- Inventory (read-only one-shot container): `pragma quick_check` = ok, `user_version` = 5,
  collector row active with the old host's final `last_seq` and `key_id`, `batches` count and `devices`
  count equal to the old host's at the backup (the standby ingest's startup retention may purge `batches`
  rows older than 7 days: counts can be lower by that amount, rowids are unchanged).
- `delivery_eligible_since` equals the old host's (rehearsal: equal, from the same backup).
- `GET /coverage?collector_id=<collector-id>` with a temporary API token
  (`python -m vigie_api tokens create --id cutover-check`, revoke afterwards): `ok:true`,
  `backlog_batches` 0, `last_seq` rising, `dropped_batches_since` accounting as expected. Note
  that `coverage` requires `collector_id`.
- No in-flight deliveries: `incident_deliveries` has 0 rows in state `sending` (old host before the
  backup, and standby after the restore).
- Pipeline journal: `run_complete` every 30 s, no `overrides_unreadable` after the first pass.
- Collector-side: new `boot_id` in the collector row, `seq` counting from 1, spool depth falling
  to 0 in `health.spool_batches`, no further 401.
- The control app works against the standby API with its existing token (tokens come with the
  restored `overrides.db`).

## 11. ntfy on the standby (after verification, in this order)

the old host's sender timer and the old host's pipeline must already be stopped (Step 3) so no message is sent
twice. Incident delivery state lives in `inventory.db` (`incident_deliveries`) and the permanent
`delivery_eligible_since` watermark came with the backup, so incidents <old-host> already delivered are
not resent and older ones stay unannounced. The sender cursor file identifies the delivery file by
inode, first line and size and restarts at 0 on a replaced file (`ntfy_sender.py read_chunk`), so a
new `delivery-messages.jsonl` needs no cursor reset; delete a stale cursor only if the sender
reports it corrupt.

1. Pipeline delivery env: add to `vigie_standby-pipeline.container`
   `Environment=VIGIE_DELIVERY_ENABLED=1` and `Environment=VIGIE_DELIVERY_FILE=/inv/delivery-messages.jsonl`,
   then `systemctl --user daemon-reload && systemctl --user restart vigie_standby-pipeline.service`.
2. Wait two pipeline passes, then decide with the delivery file and the sender cursor, not with
   the database alone: a delivery is marked `sent` as soon as it is appended to the file
   (`delivery_runner._complete()`), BEFORE the sender consumes it, so a healthy standby can have a
   non-empty file and zero pending/sending rows. The file is created only on the first publish
   (`delivery_publish.py:138-153`) and Step 5 deleted the old one. Run the sender once
   (record the cursor `offset` and set `start=$(date '+%Y-%m-%d %H:%M:%S')` BEFORE the run;
   `systemctl --user start vigie-ntfy-sender.service`, a manual start works while the timer is
   disabled) and read `cursor.json`. File size here means `podman unshare stat -c %s <delivery-file>`:

   | Delivery file | Sender cursor | Decision |
   |---|---|---|
   | absent | none | proceed (verified on the standby: exit 0, `delivery file does not exist yet`) |
   | present | `offset` == file size | caught up: proceed (subject to the exit code below) |
   | present | `offset` < size or run exited 4 | behind: stop; fix the sender (topic, network) before enabling the timer |

   Read the exit code (`ExecMainStatus`; `deploy/persistent/ntfy_sender.py:10-14`):

   | Exit | Meaning | Decision |
   |---|---|---|
   | 0 | caught up, OR another run holds the lock (nothing was sent), OR invalid records were skipped with a warning only (`ntfy_sender.py:697-699`, `:728`) | proceed only if cursor == file size AND the journal for this run (set `start=$(date '+%Y-%m-%d %H:%M:%S')` just before the start, then `journalctl --user -u vigie-ntfy-sender.service --since "$start"`; timer-fired runs in the same window also appear until the timer is disabled) has no `skipping invalid record` / `records skipped` line; if the sizes differ: (1) the lock was held, rerun; (2) more than `max_batch` (default 50, `ntfy_sender.py:279`, `:689`) records were pending: nothing is logged, rerun until cursor == size (budget exhaustion is exit 4, not 0); (3) the delivery file does not exist yet (`ntfy_sender.py:770-772`, journal `delivery file does not exist yet`): the size comparison itself fails, and an absent file means nothing to drain, which is valid; or (4) the file ends in a partial last line (the sender splits on newline only and reads only complete lines, `split_lines`, `ntfy_sender.py:487-490`): run the `podman unshare tail -c1 <delivery-file> \| od -An -tx1` check (must print `0a`). On a live file a missing `0a` can be an append in progress: re-check once after about 30 s before stopping; if still not `0a`, stop the pipeline per section 3 and investigate before rerunning |
   | 1 | unexpected internal error | stop; read the sender journal |
   | 2 | configuration, cursor or secret-file error | stop; fix config, topic file or cursor |
   | 3 | permanent publish failure, cursor NOT advanced past the record | stop; investigate the record and the server response |
   | 4 | retryable failure or run budget exhausted, cursor unchanged | behind: stop; fix topic or network, rerun |
   | 5 | caught up, but a server-rejected record was skipped: a permanently DROPPED notification | stop. The sender never logs a `delivery_id` or record text; take the offset from the journal line `record skipped permanently (rejected by the server) before offset N`, read the record ending at that offset from the delivery file (`podman unshare`), and re-send it manually. Do not treat as a pass |
   | any other value, or a signal (`podman unshare` failure, `TimeoutStartSec=300` kill) | stop; read the journal |

   Invalid-record recovery (exit 0 with `skipping invalid record before offset N`, `ntfy_sender.py:698`): the
   record was skipped, not sent. Use the `inventory.db` of the host whose sender just ran (the old host in
   section 3 step 4, before backup and restore; the standby here and in the rollback). Before each run,
   record the pre-run `offset` from the JSON file named by `cursor_file` in the sender config. Only the
   first `MAX_SKIP_LOGS` = 20 skips are logged (`ntfy_sender.py:53`, `:697`); skipped offsets beyond 20 are
   NOT in the journal, only a count in a `records skipped` line (`:719-722`). Re-parse the delivery file
   (`podman unshare`) from the pre-run offset to list every failing line with its end offset (`ok` lines
   are valid records; `<sender-dir>` is `deploy/persistent` of the checkout):

   ```sh
   podman unshare python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from ntfy_sender import parse_record
   pos = int(sys.argv[3]); f = open(sys.argv[2], "rb"); f.seek(pos)
   for line in f.read().split(b"\n")[:-1]:
       pos += len(line) + 1
       try: print("ok", parse_record(line).delivery_id)
       except ValueError as e: print("bad", pos, e)' <sender-dir> <delivery-file> <pre-run-offset>
   ```

   If this run's journal shows `delivery file was truncated or replaced` (`ntfy_sender.py:774`;
   `read_chunk` restarts at 0, `:459-462`, the section 11.2 case where Step 5 deleted the file but the
   cursor was kept), the recorded offset is stale: pass 0. (Tested on a synthetic file; a line over
   `MAX_LINE` is skipped with its whole chunk and is not listed here.)

   Most invalid records cannot be re-sent as-is: `parse_record` (`ntfy_sender.py:548-562`) rejects lines that
   are too long, not UTF-8, not JSON, not an object or the wrong shape, and the sender logs no
   `delivery_id`. `incident_deliveries` has no sent timestamp or file offset (`schema.py:269-283`). Rebuild by
   elimination: rows in state `sent` whose `delivery_id` is missing from every `ok` line above are the
   candidates. Their title and body text come from `delivery_publish.build_message` (`:103-110`,
   `TITLES`/`BODIES` at `:35-39`) using the incident label and id. Send the rebuilt notification by hand
   and write down that it was rebuilt. This is manual best effort, not an exact reconstruction. Do not
   proceed until every candidate is accounted for.

   Independently require zero `incident_deliveries` rows in state `sending`. The standby services
   are live (Keeper-held db), so use a plain `mode=ro` open, NOT `immutable=1` (which ignores the
   WAL; `server/tests/test_ro_mount_wal.py:23-31` shows a reader works while a writer holds a
   connection):
   `sqlite3.connect("file:/inv/inventory.db?mode=ro", uri=True)` in a read-only one-shot container. Absent-file acceptance is chosen over
   pre-creating an empty file, which needs `podman unshare` ownership surgery on a file the
   publisher owns.

   Positive control, once after step 1 (the pipeline must be able to create the file):
   `podman exec vigie_standby_pipeline sh -c 'test -w /inv && echo writable'` must print `writable`
   (verified on the standby; the volume is `drwx------ 10001:10001`). A wrong owner or mode after the
   restore breaks the publisher while passes still complete.

   Bounded progress check for `pending` rows. A pending row only proves intent: if the publisher
   cannot create or append the file, the row goes back to `pending` with a backoff while every pass
   still logs `run_complete`. Record, per row, `row_id, state, attempts, next_attempt_at` from
   `incident_deliveries` (`schema.py:266-283`; same read-only container). Backoff is 60 s doubling per
   failure, capped at 3600 s, `max_attempts` 6 (`config.py:99-101`, `delivery_plan.py:104-107`), so a
   failing row retries after 60 s, 120 s, 240 s. Wait about 5 minutes (a cycle is the 30 s sleep plus the pass time, so
   fewer than 10 passes may run) and query again, and grep the pipeline journal for the failure events:
   `delivery_publish_failed` (warning, `delivery_runner.py:247`), `delivery_publish_timeout`
   (error, `:244`), `delivery_transport_wedged` (error, `:205`), `delivery_incident_missing`
   (warning, `:271`) and `delivery_completion_lost` (warning, `:277`). An `aborted` attempt (the
   transmit window passed before the send) logs NOTHING, yet still counts as a failed attempt.
   `attempts` is incremented by the claim UPDATE (`delivery_sql.py:110`; `failure_statement` at `:179-190` only schedules the retry), so a rising `attempts` on a row
   that is not `sent` is a failed attempt, whether or not an event was logged.

   Precedence: a logged failure event for the row is an immediate FAIL. With no event, apply the table.
   The sleep comes after the WHOLE pass (`cli.py:97`; `--loop 30` is set at `render.py:129`), and a pass
   runs batch, stitch, sweep and monitoring before delivery and characterization and prune after it
   (`processor.py:65-76`). `_due` takes the oldest 20 rows, ordered `next_attempt_at,row_id`
   (`delivery_runner.py:289-291`, `max_per_run` 20). So the bound is a pass count, not seconds: the row
   must be `sent` within N `run_complete` log lines after its `next_attempt_at`, with
   N = ceil(due rows / 20) + 1, where "due rows" are those ordered before this one by `next_attempt_at,row_id`
   (including itself). N is a lower bound for a healthy publisher: `_drain` also stops on `drain_budget_s`
   (`delivery_runner.py:302`) and when `_reserve` returns None (`max_abandoned`, `:305-306`), so with a slow or
   stalled file append or volume (the pipeline only appends to the file, `delivery_publish.py`; ntfy is not
   involved) only about 2 rows per pass may be sent. For that case use N = ceil(due rows / 2) + 1. Cross-check only, conservative wall-clock ceiling:
   30 s + 2 x (90 s + measured non-delivery pass time), where 90 s = 60 s `drain_budget_s` + 30 s
   `transmit_deadline_s` (`config.py:98,106`): the budget is checked only before each claim
   (`delivery_runner.py:302`), so one drain can overrun it.

   | After 5 minutes, per eligible pending row | Decision |
   |---|---|
   | `state=sent` | pass |
   | still `pending`, `attempts` increased, NO failure event logged | wait: pass only if `sent` within N `run_complete` lines after `next_attempt_at` (`_due()` selects it only once that time is reached); otherwise FAIL as in the last row |
   | still `pending`, `attempts` unchanged, `next_attempt_at` in the future | not yet due: wait until `max(next_attempt_at)`, and require at least one restored or new row to reach `sent` before passing; no row reaching `sent` is not a pass |
   | still `pending`, `attempts` unchanged, row is due | FAIL: nothing was claimed, so delivery is not running. Besides the missing env lines, check for an unreadable overrides store (`if usable:`, `processor.py:71-74`, delivery is skipped) and the pipeline event `delivery_decisions_unavailable` (`delivery_runner.py:338-340`). Check that both `VIGIE_DELIVERY_*` lines are in the pipeline quadlet and that `daemon-reload` plus a pipeline restart followed |
   | still `pending` (or `failed`), `attempts` increased, and a failure event logged, or no `sent` within the pass-count bound (N = ceil(due rows / 20) + 1, or ceil(due rows / 2) + 1 when appends are slow) | FAIL: do not enable the timer. Likely cause: ownership or mode of the volume or delivery file after the restore (must be `10001:10001`, directory 0700, file 0600); check the positive control and `podman unshare ls -ln` on the volume |

3. Sender (plain unit): `systemctl --user enable --now vigie-ntfy-sender.timer`. The timer unit, config and the 0600
   topic file are already installed; the config's `delivery_file` is the host path of the file in step 2.
4. Verify one `systemctl --user start vigie-ntfy-sender.service` pass exits 0 with cursor == file size
   and no `skipping invalid record` / `records skipped` line in this run's journal (`start=$(date '+%Y-%m-%d %H:%M:%S')` before the start, `--since "$start"`; exit 5 means a dropped notification: see the section 11 exit-code table).

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

Fix: a stop-signal change is NOT the fix. `--stop-signal=SIGINT` / `STOPSIGNAL SIGINT` stop the idle
pipeline in 0.1 s (table above), but SIGINT cuts an in-flight delivery, so that approach was rejected.
The fix is real SIGTERM/SIGINT drain handlers in the pipeline (in progress in another change,
unverified here). Until an image with them is deployed on the old host, use the idle-wait SIGINT
procedure of Step 3 and avoid relying on the 10 s SIGKILL. Ingest and api (uvicorn) already stop in
0.5 s.

## 13. Risks and unknowns

- Rehearsal restarts trip the quadlets' start limit (`StartLimitBurst=5` per hour): use
  `systemctl --user reset-failed` before a start that reports `start-limit-hit`.
- Router edit is not rehearsed (hard rule). The `--check` invocation and the init path are from the
  repo templates, unverified on the device. A typo costs one rollback.
- Router restart costs: the in-progress window and the first-minute probe batch are lost.
  After a restart, `dropped_batches` history is reset to 0 on the router.
- Batch size is an estimate (section 4); check the router's reported `spool_batches` in health
  during the window for the real depth.
- The standby ingest image is newer than the old host's ingest; behaviour on live traffic is verified
  only with synthetic traffic and the signer-library tests above.
- Control app trust anchor changes (standby API certificate differs); API clients that pin it fail
  until updated.
- The old host's TLS key stays trusted as `pin1` on the router until the old host is retired; then
  rotate `pin1` to the standby's pin (docs/deploy.md rotation order).
- Two ingests must never run for one collector. Keep the old host's ingest stopped after the cutover.
- `/coverage` and the GUI show the data only from the restored backup onward for raw-derived detail
  (no shard history on the standby).
- Rehearsed the cutover once with a fresh <old-host> backup and twice for the restore itself. Human time
  per step is not measured.
- Fixed wall-clock figures come from a LAN-local VM with a warm image; a cold disk or a loaded
  host would be slower.
