# Persistent deployment and real 48-hour monitoring

These tools render plans and assess evidence; unit tests do not install services or complete a
48-hour run. Source is merged. The [2026-10-25 field report](../../docs/monitoring-field-status-2026-10-25.md)
records three healthy owned server roles, installed router files/account and the measured
20 MiB logfs capacity. Router logging and signed parsed-DNS delivery now work; corrected LAN
scope yields fresh source flags 0 and earlier flagged history is retained. Controlled drain and
stop/restart passed. Six owned boot links and the scoped root cron job are installed; a bounded
125-second ingest outage recovered with zero drops and drain to zero. PR12 processing-age source
and its API image are deployed and verified. Controlled drop-in repair and read-only-reconciled
helper respawn passed; natural rotation and cold-boot evidence remain pending. The metrics key is not installed and awaits
owner approval; the 48-hour monitor has not started.

## Rootless Tower units

`python3 deploy/persistent/render.py private-config.json private-new-output-directory` creates three `.container` files, three `.volume` files and an inert `plan.json`. The output directory must not exist. Required configuration contains `namespace` (dedicated `vigie_` prefix), `image` (reviewed local `sha256:` image ID), literal `ingest_address`, distinct unprivileged `ingest_port`/`api_port`, and `collector_key_id`. Optional `monitoring_large_upload_bytes` is a positive integer≤2**50 (default1073741824), passed only to the pipeline as `VIGIE_MONITORING_LARGE_UPLOAD_BYTES`. Optional `monitoring_baseline` is exactly `pooled` (default) or `tod`, passed only to the pipeline as `VIGIE_MONITORING_BASELINE`; switching it relearns every profile. Unknown configuration keys are rejected. No household address, hardware identifier or credential belongs in the repository.

The explicit ingest bind requires a verified stable DHCP reservation/name/certificate plan. API binds only 127.0.0.1. The existing three-volume permission matrix, user/group 10001, capability removal, read-only root, no-new-privileges and limits are retained. Each role receives only its secrets; provision the five exact names shown in the generated units before startup. Volumes and databases require reviewed initialization/enrollment before normal services start. The renderer does not silently migrate data from an earlier pilot namespace. Set the collector's separate [LAN scope](../../docs/deploy.md#collector-lan-scope) explicitly; a correct server bind does not configure multicast collection.

API and pipeline use `Wants` plus startup ordering, not a `Requires` job that can be permanently dependency-failed before their own restart policy runs. API inventory reads return unavailable until the writer recovers; the pipeline exits/retries until its schemas/keepers exist. Each service retains five bounded starts/hour. Exhausting that limit requires explicit operator repair, `reset-failed`, and restart of only the owned units; this is not a promise of indefinite automatic recovery. Native isolated failure/retry fixtures validate scheduling separately from actual application startup.

Minimum verified Podman is 4.9.3 (Ubuntu 24.04): the generator there rejects the `Memory=` quadlet key, so the memory limit is emitted as `PodmanArgs=--memory=512m --cpus=1` (identical `podman run` flags; Podman 5.x accepts both forms). Every other emitted key was accepted by 4.9.3, and a unit test pins the emitted keys to a 4.9 allowlist.

Quadlet files are inert until copied to a user generator search path. Validate with `QUADLET_UNIT_DIRS=/absolute/private/output /usr/lib/systemd/user-generators/podman-user-generator --user --dryrun`; then independently inspect generated arguments and collisions. Rootless Quadlet requires cgroup v2 and user linger. `[Install] WantedBy=default.target` supplies boot activation; do not `enable` generated transient services. Source: [Podman Quadlet documentation](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html). The renderer does not apply the plan. Installation requires exact existing unit contents/modes to be snapshotted, intended writes journaled before mutation, and conflicting resources or drift refused. Rollback stops only owned units, restores only matching snapshotted files, and retains data volumes/secrets/evidence.

## Strict real-clock monitor

`python3 deploy/persistent/run_soak.py private-config.json /private/new-or-resumable-directory/journal.jsonl --preflight` performs one observation and never reports 48-hour success. Remove `--preflight` only after reviewed deployment/recovery tests and healthy source/metric gates. It uses real wall, monotonic and boot-time clocks; there is no short-duration or fake-clock CLI option. A simulated engine result is labeled `simulated`, never real acceptance evidence.

The private 0600 config has exactly `api_port`, `api_token_file` (owned0600 bearer token), `api_ca_file` (TLS trust certificate covering 127.0.0.1), `collector_id`, `meter_executable` (fixed absolute no-argument executable), `meter_sha256`, `router_address` (the reviewed literal IPv4 router), plus optional `ingest_address` (the literal IPv4 the ingest container is published on; when present the run fails with `ingest_address_unbound` if it is not bound locally, see [monitoring](../../docs/monitoring.md)). An aborted run leaves a sticky `<journal>.ingest_address_unbound` marker that blocks resume until deleted. API is HTTPS loopback only; redirects are refused. The fixed UDP DNS probe asks only `example.com` A on port53, once per sample. Its successful response is separate from positive parsed-DNS window evidence within 120 seconds. DoH/DoT, caching and absent DHCP 55/60 remain visibility limits; DHCP fingerprint absence does not fail the resource monitor.

The meter runs without `SSH_AUTH_SOCK`, stdin or caller environment, with a 10-second timeout and 16 KiB output bound; its digest and file ownership/modes are checked. It must use a separately reviewed least-privilege runtime credential with a forced fixed read-only command. This repository does not provision that credential, use the 12-hour administrator agent, or accept arbitrary remote command strings. End-to-end authorization and live-service meter readings remain pending field gates. Missing meter data remains pending and cannot establish acceptance.

Meter execution requires native Linux `memfd` sealing, `/proc/self/fd`, `waitid(WNOWAIT)` and exclusive single-threaded child supervision with the default SIGCHLD disposition; unsupported environments fail closed. All source ancestors are opened without following symlinks and must be trusted; arbitrary writable parents are refused (trusted sticky temporary directories are permitted). The exact copied bytes are hashed and sealed against in-place writes before execution; pathname replacement cannot change the executed snapshot. Scripts must use fixed absolute resource paths, since `$0` names the sealed descriptor. The supervisor retains the leader PID until its process group is terminated, including when the leader exited before its children; only then is the leader reaped. Reviewed adapters must not daemonize or change sessions/process groups. This is supervision of a reviewed fixed adapter, not a sandbox for hostile arbitrary code. Native subprocess regressions run on the host; a container mapping trusted root directories to UID65534 will correctly refuse them rather than weaken ownership checks.

Processing acceptance uses `processing_backlog_age_s <= 180`, not raw backlog count equal to
zero. Raw count remains visible: a positive count with a fresh oldest receipt is normal handoff.
The API must provide exact `oldest_pending_received_at` and typed cap fields; zero backlog requires
null oldest receipt. Missing, capped, malformed or inconsistent receipt/count evidence is unknown
and cannot produce a pass. Future timestamps do not create a favorable age. Keep the original
raw count/caps alongside age; do not hide stalled receipts by relabeling them normal handoff.

The live meter's collector RSS is authoritative for resource acceptance. API coverage uses the exact `backlog_capped`/`summary_capped` booleans; absent or capped detail makes relevant counts unknown and blocks a favorable partial result. The API's older RSS report is retained separately as `api_collector_rss_kib` and cannot replace it. A resumed collection appends failure or missing evidence durably before applying gates, so retrying cannot silently omit that observation.

The meter returns one JSON object with the following fields only (other fields are discarded):

| Fields | Units/meaning |
|---|---|
| `router_boot_id` | Kernel boot identifier; must remain stable |
| `collector_start`, `helper_start` | `/proc` process start counters; stable across the run |
| `collector_cpu_ticks`, `total_cpu_ticks`, `logical_cpus` | Cumulative collector utime+stime; aggregate first eight `/proc/stat` CPU fields; logical CPU count |
| `collector_rss_kib`, `helper_rss_kib`, `mem_available_kib` | KiB, independently measured |
| `log_used_kib`, `log_capacity_kib` | Owned log-filesystem usage and proven capacity, KiB |

A runtime forced-command wrapper must reject supplied commands/arguments, check a fixed root-owned expiry deadline, verify fixed process executables/UIDs before reading counters, and expose only this schema. Its dedicated key must prohibit PTY, forwarding, agent and X11. Do not assume OpenSSH `restrict`/expiry key options exist on Dropbear. Root must review actual firmware behavior before key installation. The owned 20 MiB log tmpfs has passed mount and pre-writer capacity checks; consumer/recovery/reboot behavior remains a separate field gate. The monitor itself does not mount anything.

Acceptance requires 172800 actual seconds, 60-second cadence, maximum 180-second gap and ≥99% valid sample slots. Collector RSS is strictly below 9765 KiB; helper below 65536 KiB; available RAM at least 65536 KiB; log capacity/usage no more than 20480 KiB; collector average CPU ≤2% of one logical CPU using counter ratios. Unexpected restart, clock/suspend inconsistency, topology/counter reset, processing backlog age above 180 seconds, fresh dropped batches, source flags or hard resource violations fail. Missing metrics, DNS silence or stale parsed-DNS evidence block success; unmapped conntrack stays a visible attribution caveat. Historical drops are currently a strict zero gate, so start a new scoped healthy collector enrollment after resolving prior failures rather than hiding them.

Journals are locked, private 0600, append-only and fsynced, including directory creation. The journal contract is schema 2; schema-1 journals cannot resume under it. Resume requires the identical configuration hash/contract; partial records are retained and rejected. Failure evidence survives resume. Host reboot or a gap over 180 seconds invalidates the strict run; begin a separately recorded new run after recovery. Interrupting the runner leaves a pending report and durable history. Unit fixtures exercise these transitions with fake clocks, without claiming real elapsed time.

## Router startup state and recovery boundary

Install the new `vigie-state-dir.sh` with the other root-owned helpers before replacing the collector init/wrapper. Startup prepares `/var/run/vigie-collector-root` as trusted-root-owned0711, then its dedicated `vigie` UID/GID child `state` as0700. Only `state/fails` is unlinked to reset retry counting. Existing symlink/owner/mode mismatches or a directory at that leaf fail closed; no recursive removal, attribute repair of existing paths or deletion of unknown files occurs. The legacy `/var/run/vigie-collector` tree is preserved completely. This is an explicit new namespace rather than an in-place migration.

The collector init runs that guard before DNS configuration work. The log watchdog remains independent of the collector; a failed SIGUSR2 preserves the signal command's nonzero status for the operator, while retaining the rotated file. Its polling/rotation threshold alone cannot impose a hard burst-memory bound. The implemented 20 MiB mount supplies that owned filesystem bound; actual active-DNS rotation/reopen/recovery checks remain pending in the [field report](../../docs/monitoring-field-status-2026-10-25.md).
