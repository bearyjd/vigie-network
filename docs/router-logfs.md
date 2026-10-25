# Router log filesystem and pre-DNS startup

The [2026-10-25 field report](monitoring-field-status-2026-10-25.md) records actual installation,
native mount verification and a successful 20 MiB capacity/ENOSPC proof before DNS writers.
Real DNS logging and parsed delivery now work; active-full/reopen recovery, reboot and
long-duration acceptance remain separate pending gates.
The source helper itself does not modify DHCP/firewall policy.

The only production target is `/tmp/vigie`, backed by a dedicated tmpfs named `vigie-logfs` with exactly 20971520 bytes (20 MiB), `nosuid,nodev,noexec`, root ownership, the actual dedicated `vigie` group and mode 0751. Existing root-owned empty backing directories with that exact geometry are accepted; contents (including hidden entries), symlinks, foreign/stacked/child mounts and ownership/mode mismatches are refused. Preparation does not cover files, adopt foreign state or remount an existing filesystem.

`vigie-logfs.sh prepare` serializes through a verified root-owned 0700 `/var/run/vigie-logfs-lock` directory and a private 0600 single-link regular `prepare.lock` inode, using kernel FD locking. A crashed process leaves no stale directory lock to remove; an inherited lock remains held while a mounting subprocess still uses it. It creates a missing backing directory, mounts with fixed options, then verifies the result. A failed preparation leaves evidence/owned directories for review, without recursive cleanup. `check` verifies without changing files.

`require_logfs` verifies an exact single mount root/source/type and required flags/size in `/proc/self/mountinfo`, rejects child mounts, verifies directory UID/GID/mode, and independently checks statfs blocksize×blockcount equals 20971520. A missing or unreadable prerequisite fails closed. The log consumer scripts call this before creating/repairing a log/drop-in, checking successful apply state or rotating files. A missing log does not turn a missing mount into watchdog success. Collector/helper init checks it before registration/startup; no consumer creates files on shared `/tmp` as a substitute.

The new one-shot `/etc/init.d/vigie-logfs` has START 17, before this firmware's confirmed dnsmasq START 19. Its boot helper mounts/verifies the filesystem and calls drop-in `prepare` mode. That stages the exact configuration and 0640 log only: it does not reload/restart/start DNS or publish a successful-apply marker. Normal `ensure` retains the independently reviewed retryable reload confirmation contract. Merely invoking reload is not evidence that dnsmasq reread its main configuration. Installation needs an explicit reviewed controlled restart and parsing/ownership/DNS-continuity verification; reboot validation remains separate.

The independent watchdog still rotates at 8 MiB and retains one rotated file. Polling alone cannot bound a burst; the 20 MiB filesystem bounds this owned log allocation even when collection/rotation stops. Capacity exhaustion before DNS writers has been observed; logging loss, reopen/recovery and impact on active DNS still need field evidence before unattended acceptance. If dnsmasq falls back to the system logger, those allocations occur outside the owned mount and are not bounded by its cap. This filesystem cap also does not bound every router process or the collector's separate RAM spool.

Collector init resolves the dedicated account and starts the audited `vigie-privdrop` transition
as root; it also supplies zero soft/hard core limits. Helper init supplies zero core limits.
The public helper has passed a harmless real procd/kernel proof, as recorded in the
[field report](monitoring-field-status-2026-10-25.md) and [privilege contract](privdrop.md).
The actual running collector wrapper/child has also passed its kernel privilege checks;
the controlled wrapper/child stop, portable UID scan and new stop/restart also passed. Remaining
drop-in repair passed; natural-threshold rotation and boot behavior remain separate gates. Six owned
boot links and the scoped root cron job have been installed; installation does not prove a
first cron execution or cold boot. The earlier
firmware probe accepted a bare procd `no_new_privs` setting but left kernel NNP 0; that boolean
remains insufficient.

## Reviewable rollout and rollback boundary

The installation printer includes the new helpers/init and enables filesystem preparation before collector/helper startup. Printed commands are not an authorization or proof of successful runtime behavior. Before applying, journal each exact prior file/account/cron state and intended hash, verify no foreign contents/mounts, and preserve unrelated configuration. Avoid blanket UCI restoration.

Rollback first disables/removes only the owned ensure/watchdog scheduling block and stops the collector/helper. Disable the early init; its `stop` intentionally does not unmount live DNS files. Restore only exact journaled DNS changes with drift checks, restart and verify DNS, archive private evidence, then verify the owned mount and perform a normal reviewed unmount. Never use lazy/forced unmount to hide open consumers. Remove an underlying directory only with `rmdir` when the transaction created it and it remains owned/empty; preserve legacy directories, unrelated files and evidence. No recursive removal, volume prune or automatic destructive rollback is provided.

Tests use real private fixture directories plus substitutable mount-table/statfs/mount-executable ports under `VIGIE_TEST=1`; production paths and options remain fixed. Positive legacy fixtures now explicitly represent a premounted 0751 log root, so symlink/ownership attacks reach their intended file guards. These fixtures do not establish native kernel mount or firmware DNS behavior.
