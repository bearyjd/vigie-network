# Permanent collector privilege transition

`vigie-privdrop` is a small standalone dependency-free Linux64 Rust helper. It is invoked explicitly by root; it is never installed SUID/SGID or with file capabilities. Its unsafe boundary consists only of documented Linux libc ABI calls. The collector crate retains its ban on unsafe code.

The command is `vigie-privdrop UID GID /absolute/program [ARG ...]`. UID/GID must be canonical decimal values from 1000 through 4294967294, excluding 65534. System/root IDs, leading zero/plus aliases, sentinels, parent-relative executable paths and embedded NUL arguments are rejected. The permanent init resolves the existing dedicated `vigie` account as root and passes literal arguments, without a shell command string. Missing/unsafe accounts cannot register a procd instance.

Procd starts the helper as root, with core limits already zero. Do not set procd `user`/`group` before it: the helper requires both real and effective root, and refuses non-root/SUID callers. It marks inherited descriptors ≥3 close-on-exec BEFORE changing credentials, sets both core limits to 0, enables `PR_SET_NO_NEW_PRIVS`, disables keepcaps, clears ambient and every bounding capability, empties supplementary groups, sets GID and UID, and clears effective/permitted/inheritable capability sets. It verifies real/effective/saved/filesystem UID/GID, empty groups, NNP 1, all five zero capability masks and both zero core limits before executing anything.

The target receives a cleared environment with only a fixed system PATH, working directory `/`, umask 077 and null stdin. Standard output/error remain the caller's explicitly configured streams; other inherited descriptors close at exec. The production target is the root-owned 0755 `vigie-run.sh`, which launches the unprivileged collector and retains its existing failure counter behavior. No input decoder or network collection runs in the transient root helper. Any failure exits 77; it never retries the target as root or continues after incomplete verification.

## Build and install contract

Host tests and static ARM release build:

```sh
(cd collector && cargo test --locked -p vigie-privdrop)
(cd collector && cargo clippy --locked -p vigie-privdrop --all-targets -- -D warnings)
(cd collector && cargo build --locked --release --target aarch64-unknown-linux-musl -p vigie-collector -p vigie-conntrack -p vigie-privdrop)
```

The command requests the musl target and inherits the workspace size optimization and abort-on-panic profile. Record source commit, compiler/target, binary hash and static linkage before deployment. Build commands alone do not establish those runtime facts. Copy `vigie-privdrop` alongside the other two binaries; the installation printer installs it as `/usr/bin/vigie-privdrop`, root:root 0755. Verify it and the wrapper/scripts remain root-owned, non-writable by the collector, without SUID/SGID or file capabilities. Stop owned services before any reviewed replacement and retain the exact journaled prior files for rollback.

Tests cover canonical argv, unsafe IDs/paths/NULs, Linux64 ABI record layout, real inherited-FD flags, complete/malformed process-status fixtures and actual kernel non-root refusal. A root test runner drops only its test child before the refusal probe; production exposes no test bypass.

The public static release helper has now passed a separately reviewed harmless procd service
on the real router: dedicated UID/GID, empty supplementary groups, all five zero capability
masks, NNP 1 and zero core limits were observed. The installed helper also passed the collector
config/key check. The [2026-10-25 field report](monitoring-field-status-2026-10-25.md) keeps these
proofs separate from the actual running collector wrapper/child kernel checks, which have also
passed, including renewed checks after the LAN correction. A controlled stop proved the wrapper
and Rust child gone; a repaired portable UID scan and new controlled stop/restart also passed,
with the earlier unsupported auxiliary check retained as failed evidence. The bounded outage, controlled drop-in repair and read-only-reconciled helper respawn passed.
Natural rotation and boot acceptance remain separate. Neither
unit fixtures nor the earlier disposable launcher substitutes for those field checks.

This helper is required because the observed firmware accepted procd `no_new_privs` configuration but left kernel NNP 0 without its unavailable jail machinery. Merely publishing that boolean is insufficient. Filesystem boot guards, bounded retries, DNS logging/ownership, reboot/recovery and real 48-hour acceptance remain separate deployment gates; see [router log filesystem](router-logfs.md).
