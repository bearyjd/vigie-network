# P1 spike: `vigie-conntrack` root helper

Crate: `collector/conntrack-helper` (binary `vigie-conntrack`). Implements the root half of the
PRP-001 §4 privilege split: it reads `/proc/net/nf_conntrack` (root:root 0440 on the GL-XE3000),
aggregates, and serves the result to the unprivileged agent over a unix socket. std only, no
dependencies, `#![forbid(unsafe_code)]`, no network access.

## Status: NOT verified on the router

- It has **never run on the router**. Everything below was tested on an x86_64 Linux host.
- **The `/proc/net/nf_conntrack` format is assumed from kernel documentation.** No real sample has
  been captured yet. The fixtures in `collector/conntrack-helper/tests/fixtures/conntrack/` are
  hand-written. The owner must capture a real sample and run it through the parser (steps below).
- Not checked on the router: flow-offload behaviour (offloaded flows may not update counters in
  `nf_conntrack`; `[OFFLOAD]`/`[HW_OFFLOAD]` flags are ignored by the parser), the kernel's actual
  `acct` field order, the placement of `zone=`, ICMP/ICMPv6 line shape, and how many entries a
  busy network really holds.
- Not checked anywhere: the chown/lchown step (needs root or a usable second group, neither
  exists in the dev sandbox; a user namespace without a subuid range maps one id only, so it
  cannot chown to a distinct gid either); see "Running the tests as root".

## Trust model: what the parser sees

Not "no LAN data". `/proc/net/nf_conntrack` is kernel-generated text, but the **values in it are
attacker-influenced**: any host that can send packets through the router chooses source and
destination IPs (spoofed sources included), ports and, by sending or not sending, the counters.
So the parser treats every field as hostile: bounded line length (4 KiB), bounded input (32 MiB
per sample), strict numeric/IP parsing (a bad value skips the line, counted in `skipped_lines`),
bounded memory (see below), and the output is bounded no matter how many distinct sources appear.

The helper emits one record per **src_ip**; it knows no MACs. The agent maps src_ip to MAC via
the neighbor table.

## What it does

1. **Parse** (streamed: lines go straight into the aggregator, no `Vec` of flows).
   `l3name l3num protoname protonum timeout [STATE] <orig tuple> packets= bytes= [flags]
   <reply tuple> packets= bytes= extras`. Used: the original tuple, `packets=/bytes=` per
   direction, `zone=`. Everything else (state words, `[FLAGS]`, `mark= secctx= use=`) is ignored
   and not stored. ICMP uses `id=` as the source-port slot (two pings differ), dport 0. Truncated,
   garbage, non-UTF-8 and over-long lines are skipped and counted in `skipped_lines`; the parser
   never panics (prefix and noise tests).
   - **acct_off**: if a parsed line has no `bytes=` (kernel accounting off,
     `nf_conntrack_acct=0`, or a flow created before it was switched on) its counters are zero.
     That is no longer silent: the snapshot header carries `"acct_off":true` when any parsed line
     lacked `bytes=`. The agent should treat byte counts as unreliable then and say so.
2. **Aggregate** every sample (default 60 s). Flows are keyed by `(proto, original src, dst,
   sport, dport, zone)`; the original tuple is the LAN-side view even when NAT rewrites the reply.
   - **Duplicates**: identical keys within one sample merge by taking the **max per counter**, not
     the sum. A duplicated line is not extra traffic and does not disturb the next delta.
   - delta = current - previous counters per direction. If either counter went backwards the
     tuple was reused: delta = current values and it counts as a new flow.
   - **Tombstones**: a flow absent from a sample is remembered for 2 consecutive absences and
     forgotten on the 3rd. A flow that reappears within that window with counters >= the
     remembered ones is a continuation (only the growth is reported, lifetime bytes are not
     counted again); with smaller counters it is a reset (new flow). Tombstones are not active
     flows (not in `flows`) but count against the memory cap.
   - **Tracked state is capped** (`--max-flows`, default **3 x `nf_conntrack_max`**, 49152 on the
     GL-XE3000, 3 x 16384: live flows plus two samples of tombstones). Over the cap, eviction is
     ordered: **tombstones first** (absent flows, oldest first), and only then live flows, oldest
     first. An evicted *live* flow leaves a **stub** (hash of its key -> last bytes/packets per
     direction, 48 bytes) in a side table capped at 2 x `nf_conntrack_max` (`max-flows / 3 * 2`),
     oldest stubs dropped first. A flow that returns with counters >= its stub is a continuation
     (only the growth is reported); with smaller counters it is a reset. So churn from one host no
     longer makes another host's long-lived flows come back as brand-new ones (reviewer repro:
     max_flows 1000, 400 new flows per sample: B's delta stays ~200 kB, was ~1.4 GB; tests
     `churn_does_not_recount_other_hosts_lifetime_bytes`,
     `live_eviction_keeps_a_stub_so_returning_flows_continue`).
     **Limit of the design:** when the stub table itself overflows, the dropped stubs belong to
     flows that will be counted again if they return. The snapshot says so:
     `"table_pressure":true` and `"recounted_flows":N` (stubs dropped this sample, an upper bound
     on flows that may be recounted). A flow evicted as a tombstone also returns as new (same as a
     flow forgotten after 3 absences). A stub can mis-attribute when a dead flow's tuple is reused
     by a new flow with larger counters before its stub is dropped (the new flow's first delta is
     under-reported); stubs are not aged out because that would bring the recount back.
   - **`nf_conntrack_max` is enforced, fail closed.** At startup the daemon reads
     `/proc/sys/net/netfilter/nf_conntrack_max` (override: `--conntrack-max-file`). Without
     `--max-flows` the cap is derived from it (3 x; refused above 3 x 65536 so the memory cost is
     a conscious choice) and the daemon **refuses to start if the file is missing or unreadable**.
     With an explicit `--max-flows` the owner decides: a cap below 3 x the kernel limit, or an
     unreadable file, logs a loud warning and (cap too low) sets `table_pressure` from the start.
     Every 60 samples (`--ct-recheck-samples`) the file is read again; if the limit grew beyond
     `max-flows / 3`, or can no longer be read, `table_pressure` is set and a line is logged.
     Nothing continues silently.
   - The first sample after start is a **baseline**: flows are counted but bytes are 0, so
     pre-existing history is not reported as one 60 s delta. (`--once` does not baseline.)
   - Output per `(src_ip, dst_ip, dst_port, proto)`: `bytes_up` (original direction),
     `bytes_down` (reply direction), packets both ways, `flows` (active), `new_flows`.
   - **Bounded output** (a spoofed-source flood cannot blind monitoring): top-N records by
     bytes (`--top-n`, default 512, max 2048) stay named. The rest fold into one
     `"other":true` record per src_ip. Those are ranked in **two quotas**: the `--k-lan` (default
     192) LAN sources and the `--k-wan` (default 64) other sources with the most bytes are kept
     (max 2048 each); everything else folds into ONE `"other_global":true` record with
     `"src":"0.0.0.0"` carrying the summed counters. Totals are preserved exactly; at most
     `top_n + k_lan + k_wan + 1` = 769 records by default, far below the 2 MiB publisher cap
     (16384 distinct v6 sources: ~90 KiB, `tests/flood.rs`). `folded` says how many
     per-destination records were folded.
     **LAN classification** is by source address: `--lan-cidr` (repeatable; giving any replaces the
     defaults) defaults to 10/8, 172.16/12, 192.168/16, 100.64/10, fe80::/10, fc00::/7.
     Caveat: a source address is attacker-chosen, so spoofed RFC1918/ULA sources arriving from the
     WAN can fill the LAN quota (they cannot touch the WAN quota, and totals stay exact). A quiet
     LAN host is then folded into the global record. The owner should pass the real LAN prefixes
     (e.g. `--lan-cidr 192.168.8.0/24`) and have the router drop WAN-side packets with private
     sources (rp_filter / bogon rules). Tests: a quiet LAN host keeps its attribution under 1000
     spoofed WAN sources; 2000 spoofed private sources fill only `k_lan`.
   - Flows whose original source is external (port-forwards, router-originated) are emitted
     too; the agent decides what to drop.
3. **Serve**: one JSON line per interval to the connected reader, example:
   `{"v":1,"seq":3,"ts":1700000000,"interval_s":60,"skipped_lines":0,"acct_off":false,"folded":0,"evicted":0,"recounted_flows":0,"table_pressure":false,"records":[{"src":"192.168.8.10","dst":"8.8.8.8","dport":53,"proto":"udp","bytes_up":70,"bytes_down":120,"packets_up":1,"packets_down":1,"flows":1,"new_flows":0}]}`.
   `ts` comes from the router clock (no RTC): the agent should stamp by its own sane clock and use
   `seq` for ordering.
   - **One reader at a time.** A new connection never cuts a line already in flight: it waits
     (one slot, newest wins) until the current line has been fully written, then takes over and
     the previous reader is closed. A reader that connects and never reads therefore holds the
     slot until its connection closes; with a dedicated uid only the agent can connect, and an
     agent restart closes its old connection.
   - With no reader the snapshot is dropped; a slow reader gets at most one queued snapshot
     (<= 2 MiB) and later ones are dropped (`DroppedBusy`). Sampling never blocks.

## Socket and uid safety

- **Directory.** The helper creates the socket directory itself (mkdir 0755) if it is absent. If
  it exists it must be a real directory (not a symlink), owned by root (or the helper's own uid
  when not run as root, for tests), with **no group- or other-write bit** (`mode & 0o022 == 0`,
  sticky does not excuse it). Otherwise it refuses with a message and does not repair anything.
  Do **not** share this directory with the agent's own files.
- **Socket.** Refuses a symlink or non-socket at the socket path; a stale socket is replaced.
  The socket is bound inside a fresh `0700` staging directory with a random name (64 bits from
  `/dev/urandom`; a pre-existing directory of any name is never deleted or reused), chmod 0600,
  `lchown`ed (never follows a symlink) to `--uid/--gid`, verified (type, mode exactly 0600,
  owner), then renamed into place and verified again. Before the chmod, the lchown and the rename
  (tests for each, incl. `socket_replaced_before_chown_is_refused_before_the_lchown`) the staged path is re-checked to still be the very socket we created (same device and inode,
  not a symlink); after the rename the installed path is checked again and removed if it is not
  ours. The staging directory is cleaned with `remove_file` + `remove_dir`, never recursively.
  Residual: `chmod` and `rename` are path based (std has no `fchmodat(NOFOLLOW)`), so a swap in
  the microseconds between the re-check and the call is only detectable afterwards; the staging
  directory is `0700` root-owned, so only root-equivalent code could race it.
- **Dedicated uid.** The helper refuses `--uid 0`, `--uid 65534` (nobody) and any system
  uid below 1000 unless `--allow-shared-uid` is given, so a low system uid cannot be chosen by
  mistake. A uid shared with other services means every one of them can
  read conntrack data (who talks to whom). Use a dedicated `vigie` user for the agent.
- As root without `--uid` it refuses to start (the agent could not connect); the rule is the
  pure function `cli::check_root_needs_uid`, unit tested.
- **Ancestors above the socket's parent directory are not checked.** Only the socket directory
  itself (real directory, root-owned, no group/other write) is verified. If `/tmp` or any higher
  directory were replaceable by an unprivileged user, they could substitute the whole tree; the
  default `/tmp/vigie` assumes `/tmp` is the root-owned sticky directory it normally is.
- No `setuid`/`setgid` (no unsafe, no libc): it stays root; the surface is a parser of
  kernel text plus one 0600 socket. No signal handlers: after SIGTERM a stale socket remains and is
  replaced at the next start. A crash can leave a `.vigie-stage-*` directory inside the socket
  directory; inspect it and remove it by hand (the helper never deletes a directory it did not
  just create in this run).
- Check `/proc/sys/fs/protected_symlinks` (should be `1`) on the router: it stops root from
  following symlinks planted by other users in sticky world-writable directories such as `/tmp`.
  The helper does not depend on it, but it is cheap defence in depth.

## Dedicated user on OpenWrt (commands for the OWNER, run by hand on the router)

The helper does not create users. Pick a free id (here 10001) and check
`grep -E ':(10001):' /etc/passwd /etc/group` first. Then:

```sh
echo 'vigie:x:10001:' >> /etc/group
echo 'vigie:x:10001:10001:vigie:/var/empty:/bin/false' >> /etc/passwd
# optional, only if the router uses shadow:
grep -q '^vigie:' /etc/shadow || echo 'vigie:x:0:0:99999:7:::' >> /etc/shadow
id vigie     # expect uid=10001(vigie) gid=10001(vigie)
```

The shell `/bin/false` (or `/sbin/nologin` if present) means nobody can log in as it.

## procd

Run as root as its own service; the agent is a separate service under the `vigie` user:

```sh
# /etc/init.d/vigie-conntrack (sketch)
USE_PROCD=1
START=96
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/vigie-conntrack \
        --socket /tmp/vigie/conntrack.sock --uid 10001 --gid 10001 --interval 60
    procd_set_param respawn
    procd_close_instance
}
```

No `mkdir` in the init script: the helper creates `/tmp/vigie` (0755, root) itself. If something
else already created it wrongly (symlink, group/other-writable, not root-owned) the helper refuses
to start and says why. Look at it with `ls -ld /tmp/vigie` and, if it is not yours, remove or fix
it by hand after inspecting what it is; the helper and these docs never remove it.

The agent connects to `/tmp/vigie/conntrack.sock` and reads newline-delimited JSON. The agent's own
files (dnsmasq log etc.) should live in a different directory.

## Router test steps (owner)

Binary: `collector/target/aarch64-unknown-linux-musl/release/vigie-conntrack`
(`cd collector && cargo build --release --target aarch64-unknown-linux-musl -p vigie-conntrack`).

1. `scp -O collector/target/aarch64-unknown-linux-musl/release/vigie-conntrack root@192.168.1.1:/tmp/`
2. On the router, capture a raw sample first (this validates the assumed format):
   `head -5 /proc/net/nf_conntrack` (and `grep -m2 ipv6 /proc/net/nf_conntrack`,
   `grep -m2 -E 'icmp|unknown' /proc/net/nf_conntrack`). **Mask IPs** (e.g. keep the first two
   octets, replace the rest with `x`) and paste it back. Also
   `cat /proc/sys/net/netfilter/nf_conntrack_acct /proc/sys/net/netfilter/nf_conntrack_max
   /proc/sys/fs/protected_symlinks` and `ls /sys/module/nf_flow_table 2>&1` (flow offload).
3. `/tmp/vigie-conntrack --once --file /proc/net/nf_conntrack > /tmp/ct.json; echo rc=$?`
   Paste back `head -c 1500 /tmp/ct.json`, masked, and the `"skipped_lines"` and `"acct_off"`
   values. A high `skipped_lines` means the format assumption is wrong.
4. Create the `vigie` user (section above), then the daemon smoke test (also gives memory):
   `/tmp/vigie-conntrack --uid 10001 --gid 10001 --interval 10 & sleep 12; ls -ld /tmp/vigie;
   ls -l /tmp/vigie/; grep -E 'VmRSS|VmHWM' /proc/$!/status; kill $!`.
   Expect a root-owned `drwxr-xr-x` directory and `srw-------` owned by `vigie` (this is the
   lchown check the host tests could not run), and paste back the two Vm lines. If `socat` is
   installed, `socat - UNIX-CONNECT:/tmp/vigie/conntrack.sock` as `vigie` shows a snapshot line
   every 10 s.

## Running the tests as root

The chown/lchown tests need a group the test user can chown to. As an ordinary user they use a
supplementary group if one is usable and otherwise print `SKIPPED ... <reason>` and pass (run with
`-- --nocapture` to see it). As root they always run and **fail loudly** if the chown does not
work. **Root lane:** with `VIGIE_ROOT_TESTS=1` those tests (and `root_lane_runs_as_root`) FAIL
instead of skipping when the suite is not root, so a green run proves they executed. Owner, on a
machine where you have sudo:

```sh
cd collector && VIGIE_ROOT_TESTS=1 sudo -E "$(command -v cargo)" test -p vigie-conntrack -- --nocapture
```

(`-E` keeps `VIGIE_ROOT_TESTS` and the toolchain visible to root). `unshare -r -m` does not
substitute: it maps only uid/gid 0, so `lchown` to a different gid fails with EINVAL (checked;
no subuid range exists for the dev user). The dev sandbox for this work did **not** run this lane,
so the `lchown` vs `chown` mutant is **not verified**.

## Test and build evidence (host, x86_64)

- `cargo test -p vigie-conntrack`: **109 tests pass** (86 unit, 15 binary/e2e, 6 fixture, 1 flood,
  1 RSS). `cargo clippy -p vigie-conntrack --all-targets -- -D warnings` and `cargo fmt --check`
  clean. Not run as root (see above): the chown and lchown-swap tests print `SKIPPED` here, and
  FAIL with `VIGIE_ROOT_TESTS=1`.
- Release build `aarch64-unknown-linux-musl` (rust-lld): **414.6 KiB** (424552 bytes), static.
  Not run (no emulator); only built.
- Memory (x86_64 static musl release, `/usr/bin/time -v` max RSS, 3 runs each; generated tables,
  not committed):
  - `--once`, **16384 distinct sources**: **6.3-6.6 MB**, 92 KB line (meets the 8 MB target).
  - `--once`, **32768 mixed sources** (half v6 "WAN", half 10.x "LAN"): **13.3-13.6 MB**, 119 KB
    line. **Over 8 MB**: the state hash table (about 150 B per flow, doubled while it rehashes)
    dominates. Such a table cannot exist at `nf_conntrack_max` 16384.
  - Daemon, three rotating tables of 16384 distinct sources (49152 tracked = live + tombstones,
    the default cap under full churn): **VmHWM 12.7 MB**, VmRSS 9.2 MB. The default cap therefore
    trades up to ~13 MB peak under attacker-shaped churn for correct byte counts. A full stub
    table (32768 stubs, 48 B + table overhead, about 3 MB) comes on top only when live flows are
    evicted; that case was **not measured**.
  - `tests/rss.rs` (glibc debug build, 16384 sources) still holds: growth over idle <= 7 MB.
- Items 1-5 review fixes, test order: the churn repro (`churn_does_not_recount_...`, 1.37 GB
  reported against ~200 kB true), the tombstone-first, stub-reset and stub-overflow tests and the
  quiet-LAN quota test were run red against the old behaviour first, then green. The tests
  for limits, `--lan-cidr`, the periodic re-read, root-requires-uid and the re-checks were
  written with their fix and shown failing by reverting the fix as a mutant (below).
- Mutation check, this round (hand-applied, each against the whole suite):
  - Killed: tombstone-first eviction (also stub removal), stub continuation, stub not consulted,
    stub overflow flag, stub overflow count, stub cap not enforced, 3x factor, 3x check disabled,
    3x check applied to explicit caps, default cap not 3x, NotFound fail-open (check and default),
    re-check never due, re-check not called in main, re-check threshold, unreadable file silent,
    pressure not copied into the snapshot, k_wan/k_lan quota swapped, bytes-only ranking, LAN
    partition, CIDR family ignored, CIDR mask dropped, `--lan-cidr` ignored in main, default
    prefix removed, root-requires-uid (two mutants), pre-chown re-check removed, pre-install
    re-check removed.
  - **Survived: `lchown` -> `chown`** (needs a root run with a distinct gid; not verified, see
    above). **Survived: `check_root_needs_uid` not called from `main`** (only observable as root;
    the function itself is tested).
- Previous round (kept for the record):
  - Mutation check (hand-applied mutants, each run against the whole suite):
  - Killed: delta, reset (never; reply.packets only), eviction (disabled; keeps oldest), other-cap K
    disabled, global remainder dropped, LAN-first ranking, zone key, duplicate sum instead of max,
    tombstone (none; 1 absence only), baseline off in the daemon, acct_off (never; counter),
    dir symlink check, target symlink check, `0o022` -> `0o002`, no re-check before chmod, no
    post-rename re-check, predictable staging name, dir created 0750, dir owner check removed,
    in-flight line truncated, uid refusal removed / only 0, nf_conntrack_max check removed.
  - **Survived: `lchown` -> `chown`.** Observable only with a group the user can chown to; the dev
    sandbox has none and no root, so `symlink_swapped_in_before_lchown_is_never_followed` skips.
    Run the tests as root (above) to cover it. **Not verified.**
  - Survived (equivalent): no re-check before the rename. The post-rename re-check catches the
    same swap and removes the imposter, so the outcome is identical; the pre-check only avoids
    the rename.
  - Two mutants made the suite hang rather than fail (daemon kept running); the binary refusal
    tests now kill a daemon after 10 s so a regression fails cleanly.
- Test order: the agg/cli tests were run red against the old behaviour first (6 agg tests and the
  shared-uid test failed, then passed after the fix). For the socket, publisher and binary tests
  the signatures changed, so red was shown by reverting each fix as a mutant (list above) rather
  than by running the new test on the old code.
