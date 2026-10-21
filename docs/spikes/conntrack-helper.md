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
  exists in the dev sandbox); see "Running the tests as root".

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
   - Tracked state is capped (`--max-flows`, default 32768). Over the cap the **oldest** (first
     seen) tracked flows are evicted. Cost: an evicted long-lived flow later looks new and its
     cumulative bytes are counted once more. At startup the daemon reads
     `/proc/sys/net/netfilter/nf_conntrack_max` (override: `--conntrack-max-file`) and **refuses
     to run** if it exceeds `--max-flows` (the GL-XE3000 is 16384). Passing `--max-flows`
     explicitly accepts the risk (a warning is logged). An unreadable file only warns.
   - The first sample after start is a **baseline**: flows are counted but bytes are 0, so
     pre-existing history is not reported as one 60 s delta. (`--once` does not baseline.)
   - Output per `(src_ip, dst_ip, dst_port, proto)`: `bytes_up` (original direction),
     `bytes_down` (reply direction), packets both ways, `flows` (active), `new_flows`.
   - **Bounded output** (a spoofed-source flood cannot blind monitoring): top-N records by
     bytes (`--top-n`, default 512, max 2048) stay named. The rest fold into one
     `"other":true` record per src_ip. Of those, only the top K (`--other-k`, default 64, max
     2048; most bytes first, LAN/private sources ahead of public ones among equals) are kept; all
     remaining ones fold into ONE `"other_global":true` record with `"src":"0.0.0.0"` carrying
     the summed counters. Totals are preserved exactly; at most `top_n + K + 1` records, so a
     line is far below the 2 MiB publisher cap (16384 distinct v6 sources: ~90 KiB, test
     `tests/flood.rs`). `folded` says how many per-destination records were folded.
     Limitation: ranking is by bytes first, so a spoofer that moves more bytes than a quiet LAN
     host can push that host into the global remainder.
   - Flows whose original source is external (port-forwards, router-originated) are emitted
     too; the agent decides what to drop.
3. **Serve**: one JSON line per interval to the connected reader, example:
   `{"v":1,"seq":3,"ts":1700000000,"interval_s":60,"skipped_lines":0,"acct_off":false,"folded":0,"evicted":0,"records":[{"src":"192.168.8.10","dst":"8.8.8.8","dport":53,"proto":"udp","bytes_up":70,"bytes_down":120,"packets_up":1,"packets_down":1,"flows":1,"new_flows":0}]}`.
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
  the staged path is re-checked to still be the very socket we created (same device and inode,
  not a symlink); after the rename the installed path is checked again and removed if it is not
  ours. The staging directory is cleaned with `remove_file` + `remove_dir`, never recursively.
  Residual: `chmod` and `rename` are path based (std has no `fchmodat(NOFOLLOW)`), so a swap in
  the microseconds between the re-check and the call is only detectable afterwards; the staging
  directory is `0700` root-owned, so only root-equivalent code could race it.
- **Dedicated uid.** The helper refuses `--uid 0` and `--uid 65534` (nobody) unless
  `--allow-shared-uid` is given. A uid shared with other services means every one of them can
  read conntrack data (who talks to whom). Use a dedicated `vigie` user for the agent.
- As root without `--uid` it refuses to start (the agent could not connect).
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
work. Owner, on a machine where you have sudo:

```sh
cd collector && sudo -E "$(command -v cargo)" test -p vigie-conntrack -- --nocapture
```

(equivalent to `sudo cargo test -p vigie-conntrack`; `-E`/the explicit path only keep your
toolchain visible to root). The dev sandbox for this work had no sudo, so this was **not** run.

## Test and build evidence (host, x86_64)

- `cargo test -p vigie-conntrack`: **87 tests pass** (68 unit, 11 binary/e2e, 6 fixture, 1 flood,
  1 RSS). `cargo clippy -p vigie-conntrack --all-targets -- -D warnings` and `cargo fmt --check`
  clean. Not run as root (no sudo): the chown and lchown-swap tests print `SKIPPED` here.
- Release build `aarch64-unknown-linux-musl` (rust-lld): **401 KiB** (410720 bytes), static,
  stripped. Not run (no emulator); only built.
- Memory, attacker-shaped input: 16384 DISTINCT IPv6 sources (generated by the tests, not
  committed), host x86_64, `--once`, static musl release, `/usr/bin/time -v` max RSS:
  - before this change: **12.5 MB** and a 2.17 MB output line (over the 2 MiB cap, so every daemon
    sample would have been dropped as too large);
  - after: **6.6-6.7 MB** (3 runs) and a 90 KB line. Peak is the state hash table (16384 flows
    grow it to 32768 buckets; the old table coexists with the new one while it rehashes).
  - `tests/rss.rs` runs the daemon (glibc debug build) on the same shape of table and asserts
    peak growth over idle <= 7 MB (measured 6.1 MB; idle there is 2.5 MB because of glibc and
    unoptimised code) and an absolute ceiling of 12 MB. That test cannot assert the musl 8 MB
    figure itself; the musl number above is a manual measurement.
  - Changes: parse streams into the aggregator (no `Vec<Flow>`), `Flow` dropped its state and
    flag fields, one hash map holds previous and current counters, records are sorted/folded in
    place, the snapshot `String` is moved into the publisher instead of cloned.
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
