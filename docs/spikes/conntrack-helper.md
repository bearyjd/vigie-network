# P1 spike: `vigie-conntrack` root helper

Crate: `collector/conntrack-helper` (binary `vigie-conntrack`). Implements the root half of the
PRP-001 §4 privilege split: it reads `/proc/net/nf_conntrack` (root:root 0440 on the GL-XE3000),
aggregates, and serves the result to the unprivileged agent over a unix socket. std only, no
dependencies, `#![forbid(unsafe_code)]`, no network access, parses kernel-generated text only.

## Status: NOT verified on the router

- It has **never run on the router**. Everything below was tested on an x86_64 Linux host.
- **The `/proc/net/nf_conntrack` format is assumed from kernel documentation.** No real sample has
  been captured yet. The fixtures in `collector/conntrack-helper/tests/fixtures/conntrack/` are
  hand-written. The owner must capture a real sample and run it through the parser (steps below).
- Not checked on the router: flow-offload behaviour (offloaded flows may not update counters in
  `nf_conntrack`; `[OFFLOAD]`/`[HW_OFFLOAD]` flags are ignored by the parser), the kernel's actual
  `acct` field order, ICMP/ICMPv6 line shape, and how many entries a busy network really holds.

## What it does

1. **Parse** each line: `l3name l3num protoname protonum timeout [STATE] <orig tuple> packets= bytes=
   [flags] <reply tuple> packets= bytes= extras`. Keys `mark= zone= secctx= use=` and unknown
   `[FLAGS]` are ignored; missing `packets=/bytes=` (acct off) count as 0; `[UNREPLIED]`/`[ASSURED]`
   are recorded. ICMP uses `id=` as the flow's source-port slot (so two pings differ) and has
   dport 0. Truncated, garbage, non-UTF-8 and over-long (>4 KiB) lines are skipped and counted in
   `skipped_lines`; the parser never panics (prefix and noise tests). Input per sample is capped at
   32 MiB.
2. **Aggregate** every sample (default 60 s). Flows are keyed by `(proto, original src, dst, sport,
   dport)`; the original tuple is the LAN-side view even when NAT rewrites the reply.
   - delta = current - previous counters per direction. If either counter went backwards the
     tuple was reused: delta = current values and it counts as a new flow.
   - A flow absent from a sample has ended and is forgotten.
   - Tracked state is capped (`--max-flows`, default 32768). Over the cap the **oldest** (first
     seen) tracked flows are evicted. Cost: an evicted long-lived flow later looks new and its
     cumulative bytes are counted once more. Router max is 16384, so the cap normally never fires.
   - The first sample after start is a **baseline**: flows are counted but bytes are 0, so
     pre-existing history is not reported as one 60 s delta. (`--once` does not baseline.)
   - Output per `(src_ip, dst_ip, dst_port, proto)`: `bytes_up` (original direction),
     `bytes_down` (reply direction), packets both ways, `flows` (active), `new_flows`.
   - Top-N by total bytes (`--top-n`, default 512); the remainder is folded into one
     `"other":true` record per src_ip with summed counters (PRP §4 truncation order). `folded`
     says how many records were folded.
   - conntrack has IPs, not MACs: the **agent maps src_ip to MAC** via the neighbor table. Flows
     whose original source is external (port-forwards, router-originated) are emitted too; the
     agent decides what to drop.
3. **Serve**: one JSON line per interval to the connected reader, example:
   `{"v":1,"seq":3,"ts":1700000000,"interval_s":60,"skipped_lines":0,"folded":0,"evicted":0,"records":[{"src":"192.168.8.10","dst":"8.8.8.8","dport":53,"proto":"udp","bytes_up":70,"bytes_down":120,"packets_up":1,"packets_down":1,"flows":1,"new_flows":0}]}`.
   `ts` comes from the router clock (no RTC): the agent should stamp by its own sane clock and use
   `seq` for ordering. Only one reader is served (a new connection replaces the old). With no
   reader the snapshot is dropped; a slow reader gets at most one queued snapshot (<= 2 MiB) and
   later ones are dropped (`DroppedBusy`). Sampling never blocks.

## Socket safety

- Refuses to start if the socket directory is a symlink, not a directory, world-writable (sticky
  does not excuse it), or owned by anyone other than root or the helper's own uid. Not the agent's
  uid: root chmods/chowns in that directory, so a less-privileged owner must not control it.
- Refuses a symlink or non-socket at the socket path; a stale socket is replaced.
- The socket is bound inside a private `0700` staging directory, chmod 0600, chowned to
  `--uid/--gid` (`std::os::unix::fs::chown`), verified (type, mode exactly 0600, owner), then
  renamed into place. Nobody can connect before mode/owner are right. Verified again after rename.
- As root without `--uid` it refuses to start (the agent could not connect).
- No `setuid`/`setgid` (no unsafe, no libc): it stays root; the surface is a parser of
  kernel text plus one 0600 socket. No signal handlers: after SIGTERM a stale socket remains and is
  replaced at the next start.

## procd

Run as root as its own service; the agent is a separate service under `nobody`:

```sh
# /etc/init.d/vigie-conntrack (sketch)
USE_PROCD=1
START=96
start_service() {
    mkdir -p /tmp/vigie && chmod 0755 /tmp/vigie    # root-owned, not world-writable
    procd_open_instance
    procd_set_param command /usr/bin/vigie-conntrack \
        --socket /tmp/vigie/conntrack.sock --uid 65534 --gid 65534 --interval 60
    procd_set_param respawn
    procd_close_instance
}
```

The agent connects to `/tmp/vigie/conntrack.sock` and reads newline-delimited JSON. The agent's own
files (dnsmasq log etc.) should live in a different directory, since this one must not be agent-owned.

## Router test steps (owner)

Binary: `collector/target/aarch64-unknown-linux-musl/release/vigie-conntrack`
(`cd collector && cargo build --release --target aarch64-unknown-linux-musl -p vigie-conntrack`).

1. `scp -O collector/target/aarch64-unknown-linux-musl/release/vigie-conntrack root@192.168.1.1:/tmp/`
2. On the router, capture a raw sample first (this validates the assumed format):
   `head -5 /proc/net/nf_conntrack` (and `grep -m2 ipv6 /proc/net/nf_conntrack`,
   `grep -m2 -E 'icmp|unknown' /proc/net/nf_conntrack`). **Mask IPs** (e.g. keep the first two
   octets, replace the rest with `x`) and paste it back. Also `cat /proc/sys/net/netfilter/nf_conntrack_acct`
   and `ls /sys/module/nf_flow_table 2>&1` (flow offload).
3. `/tmp/vigie-conntrack --once --file /proc/net/nf_conntrack > /tmp/ct.json; echo rc=$?`
   Paste back `head -c 1500 /tmp/ct.json`, masked, and the `"skipped_lines"` value. A high
   `skipped_lines` means the format assumption is wrong.
4. Daemon smoke test (also gives memory): `mkdir -p /tmp/vigie && chmod 755 /tmp/vigie;
   /tmp/vigie-conntrack --uid 65534 --gid 65534 --interval 10 & sleep 12; ls -l /tmp/vigie/;
   grep -E 'VmRSS|VmHWM' /proc/$!/status; kill $!`.
   Expect `srw-------` owned by `nobody` (this is the chown check the host tests could not run),
   and paste back the two Vm lines. If `socat` is installed,
   `socat - UNIX-CONNECT:/tmp/vigie/conntrack.sock` as nobody shows a snapshot line every 10 s.

## Test and build evidence (host, x86_64)

- `cargo test -p vigie-conntrack`: 58 tests pass (46 unit, 6 fixture, 5 binary/e2e, 1 RSS).
  `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean.
- Release build `aarch64-unknown-linux-musl` (rust-lld): **396 KiB**, static, stripped. Not run
  (no emulator); only built.
- Memory, 16384 synthetic entries (the router's `nf_conntrack_max`), host x86_64:
  - `--once`, musl release: **10.6 MB** max RSS; 800 entries (typical): **0.5 MB**.
  - Daemon (glibc, two samples, so previous-sample state plus new state): peak VmHWM **16.7 MB**
    (VmRSS 9.6 MB after). `tests/rss.rs` asserts peak <= 24 MB. Roughly 1 KB per tracked entry.
  - This is above the 10 MB RSS budget in PRP §4 only at a completely full table; that budget
    covers the collector, and the helper is a separate process. If it matters, the next step is
    streaming parse into the aggregator instead of a `Vec<Flow>` (saves ~2 MB).
- Hand mutation check (each mutant run against lib + fixtures + binary tests):
  - Killed: delta computation (2), counter-reset conditions (each of the four counters
    individually, `<` vs `<=`), reset-counts-as-new, baseline (3), vanished-flow pruning, eviction
    cutoff / off-by-one / disabled / keeps-oldest (5), top-N (n+1, order), per-src fold (4),
    aggregation key (dport, dst), duplicate summing, world-writable check (2), dir owner check,
    dir and target symlink refusal, non-socket refusal, socket mode (loose and removed), owner and
    group verification (3), socket type check, chmod value, staging cleanup, publisher
    busy/size-cap/error-drop/newline/replace logic, IPv6 family check, tcp port requirement,
    over-long line detection, input byte cap, reply counter parsing, blank-line counting.
  - Survived: `topn <` (equivalent: with `len == n` the split is empty either way); staged and
    final `verify_socket` calls removed (equivalent: they re-check what the preceding calls just
    did, kept as defence in depth); staging dir mode 0700 -> 0777 (not observable from tests: the
    dir is removed before `bind_secure` returns); **chown skipped (a real gap)**: chown needs root
    or a usable supplementary group, and this sandbox has neither, so
    `bind_chowns_socket_to_requested_group` skips here. Run `cargo test` as root (or check
    `ls -l /tmp/vigie/` on the router per step 5) to cover it.
