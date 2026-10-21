# P1 spike: collector multicast listener (`net-spike`)

Goal: prove the two riskiest router-side assumptions from PRP-001 §4 / P0 item 8:

1. An unprivileged process can bind UDP 5353 beside `avahi-daemon` (SO_REUSEADDR + SO_REUSEPORT), join `224.0.0.251` (and `ff02::fb`), and actually receive mDNS.
2. The same process can join `239.255.255.250:1900` and parse SSDP, with a static aarch64-musl binary small enough for the router.

Code: `collector/` (workspace). `collector/parse` holds the bounds-checked mDNS/SSDP parsers (no dependencies, `#![forbid(unsafe_code)]`); `collector/net-spike` is the binary (only dependency: `socket2`, safe APIs only, `#![forbid(unsafe_code)]`).

## Build (any x86_64 Linux host with rustup)

```sh
cd collector
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
# -> target/aarch64-unknown-linux-musl/release/net-spike
```

No cross gcc is needed. `collector/.cargo/config.toml` sets `linker = "rust-lld"` for the musl targets; rustup ships `rust-lld`, the musl target ships its own libc and crt objects, and the workspace has no C dependencies. Verified on cargo 1.99.0; the only network access needed was `rustup target add` and crates.io for `socket2`/`libc`. Release profile: `opt-level="z"`, `lto`, `panic="abort"`, `strip`, `codegen-units=1`.

## Run on the router

```sh
# on the workstation (OpenWrt 21.02 dropbear has no sftp-server, hence -O)
scp -O target/aarch64-unknown-linux-musl/release/net-spike root@192.168.1.1:/tmp/
# on the router
chmod 755 /tmp/net-spike
uname -m                      # expect aarch64
ip -4 addr show br-lan        # note the LAN IPv4, normally 192.168.1.1
```

Run it as an unprivileged user, never as root. Try these in order and use the first that works (neither was verified on the router; I could not reach it). **If neither `su -s` nor `start-stop-daemon -c` works, stop and report that; do not fall back to running it as root.**

```sh
# A. busybox su with an explicit shell (nobody's login shell is /bin/false)
su -s /bin/sh nobody -c '/tmp/net-spike --addr 192.168.1.1 --iface br-lan --v6 --secs 60 > /tmp/net-spike.json 2>/tmp/net-spike.err; echo exit=$? >> /tmp/net-spike.err'

# B. if `su -s` is unavailable
start-stop-daemon -S -c nobody -x /bin/sh -- -c '/tmp/net-spike --addr 192.168.1.1 --iface br-lan --v6 --secs 60 > /tmp/net-spike.json 2>/tmp/net-spike.err; echo exit=$? >> /tmp/net-spike.err'
```

Output goes to `/tmp` files because `/tmp` is tmpfs: nothing is written to flash. While it runs (60 s), make traffic: reconnect a phone, open a cast/AirPlay picker, or run an SSDP scan from another LAN device. Then:

```sh
id nobody; cat /tmp/net-spike.err; cat /tmp/net-spike.json
ss -ulnp 2>/dev/null | grep -E ':(5353|1900)' || netstat -ulnp | grep -E ':(5353|1900)'   # while it runs, from a second shell
rm /tmp/net-spike /tmp/net-spike.json /tmp/net-spike.err
```

To make the traffic reproducible, run `python3 collector/scripts/inject.py <that-machine's-LAN-IP> <router-LAN-IP>` **from another LAN machine** while net-spike runs. It sends, as multicast, one mDNS query (`_vigie-probe._tcp.local`), one SSDP NOTIFY and one M-SEARCH (`Vigie-Inject/1.0`); those strings must appear in the JSON. It also sends one **unicast** mDNS query (`_vigie-unicast._tcp.local`) straight to `<router-LAN-IP>:5353`. That datagram is meant for avahi, so `_vigie-unicast._tcp.local` must **not** appear in net-spike's output.

Flags: `--addr` (required, router LAN IPv4, used for the IGMP join and as the "own address"), `--prefix N` (LAN prefix for the on-link source filter, 1-32, default 24; **a LAN that is not a /24 needs `--prefix`**, otherwise real neighbours outside the assumed /24 are counted as `offlink_packets` and dropped), `--iface` (needed for `--v6`), `--v6` (also join `[ff02::fb]:5353`; failure is reported in the JSON as `mdns6`, not fatal; it is skipped with `own_v6_unknown: true` if `/proc/net/if_inet6` shows no link-local address for `--iface`, because we then could not tell our own packets from a neighbour's), `--secs N` (default 30; any larger value, including numbers beyond u64, is clamped to 3600; non-numbers and negatives exit 64), `--include-own` (**never use this on the router**: it makes net-spike parse its own packets as if a neighbour sent them, which is only meant for testing on a single host).

Exit codes:

| Code | Meaning |
|---|---|
| 0 | ok |
| 2 | bind or join of the **IPv4 mDNS** group failed (this is the "does not coexist with avahi" answer). An SSDP failure (e.g. miniupnpd holding port 1900) or an IPv6 failure does **not** exit: it is recorded as `ssdp_socket: "failed: ..."` / `mdns6: "failed: ..."` and the run continues |
| 3 | a socket produced 100 consecutive read errors (reported as a clear message, exits instead of spinning) |
| 64 | bad arguments |
| 134 (SIGABRT) | a bug: release builds use `panic = "abort"`, so any panic kills the process with SIGABRT (shell status 134) instead of unwinding. Treat this as a failure to report, with the input that caused it if known |

### What to paste back

- `uname -m`, `cat /tmp/net-spike.err`, the exit code.
- `/tmp/net-spike.json`. It contains device and service names from your LAN (mDNS hostnames, SSDP SERVER/USN strings). Redact hostnames you consider private; the `packets`, `own_packets`, `offlink_packets`, `read_errors`, `parse_errors`, `mdns_truncated`, `evidence_dropped`, `VmRSS_kB`, `VmHWM_kB` fields are what matter. Also `mdns6`, `ssdp_socket` and `own_v6_unknown`; if either socket says `failed: ...`, paste that string.
- The `ss`/`netstat` line showing both avahi and net-spike on 5353 (or the failure).
- If the bind fails: `cat /proc/net/udp | grep ':14E9'` (5353 in hex) and `ps | grep avahi`.

### Pass criteria

1. Exit 0; `packets.mdns4 > 0` from real LAN devices while avahi keeps working (check `avahi-browse`/Bonjour discovery still works during the run).
2. **Unicast is not shared:** `_vigie-unicast._tcp.local` (the unicast datagram `inject.py` sends to `<router-LAN-IP>:5353`) never appears, and avahi still answers unicast queries (the receive side is bound to `224.0.0.251:5353`, not `0.0.0.0`, and `IP_MULTICAST_ALL` is cleared). If this fails, avahi could lose or we could read replies meant for it.
3. **Source filter:** `offlink_packets` is 0 on a normal LAN (with `--prefix` set correctly for a non-/24 LAN) (a nonzero value means traffic from outside `--addr/--prefix` reached the socket), `own_packets` counts only the router's own announcements, and nothing from off-link sources is in `names`.
4. `read_errors` is 0 and `parse_errors` is small relative to `packets`; `evidence_dropped` is 0 on a normal LAN.
5. `VmHWM_kB` is well under 10 MB. A 10-60 s run on an idle host says little about memory under load; the real RSS check is the 24 h soak in P1.
6. SSDP: `ssdp_socket` should be `joined`; `failed` is an acceptable result (record why), not a failure of the spike. `packets.ssdp` may legitimately be 0 on a quiet LAN, so trigger an SSDP scan to prove reception.

## Parser hardening (tested)

| Concern | Limit / behavior |
|---|---|
| mDNS packet size | more than 9000 bytes rejected |
| Records per packet | the first 128 records are parsed; more sets `truncated` (counted as `mdns_truncated`) instead of dropping the packet |
| Name length | more than 255 bytes (wire length) rejected; label bits `01`/`10` rejected |
| Compression pointers | at most 8 jumps per name, so loops fail with `PointerLoop`; names inside rdata cannot read past their own rdlen |
| Truncation | every prefix of a valid query returns an error, never a panic or partial result |
| Header | opcode other than 0 rejected; responses with a nonzero rcode rejected |
| Text | labels decoded as lossy UTF-8; controls, bidi overrides/isolates (U+202A-202E, U+2066-2069) and U+2028/2029 become `?` |
| Service types | matched label by label; a `.` inside one label cannot forge `_x._tcp` |
| SSDP | packet at most 2048 B, at most 32 lines, values at most 256 chars, stops at the blank line, only `NOTIFY `/`M-SEARCH `; obs-fold continuation lines and bare-LF packets are rejected |
| Evidence retention | each set at most 256 strings, each source IP at most 64 distinct strings, charged once per string however many sets it lands in (at most 256 sources tracked); refusals counted as `evidence_dropped` |
| Source filter | v4 source must be inside `--addr/--prefix`, v6 source must be `fe80::/10`; the router's own addresses are counted as `own_packets`, not parsed |
| Socket | bound to the group address, `IP_MULTICAST_ALL` cleared (v4 and v6), `SO_RCVBUF` 256 KiB; read errors counted and throttled (50 ms), fatal after 100 in a row |

### Known P1 production item: TTL / hop-limit 255 check not implemented

RFC 6762 section 11 says mDNS packets should arrive with TTL/hop limit 255 so off-link spoofs are rejected. With `#![forbid(unsafe_code)]` and socket2 0.5.10 it is not reachable here: socket2 has no setter for `IP_RECVTTL` on IPv4, and for IPv6 it has `set_recv_hoplimit_v6` but reading the ancillary data from `recvmsg` needs a `MaybeUninit<u8>` control buffer that can only be read through `unsafe`.

Options for the production collector: (1) the `nix` crate's `recvmsg` with `ControlMessageOwned::{Ipv4Ttl,Ipv6HopLimit}` if it can set `IP_RECVTTL`/`IPV6_RECVHOPLIMIT` and read the control messages without our own unsafe (to be verified); (2) otherwise one small, audited `unsafe` socket shim (PRP section 4 already allows a shim for sockets).

What limits exposure until then: the group-scoped bind (no unicast delivered), `IP_MULTICAST_ALL` cleared, and the on-link source filter. These do not stop an on-link host that forges an on-link source address.

## Tests

91 tests (41 parser, 50 net-spike). Parser tests cover exact boundaries with literal numbers (so changing a constant is detected), truncation at every offset, pointer loops, the rdata bounds, and 40,000-iteration xorshift "never panics" runs seeded from both a query and a full PTR+SRV+TXT response. The net-spike tests cover the socket options and bound addresses (`sock.rs`, no privileges needed), the source filter, quotas (names, services and all three SSDP sets), the receive-error policy driven by a fake reader, socket-open failure handling, argument parsing and counters.

Mutation check (hand-rolled: `python3 -I collector/scripts/mutate.py "$PWD/collector" all` from the repo root): 130 single-point mutations, 53 in the parser and 77 in net-spike (constants, comparisons, group/port/option changes in `sock.rs`, the error policy, quotas, filters). Result: 126 killed, 1 is a genuine compile error (counted as killed), and **4 survive, all equivalent or unobservable on the test host**:

- `set_only_v6(false)`: Linux forces `IPV6_V6ONLY` on once a v6 socket is bound to a specific address, so the observable state is the same.
- `ifindex`: dropping the `is_empty()` check changes nothing, because an empty name builds a path that does not exist and fails anyway.
- `if !already` in `evidence.rs`: re-inserting an already charged string into a set is a no-op.
- removing `set_recv_buffer_size`: the host's default receive buffer is already at least as large as the 256 KiB request, so it cannot be told apart here (the test only rules out a tiny value).

The first review pass found that 10 of 10 parser mutants survived because the tests used the constants themselves; they now use literals. The second pass found that `sock.rs` had no tests, so deleting `set_multicast_all_v4/v6(false)` or binding `0.0.0.0` passed everything; those mutants now die. The IPv6 socket test skips only when no interface supports a plain `ff02::fb` join, and fails if our `mdns_v6` fails where a plain join works.

Honesty note on process: tests for the first-round fixes were run red before the fixes. In round two, the `sock.rs` and `main.rs` tests were written against already-correct code, so their value was shown by the mutation runs rather than by a red run; the quota change was red-first.

## Results (host-measured, not the router)

Host: Fedora workstation, kernel 7.2, unprivileged user, real `avahi-daemon` already bound to 5353 on v4 and v6, wifi interface. Binary: `x86_64-unknown-linux-musl` release build of the same code and profile. Runs were 10 s on a mostly idle host: a **10 s idle-host VmHWM says nothing about router memory under load or after 24 h**, only that the baseline is under 1 MB.

| Metric | Result |
|---|---|
| Bind to group address + join beside avahi, unprivileged | OK (exit 0), including `[ff02::fb]%ifindex:5353` |
| Injected multicast packets from `scripts/inject.py` parsed | yes, run with `--include-own` because the injector ran on the same host (otherwise they count as `own_packets` by design); `_vigie-probe._tcp.local`, `Vigie-Inject/1.0`, `uuid:vigie-inject::upnp:rootdevice` all present |
| Injected unicast datagram to `<router-ip>:5353` | not delivered: `_vigie-unicast._tcp.local` absent (host test used the same machine as injector and listener, so it proves the group-scoped bind, not a cross-host path) |
| Own packets without `--include-own` | counted separately (6 `own_packets` in one 10 s run), 0 off-link, 0 read errors, 0 parse errors, 0 evidence drops |
| Packets in 10 s (mDNS v4 / v6 / SSDP) | 4 / 3 / 9 in the latest run; an earlier run saw 14 / 10 / 4 |
| VmRSS / VmHWM at exit | 468-476 kB / 468-476 kB |
| Failure path (`--addr 10.9.9.9`) | exit 2, bind/join error message |
| Binary size, aarch64-unknown-linux-musl (stripped, static) | **383,504 bytes (375 KiB)** |
| `cargo test` | 50 + 41 passed, 0 failed |
| `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` | clean |

### Not verified

- The aarch64 binary was cross-compiled but **not executed** (no qemu-user, no router access). Everything about actual router behavior (avahi coexistence on OpenWrt 21.02 / kernel 5.4.211, `su -s` / `start-stop-daemon` as `nobody`, `IP_MULTICAST_ALL` support on that kernel, aarch64 RSS) is pending the owner's run.
- Binding to the group address needs the router's avahi to share it; the host avahi did. A failure on the router would show as exit 2 (`Address already in use`); the fallback would be reading mDNS from avahi (e.g. `avahi-browse -a -p -r -t`), which this spike does not implement.
- The TTL/hop-limit 255 check is not implemented (known P1 production item, see above).
- If miniupnpd or another daemon holds UDP 1900 on the router, the SSDP socket will be recorded as `failed` and the run continues; whether it can share the port there is itself a result.
- One multicast group per socket and one LAN interface only; guest-network (`isolate=1`) mDNS is out of scope.
