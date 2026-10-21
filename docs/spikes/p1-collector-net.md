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

Run it as an unprivileged user. Try these in order and use the first that works (neither was verified on the router; I could not reach it):

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

To make the traffic reproducible, run `python3 collector/scripts/inject.py <that-machine's-LAN-IP>` **from another LAN machine** while net-spike runs. It sends one mDNS query (`_vigie-probe._tcp.local`), one SSDP NOTIFY and one M-SEARCH (`Vigie-Inject/1.0`), and the matching strings must appear in the JSON. `inject.py <ip> 4 unicast-only` sends a unicast datagram to the router's port 5353; its name `_vigie-unicast._tcp.local` must **not** appear (it is meant for avahi).

Flags: `--addr` (required, router LAN IPv4, used for the IGMP join and as the "own address"), `--prefix N` (LAN prefix for the on-link source filter, 1-32, default 24; set it if the LAN is not a /24), `--iface` (needed for `--v6`), `--v6` (also join `[ff02::fb]:5353`; failure is reported in the JSON, not fatal), `--secs N` (default 30, clamped to 3600), `--include-own` (single-host testing only: parse our own packets instead of counting them in `own_packets`; do not use it on the router).

Exit codes:

| Code | Meaning |
|---|---|
| 0 | ok |
| 2 | bind or join of the IPv4 mDNS or SSDP group failed (message names which one; this is the "does not coexist with avahi" answer) |
| 3 | a socket produced 100 consecutive read errors (reported as a clear message, exits instead of spinning) |
| 64 | bad arguments |
| 134 (SIGABRT) | a bug: release builds use `panic = "abort"`, so any panic kills the process with SIGABRT (shell status 134) instead of unwinding. Treat this as a failure to report, with the input that caused it if known |

### What to paste back

- `uname -m`, `cat /tmp/net-spike.err`, the exit code.
- `/tmp/net-spike.json`. It contains device and service names from your LAN (mDNS hostnames, SSDP SERVER/USN strings). Redact hostnames you consider private; the `packets`, `own_packets`, `offlink_packets`, `read_errors`, `parse_errors`, `mdns_truncated`, `evidence_dropped`, `VmRSS_kB`, `VmHWM_kB` fields are what matter. If `mdns6` is `failed: ...`, paste that string.
- The `ss`/`netstat` line showing both avahi and net-spike on 5353 (or the failure).
- If the bind fails: `cat /proc/net/udp | grep ':14E9'` (5353 in hex) and `ps | grep avahi`.

### Pass criteria

1. Exit 0; `packets.mdns4 > 0` from real LAN devices while avahi keeps working (check `avahi-browse`/Bonjour discovery still works during the run).
2. **Unicast is not shared:** the unicast-only injection never appears, and avahi still answers it (the receive side is bound to `224.0.0.251:5353`, not `0.0.0.0`, and `IP_MULTICAST_ALL` is cleared). If this fails, avahi could lose or we could read replies meant for it.
3. **Source filter:** `offlink_packets` is 0 on a normal LAN (a nonzero value means traffic from outside `--addr/--prefix` reached the socket), `own_packets` counts only the router's own announcements, and nothing from off-link sources is in `names`.
4. `read_errors` is 0 and `parse_errors` is small relative to `packets`; `evidence_dropped` is 0 on a normal LAN.
5. `VmHWM_kB` is well under 10 MB. A 10-60 s run on an idle host says little about memory under load; the real RSS check is the 24 h soak in P1.
6. SSDP: `packets.ssdp` may legitimately be 0 on a quiet LAN, so trigger an SSDP scan to prove reception.

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
| Evidence retention | each set at most 256 strings, each source IP at most 16 new strings (at most 256 sources tracked); refusals counted as `evidence_dropped` |
| Source filter | v4 source must be inside `--addr/--prefix`, v6 source must be `fe80::/10`; the router's own addresses are counted as `own_packets`, not parsed |
| Socket | bound to the group address, `IP_MULTICAST_ALL` cleared (v4 and v6), `SO_RCVBUF` 256 KiB; read errors counted and throttled (50 ms), fatal after 100 in a row |

### Known gap: TTL / hop-limit 255 check not implemented

RFC 6762 section 11 says mDNS packets should arrive with TTL/hop limit 255 so off-link spoofs are rejected. With `#![forbid(unsafe_code)]` and socket2 0.5.10 this is not reachable: socket2 has no setter for `IP_RECVTTL` on IPv4, and for IPv6 it has `set_recv_hoplimit_v6` but reading the ancillary data from `recvmsg` needs a `MaybeUninit<u8>` control buffer that can only be read through `unsafe`. The source-address filter above is the mitigation; it does not stop an on-link host that forges an on-link source. A small audited unsafe shim (PRP section 4 allows one for sockets) would close this and is left for the real collector.

## Tests

66 tests (41 parser, 25 net-spike). Parser tests cover exact boundaries with literal numbers (so changing a constant is detected), truncation at every offset, pointer loops, the rdata bounds, and 40,000-iteration xorshift "never panics" runs seeded from both a query and a full PTR+SRV+TXT response. The net-spike tests cover the source filter, quotas, error policy, argument parsing, and counters.

Mutation check (hand-rolled: `python3 -I collector/scripts/mutate.py "$PWD/collector"` from the repo root): 53 single-point mutations of the parser constants and comparisons (`>` to `>=`, each `MAX_*` plus and minus one, `rdlen >= 7`, the rdata slice bound, label/dot checks, header masks, obs-fold, bare-LF, method prefixes). All 53 are killed. The first review pass found that 10 of 10 survived because the tests used the constants themselves; they now use literals. The net-spike crate was not mutation-tested.

Tests for the new behavior were written and run red before the fixes, except the first spike's parser tests, which were written together with the implementation.

## Results (host-measured, not the router)

Host: Fedora workstation, kernel 7.2, unprivileged user, real `avahi-daemon` already bound to 5353 on v4 and v6, wifi interface. Binary: `x86_64-unknown-linux-musl` release build of the same code and profile. Runs were 10 s on a mostly idle host: a **10 s idle-host VmHWM says nothing about router memory under load or after 24 h**, only that the baseline is under 1 MB.

| Metric | Result |
|---|---|
| Bind to group address + join beside avahi, unprivileged | OK (exit 0), including `[ff02::fb]%ifindex:5353` |
| Injected multicast packets from `scripts/inject.py` parsed | yes, run with `--include-own` because the injector ran on the same host (otherwise they count as `own_packets` by design); `_vigie-probe._tcp.local`, `Vigie-Inject/1.0`, `uuid:vigie-inject::upnp:rootdevice` all present |
| Injected unicast datagram to 5353 (`unicast-only`) | not delivered: `_vigie-unicast._tcp.local` absent |
| Own packets without `--include-own` | counted separately (6 `own_packets` in one 10 s run), 0 off-link, 0 read errors, 0 parse errors, 0 evidence drops |
| Packets in 10 s (mDNS v4 / v6 / SSDP) | 4 / 1 / 8 (quiet moment); an earlier run saw 14 / 10 / 4 |
| VmRSS / VmHWM at exit | 468-476 kB / 468-476 kB |
| Failure path (`--addr 10.9.9.9`) | exit 2, bind/join error message |
| Binary size, aarch64-unknown-linux-musl (stripped, static) | **381,824 bytes (373 KiB)** |
| `cargo test` | 25 + 41 passed, 0 failed |
| `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` | clean |

### Not verified

- The aarch64 binary was cross-compiled but **not executed** (no qemu-user, no router access). Everything about actual router behavior (avahi coexistence on OpenWrt 21.02 / kernel 5.4.211, `su -s` / `start-stop-daemon` as `nobody`, `IP_MULTICAST_ALL` support on that kernel, aarch64 RSS) is pending the owner's run.
- Binding to the group address needs the router's avahi to share it; the host avahi did. A failure on the router would show as exit 2 (`Address already in use`); the fallback would be reading mDNS from avahi (e.g. `avahi-browse -a -p -r -t`), which this spike does not implement.
- The TTL/hop-limit 255 check is not implemented (see above).
- One multicast group per socket and one LAN interface only; guest-network (`isolate=1`) mDNS is out of scope.
