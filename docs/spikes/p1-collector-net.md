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

Flags: `--addr` (required, LAN IPv4 for the IGMP join), `--iface` (needed for `--v6`), `--v6` (also join `[ff02::fb]:5353`; failure is reported in the JSON, not fatal), `--secs N` (default 30).

Exit codes: `0` ok, `2` bind/join of the IPv4 mDNS or SSDP group failed (message names which one; this is the "does not coexist with avahi" answer), `64` bad arguments.

### What to paste back

- `uname -m`, `cat /tmp/net-spike.err`, the exit code.
- `/tmp/net-spike.json`. It contains device and service names from your LAN (mDNS hostnames, SSDP SERVER/USN strings). Redact hostnames you consider private; the `packets`, `parse_errors`, `VmRSS_kB`, `VmHWM_kB` fields are what matter. If `mdns6` is `failed: ...`, paste that string.
- The `ss`/`netstat` line showing both avahi and net-spike on 5353 (or the failure).
- If the bind fails: `cat /proc/net/udp | grep ':14E9'` (5353 in hex) and `ps | grep avahi`.

Pass criteria: exit 0, `packets.mdns4 > 0` (real LAN mDNS received alongside avahi), `packets.ssdp >= 0` (may legitimately be 0 on a quiet LAN, so trigger an SSDP scan to prove it), `parse_errors` small, `VmHWM_kB` well under 10 MB.

## Parser hardening (tested)

| Concern | Limit / behavior |
|---|---|
| mDNS packet size | > 9000 bytes rejected |
| Records per packet | qd+an+ns+ar > 128 rejected before any parsing |
| Name length | > 255 decoded bytes rejected; label length bits `01`/`10` rejected |
| Compression pointers | at most 8 jumps per name, so loops (self and two-cycle) fail with `PointerLoop`; out-of-range pointers fail with `Truncated` |
| Truncation | every prefix of a valid query returns an error, never a panic or partial result |
| Output bytes | non-printable / non-ASCII label bytes become `?` |
| SSDP | packet <= 2048 B, <= 32 lines, header values <= 256 chars with control chars replaced, parsing stops at the blank line, only `NOTIFY`/`M-SEARCH` accepted |
| Retained strings | each result set capped at 256 entries (bounded memory) |

Tests: 18 unit tests including truncation at every offset, pointer loops, and 20,000-iteration xorshift random/mutated-packet "never panics" tests per parser (the task asked for property-style without `cargo fuzz`; no `proptest` dependency was added). Tests were written in the same pass as the implementation, not strictly red-first.

## Results (host-measured, not the router)

Host: Fedora workstation, kernel 7.2, unprivileged user, real `avahi-daemon` already bound to 0.0.0.0:5353 and [::]:5353, wifi interface with real LAN traffic. Binary: `x86_64-unknown-linux-musl` release build, same code and profile as the aarch64 build. 10 s run with `--v6`, plus a Python script sending one mDNS query and one SSDP NOTIFY and M-SEARCH to prove receive and parse.

| Metric | Result |
|---|---|
| Bind + join beside avahi, unprivileged | **OK** (exit 0), including `[ff02::fb]:5353` |
| Packets in 10 s (mDNS v4 / mDNS v6 / SSDP) | 24 / 22 / 4 |
| Injected test packets parsed | yes (the `_airplay._tcp.local` query and both SSDP requests appeared in the summary) |
| Parse errors on real LAN traffic | 0 of 50 packets |
| VmRSS / VmHWM at exit | **444 kB / 448 kB** |
| Failure path (`--addr 10.9.9.9`, no such interface) | exit 2, `mDNS 224.0.0.251:5353 bind/join failed: No such device` |
| Binary size, aarch64-unknown-linux-musl (stripped, static) | **373,880 bytes (365 KiB)** |
| Binary size, x86_64-unknown-linux-musl (static-pie) | 418,552 bytes |
| `cargo test` | 18 passed, 0 failed |
| `cargo clippy --all-targets -- -D warnings` | clean |

### Not verified

- The aarch64 binary was cross-compiled and `file` reports `ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped`, but it was **not executed** (no qemu-user and no router access here). Everything about actual router behavior (avahi coexistence on OpenWrt 21.02 / kernel 5.4.211, `su -s`/`start-stop-daemon` as `nobody`, RSS on aarch64) is pending the owner's run.
- The host avahi binds with its own socket options; the router's avahi may differ. A failure there would show as exit 2 with `Address already in use`, and the fallback would be to read mDNS from avahi instead (e.g. via `avahi-browse -a -p -r -t`), which this spike does not implement.
- Multicast loopback is disabled on our sockets, which only affects our own sends (we never send).
- Only one multicast group per socket and one LAN interface are handled; guest-network (`isolate=1`) mDNS is out of scope.
