# P3 spike: TLS stack for the router collector

Date 2026-10-21. Goal: HTTPS transport with SPKI pinning under the router budgets (static
aarch64-unknown-linux-musl, collector RSS < 10 MB, `#![forbid(unsafe_code)]` in our crate, few
audited dependencies).

## Candidates and numbers (spike binaries, not the collector)

Each spike is a ~60-line program: rustls client, TLS 1.3+1.2, custom verifier, one GET against
`openssl s_server` on localhost. release profile identical to the workspace (opt-level z, LTO, panic
abort, strip). Baseline: the collector today is 512,840 bytes (aarch64).

| Option | aarch64-musl size | x86_64-musl size | RSS idle | RSS after handshake | Dep-tree lines (`cargo tree`) |
|---|---|---|---|---|---|
| rustls 0.23 + `ring` 0.17.14 | 1,024,928 | 1,267,392 | 560 kB | 1,200 kB | 22 |
| rustls + `rustls-rustcrypto` 0.0.2-alpha | 940,576 | 1,177,944 | 484 kB | 1,060 kB | 207 |
| rustls + `aws-lc-rs` | not built | | | | heavy (aws-lc-sys, cmake/C++ build); excluded on size and toolchain |

The sizes include std and the spike's own code, so they are upper bounds for the *growth* of the
collector (which already links std). Real growth is measured on the collector itself, see below.

## Decision: rustls + ring

* ring cross-compiles to aarch64-unknown-linux-musl with only host `clang`:
  `CC_aarch64_unknown_linux_musl=clang CFLAGS_...="--target=aarch64-unknown-linux-musl -nostdlibinc
  -ffreestanding -fno-stack-protector"`. These are now in `collector/.cargo/config.toml` `[env]`, so a
  plain `cargo build --release --target aarch64-unknown-linux-musl` works. The x86_64-musl build used
  for the RSS measurement needs the host headers instead (`-isystem /usr/include`, because ring's
  `check.h` includes `assert.h` there); that is a host-only measurement build, not a shipped one.
* The pure-Rust provider is only ~84 kB smaller and ~140 kB less RSS, but it is `0.0.2-alpha`, pulls
  ~10x the dependency tree (RustCrypto p256, aes-gcm, ...), and is not the provider the rustls
  maintainers audit and ship. ring is what rustls itself recommends/tests against. The small
  difference does not justify an alpha crypto provider on a device that authenticates by pin.
* Advisory check: RUSTSEC-2026-0104 (rustls-webpki, panic in CRL parsing) affects only users of
  CRLs; we use no CRLs and never build a chain. We still resolve a patched rustls-webpki.
* Cost: a C compiler (clang) is needed at build time. No runtime impact.

## Build-time constraint

`cargo build -p vigie-collector --target aarch64-unknown-linux-musl` now requires `clang` on PATH.
CI for the router build must provide it.


## Result on the real collector (aarch64-unknown-linux-musl, release, stripped)

| | bytes |
|---|---|
| before (no TLS) | 512,840 |
| after (rustls + ring + HttpsTransport) | 1,187,032 |
| growth | +674,192 (+131%) |

Plain `cargo build --release --target aarch64-unknown-linux-musl -p vigie-collector` works with no
extra environment (clang settings come from `collector/.cargo/config.toml`). Direct normal
dependencies of the agent crate: hmac, sha2, rustls, vigie-parse (25 unique crates in the normal
tree). `#![forbid(unsafe_code)]` still holds for our crate; ring/rustls contain their own unsafe/asm.

RSS: the `https_selftest` example (x86_64-musl release, two TLS handshakes against a local server,
including building a batch) peaks at 1,148 kB. The spike clients measured 0.5-0.6 MB idle and 1.2 MB
after a handshake. Resumption is disabled so no session cache is kept. Far below the 10 MB budget.
These are x86_64 numbers; aarch64 RSS was never measured (no device or emulator here).

## Design

* `tls_pin.rs`: `PinVerifier` accepts a server certificate iff SHA-256(SPKI DER) equals one of the two
  pins (no early exit, constant-time per pin). Chain, host name and validity period are ignored on
  purpose (self-signed, router clock may be wrong). The TLS 1.2/1.3 handshake signature is verified
  with ring's algorithms against the presented certificate's key, so the peer must hold the pinned
  private key. TLS 1.2 + 1.3 only; rustls contains no older protocol code.
* `https.rs`: blocking, one request per connection, `Connection: close`, one monotonic deadline for
  the whole exchange (default 30 s), response (head + body) capped at 64 KiB, chunked and
  missing-Content-Length responses refused (a close-delimited body can be truncated by an attacker),
  stops reading once `Content-Length` bytes are in (servers often close without close_notify).
  SNI only for DNS names; IPv6 brackets stripped for connect/SNI, kept in `Host`.
* `transport::make(cfg)` builds it; it never panics: a bad URL/pin yields a transport whose `post`
  returns the reason.
* The pin is the SHA-256 of the full SPKI DER; a test compares it with
  `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256`, and the ingest cross-check
  uses the hex pin that `deploy/gen-certs.sh` writes to `pins.txt`.

## Tests

`cargo test --workspace`: all pass. New: `tests/https_pin.rs` (pin accept/refuse, second pin,
reissued cert with same key, different key, forged handshake signature in TLS 1.2 and 1.3, expired
and not-yet-valid certs accepted, SPKI pin vs openssl), `tests/https_http.rs` (full POST with all
seven X-Vigie headers + Date + `{"duplicate":true}`, caps, chunked, slowloris, silent server,
header injection), `tests/https_hello.rs` (raw ClientHello: versions, suites, SNI),
`src/https.rs` unit tests, and `tests/vectors/test_https_against_ingest.py` (real `vigie_ingest`
over TLS with a `gen-certs.sh` certificate: wrong pin refused; correct pin: attempt 1 reply "lost",
attempt 2 returns `Sent { duplicate: true }`; one batch stored). Run with
`VIGIE_INGEST_SRC=server/src python3 tests/vectors/test_https_against_ingest.py`: passes.

## Mutation results (hand-applied textual mutants, targeted test set)

| Mutant | Result |
|---|---|
| pin compare removed (`if true`) | killed |
| `ct_eq` always true | killed |
| only the first pin checked | killed |
| hash whole certificate instead of SPKI | killed |
| TLS 1.3 handshake signature verify stubbed | killed |
| TLS 1.2 handshake signature verify stubbed | killed |
| chain check enabled (self-signed cert has no anchor) | killed |
| chunked accepted (Transfer-Encoding arm removed) | killed (needs the TE+Content-Length case) |
| missing Content-Length accepted | killed |
| response cap constant raised | killed |
| declared-length cap check removed | killed (timing assert: refused at the head) |
| header-block cap or per-read cap removed, one at a time | survived: redundant, three overlapping checks enforce the cap; the cap-constant mutant is killed |
| read timeout removed | killed |
| per-read timeout instead of overall deadline (slowloris) | killed |
| connect timeout constant unbounded | survived: equivalent, connect is still bounded by the overall deadline |
| header control characters not rejected | killed |
| `Date` ignored | killed |
| userinfo accepted | killed |
| `http://` accepted | killed |
| TLS < 1.2 enabled | not applicable: rustls has no TLS 1.0/1.1 code. The raw ClientHello test asserts only 1.2/1.3 and modern suites are offered. An end-to-end `openssl s_server -tls1_1` test exists but is skipped on this host (Fedora crypto policy refuses to start the server). |

Not mutation-tested: handshake-signature tampering by a man in the middle flipping one byte (the
forged-signer test covers the same verification path in both TLS versions).

## Not verified

* Never run on the router; aarch64 binary never executed (no emulator/device). Only built.
* The router's clock and whether its upstream path/`Date` handling behave as assumed (the transport
  returns `Date` when present; whether the router can resolve/route to the server is untested).
* x86_64 RSS only; real aarch64 RSS, entropy source (`getrandom` on the router kernel) and
  OpenWrt 21.02 kernel/ABI compatibility of the musl static binary are unverified.
* `main.rs` still contains the now-unused `NoTransport`; with it unused, `clippy -D warnings`
  reports `dead_code` for the bin. Deleting that struct (and its import) fixes it; that edit was
  left to the branch that owns `main.rs`.
