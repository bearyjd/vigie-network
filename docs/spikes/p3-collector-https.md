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

(Final collector numbers, test results and mutation table are appended below as the work completes.)
