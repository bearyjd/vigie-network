# Whole-chain smoke test (`tests/e2e/run_e2e.sh`)

Runs the real components end to end on one host, as a normal user, bound to 127.0.0.1 on random
high ports. No podman, no root, no router.

```
fixtures -> vigie-collector (real binary) --HTTPS+pin+HMAC--> vigie_ingest (real, TLS)
         -> vigie_pipeline run --once -> vigie_api (real, TLS) -> GET/PATCH checks
```

```sh
tests/e2e/run_e2e.sh [--skip-build]     # ~90 s; exit code 0 = every stage passed
VIGIE_E2E_NO_TAGS=1 tests/e2e/run_e2e.sh --skip-build   # control run, see F1
```

Env: `VIGIE_E2E_BASE` (default `~/.cache/vigie-e2e`; each run gets `run-<pid>/` with `logs/`, the
data dir, keys and certs), `VIGIE_E2E_WINDOW_S` (agent `--window-s`, default 6),
`VIGIE_E2E_STEP_S` (seconds per phone MAC, default 10), `CARGO_TARGET_DIR`, `UV_CACHE_DIR`,
`UV_PROJECT_ENVIRONMENT`, `TMPDIR` (defaults under `~/.cache/vigie-e2e-*`). The script never
deletes anything; old `run-*` directories are yours to remove.

## Stages

| Stage | What it does |
|---|---|
| build | `cargo build --release` of `vigie-collector` + `vigie-conntrack`, `uv sync` of `server/` |
| provision | `deploy/gen-certs.sh` x3 (two ingest certs for pin1/pin2, one API cert), SPKI pins from `pins.txt`, `openssl rand -hex 32` key (0600 in a 0700 dir), `python -m vigie_ingest.admin provision rtr-1 k1` |
| ingest_up | real `python -m vigie_ingest` over TLS, temp data dir, secrets dir |
| collector_check | `vigie-collector --check` on the generated `collector.conf` |
| collect | fake conntrack socket + real agent (non-root, `--window-s 6`) + `feed.py` writing fixtures in 3 timed steps |
| ingest_assert | `assert_ingest.py`: batches table, collector seq, raw shard contents |
| api_token | `python -m vigie_api tokens create` (this also creates `overrides.db`) |
| pipeline_1 | `python -m vigie_pipeline run --once` |
| api_up / api_assert | real `vigie_api` over TLS (self-signed cert, verified by the client), `assert_api.py phase1` |
| pipeline_2 / api_assert_after_rerun | second pipeline pass, then `assert_api.py phase2`: human name/group survived |

Test doubles (the only fakes):
* **dnsmasq**: the log, `dhcp.leases` and the neighbor file are fixtures from `feed.py`. The agent
  tails the log from its END on the first poll, so lines are appended after the agent started.
* **`ip neigh`**: the agent shells out to `ip -4/-6 neigh show` (`runtime.rs`) and has no file
  override, so a wrapper `ip` script is placed first in the agent's PATH and prints a fixture.
* **conntrack helper**: `fake_conntrack.py` serves a 0600 unix socket and sends snapshots produced by
  the REAL `vigie-conntrack --once --file conntrack{1,2}.txt` (re-stamped seq/ts/interval_s).
  The root daemon is never started.
* **dnsmasq drop-in** (`/tmp/dnsmasq.d/vigie.conf`) does not exist: see F4.

Devices: a stable laptop (`alice-laptop`), a camera (`cam-front`, a DNS query every second), and a
phone (`Pixel-8`, same opt55 and vendor class) that rolls through three locally administered MACs
(`c2:11:22:33:44:01..03`, one per 10 s step, all on 192.168.1.50).

## Result of the reference run (all stages PASS)

* ingest: 11 batches (seq 1..11, no gaps), `parse_failures` 0, 0 dropped.
* raw shard: 51 `raw_dns` (camera 30, laptop 9, phone MACs 4+4+4), 12 `raw_flow`, 10 `raw_lease`,
  5 `raw_neigh`, 11 `raw_health`.
* pipeline: 5 devices (laptop and camera `active`, three phone MACs `transient`), 5 `new_device`
  events. Second pass: 0 batches, 0 new devices.
* API: default `/devices` lists 2 devices; `include_transient=1` lists 5; `/macs/<mac>` resolves all
  five MACs with the right hostnames; PATCH without If-Match is 428, with the ETag 200, with a stale
  ETag 412; the name and group `trusted` are visible in the effective view and unchanged after
  the second pipeline pass.

## Findings

Severity is my judgement. Nothing outside `tests/e2e` and this file was changed.

**F1 (HIGH, collector) DHCP fingerprints (opt55, vendor class) are never captured from a log that
contains dnsmasq's `tags:` line.** `raw_lease.opt55` is `[]` and `opt60` NULL on every row and
`observations.dhcp_fingerprint` is NULL, so the device-identity inputs are empty. Cause:
`parse_dhcp` does not recognise `<id> tags: br-lan`, `poll_log` treats an unparsed line as
`break_context()`, and the assembler only attaches `requested options:` / `vendor class:` /
`client provides name:` to the packet line directly before them. dnsmasq (and the repo's own
`tests/fixtures/p0/dnsmasq-dhcp-sample.log`) prints `tags:` right after `DHCPREQUEST`. No unit test in
`dnsmasq.rs` contains a `tags:` line, so the suite is green. Repro: run the script, then
`VIGIE_E2E_NO_TAGS=1 tests/e2e/run_e2e.sh --skip-build`; the second run has fingerprints
(`[1,3,6,15,26,28,51,58,59]`, `android-dhcp-14`, and the hard assertion in `assert_ingest.py`
passes). Proposed patch (not applied): add `LogEvent::DhcpTags { id }` (also for the other per-transaction
informational lines, e.g. `next server:`, `sent size:`) that a `DhcpAssembler` treats as a no-op keeping
`ctx` when `id` equals `ctx.id`, plus a unit test using the sample file. I could not check what the
GL-XE3000's dnsmasq actually prints; the fixture is the only evidence.

**F2 (INFO, pipeline) Rolling-MAC grouping is not exercised.** Even with correct fingerprints
(control run) the three Pixel-8 MACs stay three separate `transient` devices; `identity_candidates`
and `suggestions` are empty. The pipeline README lists no linking stage, so this is the current
design, not a regression. The chain can only assert "hidden by default, visible with
`include_transient=1`, correct hostname per MAC".

**F3 (LOW, collector) lease-file rows carry no fingerprint.** After the log-derived lease (with
opt55), the next window re-emits the same leases from `dhcp.leases` with `opt55: []`. The pipeline's
first-wins rule keeps the earlier fingerprint in this run, but a MAC whose first-ever row comes from
the lease file would be stored without one. Not reproduced; noted as a risk.

**F4 (INFO, collector) `dns_log_quiet` is always true outside a router.** `DROPIN_PATH` and `LOG_DIR`
are constants (`dropin.rs`), so regular windows report quiet when `/tmp/dnsmasq.d/vigie.conf` is
missing (only the identity/probe batches report false). Harmless here, but a test hook would let the
health path be tested.

**F5 (LOW) first conntrack snapshot is unmapped.** The helper's first snapshot arrived before the
neighbor table knew the hosts: `batches.truncated = {"ct_unmapped_bytes":54800,"ct_unmapped_flows":3}`.
Expected at start-up, but the counters live in the column named `truncated`, which is confusing.

**F6 (INFO, pipeline) `run_complete.macs` is 24** for 5 distinct MACs: it counts MAC observations
across the 11 batches, not distinct MACs.

**F7 (INFO) Agent start-up ordering.** The tail starts at the end of the log, and the first batch(es)
are empty probes until the server `Date` header is seen. Anything written to the log before the agent
starts is never read. The script waits 3 s after the agent starts before feeding.

**F8 (INFO) No test seam for `ip neigh`.** Needed the PATH wrapper (above).

No ingest 4xx, no parse failures, no schema mismatches, no timing rejection (sent_ts skew,
seq/boot) were observed. The agent log was empty.

## Not verified

* A real router, real dnsmasq output (F1 depends on its format), OpenWrt busybox `ip`.
* Multicast (mDNS/SSDP): the agent was configured with `lan_addr=127.0.0.1`, `lan_iface=lo`; it
  started without error, but no multicast packet was sent, so `raw_sighting` is 0 and listening was not
  tested.
* The real conntrack daemon and `/proc/net/nf_conntrack` (the real helper binary only parsed
  fixtures in `--once` mode; the socket publisher and its root/uid checks were not run).
* IPv6 neighbors, rate limiting, clock skew, spool/backoff after an outage, certificate rotation
  (pin2), the container deployment, and anything over one hour (promotion needs >= 2 server hours).
