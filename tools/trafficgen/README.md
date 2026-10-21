# trafficgen

Deterministic synthetic collector traffic for Vigie tests: a baseline home LAN plus adversarial
profiles. Output is byte-identical for a given `--seed`, independent of `PYTHONHASHSEED`. Every
batch is validated against `api/batch.schema.json` and signed with the real ingest signing code.

Everything synthetic uses reserved values: `.example` domains, RFC 5737 addresses
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for "public" destinations, the RFC 7042
documentation MAC range (`00:00:5e:00:53:xx`) for non-randomised MACs. The DoH resolvers of the
`doh_user` profile are documentation addresses, listed in its manifest as `doh_resolvers`.

```
uv run trafficgen generate --profile mac_clone --variant same_fingerprint --seed 1 --out /tmp/out
uv run trafficgen fixtures --out ../../tests/fixtures/synthetic     # regenerate the committed set
uv run trafficgen post --profile baseline --url https://vigie.lan:8443 --key-file ./collector.key
```

(`python -m trafficgen` works too.) `generate` writes `<profile>.jsonl` (one emission per line:
batch, arrival time, expected status) and `<profile>.manifest.json` (ground truth: devices, MACs,
anomalies, a plain-language `note`).

## post

Signs each batch with the collector key and POSTs it to `/v1/batch`.

**Pacing.** The server rejects a batch whose `sent_ts` is more than 300 s from its clock, so the
synthetic timeline is mapped onto the wall clock and replayed in real time by default (10 windows
take about 9 minutes). `--no-pace` sends back to back instead; it refuses (exit 2) when the span
exceeds `--max-skew-s` (default 240) unless `--no-pace-check` is given.

**Key handling.** The key is never taken from argv (it would show up in `ps` and shell history).
Use exactly one of: `--key-file PATH` (hex), `--key-stdin`, or `$VIGIE_TRAFFICGEN_KEY`. A missing
file or bad hex gives a one-line error with exit 2, never a traceback, and key material is never
printed. Keys under 32 bytes are refused.

**TLS.** Verification is always on; there is no way to turn it off.

- `--ca-file PATH`: trust this CA, or the server's self-signed certificate itself, instead of the
  system store (the certificate needs a matching subjectAltName for the host you connect to).
- `SSL_CERT_FILE=/path/ca.pem` does the same through the environment (OpenSSL default path).
- `--pin-sha256 HEX`: additionally require the SHA-256 of the server certificate's
  SubjectPublicKeyInfo (DER) to equal HEX, compared in constant time on every new connection
  before any request is sent; a mismatch exits 2. This is the lowercase hex `pin_sha256_hex` that
  `deploy/gen-certs.sh` prints (also in `pins.txt`). A pin does not replace chain verification, so
  for a self-signed certificate combine it with `--ca-file server.crt`:

```
trafficgen post --profile baseline --url https://192.168.1.10:8443 --key-file collector.key \
  --ca-file deploy/certs/server.crt --pin-sha256 "$(sed -n 's/^pin_sha256_hex=//p' deploy/certs/pins.txt)"
```

Exit codes: 0 all responses as expected, 1 some response differed from the manifest's expectation,
2 usage, key, TLS or connection error.

## Profiles

`--variant` selects a variant (the first one listed is the default). Fixture names in
`tests/fixtures/synthetic/` add the variant as a suffix.

| profile | what it is for |
|---|---|
| `baseline` | Benign seven-device LAN. False-positive control. |
| `rolling_mac` | A phone takes a fresh private MAC every `--roll-interval` s, no overlap. |
| `hostname_spoof` | `hostname_only` (default): attacker copies hostname + mDNS name, not opt55/60. `full_fingerprint`: copies opt55, opt60, hostname and mDNS name; only behavior differs. |
| `mac_clone` | `naive` (default): attacker takes the victim's MAC but keeps its own DHCP fingerprint, so the fingerprint change is visible. This models only the naive clone. `same_fingerprint`: same MAC AND same opt55/opt60/hostname/mDNS, differing only in behavior (ports/domains); the manifest marks `detectable_only_by: behavioral_demotion`. |
| `ip_flap` | One IP alternates between two MACs in the neighbor table (ARP spoof signal). |
| `doh_user` | Large 443 traffic to DoH resolvers (documentation addresses), no DNS queries at the router. |
| `rolling_overlap_veto` | PRP section 8 overlap veto, grace window 600 s. Case `legit_rolling`: a rolling phone holds two MACs for 180 s (inside grace, same device). Case `sustained_two_devices`: two devices with one signature are both active for 840 s (beyond grace, two devices). The manifest marks each case, its overlap and the expected verdict. |
| `rolling_fingerprint_copy` | PRP section 8 accepted risk: attacker copies a rolling device's opt55, opt60 and hostname. `victim_away` (default): attacker connects after the victim left (no overlap). `victim_present`: attacker connects while the victim is on the LAN (overlap beyond grace). |
| `replay` | `replay_identical`: same batch re-sent, 200 duplicate. `replay_header_ts_bumped`: same body and ORIGINAL signature with only the `X-Vigie-Sent-Ts` header bumped; the key is not held so it cannot be re-signed and the server answers 401 signature mismatch. |
| `out_of_order` | Two adjacent batches swapped; the late one gets 409. |
| `stale_ts` | A batch with an hour-old `sent_ts`; 400. |
| `flood` | One window with more raw flows than the batch cap; PRP section 4 truncation order. |

In the overlap profiles every active MAC emits a neighbor-table entry each window, so presence is
deterministic and the overlap in the traffic equals the overlap in the manifest.

## Fixtures

`tests/fixtures/synthetic/` holds 15 committed fixtures, regenerated by `trafficgen fixtures` and
checked byte for byte by the tests. Real budget: each `.jsonl` under 200 KB, the set 613 KB
(limit 650 KB); the largest are `rolling_overlap_veto` (about 122 KB), `rolling_fingerprint_copy_*`
(about 90 KB) and `flood` (74 KB, committed with a 64 KB batch cap instead of 256 KB).

## Tests

`uv run pytest -q` (coverage gate 80 percent) includes replays against the real ingest app,
`vigie_pipeline.run_once` over every fixture, a local TLS server for the pin tests (needs the
`openssl` CLI) and a PYTHONHASHSEED determinism check.
