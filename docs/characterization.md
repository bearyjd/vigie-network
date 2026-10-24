# Deterministic device characterization v1

This contract describes heuristic type suggestions, never identity proof, trust, groups or enforcement. Multicast announcements are spoofable and are attributed through the collector neighbor mapping. No external fingerprint dataset or OUI lookup is used. Human type overrides retain precedence at integration.

`classify(observations, now, ttl_seconds=86400)` evaluates one MAC, reading at most 257 observations (256 accepted). Mixed MACs, malformed inputs, invalid clocks/TTL or excess input abstain. MACs normalize ASCII hex case only; locally administered prefixes are not vendor evidence. Inputs and evidence strings are bounded to 256 UTF-8 bytes, without control characters. Future timestamps are rejected. Support is fresh only while `observed_at <= now < observed_at + ttl_seconds`.

| Rule ID | Exact required mDNS service pair | Suggested type / role |
|---|---|---|
| android-tv-services-v1 | `_googlecast._tcp` and `_androidtvremote2._tcp` | `tv` / `television` |
| printing-services-v1 | `_printer._tcp` and either `_ipp._tcp` or `_ipps._tcp` | `iot` / `printing` |

Service matching ignores ASCII case and permits the exact `.local` suffix and optional terminal dot. It does not match substrings, instance names, whitespace or extra suffixes. Signals must belong to the same MAC; a stale member cannot complete a fresh pair. DHCP vendor strings, option lists, names, SSDP user agents and a single casting/printing advertisement alone produce `unknown`. Version 1 accepts DHCP/SSDP context but defines no sufficient rule for it. `iot` is the existing broad API type; printing is a role, not a new `printer` enum value.

The model version is `services-v1`. A single matching rule returns qualitative strength `corroborated`, with numeric confidence `None`; this is not calibrated probability or measured accuracy. Both rule families matching returns `unknown` with reason `conflicting_roles`. Evidence contains canonical protocol/service tokens and supporting timestamps, never raw names/vendor/UA. Repeated services use the latest fresh observation; alternative printing pairs use the longest remaining valid support. `valid_until` is the oldest required supporting timestamp plus TTL, never an unrelated newer observation. At expiry, recomputation abstains unless new complete support exists. Conflicting output expires when its earliest contributing support expires and must be recomputed.

The pure function does not write storage, read clocks implicitly, modify identity, apply human labels or retain history. Integration must persist the version/evidence/expiry, recompute expiration, and apply human override precedence independently. Truncated upstream evidence must not be presented as a complete characterization assessment.
