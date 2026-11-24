# Product-signal coverage inventory (M2b-I)

This is an offline report. It measures how many in-scope effective devices carry a defensible product-level evidence signal. It is **evidence only**. It never authorizes known-issue notes, trust, groups, merges or enforcement. Every report carries `authorizes_known_issue_notes: false` and a fixed notice. Known-issue work also needs an owner-approved inventory and an agreed usefulness threshold.

```sh
python -m vigie_pipeline.product_signal_cli --inventory INVENTORY.json [--threshold 0.6]
```

The command writes canonical JSON to stdout: sorted keys, compact separators, ASCII and a trailing newline. Reordering the devices, links, MACs or observations in the input does not change one byte of the output. The clock is the document's `now`, never the host clock.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Report written. |
| 2 | Arguments or threshold invalid. |
| 3 | Inventory unreadable. |
| 4 | Inventory invalid. |

Error messages are fixed text and never echo inventory values.

## Input (`vigie-product-signal-inventory`, version 1)

The input is a strict JSON document. Unknown keys, duplicate keys, `NaN` and `Infinity` are rejected, and booleans are refused where numbers are expected. Limits: 8 MiB of input, 10,000 devices, 10,000 links, 64 MACs per device and 200,000 observations. Strings are at most 256 UTF-8 bytes and contain no control characters.

The document has these fields:

- `now`: the export time, as a Unix timestamp.
- `ttl_seconds`: the freshness window. Optional; the default is 86400, the same as characterization.
- `devices`: a list of `{id, status, macs: [{mac, oui_vendor}]}`. `status` is `active`, `transient` or `retired`. `oui_vendor` is an optional lookup supplied by the owner; Vigie bundles no OUI dataset.
- `links`: a list of `{from, into, revoked}`. Merges are active links, and an undo is a revoked link.
- `observations`: a list of `{mac, kind, observed_at, ...}`. `kind` is `mdns`, `ssdp` or `dhcp`. The optional fields are `service`, `ua`, `opt55`, `opt60`, `hostname`, `manufacturer` and `model`. `manufacturer` and `model` are structured device-description fields and are accepted only on `mdns` and `ssdp` observations.

MACs use the pipeline's normalizer, so multicast, broadcast and all-zero MACs are rejected. The following are also rejected: a MAC on two devices, a duplicate device ID, a link to an unknown device, a self link, two active links from one device, link cycles, chains deeper than 32 links, and future timestamps.

## Scope and coverage

Effective devices follow `vigie_api.effective`. Only non-revoked links are followed, and aliases fold into their canonical device. The canonical row's status decides scope: `active` devices are in scope, while `transient` and `retired` devices are excluded and counted. An alias of an excluded canonical device is out of scope.

Coverage is reported as `numerator / denominator`:

- The numerator is the number of `product_level` devices.
- The denominator is the number of in-scope effective devices.
- The ratio is rounded to 6 decimals.
- When the scope is empty, the ratio is `null` with reason `empty_scope`.

The `scope` block reports the input devices, aliases folded, retired and transient exclusions, and observations for MACs absent from the inventory.

The threshold is an owner input with no default. It is a decimal with `0 < T <= 1` and at most 6 places, and it is compared exactly as a fraction. When it is omitted, `met` is `null`.

## Classes (`product-signal-v1`), first match wins

Freshness uses the characterization window: `observed_at <= now < observed_at + ttl_seconds`. Signals pool across every MAC of the effective device.

| Class | Reason(s) | Condition |
|---|---|---|
| `conflicting` | `product_claims_disagree` | Two or more distinct fresh (manufacturer, model) claims. Comparison ignores case and collapses whitespace. |
| `product_level` | `fresh_product_claim` | Exactly one distinct fresh claim. |
| `expired` | `product_claim_expired` | Product claims exist, but none is fresh. |
| `generic` | `type_level_service_match`, `vendor_without_model`, `generic_hint` | Some fresh non-product evidence exists. A services-v1 characterization match is type-level only. A manufacturer without a model, a service, a UA, or DHCP option 55 or 60 is generic. |
| `oui_only` | `oui_vendor_only`, `oui_vendors_differ` | Only OUI vendors on globally administered MACs. Differing OUIs in a merged group get their own reason. |
| `unknown` | `random_mac_oui_ignored`, `expired_generic_only`, `no_signal` | Nothing usable. An OUI on a locally administered (random) MAC is not vendor evidence. |

A product manufacturer that differs from the OUI vendor is normal, for example a radio-module vendor, and is not a conflict. Hostnames are never evidence. Human overrides (name, owner, type, group) are not inputs.

The per-device output holds:

- class and reason
- members
- MAC and random-MAC counts
- canonical source tokens: `mdns_model`, `ssdp_model`, `*_vendor`, `mdns_service`, `ssdp_ua`, `dhcp_opt55`, `dhcp_opt60` and `oui`
- `valid_until`, which is when the earliest fresh claim lapses

It never contains raw vendor, model, service, UA or hostname strings. The class and reason counts both sum to the denominator.

## Open owner decisions

- Which observation sources count as product-level. v1 accepts only structured mDNS/SSDP manufacturer and model fields. The collector does not yet export these fields.
- Where the inventory comes from. There is no exporter yet, and a read-only database adapter is a separate slice.
- Which OUI lookup to use, if any, and the usefulness threshold.
