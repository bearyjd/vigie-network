//! Batch builder: fits one window of data into the 256 KB cap in PRP section 4 order.
//!
//! Reading of the PRP order ("leases/neigh/mDNS first; then DNS; then conntrack top-N by bytes;
//! remainder folded into one `other` bucket per MAC"): it is a retention priority, so a flood
//! of the bulkiest/least identifying data (conntrack, then DNS) cannot evict the small
//! identity records that re-attach a rolled MAC. Budgets are filled in that order; the
//! identity group is capped so a lease/mDNS flood cannot starve DNS and conntrack either.

use std::collections::{BTreeMap, HashMap};

use crate::model::*;

pub const BATCH_CAP: usize = 256 * 1024;
/// The ingest server's request body limit (`MAX_BODY_BYTES` in server `config.py`, 512 KiB). The
/// agent stays at half of it; `BATCH_CAP` must never exceed this.
pub const SERVER_MAX_BODY: usize = 512 * 1024;
/// Most of the cap the identity group (leases, neigh, sightings) may use.
pub const IDENTITY_BUDGET: usize = 96 * 1024;
/// Conntrack is guaranteed this much (or what it needs, if less) before DNS may use the rest.
pub const CONNTRACK_RESERVE: usize = 48 * 1024;
/// Room kept for the `truncated` map (the schema allows 16 keys; we emit at most 14).
pub const TRUNCATED_RESERVE: usize = 768;
/// Server rule: a window may span at most 24 h.
pub const MAX_WINDOW_S: u64 = 24 * 3600;
/// Server rule: every `dns.ts` must lie within this many seconds of the window.
pub const DNS_TS_SLACK_S: u64 = 300;

pub struct Built {
    pub encoded: EncodedBatch,
    pub truncated: BTreeMap<String, u64>,
}

fn json_len(write: impl Fn(&mut String)) -> usize {
    let mut s = String::new();
    write(&mut s);
    s.len()
}

/// Keep a prefix of `items` within `budget` bytes and `hard_cap` items. Returns the kept items,
/// the number dropped and the bytes used (each item costs its JSON plus a comma).
fn take_within<T>(
    items: Vec<T>,
    budget: usize,
    hard_cap: usize,
    size: impl Fn(&T) -> usize,
) -> (Vec<T>, u64, usize) {
    let total = items.len();
    let mut used = 0usize;
    let mut kept = Vec::new();
    for it in items.into_iter().take(hard_cap) {
        let sz = size(&it) + 1;
        if used + sz > budget {
            break;
        }
        used += sz;
        kept.push(it);
    }
    let dropped = (total - kept.len()) as u64;
    (kept, dropped, used)
}

fn note(truncated: &mut BTreeMap<String, u64>, kind: &str, dropped: u64) {
    if dropped > 0 {
        truncated.insert(kind.to_string(), dropped);
    }
}

/// Server limit: a `truncated` map with more keys is a 422 for the whole batch.
pub const MAX_TRUNCATED_KEYS: usize = 16;
/// Bitmask key (not a count): never merged into the overflow key.
pub const FLAGS_KEY: &str = "source_flags";
pub const OTHER_KEY: &str = "truncated_other";
/// Keys that yield first when the map is over the key cap, whatever their count: the redundant
/// companions of a kept signal (`ct_unmapped_flows` accompanies `ct_unmapped_bytes`).
const YIELD_FIRST: [&str; 1] = ["ct_unmapped_flows"];

/// At most `MAX_TRUNCATED_KEYS` keys: the `YIELD_FIRST` keys go first, then the smallest counts;
/// the removed counts are summed into `truncated_other`. The `source_flags` bitmask is always kept verbatim.
fn cap_truncated_keys(t: &mut BTreeMap<String, u64>) {
    if t.len() <= MAX_TRUNCATED_KEYS {
        return;
    }
    let flags = t.remove(FLAGS_KEY);
    let mut rows: Vec<(String, u64)> = std::mem::take(t).into_iter().collect();
    rows.sort_by(|a, b| {
        let yields = |k: &str| YIELD_FIRST.contains(&k);
        yields(&a.0)
            .cmp(&yields(&b.0))
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    let keep = MAX_TRUNCATED_KEYS - 1 - usize::from(flags.is_some());
    let overflow = rows
        .split_off(keep.min(rows.len()))
        .iter()
        .fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
    t.extend(rows);
    t.insert(OTHER_KEY.to_string(), overflow);
    if let Some(f) = flags {
        t.insert(FLAGS_KEY.to_string(), f);
    }
}

fn conntrack_size(rows: &[ConntrackSummary]) -> usize {
    rows.iter().map(|r| json_len(|o| r.write(o)) + 1).sum()
}

/// Top `k` rows by bytes kept verbatim; the rest summed into one `other` bucket per MAC.
fn fold_after(sorted: &[ConntrackSummary], k: usize) -> Vec<ConntrackSummary> {
    let mut buckets: BTreeMap<&str, (u64, u64, u64)> = BTreeMap::new();
    for r in &sorted[k..] {
        let b = buckets.entry(r.mac.as_str()).or_default();
        b.0 = b.0.saturating_add(r.bytes_up);
        b.1 = b.1.saturating_add(r.bytes_down);
        b.2 = b.2.saturating_add(r.flows);
    }
    let mut out: Vec<ConntrackSummary> = sorted[..k].to_vec();
    // A surviving verbatim `other` row of a MAC absorbs that MAC's bucket: one row per MAC.
    let verbatim_other: HashMap<&str, usize> = sorted[..k]
        .iter()
        .enumerate()
        .filter(|(_, r)| r.dst_ip.is_none() && r.dst_port.is_none() && r.proto == Proto::Other)
        .map(|(i, r)| (r.mac.as_str(), i))
        .collect();
    for (mac, (up, down, flows)) in buckets {
        match verbatim_other.get(mac) {
            Some(&i) => {
                let r = &mut out[i];
                r.bytes_up = r.bytes_up.saturating_add(up);
                r.bytes_down = r.bytes_down.saturating_add(down);
                r.flows = r.flows.saturating_add(flows);
            }
            None => out.push(ConntrackSummary {
                mac: mac.to_string(),
                dst_ip: None,
                dst_port: None,
                proto: Proto::Other,
                bytes_up: up,
                bytes_down: down,
                flows,
            }),
        }
    }
    out
}

fn fits(rows: &[ConntrackSummary], budget: usize) -> bool {
    rows.len() <= MAX_CONNTRACK && conntrack_size(rows) <= budget
}

/// Top-N by bytes, remainder folded per MAC. Returns (rows, folded input rows, lost buckets).
fn truncate_conntrack(
    mut rows: Vec<ConntrackSummary>,
    budget: usize,
) -> (Vec<ConntrackSummary>, u64, u64) {
    rows.sort_by(|a, b| {
        b.total_bytes()
            .cmp(&a.total_bytes())
            .then_with(|| (&a.mac, &a.dst_ip, a.dst_port).cmp(&(&b.mac, &b.dst_ip, b.dst_port)))
    });
    let n = rows.len();
    if fits(&fold_after(&rows, n), budget) {
        return (rows, 0, 0);
    }
    // Largest k whose verbatim rows plus folded buckets fit (binary search, then verify).
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(&fold_after(&rows, mid), budget) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let mut k = lo;
    while k > 0 && !fits(&fold_after(&rows, k), budget) {
        k -= 1;
    }
    let mut out = fold_after(&rows, k);
    let folded = (n - k) as u64;
    let mut lost = 0u64;
    // Even k = 0 can overflow when there are very many MACs: drop the smallest buckets.
    while !fits(&out, budget) {
        let Some(i) = (k..out.len()).min_by_key(|&i| out[i].total_bytes()) else {
            break;
        };
        out.remove(i);
        lost += 1;
    }
    (out, folded, lost)
}

/// Build one batch from a window of data. `cap` is the maximum body size including the tail.
pub fn build(meta: &Meta, input: Sections, health: &Health, cap: usize) -> Built {
    build_with_drops(meta, input, health, cap, &BTreeMap::new())
}

/// As `build`, also reporting `drops` (rows lost before the builder, by `truncated` key).
pub fn build_with_drops(
    meta: &Meta,
    input: Sections,
    health: &Health,
    cap: usize,
    drops: &BTreeMap<String, u64>,
) -> Built {
    // The server rejects a whole batch for an overlong window or a DNS row outside the window
    // (both happen after an NTP step on a router without an RTC), so enforce them here.
    let meta = &Meta {
        window_start: meta
            .window_start
            .max(meta.window_end.saturating_sub(MAX_WINDOW_S)),
        ..meta.clone()
    };
    let (lo, hi) = (
        meta.window_start.saturating_sub(DNS_TS_SLACK_S),
        meta.window_end.saturating_add(DNS_TS_SLACK_S),
    );
    let total_dns = input.dns.len();
    let mut input = input;
    input.dns.retain(|q| (lo..=hi).contains(&q.ts));
    let out_of_window = (total_dns - input.dns.len()) as u64;
    let base = encode(meta, &Sections::default(), &BTreeMap::new(), health).len();
    let avail = cap.saturating_sub(base + TRUNCATED_RESERVE);
    let mut truncated = BTreeMap::new();
    note(&mut truncated, "dns_out_of_window", out_of_window);
    for (kind, n) in drops {
        note(&mut truncated, kind, *n);
    }

    // 1. Identity group: leases, then neighbours, then mDNS/SSDP sightings.
    let mut left = avail.min(IDENTITY_BUDGET);
    let (leases, d, used) =
        take_within(input.leases, left, MAX_LEASES, |x| json_len(|o| x.write(o)));
    note(&mut truncated, "leases", d);
    left -= used;
    let (neigh, d, used) = take_within(input.neigh, left, MAX_NEIGH, |x| json_len(|o| x.write(o)));
    note(&mut truncated, "neigh", d);
    left -= used;
    let (sightings, d, used) = take_within(input.sightings, left, MAX_SIGHTINGS, |x| {
        json_len(|o| x.write(o))
    });
    note(&mut truncated, "sightings", d);
    left -= used;
    let identity_used = avail.min(IDENTITY_BUDGET) - left;

    // 2. DNS, leaving conntrack its reserve.
    let rest = avail - identity_used;
    let ct_need = conntrack_size(&input.conntrack);
    let dns_budget = rest - CONNTRACK_RESERVE.min(ct_need).min(rest);
    let (dns, d, dns_used) =
        take_within(input.dns, dns_budget, MAX_DNS, |x| json_len(|o| x.write(o)));
    note(&mut truncated, "dns", d);

    // 3. Conntrack gets whatever is left: top-N by bytes, remainder folded per MAC.
    let (conntrack, folded, lost) = truncate_conntrack(input.conntrack, rest - dns_used);
    note(&mut truncated, "conntrack", folded);
    note(&mut truncated, "conntrack_lost", lost);

    cap_truncated_keys(&mut truncated);
    let sections = Sections {
        leases,
        neigh,
        dns,
        conntrack,
        sightings,
    };
    Built {
        encoded: encode(meta, &sections, &truncated, health),
        truncated,
    }
}
