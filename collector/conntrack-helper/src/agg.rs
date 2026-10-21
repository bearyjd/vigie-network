//! Per-flow delta tracking (bounded) and aggregation per (src_ip, dst_ip, dst_port, proto).
//! Samples are streamed in with `begin`/`add`/`finish`; no per-sample flow list is kept.

use crate::parse::{Counters, Flow, FlowKey};
use std::collections::hash_map::Entry as MapEntry;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

pub const DEFAULT_MAX_FLOWS: usize = 32_768;
pub const DEFAULT_TOP_N: usize = 512;
pub const DEFAULT_OTHER_K: usize = 64;
/// Consecutive samples a tracked flow may be absent and still be remembered; it is forgotten on
/// the next absence after that.
pub const TOMBSTONE_SAMPLES: u8 = 2;

#[derive(Debug, Clone, Copy)]
pub struct AggConfig {
    pub max_flows: usize,
    pub top_n: usize,
    /// Per-src `other` records kept; the rest fold into one global remainder record.
    pub other_k: usize,
    /// First sample only records baselines (no historic bytes are reported as a delta).
    pub baseline_first: bool,
}

impl Default for AggConfig {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            top_n: DEFAULT_TOP_N,
            other_k: DEFAULT_OTHER_K,
            baseline_first: true,
        }
    }
}

/// One output record. `dst`, `dport` and `proto` are `None` on `other` records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub src: IpAddr,
    pub dst: Option<IpAddr>,
    pub dport: Option<u16>,
    pub proto: Option<u8>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub packets_up: u64,
    pub packets_down: u64,
    pub flows: u64,
    pub new_flows: u64,
    /// The single global remainder record: `src` is unspecified (`0.0.0.0`).
    pub global: bool,
}

#[derive(Debug, Default)]
pub struct Snapshot {
    pub records: Vec<Record>,
    /// Number of per-destination records folded into `other` records.
    pub folded: usize,
    /// Tracked flows evicted by the memory cap during this sample.
    pub evicted: usize,
}

#[derive(Clone, Copy, Default)]
struct Pair {
    orig: Counters,
    reply: Counters,
}

impl Pair {
    fn max(self, o: Pair) -> Pair {
        let m = |a: Counters, b: Counters| Counters {
            packets: a.packets.max(b.packets),
            bytes: a.bytes.max(b.bytes),
        };
        Pair {
            orig: m(self.orig, o.orig),
            reply: m(self.reply, o.reply),
        }
    }

    /// Counters moved backwards in either direction: the tuple was reused by a new flow.
    fn is_reset_from(&self, prev: &Pair) -> bool {
        self.orig.bytes < prev.orig.bytes
            || self.orig.packets < prev.orig.packets
            || self.reply.bytes < prev.reply.bytes
            || self.reply.packets < prev.reply.packets
    }
}

fn sub(a: Counters, b: Counters) -> Counters {
    Counters {
        packets: a.packets - b.packets,
        bytes: a.bytes - b.bytes,
    }
}

struct Entry {
    /// Counters committed at the end of the previous sample the flow was seen in.
    base: Pair,
    /// Counters seen so far in the current sample (max over duplicate lines).
    cur: Pair,
    /// Insertion order (first seen); eviction removes the smallest.
    seq: u64,
    /// Sample number this entry was last seen in.
    seen: u64,
    /// Consecutive samples the flow has been absent.
    absent: u8,
    /// No committed `base` yet.
    fresh: bool,
}

pub struct Aggregator {
    cfg: AggConfig,
    state: HashMap<FlowKey, Entry>,
    next_seq: u64,
    sample: u64,
    primed: bool,
}

impl Aggregator {
    pub fn new(cfg: AggConfig) -> Self {
        Self {
            cfg,
            state: HashMap::new(),
            next_seq: 0,
            sample: 0,
            primed: false,
        }
    }

    /// Flows remembered, including absent ones kept as tombstones.
    pub fn tracked(&self) -> usize {
        self.state.len()
    }

    /// Starts a new sample.
    pub fn begin(&mut self) {
        self.sample += 1;
    }

    /// Folds one flow line of the current sample in. Duplicate keys within a sample merge by
    /// taking the larger value per counter (a duplicate line is not extra traffic).
    pub fn add(&mut self, f: &Flow) {
        let cur = Pair {
            orig: f.orig,
            reply: f.reply,
        };
        match self.state.entry(f.key) {
            MapEntry::Occupied(mut o) => {
                let e = o.get_mut();
                e.cur = if e.seen == self.sample {
                    e.cur.max(cur)
                } else {
                    cur
                };
                e.seen = self.sample;
            }
            MapEntry::Vacant(v) => {
                self.next_seq += 1;
                v.insert(Entry {
                    base: Pair::default(),
                    cur,
                    seq: self.next_seq,
                    seen: self.sample,
                    absent: 0,
                    fresh: true,
                });
            }
        }
    }

    /// Convenience: a whole sample at once.
    pub fn ingest(&mut self, flows: &[Flow]) -> Snapshot {
        self.begin();
        for f in flows {
            self.add(f);
        }
        self.finish()
    }

    /// Ends the sample: computes deltas, forgets flows absent for too long, enforces the cap
    /// and returns the aggregated records.
    pub fn finish(&mut self) -> Snapshot {
        let baseline = self.cfg.baseline_first && !self.primed;
        self.primed = true;
        let (sample, mut next_seq) = (self.sample, self.next_seq);
        let mut recs: Vec<Record> = Vec::with_capacity(self.state.len());
        self.state.retain(|key, e| {
            if e.seen != sample {
                e.absent += 1;
                return e.absent <= TOMBSTONE_SAMPLES;
            }
            e.absent = 0;
            let (d, new) = if e.fresh || e.cur.is_reset_from(&e.base) {
                next_seq += 1;
                e.seq = next_seq;
                (e.cur, !baseline)
            } else {
                (
                    Pair {
                        orig: sub(e.cur.orig, e.base.orig),
                        reply: sub(e.cur.reply, e.base.reply),
                    },
                    false,
                )
            };
            e.base = e.cur;
            e.fresh = false;
            let (up, down) = if baseline {
                (Counters::default(), Counters::default())
            } else {
                (d.orig, d.reply)
            };
            recs.push(Record {
                src: key.src,
                dst: Some(key.dst),
                dport: Some(key.dport),
                proto: Some(key.proto),
                bytes_up: up.bytes,
                bytes_down: down.bytes,
                packets_up: up.packets,
                packets_down: down.packets,
                flows: 1,
                new_flows: u64::from(new),
                global: false,
            });
            true
        });
        self.next_seq = next_seq;
        let evicted = evict_oldest(&mut self.state, self.cfg.max_flows);
        recs.sort_unstable_by_key(|r| (r.src, r.dst, r.dport, r.proto));
        recs.dedup_by(|b, a| {
            let same = (a.src, a.dst, a.dport, a.proto) == (b.src, b.dst, b.dport, b.proto);
            if same {
                merge(a, b);
            }
            same
        });
        let (records, folded) = top_n_fold(recs, self.cfg.top_n, self.cfg.other_k);
        Snapshot {
            records,
            folded,
            evicted,
        }
    }
}

fn merge(a: &mut Record, b: &Record) {
    a.bytes_up = a.bytes_up.saturating_add(b.bytes_up);
    a.bytes_down = a.bytes_down.saturating_add(b.bytes_down);
    a.packets_up = a.packets_up.saturating_add(b.packets_up);
    a.packets_down = a.packets_down.saturating_add(b.packets_down);
    a.flows = a.flows.saturating_add(b.flows);
    a.new_flows = a.new_flows.saturating_add(b.new_flows);
}

fn total(r: &Record) -> u64 {
    r.bytes_up.saturating_add(r.bytes_down)
}

/// Private, link-local, loopback and unique-local sources: the router's own LAN.
fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_link_local() || a.is_loopback(),
        IpAddr::V6(a) => {
            let s0 = a.segments()[0];
            a.is_loopback() || s0 & 0xfe00 == 0xfc00 || s0 & 0xffc0 == 0xfe80
        }
    }
}

/// Keeps the `max` newest entries; returns how many were evicted.
fn evict_oldest(map: &mut HashMap<FlowKey, Entry>, max: usize) -> usize {
    if map.len() <= max {
        return 0;
    }
    let evict = map.len() - max;
    let mut seqs: Vec<u64> = map.values().map(|e| e.seq).collect();
    // `seq` values are unique, so the evict-th smallest is an exact cut-off.
    let (_, cut, _) = seqs.select_nth_unstable(evict - 1);
    let cut = *cut;
    map.retain(|_, e| e.seq > cut);
    evict
}

fn empty_other(src: IpAddr, global: bool) -> Record {
    Record {
        src,
        dst: None,
        dport: None,
        proto: None,
        bytes_up: 0,
        bytes_down: 0,
        packets_up: 0,
        packets_down: 0,
        flows: 0,
        new_flows: 0,
        global,
    }
}

/// Keeps the `n` records with the most bytes (ties broken by key for determinism), folds the
/// rest into one `other` record per src, keeps the `k` best of those (most bytes; LAN sources
/// first among equals) and folds all remaining ones into ONE global record. In place, so peak
/// memory stays one record vector. Returns (records, number of records folded).
fn top_n_fold(mut recs: Vec<Record>, n: usize, k: usize) -> (Vec<Record>, usize) {
    recs.sort_unstable_by(|a, b| {
        total(b)
            .cmp(&total(a))
            .then_with(|| (a.src, a.dst, a.dport, a.proto).cmp(&(b.src, b.dst, b.dport, b.proto)))
    });
    if recs.len() <= n {
        return (recs, 0);
    }
    let folded = recs.len() - n;
    recs[n..].sort_unstable_by_key(|r| r.src);
    let mut w = n; // recs[n..w] are the per-src others built so far
    for r in n..recs.len() {
        let rec = recs[r];
        if w > n && recs[w - 1].src == rec.src {
            merge(&mut recs[w - 1], &rec);
        } else {
            let mut o = empty_other(rec.src, false);
            merge(&mut o, &rec);
            recs[w] = o;
            w += 1;
        }
    }
    recs.truncate(w);
    recs[n..].sort_unstable_by(|a, b| {
        total(b)
            .cmp(&total(a))
            .then_with(|| is_lan(b.src).cmp(&is_lan(a.src)))
            .then_with(|| a.src.cmp(&b.src))
    });
    if recs.len() > n + k {
        let mut g = empty_other(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true);
        for r in &recs[n + k..] {
            merge(&mut g, r);
        }
        recs.truncate(n + k);
        recs.push(g);
    }
    (recs, folded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{Counters, FlowKey};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn flow(src: &str, dst: &str, sport: u16, dport: u16, up: u64, down: u64) -> Flow {
        Flow {
            key: FlowKey {
                proto: 6,
                src: ip(src),
                dst: ip(dst),
                sport,
                dport,
                zone: 0,
            },
            orig: Counters {
                packets: up / 100,
                bytes: up,
            },
            reply: Counters {
                packets: down / 100,
                bytes: down,
            },
            acct: true,
        }
    }

    fn cfg(baseline_first: bool) -> AggConfig {
        AggConfig {
            baseline_first,
            ..AggConfig::default()
        }
    }

    fn one(s: &Snapshot) -> &Record {
        assert_eq!(s.records.len(), 1, "{:?}", s.records);
        &s.records[0]
    }

    #[test]
    fn without_baseline_first_sample_reports_current_values() {
        let mut a = Aggregator::new(cfg(false));
        let s = a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000)]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down), (1000, 9000));
        assert_eq!((r.packets_up, r.packets_down), (10, 90));
        assert_eq!((r.flows, r.new_flows), (1, 1));
    }

    #[test]
    fn baseline_first_reports_zero_bytes_but_counts_flows() {
        let mut a = Aggregator::new(cfg(true));
        let s = a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000)]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down, r.packets_up), (0, 0, 0));
        assert_eq!((r.flows, r.new_flows), (1, 0));
    }

    #[test]
    fn second_sample_reports_delta_only() {
        let mut a = Aggregator::new(cfg(true));
        a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000)]);
        let s = a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 1500, 9700)]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down), (500, 700));
        assert_eq!((r.packets_up, r.packets_down), (5, 7));
        assert_eq!((r.flows, r.new_flows), (1, 0));
    }

    #[test]
    fn new_flow_after_baseline_starts_at_current_values() {
        let mut a = Aggregator::new(cfg(true));
        a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000)]);
        let s = a.ingest(&[
            flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000),
            flow("10.0.0.2", "1.1.1.1", 5001, 443, 300, 400),
        ]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down), (300, 400));
        assert_eq!((r.flows, r.new_flows), (2, 1));
    }

    fn flow_c(up: (u64, u64), down: (u64, u64)) -> Flow {
        let mut f = flow("10.0.0.2", "1.1.1.1", 5000, 443, 0, 0);
        f.orig = Counters {
            packets: up.0,
            bytes: up.1,
        };
        f.reply = Counters {
            packets: down.0,
            bytes: down.1,
        };
        f
    }

    #[test]
    fn each_single_counter_decrease_is_a_reset() {
        // (orig packets, orig bytes), (reply packets, reply bytes); one of the four goes down
        // while the other three go up.
        let cases = [
            (((5, 1100), (11, 1100)), "orig packets"),
            (((11, 900), (11, 1100)), "orig bytes"),
            (((11, 1100), (4, 1100)), "reply packets"),
            (((11, 1100), (11, 900)), "reply bytes"),
        ];
        for ((up, down), what) in cases {
            let mut a = Aggregator::new(cfg(true));
            a.ingest(&[flow_c((10, 1000), (10, 1000))]);
            let s = a.ingest(&[flow_c(up, down)]);
            let r = one(&s);
            assert_eq!(r.new_flows, 1, "{what} decrease must reset");
            assert_eq!((r.bytes_up, r.bytes_down), (up.1, down.1), "{what}");
        }
    }

    #[test]
    fn counter_decrease_is_a_reset_starting_at_current_values() {
        let mut a = Aggregator::new(cfg(true));
        a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000)]);
        // orig decreased
        let s = a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 200, 9500)]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down, r.new_flows), (200, 9500, 1));
        // reply decreased only
        let s = a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 250, 100)]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down, r.new_flows), (250, 100, 1));
        // equal counters: a plain zero delta, not a reset
        let s = a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 250, 100)]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down, r.new_flows), (0, 0, 0));
    }

    #[test]
    fn flow_absent_three_samples_is_forgotten_and_reappears_as_new() {
        let mut a = Aggregator::new(cfg(true));
        let f = flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000);
        a.ingest(std::slice::from_ref(&f));
        assert_eq!(a.tracked(), 1);
        a.ingest(&[]);
        a.ingest(&[]);
        assert_eq!(a.tracked(), 1, "two absences keep the tombstone");
        a.ingest(&[]);
        assert_eq!(a.tracked(), 0, "third consecutive absence forgets it");
        let s = a.ingest(&[f]);
        assert_eq!((one(&s).new_flows, one(&s).bytes_up), (1, 1000));
    }

    #[test]
    fn flow_vanishing_one_sample_and_returning_is_not_recounted() {
        let mut a = Aggregator::new(cfg(true));
        let f = flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000);
        a.ingest(std::slice::from_ref(&f));
        let s = a.ingest(&[]);
        assert!(s.records.is_empty(), "absent flows are not active");
        let s = a.ingest(std::slice::from_ref(&f));
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down, r.new_flows), (0, 0, 0));
        // continuation after two absences too, and only the growth is reported
        a.ingest(&[]);
        a.ingest(&[]);
        let g = flow("10.0.0.2", "1.1.1.1", 5000, 443, 1300, 9100);
        let s = a.ingest(&[g]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down, r.new_flows), (300, 100, 0));
    }

    #[test]
    fn returning_flow_with_smaller_counters_is_a_reset() {
        let mut a = Aggregator::new(cfg(true));
        a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000)]);
        a.ingest(&[]);
        let s = a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 400, 500)]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down, r.new_flows), (400, 500, 1));
    }

    #[test]
    fn same_tuple_in_two_zones_is_two_flows() {
        let mut a = Aggregator::new(cfg(true));
        let mut z1 = flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000);
        z1.key.zone = 1;
        let z0 = flow("10.0.0.2", "1.1.1.1", 5000, 443, 50, 60);
        a.ingest(&[z0.clone(), z1.clone()]);
        assert_eq!(a.tracked(), 2);
        let mut z1b = z1;
        z1b.orig.bytes = 1100;
        let s = a.ingest(&[z0, z1b]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.flows, r.new_flows), (100, 2, 0));
    }

    #[test]
    fn flows_merge_per_src_dst_dport_proto() {
        let mut a = Aggregator::new(cfg(false));
        let s = a.ingest(&[
            flow("10.0.0.2", "1.1.1.1", 5000, 443, 100, 200),
            flow("10.0.0.2", "1.1.1.1", 5001, 443, 10, 20),
            flow("10.0.0.2", "1.1.1.1", 5002, 80, 1, 2),
            flow("10.0.0.3", "1.1.1.1", 5003, 443, 7, 8),
        ]);
        assert_eq!(s.records.len(), 3);
        let r = s
            .records
            .iter()
            .find(|r| r.src == ip("10.0.0.2") && r.dport == Some(443))
            .unwrap();
        assert_eq!((r.bytes_up, r.bytes_down, r.flows), (110, 220, 2));
    }

    #[test]
    fn duplicate_keys_in_one_sample_merge_by_max_not_sum() {
        let mut a = Aggregator::new(cfg(false));
        let s = a.ingest(&[
            flow("10.0.0.2", "1.1.1.1", 5000, 443, 100, 200),
            flow("10.0.0.2", "1.1.1.1", 5000, 443, 10, 400),
        ]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down), (100, 400), "per-counter max");
        assert_eq!((r.packets_up, r.packets_down), (1, 4));
        assert_eq!(r.flows, 1);
    }

    #[test]
    fn duplicate_line_in_one_sample_does_not_change_the_next_delta() {
        let mut a = Aggregator::new(cfg(true));
        let f = flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000);
        a.ingest(&[f.clone(), f]);
        let s = a.ingest(&[flow("10.0.0.2", "1.1.1.1", 5000, 443, 1500, 9700)]);
        let r = one(&s);
        assert_eq!((r.bytes_up, r.bytes_down, r.new_flows), (500, 700, 0));
    }

    fn v6(i: usize) -> String {
        format!("2001:db8:{:x}:{:x}::1", i >> 8, i & 255)
    }

    fn sum_bytes(s: &Snapshot) -> u64 {
        s.records.iter().map(|r| r.bytes_up + r.bytes_down).sum()
    }

    #[test]
    fn spoofed_source_flood_is_capped_and_totals_are_preserved() {
        let mut a = Aggregator::new(cfg(false));
        let flows: Vec<Flow> = (0..16_384)
            .map(|i| flow(&v6(i), "fd00::1", 1000, 443, 10 + i as u64, 5))
            .collect();
        let want: u64 = flows.iter().map(|f| f.orig.bytes + f.reply.bytes).sum();
        let s = a.ingest(&flows);
        assert!(
            s.records.len() <= DEFAULT_TOP_N + DEFAULT_OTHER_K + 1,
            "{} records",
            s.records.len()
        );
        assert_eq!(sum_bytes(&s), want);
        let globals: Vec<_> = s.records.iter().filter(|r| r.global).collect();
        assert_eq!(globals.len(), 1);
        assert!(globals[0].src.is_unspecified() && globals[0].dst.is_none());
        let others = s
            .records
            .iter()
            .filter(|r| r.dst.is_none() && !r.global)
            .count();
        assert_eq!(others, DEFAULT_OTHER_K);
        assert_eq!(s.records.iter().map(|r| r.flows).sum::<u64>(), 16_384);
    }

    #[test]
    fn other_records_keep_lan_sources_first_among_equals() {
        let mut a = Aggregator::new(AggConfig {
            top_n: 1,
            other_k: 2,
            ..cfg(false)
        });
        let mut fl = vec![flow("8.8.4.4", "9.9.9.9", 1, 1, 9999, 9999)];
        for (i, src) in ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
            .iter()
            .enumerate()
        {
            fl.push(flow(src, "9.9.9.9", i as u16, 443, 10, 10));
        }
        fl.push(flow("192.168.8.50", "9.9.9.9", 7, 443, 10, 10));
        fl.push(flow("fd12::7", "9.9.9.9", 8, 443, 10, 10));
        let s = a.ingest(&fl);
        let mut kept: Vec<String> = s
            .records
            .iter()
            .filter(|r| r.dst.is_none() && !r.global)
            .map(|r| r.src.to_string())
            .collect();
        kept.sort();
        assert_eq!(kept, ["192.168.8.50", "fd12::7"]);
        let g = s.records.iter().find(|r| r.global).unwrap();
        assert_eq!((g.bytes_up, g.bytes_down, g.flows), (30, 30, 3));
    }

    #[test]
    fn no_global_record_when_other_records_fit() {
        let mut a = Aggregator::new(AggConfig {
            top_n: 2,
            ..cfg(false)
        });
        let s = a.ingest(&top_n_input());
        assert!(s.records.iter().all(|r| !r.global));
    }

    #[test]
    fn cap_evicts_oldest_tracked_flows() {
        let mut a = Aggregator::new(AggConfig {
            max_flows: 3,
            ..cfg(true)
        });
        let f = |p: u16| flow("10.0.0.2", "1.1.1.1", p, 443, 1000, 1000);
        a.ingest(&[f(1), f(2), f(3)]);
        let s = a.ingest(&[f(1), f(2), f(3), f(4), f(5)]);
        assert_eq!(a.tracked(), 3);
        assert_eq!(s.evicted, 2);
        // 1 and 2 were the oldest, so they were evicted and now look new; 3, 4, 5 are tracked.
        let s = a.ingest(&[f(1), f(2), f(3), f(4), f(5)]);
        assert_eq!(one(&s).new_flows, 2);
    }

    fn top_n_input() -> Vec<Flow> {
        vec![
            flow("10.0.0.2", "9.9.9.1", 1, 443, 5000, 5000),
            flow("10.0.0.2", "9.9.9.2", 2, 443, 3000, 3000),
            flow("10.0.0.2", "9.9.9.3", 3, 443, 100, 100),
            flow("10.0.0.2", "9.9.9.4", 4, 443, 50, 50),
            flow("10.0.0.3", "9.9.9.5", 5, 443, 10, 10),
        ]
    }

    #[test]
    fn top_n_keeps_largest_and_folds_remainder_per_src() {
        let mut a = Aggregator::new(AggConfig {
            top_n: 2,
            ..cfg(false)
        });
        let s = a.ingest(&top_n_input());
        assert_eq!(s.folded, 3);
        assert_eq!(s.records.len(), 4);
        let named: Vec<_> = s.records.iter().filter(|r| r.dst.is_some()).collect();
        assert_eq!(named.len(), 2);
        assert!(named.iter().all(|r| r.bytes_up + r.bytes_down >= 6000));
        let other2 = s
            .records
            .iter()
            .find(|r| r.dst.is_none() && r.src == ip("10.0.0.2"))
            .unwrap();
        assert_eq!((other2.bytes_up, other2.bytes_down), (150, 150));
        assert_eq!((other2.flows, other2.new_flows), (2, 2));
        assert_eq!((other2.dport, other2.proto), (None, None));
        let other3 = s
            .records
            .iter()
            .find(|r| r.dst.is_none() && r.src == ip("10.0.0.3"))
            .unwrap();
        assert_eq!((other3.bytes_up, other3.flows), (10, 1));
    }

    #[test]
    fn top_n_at_or_above_record_count_folds_nothing() {
        let mut a = Aggregator::new(AggConfig {
            top_n: 5,
            ..cfg(false)
        });
        let s = a.ingest(&top_n_input());
        assert_eq!(s.folded, 0);
        assert!(s.records.iter().all(|r| r.dst.is_some()));
        assert_eq!(s.records.len(), 5);
    }
}
