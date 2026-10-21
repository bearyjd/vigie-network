//! Per-flow delta tracking (bounded) and aggregation per (src_ip, dst_ip, dst_port, proto).
//! Samples are streamed in with `begin`/`add`/`finish`; no per-sample flow list is kept.

use crate::lan::{default_lan, is_lan, Cidr};
use crate::parse::{Counters, Flow, FlowKey};
use std::collections::hash_map::{Entry as MapEntry, RandomState};
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr};

/// 3 x the GL-XE3000's nf_conntrack_max (16384): live flows plus two samples of tombstones.
pub const DEFAULT_MAX_FLOWS: usize = 3 * 16_384;
pub const DEFAULT_TOP_N: usize = 512;
/// Per-src `other` records kept for LAN sources / for all other sources.
pub const DEFAULT_K_LAN: usize = 192;
pub const DEFAULT_K_WAN: usize = 64;
/// Consecutive samples a tracked flow may be absent and still be remembered; it is forgotten on
/// the next absence after that.
pub const TOMBSTONE_SAMPLES: u8 = 2;

#[derive(Debug, Clone)]
pub struct AggConfig {
    pub max_flows: usize,
    pub top_n: usize,
    /// Per-src `other` records kept for LAN sources (most bytes first).
    pub k_lan: usize,
    /// Per-src `other` records kept for all other sources; whatever neither quota keeps folds
    /// into one global remainder record.
    pub k_wan: usize,
    /// Which sources count as LAN. Spoofed sources from the WAN can still claim these
    /// prefixes, so the owner should list the real LAN prefixes.
    pub lan: Vec<Cidr>,
    /// Compact stubs kept for evicted live flows (see `Aggregator`).
    pub max_stubs: usize,
    /// First sample only records baselines (no historic bytes are reported as a delta).
    pub baseline_first: bool,
}

impl Default for AggConfig {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            top_n: DEFAULT_TOP_N,
            k_lan: DEFAULT_K_LAN,
            k_wan: DEFAULT_K_WAN,
            lan: default_lan(),
            max_stubs: DEFAULT_MAX_FLOWS / 3 * 2,
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
    /// Flows that lost their counters (stub table overflow) and may be counted again.
    pub recounted_flows: usize,
    /// The tracking tables were under pressure: some byte counts may be inflated.
    pub table_pressure: bool,
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

/// What is remembered about a live flow evicted by the cap: its last committed counters, keyed
/// by a 64-bit hash of the flow key (a collision can only mis-attribute one delta).
#[derive(Clone, Copy)]
struct Stub {
    pair: Pair,
    /// Eviction order; the smallest is dropped first when the stub table overflows.
    seq: u64,
}

fn stub_key(h: &RandomState, key: &FlowKey) -> u64 {
    h.hash_one(key)
}

pub struct Aggregator {
    cfg: AggConfig,
    state: HashMap<FlowKey, Entry>,
    stubs: HashMap<u64, Stub>,
    /// Hashes of tombstones evicted by the cap (sample stamp), to notice when one comes back.
    forgotten: HashMap<u64, u64>,
    /// Evicted-tombstone flows that returned (and are counted again) in the current sample.
    tomb_recounts: usize,
    hasher: RandomState,
    stub_seq: u64,
    next_seq: u64,
    sample: u64,
    primed: bool,
}

impl Aggregator {
    pub fn new(cfg: AggConfig) -> Self {
        Self {
            cfg,
            state: HashMap::new(),
            stubs: HashMap::new(),
            forgotten: HashMap::new(),
            tomb_recounts: 0,
            hasher: RandomState::new(),
            stub_seq: 0,
            next_seq: 0,
            sample: 0,
            primed: false,
        }
    }

    /// Flows remembered, including absent ones kept as tombstones.
    pub fn tracked(&self) -> usize {
        self.state.len()
    }

    /// Compact counter stubs kept for evicted live flows.
    pub fn stubs(&self) -> usize {
        self.stubs.len()
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
                // A returning evicted flow continues from its stub (a smaller counter than the
                // stub is a reset, decided in `finish` like for any tracked flow).
                let stub = if self.stubs.is_empty() {
                    None
                } else {
                    self.stubs.remove(&stub_key(&self.hasher, v.key()))
                };
                if stub.is_none()
                    && !self.forgotten.is_empty()
                    && self
                        .forgotten
                        .remove(&stub_key(&self.hasher, v.key()))
                        .is_some()
                {
                    self.tomb_recounts += 1;
                }
                v.insert(Entry {
                    base: stub.map_or_else(Pair::default, |s| s.pair),
                    cur,
                    seq: self.next_seq,
                    seen: self.sample,
                    absent: 0,
                    fresh: stub.is_none(),
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
        let (evicted, dropped_stubs) = self.enforce_cap();
        let recounted_flows = dropped_stubs + std::mem::take(&mut self.tomb_recounts);
        recs.sort_unstable_by_key(|r| (r.src, r.dst, r.dport, r.proto));
        recs.dedup_by(|b, a| {
            let same = (a.src, a.dst, a.dport, a.proto) == (b.src, b.dst, b.dport, b.proto);
            if same {
                merge(a, b);
            }
            same
        });
        let (records, folded) = top_n_fold(
            recs,
            self.cfg.top_n,
            (self.cfg.k_lan, self.cfg.k_wan),
            &self.cfg.lan,
        );
        Snapshot {
            records,
            folded,
            evicted,
            recounted_flows,
            table_pressure: recounted_flows > 0,
        }
    }

    /// Brings the table to `max_flows`: absent flows (tombstones) go first, oldest first; only
    /// then live flows, oldest first, each leaving a stub. Stubs are capped too; dropping one
    /// means that flow is counted again if it returns. Returns (evicted, stubs dropped).
    fn enforce_cap(&mut self) -> (usize, usize) {
        let over = self.state.len().saturating_sub(self.cfg.max_flows);
        if over == 0 {
            return (0, 0);
        }
        let mut tomb: Vec<u64> = (self.state.values())
            .filter(|e| e.absent > 0)
            .map(|e| e.seq)
            .collect();
        let from_tomb = over.min(tomb.len());
        // `seq` values are unique, so the n-th smallest is an exact cut-off.
        let tomb_cut = (from_tomb > 0).then(|| *tomb.select_nth_unstable(from_tomb - 1).1);
        let from_live = over - from_tomb;
        let live_cut = (from_live > 0).then(|| {
            let mut live: Vec<u64> = (self.state.values())
                .filter(|e| e.absent == 0)
                .map(|e| e.seq)
                .collect();
            *live.select_nth_unstable(from_live - 1).1
        });
        let mut evicted_live: Vec<(u64, Pair, u64)> = Vec::with_capacity(from_live);
        let hasher = &self.hasher;
        let mut forgotten: Vec<u64> = Vec::with_capacity(from_tomb);
        self.state.retain(|key, e| {
            if e.absent > 0 {
                let keep = tomb_cut.is_none_or(|c| e.seq > c);
                if !keep {
                    forgotten.push(stub_key(hasher, key));
                }
                return keep;
            }
            match live_cut {
                Some(c) if e.seq <= c => {
                    evicted_live.push((e.seq, e.base, stub_key(hasher, key)));
                    false
                }
                _ => true,
            }
        });
        let sample = self.sample;
        self.forgotten
            .extend(forgotten.into_iter().map(|k| (k, sample)));
        let over_f = self.forgotten.len().saturating_sub(self.cfg.max_stubs);
        if over_f > 0 {
            let mut st: Vec<u64> = self.forgotten.values().copied().collect();
            let cut = *st.select_nth_unstable(over_f - 1).1;
            self.forgotten.retain(|_, s| *s > cut);
        }
        evicted_live.sort_unstable_by_key(|(seq, ..)| *seq);
        for (_, pair, k) in evicted_live {
            self.stub_seq += 1;
            let seq = self.stub_seq;
            self.stubs.insert(k, Stub { pair, seq });
        }
        let dropped = self.stubs.len().saturating_sub(self.cfg.max_stubs);
        if dropped > 0 {
            let mut seqs: Vec<u64> = self.stubs.values().map(|s| s.seq).collect();
            let cut = *seqs.select_nth_unstable(dropped - 1).1;
            self.stubs.retain(|_, s| s.seq > cut);
        }
        (over, dropped)
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

/// Keeps the `n` records with the most bytes (ties broken by key for determinism) and folds the
/// rest into one `other` record per src. Of those, the `k_lan` LAN sources and the `k_wan` other
/// sources with the most bytes are kept (separate quotas, so a flood of one kind cannot push the
/// other out); all remaining ones fold into ONE global record. In place, so peak memory stays
/// one record vector. Returns (records, number of records folded).
fn top_n_fold(
    mut recs: Vec<Record>,
    n: usize,
    (k_lan, k_wan): (usize, usize),
    lan: &[Cidr],
) -> (Vec<Record>, usize) {
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
        is_lan(lan, b.src)
            .cmp(&is_lan(lan, a.src))
            .then_with(|| total(b).cmp(&total(a)))
            .then_with(|| a.src.cmp(&b.src))
    });
    let lan_end = n + recs[n..].partition_point(|r| is_lan(lan, r.src));
    let mut global = empty_other(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true);
    let (mut w, mut any) = (n, false);
    for i in n..recs.len() {
        let (rank, quota) = if i < lan_end {
            (i - n, k_lan)
        } else {
            (i - lan_end, k_wan)
        };
        let rec = recs[i];
        if rank < quota {
            recs[w] = rec;
            w += 1;
        } else {
            merge(&mut global, &rec);
            any = true;
        }
    }
    recs.truncate(w);
    if any {
        recs.push(global);
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
            s.records.len() <= DEFAULT_TOP_N + DEFAULT_K_LAN + DEFAULT_K_WAN + 1,
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
        assert_eq!(others, DEFAULT_K_WAN);
        assert_eq!(s.records.iter().map(|r| r.flows).sum::<u64>(), 16_384);
    }

    #[test]
    fn other_records_keep_lan_sources_first_among_equals() {
        let mut a = Aggregator::new(AggConfig {
            top_n: 1,
            k_lan: 2,
            k_wan: 0,
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
    fn cap_evicts_oldest_tracked_flows_when_no_stubs_are_allowed() {
        let mut a = Aggregator::new(AggConfig {
            max_flows: 3,
            max_stubs: 0,
            ..cfg(true)
        });
        let f = |p: u16| flow("10.0.0.2", "1.1.1.1", p, 443, 1000, 1000);
        a.ingest(&[f(1), f(2), f(3)]);
        let s = a.ingest(&[f(1), f(2), f(3), f(4), f(5)]);
        assert_eq!(a.tracked(), 3);
        assert_eq!(s.evicted, 2);
        // 1 and 2 were the oldest and (without stubs) were forgotten: they now look new.
        let s = a.ingest(&[f(1), f(2), f(3), f(4), f(5)]);
        assert_eq!(one(&s).new_flows, 2);
    }

    fn bytes_of(s: &Snapshot, src: &str) -> u64 {
        s.records
            .iter()
            .filter(|r| r.src == ip(src))
            .map(|r| r.bytes_up + r.bytes_down)
            .sum()
    }

    /// Host B holds 200 long-lived flows (~10 MB lifetime each, +1000 B per sample); host A
    /// opens `churn` fresh flows every sample. Returns B's reported bytes per sample.
    fn churn_run(
        max_flows: usize,
        churn: u64,
        samples: u64,
    ) -> (Aggregator, Vec<u64>, Vec<Snapshot>) {
        let mut a = Aggregator::new(AggConfig {
            max_flows,
            max_stubs: 2 * max_flows / 3,
            ..cfg(true)
        });
        let (mut b_bytes, mut snaps) = (Vec::new(), Vec::new());
        for t in 0..samples {
            let mut fl: Vec<Flow> = (0..200)
                .map(|i| {
                    let life = 5_000_000 + t * 500;
                    flow("192.168.1.9", "1.1.1.1", 2000 + i, 443, life, life)
                })
                .collect();
            fl.extend((0..churn).map(|i| {
                flow(
                    "192.168.1.7",
                    "2.2.2.2",
                    (10_000 + t * churn + i) as u16,
                    80,
                    100,
                    100,
                )
            }));
            let s = a.ingest(&fl);
            b_bytes.push(bytes_of(&s, "192.168.1.9"));
            snaps.push(s);
        }
        (a, b_bytes, snaps)
    }

    #[test]
    fn churn_does_not_recount_other_hosts_lifetime_bytes() {
        // The reviewer's repro: max_flows 1000, 400 new flows per sample.
        let (_, b, _) = churn_run(1000, 400, 8);
        assert_eq!(b[0], 0, "baseline sample");
        for (t, got) in b.iter().enumerate().skip(1) {
            assert_eq!(
                *got, 200_000,
                "sample {t}: B's delta, not its lifetime bytes"
            );
        }
    }

    #[test]
    fn live_eviction_keeps_a_stub_so_returning_flows_continue() {
        // 1000 live churn flows per sample: tombstones alone cannot make room.
        let (a, b, snaps) = churn_run(1000, 1000, 8);
        for (t, got) in b.iter().enumerate().skip(1) {
            assert_eq!(*got, 200_000, "sample {t}");
        }
        assert!(
            snaps.iter().any(|s| s.evicted > 0),
            "live flows were evicted"
        );
        assert!(a.stubs() > 0 && a.stubs() <= 666, "{}", a.stubs());
        assert!(snaps
            .iter()
            .all(|s| !s.table_pressure && s.recounted_flows == 0));
    }

    #[test]
    fn stubs_of_flows_sharing_a_sport_keep_separate_baselines() {
        let mut a = Aggregator::new(AggConfig {
            max_flows: 2,
            max_stubs: 10,
            ..cfg(true)
        });
        let fa = |n: u64| flow("10.0.0.2", "1.1.1.1", 5, 443, n, n);
        let fb = |n: u64| flow("10.0.0.3", "2.2.2.2", 5, 80, n, n);
        let fill = |p: u16| flow("10.0.0.9", "3.3.3.3", p, 53, 10, 10);
        a.ingest(&[fa(1000), fb(5000)]);
        a.ingest(&[fa(1000), fb(5000), fill(1), fill(2)]); // A and B evicted to stubs
        assert_eq!(a.stubs(), 2);
        let s = a.ingest(&[fa(1100), fb(5200), fill(1), fill(2)]);
        assert_eq!(
            bytes_of(&s, "10.0.0.2"),
            200,
            "A continues from its own stub"
        );
        assert_eq!(
            bytes_of(&s, "10.0.0.3"),
            400,
            "B continues from its own stub"
        );
        let new: u64 = s.records.iter().map(|r| r.new_flows).sum();
        assert_eq!(new, 0);
    }

    #[test]
    fn stub_with_smaller_counters_is_a_reset() {
        let mut a = Aggregator::new(AggConfig {
            max_flows: 1,
            max_stubs: 10,
            ..cfg(true)
        });
        let f = |p: u16, up: u64| flow("10.0.0.2", "1.1.1.1", p, 443, up, up);
        a.ingest(&[f(1, 5000)]);
        a.ingest(&[f(1, 6000), f(2, 100)]); // f1 oldest: evicted with a stub
        assert_eq!(a.stubs(), 1);
        let s = a.ingest(&[f(1, 300), f(2, 100)]); // returns below its stub: tuple reused
        let r = one(&s);
        assert_eq!((r.bytes_up + r.bytes_down, r.new_flows), (600, 1));
    }

    #[test]
    fn eviction_takes_tombstones_before_live_flows() {
        let mut a = Aggregator::new(AggConfig {
            max_flows: 3,
            max_stubs: 10,
            ..cfg(true)
        });
        let f = |src: &str, p: u16, up: u64| flow(src, "1.1.1.1", p, 443, up, up);
        a.ingest(&[
            f("10.0.0.1", 1, 1000),
            f("10.0.0.2", 2, 1000),
            f("10.0.0.3", 3, 1000),
        ]);
        // flow 3 (newest) vanishes and becomes a tombstone; a 4th flow arrives: over the cap.
        let s = a.ingest(&[
            f("10.0.0.1", 1, 1100),
            f("10.0.0.2", 2, 1100),
            f("10.0.0.4", 4, 70),
        ]);
        assert_eq!(s.evicted, 1);
        assert_eq!(
            a.stubs(),
            0,
            "the tombstone went, no live flow needed a stub"
        );
        let s = a.ingest(&[
            f("10.0.0.1", 1, 1200),
            f("10.0.0.2", 2, 1200),
            f("10.0.0.3", 3, 1000),
            f("10.0.0.4", 4, 70),
        ]);
        let new = |src: &str| {
            s.records
                .iter()
                .find(|r| r.src == ip(src))
                .unwrap()
                .new_flows
        };
        assert_eq!(new("10.0.0.1"), 0, "live flow kept its state");
        assert_eq!(new("10.0.0.2"), 0);
        assert_eq!(new("10.0.0.3"), 1, "the evicted tombstone returns as new");
    }

    #[test]
    fn recounting_a_tombstone_evicted_flow_raises_table_pressure() {
        let mut a = Aggregator::new(AggConfig {
            max_flows: 3,
            max_stubs: 10,
            ..cfg(true)
        });
        let f = |p: u16, up: u64| flow("10.0.0.1", "1.1.1.1", p, 443, up, up);
        a.ingest(&[f(1, 1000), f(2, 1000), f(3, 1000)]);
        // flow 3 is absent (tombstone) while a 4th arrives: the tombstone is evicted.
        let s = a.ingest(&[f(1, 1100), f(2, 1100), f(4, 70)]);
        assert_eq!(s.evicted, 1);
        assert!(!s.table_pressure, "nothing was recounted yet");
        // the dump was racing churn: flow 3 is alive after all and is counted again.
        let s = a.ingest(&[f(1, 1200), f(2, 1200), f(3, 1000), f(4, 70)]);
        assert!(s.table_pressure);
        assert_eq!(s.recounted_flows, 1);
        let s = a.ingest(&[f(1, 1300), f(2, 1300), f(3, 1100), f(4, 70)]);
        assert!(!s.table_pressure, "pressure is per sample");
    }

    #[test]
    fn stub_overflow_sets_pressure_and_counts_recounted_flows() {
        let mut a = Aggregator::new(AggConfig {
            max_flows: 2,
            max_stubs: 3,
            ..cfg(true)
        });
        let flows: Vec<Flow> = (0..8)
            .map(|i| flow("10.0.0.2", "1.1.1.1", i, 443, 1000, 1000))
            .collect();
        a.ingest(&flows[..2]);
        let s = a.ingest(&flows); // 6 live flows over the cap of 2 -> 6 stubs wanted, 3 kept
        assert_eq!(s.evicted, 6);
        assert_eq!(a.stubs(), 3);
        assert!(s.table_pressure);
        assert_eq!(s.recounted_flows, 3);
        let s = a.ingest(&flows[..2]);
        assert!(!s.table_pressure, "pressure is per sample");
    }

    fn wan(i: usize) -> String {
        format!("203.0.{}.{}", i / 250, i % 250 + 1)
    }

    fn is_other(r: &Record) -> bool {
        r.dst.is_none() && !r.global
    }

    #[test]
    fn quiet_lan_host_keeps_its_attribution_under_a_spoofed_wan_flood() {
        let mut a = Aggregator::new(cfg(false));
        let mut fl = vec![flow("192.168.1.50", "9.9.9.9", 1, 443, 5000, 0)];
        fl.extend((0..1000).map(|i| flow(&wan(i), "9.9.9.9", 2, 443, 1_000_000, 0)));
        let want: u64 = 5000 + 1000 * 1_000_000;
        let s = a.ingest(&fl);
        assert_eq!(sum_bytes(&s), want, "totals stay exact");
        let lan = s
            .records
            .iter()
            .find(|r| r.src == ip("192.168.1.50"))
            .unwrap();
        assert_eq!(
            lan.bytes_up, 5000,
            "LAN host is attributed, not folded into global"
        );
        assert!(!lan.global);
        let wan_others = s.records.iter().filter(|r| is_other(r)).count();
        assert!(wan_others <= DEFAULT_K_LAN + DEFAULT_K_WAN, "{wan_others}");
    }

    #[test]
    fn spoofed_private_sources_fill_only_the_lan_quota() {
        let mut a = Aggregator::new(cfg(false));
        let mut fl: Vec<Flow> = (0..2000)
            .map(|i| {
                flow(
                    &format!("10.{}.{}.1", i / 250, i % 250),
                    "9.9.9.9",
                    2,
                    443,
                    1_000_000,
                    0,
                )
            })
            .collect();
        fl.push(flow("8.8.4.4", "9.9.9.9", 3, 443, 5000, 0));
        let want: u64 = 2000 * 1_000_000 + 5000;
        let s = a.ingest(&fl);
        assert_eq!(sum_bytes(&s), want);
        let others: Vec<&Record> = s.records.iter().filter(|r| is_other(r)).collect();
        let lan = others
            .iter()
            .filter(|r| is_lan(&default_lan(), r.src))
            .count();
        assert_eq!(lan, DEFAULT_K_LAN, "the flood is limited to the LAN quota");
        let wanrec = s.records.iter().find(|r| r.src == ip("8.8.4.4")).unwrap();
        assert_eq!(
            wanrec.bytes_up, 5000,
            "the WAN quota is untouched by the flood"
        );
        assert_eq!(s.records.iter().filter(|r| r.global).count(), 1);
    }

    #[test]
    fn lan_cidr_overrides_the_default_lan_definition() {
        let lan_net = vec![Cidr::parse("203.0.113.0/24").unwrap()];
        let mut a = Aggregator::new(AggConfig {
            top_n: 1,
            k_lan: 1,
            k_wan: 1,
            lan: lan_net,
            ..cfg(false)
        });
        let s = a.ingest(&[
            flow("8.8.8.8", "9.9.9.9", 1, 443, 9999, 0),
            flow("203.0.113.5", "9.9.9.9", 2, 443, 10, 0),
            flow("192.168.1.2", "9.9.9.9", 3, 443, 20, 0),
            flow("1.2.3.4", "9.9.9.9", 4, 443, 30, 0),
        ]);
        let src = |ip_s: &str| s.records.iter().any(|r| r.src == ip(ip_s) && is_other(r));
        assert!(src("203.0.113.5"), "inside the configured LAN: LAN quota");
        assert!(src("1.2.3.4"), "WAN quota, best by bytes among the rest");
        assert!(
            !src("192.168.1.2"),
            "RFC1918 is WAN once --lan-cidr replaces the default"
        );
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
