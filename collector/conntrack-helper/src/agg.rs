//! Per-flow delta tracking (bounded) and aggregation per (src_ip, dst_ip, dst_port, proto).

use crate::parse::{Counters, Flow, FlowKey};
use std::collections::HashMap;
use std::net::IpAddr;

pub const DEFAULT_MAX_FLOWS: usize = 32_768;
pub const DEFAULT_TOP_N: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct AggConfig {
    pub max_flows: usize,
    pub top_n: usize,
    /// First sample only records baselines (no historic bytes are reported as a delta).
    pub baseline_first: bool,
}

impl Default for AggConfig {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            top_n: DEFAULT_TOP_N,
            baseline_first: true,
        }
    }
}

/// One output record. `dst`, `dport` and `proto` are `None` on the per-src `other` record.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

#[derive(Debug, Default)]
pub struct Snapshot {
    pub records: Vec<Record>,
    /// Number of per-destination records folded into `other` records.
    pub folded: usize,
    /// Tracked flows evicted by the memory cap during this sample.
    pub evicted: usize,
}

#[derive(Clone, Copy)]
struct Entry {
    orig: Counters,
    reply: Counters,
    /// Insertion order (first seen); eviction removes the smallest.
    seq: u64,
}

type AggKey = (IpAddr, IpAddr, u16, u8);

pub struct Aggregator {
    cfg: AggConfig,
    state: HashMap<FlowKey, Entry>,
    next_seq: u64,
    primed: bool,
}

/// Counters moved backwards in either direction: the tuple was reused by a new flow.
fn is_reset(prev: &Entry, orig: &Counters, reply: &Counters) -> bool {
    orig.bytes < prev.orig.bytes
        || orig.packets < prev.orig.packets
        || reply.bytes < prev.reply.bytes
        || reply.packets < prev.reply.packets
}

fn bump(rec: &mut Record, up: Counters, down: Counters, new: bool) {
    rec.bytes_up = rec.bytes_up.saturating_add(up.bytes);
    rec.bytes_down = rec.bytes_down.saturating_add(down.bytes);
    rec.packets_up = rec.packets_up.saturating_add(up.packets);
    rec.packets_down = rec.packets_down.saturating_add(down.packets);
    rec.flows += 1;
    rec.new_flows += u64::from(new);
}

fn sub(a: Counters, b: Counters) -> Counters {
    Counters {
        packets: a.packets - b.packets,
        bytes: a.bytes - b.bytes,
    }
}

fn total(r: &Record) -> u64 {
    r.bytes_up.saturating_add(r.bytes_down)
}

impl Aggregator {
    pub fn new(cfg: AggConfig) -> Self {
        Self {
            cfg,
            state: HashMap::new(),
            next_seq: 0,
            primed: false,
        }
    }

    pub fn tracked(&self) -> usize {
        self.state.len()
    }

    /// Folds one full conntrack sample into per-flow state and returns the aggregated deltas.
    /// Flows absent from the sample have ended and are forgotten.
    pub fn ingest(&mut self, flows: &[Flow]) -> Snapshot {
        let baseline = self.cfg.baseline_first && !self.primed;
        self.primed = true;
        let mut next: HashMap<FlowKey, Entry> = HashMap::with_capacity(flows.len());
        for f in flows {
            let e = next.entry(f.key.clone()).or_insert(Entry {
                orig: Counters::default(),
                reply: Counters::default(),
                seq: 0,
            });
            e.orig.packets = e.orig.packets.saturating_add(f.orig.packets);
            e.orig.bytes = e.orig.bytes.saturating_add(f.orig.bytes);
            e.reply.packets = e.reply.packets.saturating_add(f.reply.packets);
            e.reply.bytes = e.reply.bytes.saturating_add(f.reply.bytes);
        }
        let mut agg: HashMap<AggKey, Record> = HashMap::new();
        for (key, entry) in next.iter_mut() {
            let (orig, reply) = (entry.orig, entry.reply);
            let prev = self.state.get(key).filter(|p| !is_reset(p, &orig, &reply));
            let (d_up, d_down, new, seq) = match prev {
                Some(p) => (sub(orig, p.orig), sub(reply, p.reply), false, p.seq),
                None => {
                    self.next_seq += 1;
                    (orig, reply, !baseline, self.next_seq)
                }
            };
            entry.seq = seq;
            let (d_up, d_down) = if baseline {
                (Counters::default(), Counters::default())
            } else {
                (d_up, d_down)
            };
            let rec = agg
                .entry((key.src, key.dst, key.dport, key.proto))
                .or_insert_with(|| Record {
                    src: key.src,
                    dst: Some(key.dst),
                    dport: Some(key.dport),
                    proto: Some(key.proto),
                    bytes_up: 0,
                    bytes_down: 0,
                    packets_up: 0,
                    packets_down: 0,
                    flows: 0,
                    new_flows: 0,
                });
            bump(rec, d_up, d_down, new);
        }
        let evicted = evict_oldest(&mut next, self.cfg.max_flows);
        self.state = next;
        let (records, folded) = top_n_fold(agg.into_values().collect(), self.cfg.top_n);
        Snapshot {
            records,
            folded,
            evicted,
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

/// Keeps the `n` records with the most bytes (ties broken by key for determinism) and folds the
/// rest into one `other` record per src. Returns (records, number of records folded).
fn top_n_fold(mut recs: Vec<Record>, n: usize) -> (Vec<Record>, usize) {
    recs.sort_by(|a, b| {
        total(b)
            .cmp(&total(a))
            .then_with(|| (a.src, a.dst, a.dport, a.proto).cmp(&(b.src, b.dst, b.dport, b.proto)))
    });
    if recs.len() <= n {
        return (recs, 0);
    }
    let rest = recs.split_off(n);
    let folded = rest.len();
    let mut others: HashMap<IpAddr, Record> = HashMap::new();
    for r in rest {
        let o = others.entry(r.src).or_insert_with(|| Record {
            src: r.src,
            dst: None,
            dport: None,
            proto: None,
            bytes_up: 0,
            bytes_down: 0,
            packets_up: 0,
            packets_down: 0,
            flows: 0,
            new_flows: 0,
        });
        o.bytes_up = o.bytes_up.saturating_add(r.bytes_up);
        o.bytes_down = o.bytes_down.saturating_add(r.bytes_down);
        o.packets_up = o.packets_up.saturating_add(r.packets_up);
        o.packets_down = o.packets_down.saturating_add(r.packets_down);
        o.flows += r.flows;
        o.new_flows += r.new_flows;
    }
    let mut others: Vec<Record> = others.into_values().collect();
    others.sort_by_key(|r| r.src);
    recs.extend(others);
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
            },
            orig: Counters {
                packets: up / 100,
                bytes: up,
            },
            reply: Counters {
                packets: down / 100,
                bytes: down,
            },
            state: None,
            unreplied: false,
            assured: false,
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
    fn vanished_flow_is_forgotten_and_reappears_as_new() {
        let mut a = Aggregator::new(cfg(true));
        let f = flow("10.0.0.2", "1.1.1.1", 5000, 443, 1000, 9000);
        a.ingest(std::slice::from_ref(&f));
        assert_eq!(a.tracked(), 1);
        a.ingest(&[]);
        assert_eq!(a.tracked(), 0);
        let s = a.ingest(&[f]);
        assert_eq!(one(&s).new_flows, 1);
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
    fn duplicate_keys_in_one_sample_are_summed() {
        let mut a = Aggregator::new(cfg(false));
        let s = a.ingest(&[
            flow("10.0.0.2", "1.1.1.1", 5000, 443, 100, 200),
            flow("10.0.0.2", "1.1.1.1", 5000, 443, 10, 20),
        ]);
        assert_eq!(one(&s).bytes_up, 110);
        assert_eq!(one(&s).flows, 1);
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
