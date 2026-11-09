//! Maps helper snapshots onto MACs and accumulates them over one window.
//!
//! The helper reports per source IP; the batch wants per MAC. The neighbor table maps IP to MAC
//! (IPv4 and IPv6, every address a device uses, so privacy addresses map as long as the kernel
//! still has the entry). A source with no entry cannot become a row (the schema requires a MAC),
//! so its bytes and flows are folded into the window's counters instead. Two pairs, by cause:
//! `unmapped` is EXPECTED (the helper's global remainder record, `other_global`, and the router's
//! own addresses); `lan_unmapped` is a genuine attribution failure (any other source without a MAC).
//!
//! Semantics: `bytes_*` are deltas per helper interval, so they add up over a window. `flows` is
//! the number of live flows in that sample, so the same flow seen in two samples must not be
//! counted twice: across samples of one window `flows` takes the maximum, within one sample the
//! rows of different IPs of one device add.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use crate::ctparse::{Kind, Snapshot};
use crate::model::{ConntrackSummary, Proto};

/// Distinct `(mac, dst, port, proto)` rows kept per window; beyond it a row folds into its MAC's
/// `other` bucket (nothing is lost, detail is).
pub const MAX_KEYS: usize = 20_000;

type Key = (String, Option<String>, Option<u16>, u8);
type Val = (u64, u64, u64);

fn proto_code(p: Proto) -> u8 {
    match p {
        Proto::Tcp => 0,
        Proto::Udp => 1,
        Proto::Icmp => 2,
        Proto::Icmpv6 => 3,
        Proto::Other => 4,
    }
}

fn proto_of(c: u8) -> Proto {
    match c {
        0 => Proto::Tcp,
        1 => Proto::Udp,
        2 => Proto::Icmp,
        3 => Proto::Icmpv6,
        _ => Proto::Other,
    }
}

#[derive(Debug, Default)]
pub struct CtAccum {
    rows: BTreeMap<Key, Val>,
    pub unmapped_bytes: u64,
    pub unmapped_flows: u64,
    pub lan_unmapped_bytes: u64,
    pub lan_unmapped_flows: u64,
    pub snapshots: u64,
}

fn other_key(mac: &str) -> Key {
    (mac.to_string(), None, None, proto_code(Proto::Other))
}

impl CtAccum {
    /// `add_snapshot_with_own` with no known router addresses (nothing is treated as own).
    pub fn add_snapshot(&mut self, snap: &Snapshot, ip_to_mac: &HashMap<String, String>) {
        self.add_snapshot_with_own(snap, ip_to_mac, &HashSet::new());
    }

    /// `own` holds the router's own addresses: unmapped traffic from them is expected.
    pub fn add_snapshot_with_own(
        &mut self,
        snap: &Snapshot,
        ip_to_mac: &HashMap<String, String>,
        own: &HashSet<IpAddr>,
    ) {
        self.snapshots += 1;
        let mut sample: BTreeMap<Key, Val> = BTreeMap::new();
        for r in &snap.records {
            let mac = match (r.kind, ip_to_mac.get(&r.src.to_string())) {
                (Kind::Tuple | Kind::Other, Some(m)) => m,
                _ => {
                    let bytes = r.bytes_up.saturating_add(r.bytes_down);
                    let (b, f) = if r.kind == Kind::OtherGlobal || own.contains(&r.src) {
                        (&mut self.unmapped_bytes, &mut self.unmapped_flows)
                    } else {
                        (&mut self.lan_unmapped_bytes, &mut self.lan_unmapped_flows)
                    };
                    *b = b.saturating_add(bytes);
                    *f = f.saturating_add(r.flows);
                    continue;
                }
            };
            let key = match (r.kind, r.dst) {
                (Kind::Tuple, Some(d)) => (
                    mac.clone(),
                    Some(d.to_string()),
                    r.dport,
                    proto_code(r.proto),
                ),
                _ => other_key(mac),
            };
            let v = sample.entry(key).or_default();
            *v = (
                v.0.saturating_add(r.bytes_up),
                v.1.saturating_add(r.bytes_down),
                v.2.saturating_add(r.flows),
            );
        }
        for (key, (up, down, flows)) in sample {
            let key = if self.rows.contains_key(&key) || self.rows.len() < MAX_KEYS {
                key
            } else {
                other_key(&key.0)
            };
            let v = self.rows.entry(key).or_default();
            *v = (
                v.0.saturating_add(up),
                v.1.saturating_add(down),
                v.2.max(flows),
            );
        }
    }

    /// The window's attribution failures `(bytes, flows)`; resets them.
    pub fn take_lan_unmapped(&mut self) -> (u64, u64) {
        (
            std::mem::take(&mut self.lan_unmapped_bytes),
            std::mem::take(&mut self.lan_unmapped_flows),
        )
    }

    /// Rows and expected-unmapped counters of the window so far; leaves them empty.
    pub fn take(&mut self) -> (Vec<ConntrackSummary>, u64, u64) {
        let rows = std::mem::take(&mut self.rows)
            .into_iter()
            .map(
                |((mac, dst_ip, dst_port, p), (up, down, flows))| ConntrackSummary {
                    mac,
                    dst_ip,
                    dst_port,
                    proto: proto_of(p),
                    bytes_up: up,
                    bytes_down: down,
                    flows,
                },
            )
            .collect();
        let out = (
            rows,
            std::mem::take(&mut self.unmapped_bytes),
            std::mem::take(&mut self.unmapped_flows),
        );
        self.snapshots = 0;
        out
    }
}
