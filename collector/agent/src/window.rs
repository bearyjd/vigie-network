//! One 60 s window of deltas: dedupes what the sources report and remembers what was already
//! sent so only changes go out ("deltas only").

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::model::{ConntrackSummary, DnsQuery, Lease, Neighbor, Sections, Sighting};

/// (mac, kind, name, service, ua)
type SightingKey = (String, u8, Option<String>, Option<String>, Option<String>);

/// Most DNS rows one window holds (memory bound; the batch itself is capped separately).
pub const MAX_WINDOW_DNS: usize = 10_000;
/// Most DNS rows one MAC may contribute per window, so one chatty device cannot crowd out others.
pub const DNS_PER_MAC_QUOTA: usize = 1024;
/// Most distinct sightings one window holds.
pub const MAX_WINDOW_SIGHTINGS: usize = 4096;
/// Distinct sightings one device may add per window (a chatty or hostile host cannot crowd out
/// the others). Refusals are counted in `sightings_dropped`.
pub const SIGHTINGS_PER_MAC_QUOTA: usize = 64;

/// Window start derived from the monotonic clock. The router has no RTC, so NTP can jump the
/// wall clock by days mid-window; a start taken from the wall clock at the last flush would then
/// span the jump and the server would reject the whole batch (window > 24 h).
#[derive(Debug, Default)]
pub struct WindowClock {
    last_flush_mono_s: u64,
}

impl WindowClock {
    pub fn new(mono_s: u64) -> Self {
        Self {
            last_flush_mono_s: mono_s,
        }
    }
    /// Wall time the current window started, given the current wall and monotonic clocks.
    pub fn start(&self, wall_s: u64, mono_s: u64) -> u64 {
        wall_s.saturating_sub(mono_s.saturating_sub(self.last_flush_mono_s))
    }
    /// Call after every flush attempt, including one skipped because the clock is not sane.
    pub fn mark_flush(&mut self, mono_s: u64) {
        self.last_flush_mono_s = mono_s;
    }
}

#[derive(Debug, Default)]
pub struct Window {
    leases: BTreeMap<String, Lease>,
    neigh: BTreeMap<(String, String), Neighbor>,
    dns: Vec<DnsQuery>,
    conntrack: Vec<ConntrackSummary>,
    sightings: BTreeMap<SightingKey, Sighting>,
    dns_per_mac: HashMap<String, usize>,
    sightings_per_mac: HashMap<String, usize>,
    /// Rows dropped by the caps above, by `truncated` key.
    drops: BTreeMap<String, u64>,
}

impl Window {
    /// Latest lease per MAC wins (a later DHCPACK carries the fuller fingerprint).
    pub fn add_lease(&mut self, l: Lease) {
        self.leases.insert(l.mac.clone(), l);
    }
    pub fn add_neighbor(&mut self, n: Neighbor) {
        self.neigh.insert((n.ip.clone(), n.mac.clone()), n);
    }
    /// Adds a DNS row unless the MAC's quota or the window cap is used up (counted, not silent).
    pub fn add_dns(&mut self, q: DnsQuery) {
        if self.dns.len() >= MAX_WINDOW_DNS {
            self.note_drops("dns_dropped", 1);
            return;
        }
        let used = self.dns_per_mac.entry(q.mac.clone()).or_default();
        if *used >= DNS_PER_MAC_QUOTA {
            self.note_drops("dns_quota_dropped", 1);
            return;
        }
        *used += 1;
        self.dns.push(q);
    }
    pub fn add_conntrack(&mut self, c: ConntrackSummary) {
        self.conntrack.push(c);
    }
    pub fn add_sighting(&mut self, s: Sighting) {
        let key = (
            s.mac.clone(),
            s.kind as u8,
            s.name.clone(),
            s.service.clone(),
            s.ua.clone(),
        );
        // The key holds every field of a sighting, so a repeat is identical: free, no quota.
        if self.sightings.contains_key(&key) {
            return;
        }
        let used = self.sightings_per_mac.get(&s.mac).copied().unwrap_or(0);
        if self.sightings.len() >= MAX_WINDOW_SIGHTINGS || used >= SIGHTINGS_PER_MAC_QUOTA {
            self.note_drops("sightings_dropped", 1);
            return;
        }
        self.sightings_per_mac.insert(s.mac.clone(), used + 1);
        self.sightings.insert(key, s);
    }

    pub fn dns_count(&self) -> usize {
        self.dns.len()
    }
    pub fn flow_count(&self) -> u64 {
        self.conntrack.iter().map(|c| c.flows).sum()
    }

    /// Everything collected so far, leaving the window empty.
    pub fn take(&mut self) -> Sections {
        self.take_with_drops().0
    }

    /// Like `take`, plus what the window caps dropped (for the batch `truncated` map).
    pub fn take_with_drops(&mut self) -> (Sections, BTreeMap<String, u64>) {
        let w = std::mem::take(self);
        let sections = Sections {
            leases: w.leases.into_values().collect(),
            neigh: w.neigh.into_values().collect(),
            dns: w.dns,
            conntrack: w.conntrack,
            sightings: w.sightings.into_values().collect(),
        };
        (sections, w.drops)
    }

    /// Shift every DNS timestamp by `offset` seconds (provisional monotonic stamps to wall time).
    pub fn rebase_dns(&mut self, offset: u64) {
        for q in &mut self.dns {
            q.ts = q.ts.saturating_add(offset).min(crate::model::MAX_EPOCH);
        }
    }

    /// Record `n` items lost upstream of the window (e.g. by the DNS correlator).
    pub fn note_drops(&mut self, kind: &str, n: u64) {
        if n > 0 {
            let c = self.drops.entry(kind.to_string()).or_default();
            *c = c.saturating_add(n);
        }
    }

    /// Only the identity part (leases + neighbours), for an urgent push. DNS, conntrack and
    /// sightings stay in the window for the next regular batch.
    /// OR `bits` into the `source_flags` bitmask reported in `truncated` (see `SourceFlag`).
    pub fn note_flags(&mut self, bits: u64) {
        if bits != 0 {
            *self
                .drops
                .entry(crate::builder::FLAGS_KEY.to_string())
                .or_default() |= bits;
        }
    }

    pub fn take_identity(&mut self) -> Sections {
        Sections {
            leases: std::mem::take(&mut self.leases).into_values().collect(),
            neigh: std::mem::take(&mut self.neigh).into_values().collect(),
            ..Sections::default()
        }
    }
}

/// Remembers what snapshot sources (neighbor table, lease file) reported last time.
#[derive(Debug, Default)]
pub struct SnapshotDelta {
    neigh: HashSet<(String, String)>,
    leases: HashMap<String, (String, Option<String>)>,
}

impl SnapshotDelta {
    /// Neighbor entries that are new since the previous snapshot. An entry that disappeared
    /// and returns is reported again.
    pub fn new_neighbors(&mut self, current: &[Neighbor]) -> Vec<Neighbor> {
        let now: HashSet<(String, String)> = current
            .iter()
            .map(|n| (n.ip.clone(), n.mac.clone()))
            .collect();
        let fresh = current
            .iter()
            .filter(|n| !self.neigh.contains(&(n.ip.clone(), n.mac.clone())))
            .cloned()
            .collect();
        self.neigh = now;
        fresh
    }

    /// Leases whose (ip, hostname) changed or that are new since the previous snapshot.
    pub fn changed_leases(&mut self, current: Vec<Lease>) -> Vec<Lease> {
        let mut out = Vec::new();
        for l in current {
            let sig = (l.ip.clone(), l.hostname.clone());
            if self.leases.get(&l.mac) != Some(&sig) {
                self.leases.insert(l.mac.clone(), sig);
                out.push(l);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SightingKind;

    fn n(ip: &str, mac: &str) -> Neighbor {
        Neighbor::new(ip, mac).unwrap()
    }

    #[test]
    fn snapshot_delta_reports_only_changes() {
        let mut d = SnapshotDelta::default();
        let a = [
            n("10.0.0.1", "aa:bb:cc:dd:ee:01"),
            n("10.0.0.2", "aa:bb:cc:dd:ee:02"),
        ];
        assert_eq!(d.new_neighbors(&a).len(), 2);
        assert!(d.new_neighbors(&a).is_empty());
        let b = [a[0].clone(), n("10.0.0.3", "aa:bb:cc:dd:ee:03")];
        assert_eq!(d.new_neighbors(&b), vec![b[1].clone()]);
        assert_eq!(
            d.new_neighbors(&a).len(),
            1,
            "10.0.0.2 returned after disappearing"
        );

        let l =
            |ip: &str, h: &str| Lease::new("aa:bb:cc:dd:ee:01", ip, Some(h), &[], None).unwrap();
        assert_eq!(d.changed_leases(vec![l("10.0.0.1", "x")]).len(), 1);
        assert!(d.changed_leases(vec![l("10.0.0.1", "x")]).is_empty());
        assert_eq!(
            d.changed_leases(vec![l("10.0.0.9", "x")]).len(),
            1,
            "ip changed"
        );
        assert_eq!(
            d.changed_leases(vec![l("10.0.0.9", "y")]).len(),
            1,
            "hostname changed"
        );
    }

    #[test]
    fn window_dedupes_and_take_empties_it() {
        let mut w = Window::default();
        w.add_neighbor(n("10.0.0.1", "aa:bb:cc:dd:ee:01"));
        w.add_neighbor(n("10.0.0.1", "aa:bb:cc:dd:ee:01"));
        let s = |k| Sighting::new("aa:bb:cc:dd:ee:01", k, Some("h"), None, None).unwrap();
        w.add_sighting(s(SightingKind::Mdns));
        w.add_sighting(s(SightingKind::Mdns));
        w.add_sighting(s(SightingKind::Ssdp));
        let l1 = Lease::new("aa:bb:cc:dd:ee:01", "10.0.0.1", None, &[], None).unwrap();
        let l2 = Lease::new("aa:bb:cc:dd:ee:01", "10.0.0.1", Some("full"), &[1], None).unwrap();
        w.add_lease(l1);
        w.add_lease(l2.clone());
        let t = w.take();
        assert_eq!(
            (t.neigh.len(), t.sightings.len(), t.leases.len()),
            (1, 2, 1)
        );
        assert_eq!(t.leases[0], l2, "later lease wins");
        assert_eq!(w.take(), Sections::default());
    }

    fn mac_n(n: usize) -> String {
        format!("02:00:00:00:{:02x}:{:02x}", (n >> 8) & 0xff, n & 0xff)
    }

    #[test]
    fn one_mac_cannot_fill_the_sightings_table() {
        let mut w = Window::default();
        for i in 0..(SIGHTINGS_PER_MAC_QUOTA + 40) {
            let name = format!("h{i}");
            w.add_sighting(
                Sighting::new(&mac_n(1), SightingKind::Mdns, Some(&name), None, None).unwrap(),
            );
        }
        // another device is unaffected
        w.add_sighting(
            Sighting::new(&mac_n(2), SightingKind::Mdns, Some("x"), None, None).unwrap(),
        );
        let (s, drops) = w.take_with_drops();
        assert_eq!(s.sightings.len(), SIGHTINGS_PER_MAC_QUOTA + 1);
        assert_eq!(drops.get("sightings_dropped"), Some(&40));
    }

    #[test]
    fn a_repeated_sighting_is_free_even_at_the_quota() {
        let mut w = Window::default();
        for i in 0..SIGHTINGS_PER_MAC_QUOTA {
            let name = format!("h{i}");
            w.add_sighting(
                Sighting::new(&mac_n(1), SightingKind::Mdns, Some(&name), None, None).unwrap(),
            );
        }
        w.add_sighting(
            Sighting::new(&mac_n(1), SightingKind::Mdns, Some("h0"), None, None).unwrap(),
        );
        let (s, drops) = w.take_with_drops();
        assert_eq!(s.sightings.len(), SIGHTINGS_PER_MAC_QUOTA);
        assert!(drops.is_empty(), "{drops:?}");
    }

    #[test]
    fn the_global_sightings_cap_holds_across_macs() {
        let mut w = Window::default();
        for i in 0..(MAX_WINDOW_SIGHTINGS + 10) {
            w.add_sighting(
                Sighting::new(&mac_n(i), SightingKind::Ssdp, Some("n"), None, None).unwrap(),
            );
        }
        let (s, drops) = w.take_with_drops();
        assert_eq!(s.sightings.len(), MAX_WINDOW_SIGHTINGS);
        assert_eq!(drops.get("sightings_dropped"), Some(&10));
    }

    #[test]
    fn flag_bits_accumulate_as_a_bitmask_not_a_sum() {
        let mut w = Window::default();
        w.note_flags(0b0001);
        w.note_flags(0b0001);
        w.note_flags(0b0100);
        w.note_flags(0);
        let (_, drops) = w.take_with_drops();
        assert_eq!(drops.get("source_flags"), Some(&0b0101));
        let (_, none) = w.take_with_drops();
        assert!(none.is_empty(), "no flags, no key");
    }

    #[test]
    fn take_identity_leaves_the_rest() {
        let mut w = Window::default();
        w.add_lease(Lease::new("aa:bb:cc:dd:ee:01", "10.0.0.1", None, &[], None).unwrap());
        w.add_dns(DnsQuery::new(1, "aa:bb:cc:dd:ee:01", "x.test", "A", None).unwrap());
        let id = w.take_identity();
        assert_eq!((id.leases.len(), id.dns.len()), (1, 0));
        assert_eq!(w.take().dns.len(), 1);
    }
}
