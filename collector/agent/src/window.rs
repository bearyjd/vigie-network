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
/// New distinct sightings admitted per window across all devices. Multicast source addresses are
/// spoofable, so the per-device quota alone lets a flood spread over many neighbor-table MACs
/// fill `MAX_WINDOW_SIGHTINGS`; this rate bounds the whole flood. Drops are counted in
/// `sightings_dropped`.
pub const SIGHTINGS_ADMIT_PER_WINDOW: usize = 1024;
/// MACs whose fingerprint is remembered across windows (memory bound).
pub const MAX_FP_MEMORY: usize = 1024;

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
    /// Last non-empty (opt55, opt60, store order) per MAC. Survives `take`: a lease re-read from
    /// `dhcp.leases` has no fingerprint and must not shadow one already captured from the log.
    fingerprints: BTreeMap<String, (Vec<u8>, Option<String>, u64)>,
    /// Monotonic store counter for `fingerprints` eviction order.
    fp_seq: u64,
    neigh: BTreeMap<(String, String), Neighbor>,
    dns: Vec<DnsQuery>,
    conntrack: Vec<ConntrackSummary>,
    sightings: BTreeMap<SightingKey, Sighting>,
    dns_per_mac: HashMap<String, usize>,
    sightings_per_mac: HashMap<String, usize>,
    /// Distinct sightings admitted this window (see `SIGHTINGS_ADMIT_PER_WINDOW`).
    sightings_admitted: usize,
    /// Rows dropped by the caps above, by `truncated` key.
    drops: BTreeMap<String, u64>,
}

impl Window {
    /// Latest lease per MAC wins (a later DHCPACK carries the fuller fingerprint).
    /// The fingerprint (opt55, opt60) is one unit: a lease carrying any non-empty field replaces
    /// the stored pair exactly as received (never mixed with the old one), and an entirely empty
    /// lease (or one whose only field repeats the stored vendor class) never overwrites it, within the window or across windows (see `fingerprints`).
    /// When the memory is full the least recently stored MAC is evicted.
    pub fn add_lease(&mut self, mut l: Lease) {
        // An options-less lease must not shrink a stored pair either: one that adds nothing
        // (no vendor class, or the same one) is as good as an empty lease.
        let adds_nothing = |stored: &(Vec<u8>, Option<String>, u64)| {
            l.opt55.is_empty() && !stored.0.is_empty() && (l.opt60.is_none() || l.opt60 == stored.1)
        };
        if self.fingerprints.get(&l.mac).is_some_and(adds_nothing) {
            l.opt60 = None;
        }
        if l.opt55.is_empty() && l.opt60.is_none() {
            if let Some((o, c, _)) = self.fingerprints.get(&l.mac) {
                l.opt55 = o.clone();
                l.opt60 = c.clone();
            }
        } else {
            if !self.fingerprints.contains_key(&l.mac) && self.fingerprints.len() >= MAX_FP_MEMORY {
                let oldest = self
                    .fingerprints
                    .iter()
                    .min_by_key(|(_, (_, _, seq))| *seq)
                    .map(|(m, _)| m.clone());
                if let Some(m) = oldest {
                    self.fingerprints.remove(&m);
                }
            }
            self.fp_seq += 1;
            self.fingerprints.insert(
                l.mac.clone(),
                (l.opt55.clone(), l.opt60.clone(), self.fp_seq),
            );
        }
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
        if self.sightings.len() >= MAX_WINDOW_SIGHTINGS
            || self.sightings_admitted >= SIGHTINGS_ADMIT_PER_WINDOW
            || used >= SIGHTINGS_PER_MAC_QUOTA
        {
            self.note_drops("sightings_dropped", 1);
            return;
        }
        self.sightings_admitted += 1;
        self.sightings_per_mac.insert(s.mac.clone(), used + 1);
        self.sightings.insert(key, s);
    }

    pub fn dns_count(&self) -> usize {
        self.dns.len()
    }
    pub fn flow_count(&self) -> u64 {
        self.conntrack
            .iter()
            .fold(0u64, |a, c| a.saturating_add(c.flows))
    }

    /// Everything collected so far, leaving the window empty.
    pub fn take(&mut self) -> Sections {
        self.take_with_drops().0
    }

    /// Like `take`, plus what the window caps dropped (for the batch `truncated` map).
    pub fn take_with_drops(&mut self) -> (Sections, BTreeMap<String, u64>) {
        let mut w = std::mem::take(self);
        self.fingerprints = std::mem::take(&mut w.fingerprints);
        self.fp_seq = w.fp_seq;
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
        for i in 0..(SIGHTINGS_ADMIT_PER_WINDOW + 10) {
            w.add_sighting(
                Sighting::new(&mac_n(i), SightingKind::Ssdp, Some("n"), None, None).unwrap(),
            );
        }
        let (s, drops) = w.take_with_drops();
        assert_eq!(s.sightings.len(), SIGHTINGS_ADMIT_PER_WINDOW);
        assert_eq!(drops.get("sightings_dropped"), Some(&10));
    }

    #[test]
    fn a_spoofed_source_flood_is_bounded_per_mac_and_per_window() {
        let mut w = Window::default();
        // Real devices announce first.
        for m in 1..=10 {
            w.add_sighting(
                Sighting::new(&mac_n(m), SightingKind::Mdns, Some("real"), None, None).unwrap(),
            );
        }
        // A flood of spoofed source IPs: many victim MACs, each with many distinct names.
        for m in 100..2100 {
            for i in 0..8 {
                let name = format!("spoof{i}");
                w.add_sighting(
                    Sighting::new(&mac_n(m), SightingKind::Mdns, Some(&name), None, None).unwrap(),
                );
            }
        }
        // A victim MAC hammered with distinct names stays within its quota.
        for i in 0..500 {
            let name = format!("v{i}");
            w.add_sighting(
                Sighting::new(&mac_n(5000), SightingKind::Mdns, Some(&name), None, None).unwrap(),
            );
        }
        let (s, drops) = w.take_with_drops();
        assert!(
            s.sightings.len() <= SIGHTINGS_ADMIT_PER_WINDOW,
            "{} admitted",
            s.sightings.len()
        );
        let of = |m: usize| s.sightings.iter().filter(|x| x.mac == mac_n(m)).count();
        assert_eq!(
            (1..=10).map(of).sum::<usize>(),
            10,
            "earlier real sightings are never evicted"
        );
        assert!(of(5000) <= SIGHTINGS_PER_MAC_QUOTA);
        assert!(drops["sightings_dropped"] > 0);
    }

    #[test]
    fn the_admission_budget_resets_each_window_and_repeats_are_free() {
        let mut w = Window::default();
        let add = |w: &mut Window, m: usize| {
            w.add_sighting(
                Sighting::new(&mac_n(m), SightingKind::Ssdp, Some("n"), None, None).unwrap(),
            )
        };
        for m in 0..SIGHTINGS_ADMIT_PER_WINDOW + 5 {
            add(&mut w, m);
        }
        add(&mut w, 0); // a repeat costs nothing and is not counted as dropped
        let (s, drops) = w.take_with_drops();
        assert_eq!(s.sightings.len(), SIGHTINGS_ADMIT_PER_WINDOW);
        assert_eq!(drops["sightings_dropped"], 5);
        add(&mut w, 9000);
        assert_eq!(
            w.take().sightings.len(),
            1,
            "a new window has a fresh budget"
        );
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
    fn flow_count_saturates_instead_of_overflowing() {
        let mut w = Window::default();
        for i in 0..2 {
            w.add_conntrack(ConntrackSummary {
                mac: mac_n(i),
                dst_ip: None,
                dst_port: None,
                proto: crate::model::Proto::Other,
                bytes_up: 0,
                bytes_down: 0,
                flows: u64::MAX,
            });
        }
        assert_eq!(w.flow_count(), u64::MAX);
    }

    fn lease(opt55: &[u8], opt60: Option<&str>) -> Lease {
        Lease::new("aa:bb:cc:dd:ee:01", "10.0.0.1", None, opt55, opt60).unwrap()
    }

    #[test]
    fn empty_fingerprint_never_overwrites_within_a_window() {
        let mut w = Window::default();
        w.add_lease(lease(&[1, 3], Some("android")));
        w.add_lease(lease(&[], None));
        let t = w.take();
        assert_eq!(t.leases[0].opt55, vec![1, 3]);
        assert_eq!(t.leases[0].opt60.as_deref(), Some("android"));
    }

    #[test]
    fn empty_fingerprint_never_overwrites_across_windows() {
        let mut w = Window::default();
        w.add_lease(lease(&[1, 3], Some("android")));
        drop(w.take());
        w.add_lease(lease(&[], None));
        let t = w.take();
        assert_eq!(t.leases[0].opt55, vec![1, 3]);
        assert_eq!(t.leases[0].opt60.as_deref(), Some("android"));
        // a new non-empty value does replace the old one
        w.add_lease(lease(&[9], None));
        assert_eq!(w.take().leases[0].opt55, vec![9]);
    }

    #[test]
    fn new_opt55_only_lease_does_not_inherit_the_old_opt60() {
        let mut w = Window::default();
        w.add_lease(lease(&[1, 3], Some("android")));
        drop(w.take());
        w.add_lease(lease(&[9], None));
        let t = w.take();
        assert_eq!(
            (t.leases[0].opt55.clone(), t.leases[0].opt60.clone()),
            (vec![9], None)
        );
        // and the pair stored is the new one: an empty lease now inherits [9]/None
        w.add_lease(lease(&[], None));
        let t = w.take();
        assert_eq!(
            (t.leases[0].opt55.clone(), t.leases[0].opt60.clone()),
            (vec![9], None)
        );
    }

    #[test]
    fn new_opt60_only_lease_does_not_inherit_the_old_opt55() {
        let mut w = Window::default();
        w.add_lease(lease(&[1, 3], Some("android")));
        w.add_lease(lease(&[], Some("udhcp")));
        let t = w.take();
        assert_eq!(t.leases[0].opt55, Vec::<u8>::new());
        assert_eq!(t.leases[0].opt60.as_deref(), Some("udhcp"));
    }

    fn fp_of(w: &Window, m: &str) -> Option<Vec<u8>> {
        w.fingerprints.get(m).map(|e| e.0.clone())
    }

    #[test]
    fn fingerprint_memory_is_bounded() {
        let mut w = Window::default();
        for i in 0..(MAX_FP_MEMORY + 10) {
            w.add_lease(Lease::new(&mac_n(i), "10.0.0.1", None, &[1], None).unwrap());
        }
        drop(w.take());
        assert_eq!(w.fingerprints.len(), MAX_FP_MEMORY);
    }

    #[test]
    fn full_fingerprint_memory_evicts_the_oldest_not_the_newcomer() {
        let mut w = Window::default();
        for i in 0..MAX_FP_MEMORY {
            w.add_lease(Lease::new(&mac_n(i), "10.0.0.1", None, &[1], None).unwrap());
        }
        // mac 0 is seen again (most recent), so mac 1 is now the oldest
        w.add_lease(Lease::new(&mac_n(0), "10.0.0.1", None, &[2], None).unwrap());
        w.add_lease(Lease::new(&mac_n(MAX_FP_MEMORY), "10.0.0.1", None, &[3], None).unwrap());
        assert_eq!(w.fingerprints.len(), MAX_FP_MEMORY);
        assert_eq!(fp_of(&w, &mac_n(1)), None, "oldest evicted");
        assert_eq!(fp_of(&w, &mac_n(0)), Some(vec![2]), "recently seen kept");
        assert_eq!(
            fp_of(&w, &mac_n(MAX_FP_MEMORY)),
            Some(vec![3]),
            "newcomer stored"
        );
        // a spoofing cycle of 1024 fresh MACs cannot freeze the memory: a real device still lands
        for i in 2000..2000 + MAX_FP_MEMORY {
            w.add_lease(Lease::new(&mac_n(i), "10.0.0.1", None, &[4], None).unwrap());
        }
        w.add_lease(Lease::new("aa:bb:cc:00:00:01", "10.0.0.2", None, &[5], None).unwrap());
        assert_eq!(fp_of(&w, "aa:bb:cc:00:00:01"), Some(vec![5]));
        assert_eq!(w.fingerprints.len(), MAX_FP_MEMORY);
    }

    #[test]
    fn first_mac_is_evicted_by_the_1025th() {
        let mut w = Window::default();
        for i in 0..=MAX_FP_MEMORY {
            w.add_lease(Lease::new(&mac_n(i), "10.0.0.1", None, &[1], None).unwrap());
        }
        assert_eq!(fp_of(&w, &mac_n(0)), None);
        assert_eq!(fp_of(&w, &mac_n(MAX_FP_MEMORY)), Some(vec![1]));
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
