//! One 60 s window of deltas: dedupes what the sources report and remembers what was already
//! sent so only changes go out ("deltas only").

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::model::{ConntrackSummary, DnsQuery, Lease, Neighbor, Sections, Sighting};

/// (mac, kind, name, service, ua)
type SightingKey = (String, u8, Option<String>, Option<String>, Option<String>);

#[derive(Debug, Default)]
pub struct Window {
    leases: BTreeMap<String, Lease>,
    neigh: BTreeMap<(String, String), Neighbor>,
    dns: Vec<DnsQuery>,
    conntrack: Vec<ConntrackSummary>,
    sightings: BTreeMap<SightingKey, Sighting>,
}

impl Window {
    /// Latest lease per MAC wins (a later DHCPACK carries the fuller fingerprint).
    pub fn add_lease(&mut self, l: Lease) {
        self.leases.insert(l.mac.clone(), l);
    }
    pub fn add_neighbor(&mut self, n: Neighbor) {
        self.neigh.insert((n.ip.clone(), n.mac.clone()), n);
    }
    pub fn add_dns(&mut self, q: DnsQuery) {
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
        let w = std::mem::take(self);
        Sections {
            leases: w.leases.into_values().collect(),
            neigh: w.neigh.into_values().collect(),
            dns: w.dns,
            conntrack: w.conntrack,
            sightings: w.sightings.into_values().collect(),
        }
    }

    /// Only the identity part (leases + neighbours), for an urgent push. DNS, conntrack and
    /// sightings stay in the window for the next regular batch.
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
