//! Bounded evidence retention with a per-source quota so one chatty or hostile host cannot
//! fill the retained sets.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Max distinct strings retained per set.
pub const MAX_ITEMS: usize = 256;
/// Max new strings any single source may contribute (across all sets).
pub const PER_SOURCE: usize = 64;
/// Max distinct sources tracked; further sources are dropped.
pub const MAX_SOURCES: usize = 256;

#[derive(Debug, Default)]
pub struct Evidence {
    /// Distinct strings charged to each source (a string is charged once per source, however
    /// many sets it lands in).
    per_source: BTreeMap<IpAddr, BTreeSet<String>>,
    pub dropped: u64,
}

impl Evidence {
    /// Insert `v` into `set` if allowed; true when newly inserted. Strings already in `set` are
    /// free; refusals bump `dropped`.
    pub fn admit(&mut self, src: IpAddr, set: &mut BTreeSet<String>, v: String) -> bool {
        if set.contains(&v) {
            return false;
        }
        let charged = self.per_source.get(&src);
        let already = charged.is_some_and(|c| c.contains(&v));
        let used = charged.map_or(0, BTreeSet::len);
        let new_source = charged.is_none();
        let refused = set.len() >= MAX_ITEMS
            || (!already
                && (used >= PER_SOURCE || (new_source && self.per_source.len() >= MAX_SOURCES)));
        if refused {
            self.dropped += 1;
            return false;
        }
        if !already {
            self.per_source.entry(src).or_default().insert(v.clone());
        }
        set.insert(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u32) -> IpAddr {
        IpAddr::from(std::net::Ipv4Addr::from(0xC0A8_0100 + n))
    }

    #[test]
    fn duplicates_are_free() {
        let mut e = Evidence::default();
        let mut set = BTreeSet::new();
        for _ in 0..100 {
            e.admit(ip(1), &mut set, "same".into());
        }
        assert_eq!((set.len(), e.dropped), (1, 0));
        // same value from another source: already present, still free
        assert!(!e.admit(ip(2), &mut set, "same".into()));
        assert_eq!(e.dropped, 0);
    }

    #[test]
    fn per_source_quota_boundary() {
        let mut e = Evidence::default();
        let mut set = BTreeSet::new();
        for i in 0..64 {
            assert!(e.admit(ip(1), &mut set, format!("n{i}")), "i={i}");
        }
        assert!(!e.admit(ip(1), &mut set, "one-too-many".into()));
        assert_eq!((set.len(), e.dropped), (64, 1));
        // another source is unaffected
        assert!(e.admit(ip(2), &mut set, "other".into()));
    }

    #[test]
    fn quota_is_shared_across_sets() {
        let mut e = Evidence::default();
        let (mut a, mut b) = (BTreeSet::new(), BTreeSet::new());
        for i in 0..64 {
            e.admit(ip(1), &mut a, format!("a{i}"));
        }
        assert!(!e.admit(ip(1), &mut b, "b0".into()));
    }

    #[test]
    fn one_string_in_two_sets_is_charged_once() {
        let mut e = Evidence::default();
        let (mut a, mut b) = (BTreeSet::new(), BTreeSet::new());
        assert!(e.admit(ip(1), &mut a, "x".into()));
        assert!(e.admit(ip(1), &mut b, "x".into()));
        for i in 0..63 {
            assert!(e.admit(ip(1), &mut a, format!("n{i}")), "i={i}");
        }
        // 64 distinct strings charged so far; the 65th is refused
        assert!(!e.admit(ip(1), &mut a, "over".into()));
        // a string already charged to this source is still free in another set
        assert!(e.admit(ip(1), &mut b, "n0".into()));
        assert_eq!(e.dropped, 1);
    }

    #[test]
    fn set_capacity_boundary() {
        let mut e = Evidence::default();
        let mut set = BTreeSet::new();
        // many sources, one item each, until the set is full
        for i in 0..256 {
            assert!(e.admit(ip(i as u32), &mut set, format!("n{i}")), "i={i}");
        }
        assert!(!e.admit(ip(0), &mut set, "overflow".into()));
        assert_eq!((set.len(), e.dropped), (256, 1));
    }

    #[test]
    fn source_table_is_bounded() {
        let mut e = Evidence::default();
        let mut sets: Vec<BTreeSet<String>> = Vec::new();
        for i in 0..256 {
            let mut s = BTreeSet::new();
            assert!(e.admit(ip(i as u32), &mut s, "x".into()), "i={i}");
            sets.push(s);
        }
        let mut s = BTreeSet::new();
        assert!(!e.admit(ip(256 as u32), &mut s, "x".into()));
        assert_eq!(e.dropped, 1);
        // a known source keeps its remaining quota
        assert!(e.admit(ip(0), &mut s, "y".into()));
    }
}
