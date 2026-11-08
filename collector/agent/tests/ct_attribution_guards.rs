//! Guards of the sticky IP -> MAC memory and of the own-address classification.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vigie_agent::ctfold::CtAccum;
use vigie_agent::ctparse::{Kind, Record, Snapshot};
use vigie_agent::ipmemory::{IpMemory, IP_MEMORY_TTL_S};
use vigie_agent::model::Proto;
use vigie_agent::neigh::parse_ip_neigh_table;
use vigie_agent::ownaddr::{
    read_bounded, read_bounded_from, OwnAddrs, FIB_TRIE_MAX, OWN_REFRESH_S,
};

const A: &str = "aa:bb:cc:dd:ee:01";
const V6: &str = "fd00::10";
const V4: &str = "192.168.8.10";

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(i, m)| ((*i).to_string(), (*m).to_string()))
        .collect()
}

fn none() -> HashSet<String> {
    HashSet::new()
}

// ---- IPv6 only ----

#[test]
fn ipv4_addresses_are_never_remembered_or_served() {
    let mut m = IpMemory::default();
    m.observe(&map(&[(V4, A), (V6, A)]), 100);
    assert_eq!(m.len(), 1, "only the IPv6 pairing is held");
    let got = m.overlay(&HashMap::new(), &none(), 101);
    assert!(
        !got.contains_key(V4),
        "DHCP-reused IPv4 is never served from memory"
    );
    assert_eq!(got.get(V6).map(String::as_str), Some(A));
}

#[test]
fn ipv6_is_served_within_the_ttl_and_not_after() {
    let mut m = IpMemory::default();
    m.observe(&map(&[(V6, A)]), 100);
    let at_ttl = m.overlay(&HashMap::new(), &none(), 100 + IP_MEMORY_TTL_S);
    assert!(at_ttl.contains_key(V6));
    let past = m.overlay(&HashMap::new(), &none(), 100 + IP_MEMORY_TTL_S + 1);
    assert!(!past.contains_key(V6));
}

// ---- FAILED / INCOMPLETE ----

#[test]
fn an_address_the_table_reports_failed_is_not_served_from_memory() {
    let mut m = IpMemory::default();
    m.observe(&map(&[(V6, A)]), 100);
    let failed: HashSet<String> = [V6.to_string()].into();
    let got = m.overlay(&HashMap::new(), &failed, 101);
    assert!(!got.contains_key(V6));
    let other = m.overlay(&HashMap::new(), &none(), 101);
    assert!(
        other.contains_key(V6),
        "served again once it is no longer failed"
    );
}

#[test]
fn the_parser_reports_failed_and_incomplete_addresses() {
    let t = "fd00::10 dev br-lan  FAILED\n\
             fd00::11 dev br-lan  INCOMPLETE\n\
             fd00::12 dev br-lan lladdr aa:bb:cc:dd:ee:01 STALE\n\
             192.168.8.9 dev br-lan  FAILED\n\
             ff02::1 dev br-lan  FAILED\n";
    let table = parse_ip_neigh_table(t);
    assert_eq!(table.neighbors.len(), 1);
    let want: HashSet<String> = ["fd00::10", "fd00::11", "192.168.8.9"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(table.failed, want, "unicast FAILED/INCOMPLETE only");
}

// ---- own addresses: mapped first ----

#[test]
fn a_mapped_source_is_never_classified_as_own() {
    let own: HashSet<IpAddr> = [V4.parse().unwrap()].into();
    let mut acc = CtAccum::default();
    let r = Record {
        src: V4.parse().unwrap(),
        kind: Kind::Tuple,
        dst: Some("1.1.1.1".parse().unwrap()),
        dport: Some(443),
        proto: Proto::Tcp,
        bytes_up: 5,
        bytes_down: 6,
        flows: 1,
    };
    let snap = Snapshot {
        records: vec![r],
        ..Snapshot::default()
    };
    acc.add_snapshot_with_own(&snap, &map(&[(V4, A)]), &own);
    assert_eq!(acc.take_lan_unmapped(), (0, 0));
    let (rows, ub, uf) = acc.take();
    assert_eq!(
        (rows.len(), ub, uf),
        (1, 0, 0),
        "billed to its MAC, not hidden"
    );
    assert_eq!(rows[0].mac, A);
}

// ---- bounded procfs reads ----

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ownaddr-{}-{name}", std::process::id()));
    std::fs::write(&d, "").unwrap();
    d
}

#[test]
fn a_file_over_the_bound_is_a_read_failure() {
    let p = scratch("big");
    std::fs::write(&p, vec![b'x'; FIB_TRIE_MAX + 1]).unwrap();
    assert!(read_bounded(&p, FIB_TRIE_MAX).is_none());
    std::fs::write(&p, vec![b'x'; FIB_TRIE_MAX]).unwrap();
    assert_eq!(
        read_bounded(&p, FIB_TRIE_MAX).map(|s| s.len()),
        Some(FIB_TRIE_MAX)
    );
    std::fs::write(&p, [0xff, 0xfe]).unwrap();
    assert!(read_bounded(&p, 10).is_none(), "not UTF-8");
    assert!(read_bounded(&p.with_extension("missing"), 10).is_none());
    let _ = std::fs::remove_file(&p);
}

// ---- refresh throttle ----

static READS: AtomicUsize = AtomicUsize::new(0);

fn counting_reader() -> Option<HashSet<IpAddr>> {
    READS.fetch_add(1, Ordering::SeqCst);
    Some(HashSet::new())
}

#[test]
fn own_addresses_are_re_read_only_after_the_refresh_period() {
    let mut o = OwnAddrs::new(Ipv4Addr::new(192, 168, 8, 1), counting_reader);
    o.refresh(1000);
    assert_eq!(READS.load(Ordering::SeqCst), 1);
    o.refresh(1000 + OWN_REFRESH_S - 1);
    assert_eq!(READS.load(Ordering::SeqCst), 1, "throttled");
    o.refresh(1000 + OWN_REFRESH_S);
    assert_eq!(READS.load(Ordering::SeqCst), 2, "due at the period");
}

static HEALTHY: AtomicBool = AtomicBool::new(true);

fn flaky_reader() -> Option<HashSet<IpAddr>> {
    HEALTHY
        .load(Ordering::SeqCst)
        .then(|| ["fd00::1".parse().unwrap()].into())
}

#[test]
fn a_failed_re_read_drops_the_previously_known_addresses() {
    let mut o = OwnAddrs::new(Ipv4Addr::new(192, 168, 8, 1), flaky_reader);
    o.refresh(0);
    assert!(!o.set().is_empty());
    HEALTHY.store(false, Ordering::SeqCst);
    o.refresh(OWN_REFRESH_S);
    assert!(o.set().is_empty(), "nothing is own after a failed read");
}

/// Endless 'a' bytes; panics the moment more than `cap` bytes were ever served.
struct Guarded {
    served: usize,
    cap: usize,
}

impl std::io::Read for Guarded {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.served += buf.len();
        assert!(
            self.served <= self.cap,
            "read past the bound: {} bytes",
            self.served
        );
        buf.fill(b'a');
        Ok(buf.len())
    }
}

#[test]
fn a_bounded_read_never_asks_the_source_for_more_than_limit_plus_one() {
    let r = Guarded {
        served: 0,
        cap: 4096 + 1,
    };
    assert!(
        read_bounded_from(r, 4096).is_none(),
        "endless source: rejected, bounded"
    );
}

#[test]
fn a_source_of_exactly_the_limit_is_accepted_and_one_more_is_rejected() {
    let at = [b'a'; 100];
    let over = [b'a'; 101];
    assert_eq!(read_bounded_from(&at[..], 100).map(|s| s.len()), Some(100));
    assert!(read_bounded_from(&over[..], 100).is_none());
}

#[test]
fn ipv4_mapped_ipv6_addresses_are_not_remembered_or_served() {
    let mut m = IpMemory::default();
    m.observe(&map(&[("::ffff:192.168.8.10", A), (V6, A)]), 100);
    assert_eq!(m.len(), 1);
    let got = m.overlay(&HashMap::new(), &none(), 101);
    assert!(!got.contains_key("::ffff:192.168.8.10"));
    assert!(got.contains_key(V6));
}
