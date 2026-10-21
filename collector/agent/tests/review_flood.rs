//! Security review item 4: a chatty device (or log flood) must not crowd out other devices, grow
//! memory without bound, or make drops silent.

use std::collections::{BTreeMap, HashMap};

use vigie_agent::builder::{build_with_drops, BATCH_CAP, TRUNCATED_RESERVE};
use vigie_agent::dnsmasq::{parse_line, DnsCorrelator};
use vigie_agent::model::*;
use vigie_agent::window::{Window, DNS_PER_MAC_QUOTA, MAX_WINDOW_DNS, MAX_WINDOW_SIGHTINGS};

fn mac_n(n: usize) -> String {
    format!("02:00:00:00:{:02x}:{:02x}", (n >> 8) & 0xff, n & 0xff)
}

fn q(mac: &str, i: usize) -> DnsQuery {
    DnsQuery::new(1_760_000_010, mac, &format!("n{i}.example.com"), "A", None).unwrap()
}

fn meta() -> Meta {
    Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq: 1,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: 1_760_000_000,
        window_end: 1_760_000_060,
    }
}

#[test]
fn one_chatty_mac_is_capped_by_the_per_mac_quota_and_counted() {
    let mut w = Window::default();
    let flooder = mac_n(9000);
    // 2000 queries per second for a whole 60 s window, interleaved with 50 normal devices.
    for i in 0..120_000 {
        w.add_dns(q(&flooder, i));
        if i % 2400 == 0 {
            for d in 0..50 {
                w.add_dns(q(&mac_n(d), i));
            }
        }
    }
    let (s, drops) = w.take_with_drops();
    let per: HashMap<&str, usize> = s.dns.iter().fold(HashMap::new(), |mut m, r| {
        *m.entry(r.mac.as_str()).or_default() += 1;
        m
    });
    assert_eq!(per[flooder.as_str()], DNS_PER_MAC_QUOTA);
    for d in 0..50 {
        assert_eq!(
            per[mac_n(d).as_str()],
            50,
            "normal device {d} keeps every query"
        );
    }
    assert_eq!(
        drops["dns_quota_dropped"],
        (120_000 - DNS_PER_MAC_QUOTA) as u64
    );
    assert!(!drops.contains_key("dns_dropped"));
}

#[test]
fn quota_resets_with_each_window() {
    let mut w = Window::default();
    for i in 0..(DNS_PER_MAC_QUOTA + 10) {
        w.add_dns(q(&mac_n(1), i));
    }
    let (s, _) = w.take_with_drops();
    assert_eq!(s.dns.len(), DNS_PER_MAC_QUOTA);
    for i in 0..5 {
        w.add_dns(q(&mac_n(1), i));
    }
    let (s, drops) = w.take_with_drops();
    assert_eq!((s.dns.len(), drops.len()), (5, 0));
}

#[test]
fn window_dns_is_bounded_even_with_many_macs() {
    let mut w = Window::default();
    for n in 0..(MAX_WINDOW_DNS + 500) {
        w.add_dns(q(&mac_n(n), 0));
    }
    assert_eq!(w.dns_count(), MAX_WINDOW_DNS);
    let (_, drops) = w.take_with_drops();
    assert_eq!(drops["dns_dropped"], 500);
}

#[test]
fn window_sightings_are_bounded_and_counted() {
    let mut w = Window::default();
    for n in 0..(MAX_WINDOW_SIGHTINGS + 7) {
        let s = Sighting::new(
            &mac_n(1),
            SightingKind::Mdns,
            Some(&format!("h{n}")),
            None,
            None,
        )
        .unwrap();
        w.add_sighting(s);
    }
    // Re-seeing an existing key is not growth.
    let again = Sighting::new(&mac_n(1), SightingKind::Mdns, Some("h0"), None, None).unwrap();
    w.add_sighting(again);
    let (s, drops) = w.take_with_drops();
    assert_eq!(s.sightings.len(), MAX_WINDOW_SIGHTINGS);
    assert_eq!(drops["sightings_dropped"], 7);
}

#[test]
fn drops_reach_the_batch_truncated_map_and_normal_devices_survive() {
    let mut w = Window::default();
    let flooder = mac_n(9000);
    for i in 0..5000 {
        w.add_dns(q(&flooder, i));
    }
    for d in 0..50 {
        for i in 0..10 {
            w.add_dns(q(&mac_n(d), i));
        }
    }
    let (s, drops) = w.take_with_drops();
    let b = build_with_drops(&meta(), s, &Health::default(), BATCH_CAP, &drops);
    assert_eq!(
        b.truncated["dns_quota_dropped"],
        (5000 - DNS_PER_MAC_QUOTA) as u64
    );
    let body = String::from_utf8(b.encoded.body(1_760_000_061, 0)).unwrap();
    assert!(body.contains(r#""dns_quota_dropped":"#));
    for d in 0..50 {
        assert_eq!(
            body.matches(&format!(r#""mac":"{}""#, mac_n(d))).count(),
            10,
            "device {d}"
        );
    }
    assert!(body.len() <= BATCH_CAP);
}

#[test]
fn all_truncated_kinds_fit_the_schema_and_the_reserve() {
    let mut drops: BTreeMap<String, u64> = BTreeMap::new();
    for k in [
        "dns_quota_dropped",
        "dns_dropped",
        "sightings_dropped",
        "dns_pending_evicted",
        "dns_client_throttled",
    ] {
        drops.insert(k.into(), u64::MAX);
    }
    let b = build_with_drops(
        &meta(),
        Sections::default(),
        &Health::default(),
        BATCH_CAP,
        &drops,
    );
    assert!(b.truncated.len() <= 16, "server schema allows 16 keys");
    for k in b.truncated.keys() {
        assert!(k.len() <= 32 && k.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'));
    }
    // Worst case: every kind the builder itself can add, plus all of ours, at i64::MAX.
    let mut full = drops.clone();
    for k in [
        "dns_out_of_window",
        "leases",
        "neigh",
        "sightings",
        "dns",
        "conntrack",
        "conntrack_lost",
    ] {
        full.insert(k.into(), u64::MAX);
    }
    assert!(full.len() <= 16);
    let sizes: usize = full.iter().map(|(k, _)| k.len() + 3 + 19 + 1).sum();
    assert!(
        sizes <= TRUNCATED_RESERVE,
        "reserve must cover the worst case: {sizes}"
    );
}

// ---- correlator ----

fn query_line(serial: usize, ip: &str, name: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq[1]: {serial} {ip}/5353 query[A] {name} from {ip}")
}

#[test]
fn pending_eviction_is_counted_not_silent() {
    let mut c = DnsCorrelator::default();
    for n in 0..1100usize {
        let ip = format!("10.0.{}.{}", n / 250, n % 250 + 1);
        let ev = parse_line(&query_line(n + 1, &ip, "a.example.com")).unwrap();
        c.feed(&ev, 5);
    }
    let counts = c.take_counts();
    assert_eq!(counts["dns_pending_evicted"], 1100 - 1024);
    assert!(c.take_counts().is_empty(), "counters are drained");
}

#[test]
fn one_client_flood_does_not_evict_other_clients_pending_queries() {
    let mut c = DnsCorrelator::default();
    let mut ip_to_mac = HashMap::new();
    for d in 0..50usize {
        let ip = format!("10.0.0.{}", d + 1);
        ip_to_mac.insert(ip.clone(), mac_n(d));
        for k in 0..5usize {
            let ev = parse_line(&query_line(d * 10 + k + 1, &ip, "ok.example.com")).unwrap();
            c.feed(&ev, 5);
        }
    }
    ip_to_mac.insert("10.0.9.9".into(), mac_n(9000));
    // 4000 queries (2 s of a 2000 q/s flood, i.e. one poll) from a single client.
    for k in 0..4000usize {
        let ev = parse_line(&query_line(10_000 + k, "10.0.9.9", "flood.example.com")).unwrap();
        c.feed(&ev, 5);
    }
    let counts = c.take_counts();
    let rows = c.take_ready(&ip_to_mac);
    let normal = rows.iter().filter(|r| r.mac != mac_n(9000)).count();
    assert_eq!(normal, 250, "no normal query lost");
    assert!(
        rows.len() <= 250 + 256,
        "flooder limited to its per-client share"
    );
    assert_eq!(counts["dns_client_throttled"], 4000 - 256);
    assert!(!counts.contains_key("dns_pending_evicted"));
}
