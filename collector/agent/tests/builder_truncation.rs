use vigie_agent::builder::{build, BATCH_CAP};
use vigie_agent::model::*;

const MAC: &str = "aa:bb:cc:dd:ee:01";

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

fn mac_n(n: usize) -> String {
    format!("02:00:00:00:{:02x}:{:02x}", (n >> 8) & 0xff, n & 0xff)
}

fn lease(n: usize, host_len: usize) -> Lease {
    Lease::new(
        &mac_n(n),
        &format!("10.{}.{}.1", (n >> 8) & 255, n & 255),
        Some(&"h".repeat(host_len)),
        &[1, 3, 6],
        Some("vendor"),
    )
    .unwrap()
}

fn dns(n: usize, name_len: usize) -> DnsQuery {
    let name = format!("{}{}.example.com", "d".repeat(name_len), n);
    DnsQuery::new(1_760_000_010, MAC, &name, "A", Some("1.2.3.4")).unwrap()
}

fn ct(mac: &str, port: u16, bytes: u64) -> ConntrackSummary {
    ConntrackSummary {
        mac: mac.into(),
        dst_ip: Some(format!("203.0.{}.{}", port >> 8, port & 255)),
        dst_port: Some(port),
        proto: Proto::Tcp,
        bytes_up: bytes,
        bytes_down: bytes,
        flows: 1,
    }
}

fn body(b: &vigie_agent::builder::Built) -> String {
    String::from_utf8(b.encoded.body(1_760_000_061, 0)).unwrap()
}

#[test]
fn small_batch_passes_through_untouched() {
    let input = Sections {
        leases: vec![lease(1, 5)],
        neigh: vec![Neighbor::new("10.0.0.1", MAC).unwrap()],
        dns: vec![dns(1, 3)],
        conntrack: vec![ct(MAC, 443, 10)],
        sightings: vec![],
    };
    let b = build(&meta(), input, &Health::default(), BATCH_CAP);
    assert!(b.truncated.is_empty());
    let s = body(&b);
    assert!(s.contains(r#""truncated":{}"#));
    assert!(s.contains(r#""dst_port":443"#));
    assert!(s.contains("1.example.com"));
}

#[test]
fn dns_flood_keeps_identity_and_conntrack_evidence() {
    let input = Sections {
        leases: (0..50).map(|n| lease(n, 20)).collect(),
        neigh: vec![Neighbor::new("10.0.0.1", MAC).unwrap()],
        dns: (0..5000).map(|n| dns(n, 80)).collect(),
        conntrack: (0..100u16).map(|p| ct(MAC, p + 1, 1000)).collect(),
        sightings: vec![],
    };
    let b = build(&meta(), input, &Health::default(), BATCH_CAP);
    let s = body(&b);
    assert!(s.len() <= BATCH_CAP, "{}", s.len());
    assert_eq!(s.matches(r#""vendor""#).count(), 50, "leases kept");
    assert_eq!(s.matches(r#""dst_port":"#).count(), 100, "conntrack kept");
    let dropped = *b.truncated.get("dns").expect("dns truncated");
    assert!(dropped > 0 && dropped < 5000);
    assert_eq!(s.matches(r#""qtype":"A""#).count() as u64, 5000 - dropped);
    assert!(s.contains(&format!(r#""truncated":{{"dns":{dropped}}}"#)));
}

#[test]
fn lease_flood_cannot_evict_dns() {
    let input = Sections {
        leases: (0..1000).map(|n| lease(n, 250)).collect(),
        dns: (0..200).map(|n| dns(n, 10)).collect(),
        ..Sections::default()
    };
    let b = build(&meta(), input, &Health::default(), BATCH_CAP);
    let s = body(&b);
    assert!(s.len() <= BATCH_CAP);
    assert!(b.truncated.get("leases").copied().unwrap_or(0) > 0);
    assert_eq!(
        s.matches(r#""qtype":"A""#).count(),
        200,
        "dns survives a lease flood"
    );
    assert!(!b.truncated.contains_key("dns"));
}

#[test]
fn conntrack_flood_keeps_top_by_bytes_and_folds_rest_per_mac() {
    let macs = [mac_n(1), mac_n(2), mac_n(3)];
    let mut rows = Vec::new();
    for i in 0..20_000u32 {
        let port = (i % 60_000) as u16;
        // Port 4242 on mac 0 is the single biggest talker.
        let bytes = if i == 777 {
            10_000_000
        } else {
            1 + u64::from(i % 97)
        };
        let mut r = ct(&macs[(i % 3) as usize], port, bytes);
        r.dst_ip = Some(format!("198.51.{}.{}", (i >> 8) & 255, i & 255));
        if i == 777 {
            r.dst_port = Some(4242);
        }
        rows.push(r);
    }
    let total_bytes: u64 = rows.iter().map(|r| r.total_bytes()).sum();
    let total_flows: u64 = rows.iter().map(|r| r.flows).sum();
    let input = Sections {
        conntrack: rows,
        ..Sections::default()
    };
    let b = build(&meta(), input, &Health::default(), BATCH_CAP);
    let s = body(&b);
    assert!(s.len() <= BATCH_CAP, "{}", s.len());
    assert!(s.contains(r#""dst_port":4242"#), "top talker kept");
    let others = s.matches(r#""proto":"other""#).count();
    assert_eq!(others, 3, "one other bucket per MAC");
    let folded = *b.truncated.get("conntrack").unwrap();
    assert!(folded > 0);
    // Totals are conserved: parse the numbers back out of the body.
    let mut bytes = 0u64;
    let mut flows = 0u64;
    for part in s.split(r#""bytes_up":"#).skip(1) {
        let up: u64 = part.split(',').next().unwrap().parse().unwrap();
        let down: u64 = part
            .split(r#""bytes_down":"#)
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let fl: u64 = part
            .split(r#""flows":"#)
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        bytes += up + down;
        flows += fl;
    }
    assert_eq!(bytes, total_bytes);
    assert_eq!(flows, total_flows);
    let kept = s.matches(r#""dst_port":"#).count() as u64 - others as u64;
    assert_eq!(kept + folded, 20_000);
}

#[test]
fn schema_array_hard_caps_are_counted() {
    let input = Sections {
        dns: (0..5200).map(|n| dns(n, 0)).collect(),
        ..Sections::default()
    };
    let b = build(&meta(), input, &Health::default(), 4 * BATCH_CAP);
    assert_eq!(body(&b).matches(r#""qtype":"A""#).count(), 5000);
    assert_eq!(b.truncated.get("dns"), Some(&200));
}

#[test]
fn truncation_priority_is_identity_then_dns_then_conntrack() {
    // Everything fits except conntrack: only conntrack is squeezed (folded), identity and DNS
    // are intact.
    let input = Sections {
        leases: (0..10).map(|n| lease(n, 10)).collect(),
        dns: (0..200).map(|n| dns(n, 10)).collect(),
        conntrack: (0..4000u32)
            .map(|i| {
                let mut r = ct(MAC, (i % 60000) as u16, u64::from(i) + 1);
                r.dst_ip = Some(format!("198.51.{}.{}", (i >> 8) & 255, i & 255));
                r
            })
            .collect(),
        ..Sections::default()
    };
    let b = build(&meta(), input, &Health::default(), BATCH_CAP);
    assert!(body(&b).len() <= BATCH_CAP);
    assert!(b.truncated.contains_key("conntrack"), "{:?}", b.truncated);
    assert!(!b.truncated.contains_key("dns"));
    assert!(!b.truncated.contains_key("leases"));
}

#[test]
fn conntrack_keeps_its_reserve_when_dns_floods() {
    let input = Sections {
        dns: (0..5000).map(|n| dns(n, 100)).collect(),
        conntrack: (0..3000u32)
            .map(|i| {
                let mut r = ct(MAC, (i % 60000) as u16, u64::from(i) + 1);
                r.dst_ip = Some(format!("198.51.{}.{}", (i >> 8) & 255, i & 255));
                r
            })
            .collect(),
        ..Sections::default()
    };
    let b = build(&meta(), input, &Health::default(), BATCH_CAP);
    let s = body(&b);
    assert!(s.len() <= BATCH_CAP);
    assert!(b.truncated.contains_key("dns") && b.truncated.contains_key("conntrack"));
    // At least 48 KiB worth of verbatim conntrack rows survive (rows are ~130 bytes each).
    assert!(s.matches(r#""dst_port":"#).count() > 300);
}

#[test]
fn a_surviving_verbatim_other_row_is_merged_with_the_folded_bucket() {
    let m = mac_n(1);
    let mut rows = Vec::new();
    // The MAC's own accumulator `other` row is huge, so it stays verbatim in the top-k.
    rows.push(ConntrackSummary {
        mac: m.clone(),
        dst_ip: None,
        dst_port: None,
        proto: Proto::Other,
        bytes_up: 1_000_000,
        bytes_down: 1_000_000,
        flows: 7,
    });
    // Enough small detail rows of the same MAC to force folding.
    for i in 0..6000u32 {
        let mut r = ct(&m, (i % 60_000) as u16, 1);
        r.dst_ip = Some(format!("198.51.{}.{}", (i >> 8) & 255, i & 255));
        rows.push(r);
    }
    let total_bytes: u64 = rows.iter().map(|r| r.total_bytes()).sum();
    let total_flows: u64 = rows.iter().map(|r| r.flows).sum();
    let input = Sections {
        conntrack: rows,
        ..Sections::default()
    };
    let b = build(&meta(), input, &Health::default(), BATCH_CAP);
    let v: serde_json::Value = serde_json::from_str(&body(&b)).unwrap();
    let ct_rows = v["conntrack"].as_array().unwrap();
    let others = ct_rows
        .iter()
        .filter(|r| r["dst_ip"].is_null() && r["mac"] == m.as_str())
        .count();
    assert_eq!(others, 1, "one other row per MAC, not two");
    let sum = |k: &str| ct_rows.iter().map(|r| r[k].as_u64().unwrap()).sum::<u64>();
    assert_eq!(sum("bytes_up") + sum("bytes_down"), total_bytes);
    assert_eq!(sum("flows"), total_flows);
}
