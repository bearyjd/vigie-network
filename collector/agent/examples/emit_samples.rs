#![allow(clippy::field_reassign_with_default)]
//! Emits signed request samples (one JSON object per line) produced through the real batch
//! builder and send engine, for the Python cross-check in tests/vectors/test_rust_batches.py.
//! Key: bytes 0..32 (hex 000102...1f). Not part of the shipped binary.

use std::collections::BTreeMap;

use vigie_agent::builder::{build, build_with_drops, BATCH_CAP};
use vigie_agent::ids;
use vigie_agent::model::*;
use vigie_agent::sender::*;
use vigie_agent::sign::hex;

const NOW: u64 = 1_792_533_600;
const MAC: &str = "aa:bb:cc:dd:ee:01";

struct Capture(Vec<(Headers, Vec<u8>)>);

impl Transport for Capture {
    fn post(&mut self, h: &Headers, body: &[u8]) -> Result<HttpReply, TransportError> {
        self.0.push((h.clone(), body.to_vec()));
        Ok(HttpReply {
            status: 200,
            date: None,
            body: b"{}".to_vec(),
        })
    }
}

fn meta(seq: u64) -> Meta {
    Meta {
        collector_id: "router-1".into(),
        key_id: "k2026-10".into(),
        boot_id: "0123456789abcdef".into(),
        seq,
        batch_id: ids::uuid7(NOW * 1000 + seq, [seq as u8; 10]),
        window_start: NOW - 60,
        window_end: NOW,
    }
}

fn mac_n(n: usize) -> String {
    format!("02:00:00:00:{:02x}:{:02x}", (n >> 8) & 0xff, n & 0xff)
}

fn main() {
    let key: Vec<u8> = (0u8..32).collect();
    let mut cases: Vec<(&str, Meta, Sections, Health)> = Vec::new();

    cases.push(("empty", meta(1), Sections::default(), Health::default()));

    let hostile = "ho\"st\\name\n\t\u{0}\u{7f} caf\u{e9} \u{65e5}\u{672c} \u{1f600} \u{202e}rtl";
    let mut s = Sections::default();
    s.leases.push(
        Lease::new(
            MAC,
            "192.168.1.50",
            Some(hostile),
            &[1, 3, 6, 255, 0],
            Some(hostile),
        )
        .unwrap(),
    );
    s.neigh
        .push(Neighbor::new("2001:DB8::5", "AA-BB-CC-DD-EE-01").unwrap());
    s.dns.push(
        DnsQuery::new(NOW - 5, MAC, "xn--caf-dma.example", "type=65", Some("::1")).unwrap_or_else(
            || DnsQuery::new(NOW - 5, MAC, "xn--caf-dma.example", "TYPE65", Some("::1")).unwrap(),
        ),
    );
    s.sightings.push(
        Sighting::new(
            MAC,
            SightingKind::Ssdp,
            Some(hostile),
            Some(&"s".repeat(400)),
            None,
        )
        .unwrap(),
    );
    s.conntrack.push(ConntrackSummary {
        mac: MAC.into(),
        dst_ip: Some("203.0.113.9".into()),
        dst_port: Some(65535),
        proto: Proto::Icmpv6,
        bytes_up: u64::MAX,
        bytes_down: 0,
        flows: 1,
    });
    cases.push((
        "hostile strings and boundaries",
        meta(2),
        s,
        Health {
            dns_log_quiet: true,
            rss_kb: Some(900),
            spool_batches: Some(0),
            uptime_s: Some(1),
        },
    ));

    let mut flood = Sections::default();
    flood.leases = (0..1500)
        .map(|n| {
            Lease::new(
                &mac_n(n),
                "10.0.0.1",
                Some(&"h".repeat(250)),
                &[1; 64],
                Some(&"v".repeat(250)),
            )
            .unwrap()
        })
        .collect();
    flood.neigh = (0..2500)
        .map(|n| Neighbor::new(&format!("10.1.{}.{}", n >> 8, n & 255), &mac_n(n)).unwrap())
        .collect();
    flood.dns = (0..6000)
        .map(|n| {
            DnsQuery::new(
                NOW - 10,
                &mac_n(n % 50),
                &format!("{}{n}.flood.example", "d".repeat(100)),
                "A",
                Some("1.2.3.4"),
            )
            .unwrap()
        })
        .collect();
    flood.conntrack = (0..30_000u32)
        .map(|i| ConntrackSummary {
            mac: mac_n((i % 40) as usize),
            dst_ip: Some(format!("198.51.{}.{}", (i >> 8) & 255, i & 255)),
            dst_port: Some((i % 65536) as u16),
            proto: Proto::Tcp,
            bytes_up: u64::from(i),
            bytes_down: u64::from(i) * 3,
            flows: 1,
        })
        .collect();
    flood.sightings = (0..1200)
        .map(|n| {
            Sighting::new(
                &mac_n(n),
                SightingKind::Mdns,
                Some(&"n".repeat(250)),
                Some("_x._tcp.local"),
                None,
            )
            .unwrap()
        })
        .collect();
    cases.push(("flood truncated", meta(3), flood, Health::default()));

    cases.push((
        "seq int64 max",
        meta((1u64 << 63) - 1),
        Sections::default(),
        Health::default(),
    ));

    let id = Identity {
        collector_id: "router-1".into(),
        key_id: "k2026-10".into(),
        boot_id: "0123456789abcdef".into(),
    };
    let mut engine = Engine::new(id, key, 1_700_000_000, 4 * BATCH_CAP);
    let mut names = Vec::new();
    for (name, m, sections, health) in cases {
        let b = build(&m, sections, &health, BATCH_CAP);
        names.push((name, b.truncated.clone()));
        engine.enqueue(b.encoded);
    }
    // Every flood/clock drop counter at its maximum: keys and sizes must satisfy the server schema.
    let drops: BTreeMap<String, u64> = [
        "dns_quota_dropped",
        "dns_dropped",
        "sightings_dropped",
        "dns_pending_evicted",
        "dns_client_throttled",
    ]
    .iter()
    .map(|k| (k.to_string(), i64::MAX as u64))
    .collect();
    let b = build_with_drops(
        &meta(4),
        Sections::default(),
        &Health::default(),
        BATCH_CAP,
        &drops,
    );
    names.push(("all drop counters", b.truncated.clone()));
    engine.enqueue(b.encoded);
    engine.spool.note_dropped(2);
    let mut cap = Capture(Vec::new());
    for i in 0..names.len() {
        let t = engine.tick(&mut cap, NOW + 1, i as u64, 1);
        assert!(matches!(t, Tick::Sent { .. }), "{t:?}");
    }
    for ((name, trunc), (h, body)) in names.iter().zip(&cap.0) {
        let t: BTreeMap<_, _> = trunc.iter().collect();
        println!(
            "{{\"name\":{:?},\"truncated\":{:?},\"headers\":{{{}}},\"body_hex\":\"{}\"}}",
            name,
            format!("{t:?}"),
            h.pairs()
                .iter()
                .map(|(k, v)| format!("{k:?}:{v:?}"))
                .collect::<Vec<_>>()
                .join(","),
            hex(body)
        );
    }
}
