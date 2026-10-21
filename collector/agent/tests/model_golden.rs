use std::collections::BTreeMap;

use vigie_agent::model::*;

fn meta() -> Meta {
    Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq: 7,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: 1_760_000_000,
        window_end: 1_760_000_060,
    }
}

#[test]
fn empty_batch_golden() {
    let e = encode(
        &meta(),
        &Sections::default(),
        &BTreeMap::new(),
        &Health::default(),
    );
    let body = String::from_utf8(e.body(1_760_000_061, 0)).unwrap();
    assert_eq!(
        body,
        concat!(
            r#"{"collector_id":"c1","key_id":"k1","boot_id":"boot1","seq":7,"#,
            r#""batch_id":"01927f3e-8a1b-7c2d-9e4f-0123456789ab","#,
            r#""window_start":1760000000,"window_end":1760000060,"truncated":{},"#,
            r#""leases":[],"neigh":[],"dns":[],"conntrack":[],"sightings":[],"#,
            r#""health":{"dns_log_quiet":false,"rss_kb":null,"spool_batches":null,"uptime_s":null},"#,
            r#""sent_ts":1760000061,"dropped_batches":0}"#
        )
    );
}

#[test]
fn full_batch_golden() {
    let mut s = Sections::default();
    s.leases.push(
        Lease::new(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.50",
            Some("Pixel \"8\""),
            &[1, 3, 6],
            Some("android-dhcp-14"),
        )
        .unwrap(),
    );
    s.neigh
        .push(Neighbor::new("fe80::1", "aa:bb:cc:dd:ee:01").unwrap());
    s.dns.push(
        DnsQuery::new(
            1_760_000_010,
            "aa:bb:cc:dd:ee:01",
            "example.com",
            "a",
            Some("93.184.216.34"),
        )
        .unwrap(),
    );
    s.conntrack.push(ConntrackSummary {
        mac: "aa:bb:cc:dd:ee:01".into(),
        dst_ip: None,
        dst_port: None,
        proto: Proto::Other,
        bytes_up: 5,
        bytes_down: 6,
        flows: 2,
    });
    s.sightings.push(
        Sighting::new(
            "aa:bb:cc:dd:ee:01",
            SightingKind::Mdns,
            Some("host.local"),
            None,
            None,
        )
        .unwrap(),
    );
    let mut t = BTreeMap::new();
    t.insert("dns".to_string(), 3u64);
    let h = Health {
        dns_log_quiet: true,
        rss_kb: Some(900),
        spool_batches: Some(1),
        uptime_s: Some(60),
    };
    let body = String::from_utf8(encode(&meta(), &s, &t, &h).body(1_760_000_061, 2)).unwrap();
    assert!(body.contains(r#""truncated":{"dns":3}"#), "{body}");
    assert!(body.contains(
        r#""leases":[{"mac":"aa:bb:cc:dd:ee:01","ip":"192.168.1.50","hostname":"Pixel \"8\"","opt55":[1,3,6],"opt60":"android-dhcp-14"}]"#
    ));
    assert!(
        body.contains(r#""neigh":[{"ip":"fe80::1","mac":"aa:bb:cc:dd:ee:01","family":"inet6"}]"#)
    );
    assert!(body.contains(r#""dns":[{"ts":1760000010,"mac":"aa:bb:cc:dd:ee:01","qname":"example.com","qtype":"A","answer_ip":"93.184.216.34"}]"#));
    assert!(body.contains(r#""conntrack":[{"mac":"aa:bb:cc:dd:ee:01","dst_ip":null,"dst_port":null,"proto":"other","bytes_up":5,"bytes_down":6,"flows":2}]"#));
    assert!(body.contains(r#""sightings":[{"mac":"aa:bb:cc:dd:ee:01","kind":"mdns","name":"host.local","service":null,"ua":null}]"#));
    assert!(body.ends_with(r#""health":{"dns_log_quiet":true,"rss_kb":900,"spool_batches":1,"uptime_s":60},"sent_ts":1760000061,"dropped_batches":2}"#));
}

#[test]
fn constructors_enforce_schema_limits() {
    assert!(Lease::new("zz", "1.2.3.4", None, &[], None).is_none());
    assert!(Lease::new("aa:bb:cc:dd:ee:01", "not-an-ip", None, &[], None).is_none());
    let l = Lease::new(
        "aa:bb:cc:dd:ee:01",
        "10.0.0.1",
        Some(&"h".repeat(400)),
        &[7; 100],
        Some("a\nb"),
    )
    .unwrap();
    assert_eq!(l.hostname.unwrap().chars().count(), 253);
    assert_eq!(l.opt55.len(), 64);
    assert_eq!(l.opt60.as_deref(), Some("a?b"));
    assert!(DnsQuery::new(1, "aa:bb:cc:dd:ee:01", "", "A", None).is_none());
    assert!(DnsQuery::new(1, "aa:bb:cc:dd:ee:01", "x", "A B", None).is_none());
    assert!(DnsQuery::new(1, "aa:bb:cc:dd:ee:01", "x", &"A".repeat(17), None).is_none());
    assert!(DnsQuery::new(MAX_EPOCH + 1, "aa:bb:cc:dd:ee:01", "x", "A", None).is_none());
    let d = DnsQuery::new(
        1,
        "aa:bb:cc:dd:ee:01",
        &"q".repeat(300),
        "AAAA",
        Some("bogus"),
    )
    .unwrap();
    assert_eq!(d.qname.len(), 253);
    assert_eq!(d.answer_ip, None);
}
