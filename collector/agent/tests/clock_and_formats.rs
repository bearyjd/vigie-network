//! Clock-jump safety (the router has no RTC) and two hedges on assumed dnsmasq formats.

use std::collections::HashMap;

use vigie_agent::builder::{build, BATCH_CAP};
use vigie_agent::dnsmasq::{parse_line, DhcpAssembler, DnsCorrelator};
use vigie_agent::model::*;
use vigie_agent::window::WindowClock;

const MAC: &str = "aa:bb:cc:dd:ee:01";

fn meta(start: u64, end: u64) -> Meta {
    Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq: 1,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: start,
        window_end: end,
    }
}

fn body(b: &vigie_agent::builder::Built, sent: u64) -> String {
    String::from_utf8(b.encoded.body(sent, 0)).unwrap()
}

#[test]
fn window_start_follows_the_monotonic_clock_across_a_wall_clock_jump() {
    let mut c = WindowClock::new(100);
    // 60 s of monotonic time elapsed, wall clock unremarkable.
    assert_eq!(c.start(1_760_000_060, 160), 1_760_000_000);
    // NTP jumps the wall clock forward 2 days while 90 s of monotonic time pass.
    let jumped = 1_760_000_000 + 172_800;
    assert_eq!(
        c.start(jumped, 190),
        jumped - 90,
        "start is 90 s before now, not 2 days"
    );
    c.mark_flush(190);
    assert_eq!(
        c.start(jumped + 5, 195),
        jumped,
        "a skipped (held) flush also restarts it"
    );
    assert_eq!(c.start(5, 1000), 0, "never underflows");
}

#[test]
fn dns_rows_outside_the_window_are_dropped_and_counted() {
    let now = 1_760_000_100;
    let q = |ts: u64| DnsQuery::new(ts, MAC, "x.test", "A", None).unwrap();
    let input = Sections {
        dns: vec![
            q(now - 100),
            q(now - 100 - 300),
            q(now - 100 - 301), // stale: read before a clock step
            q(now),
            q(now + 300),
            q(now + 301),
        ],
        ..Sections::default()
    };
    let b = build(&meta(now - 100, now), input, &Health::default(), BATCH_CAP);
    assert_eq!(body(&b, now).matches(r#""qtype":"A""#).count(), 4);
    assert_eq!(b.truncated.get("dns_out_of_window"), Some(&2));
    assert!(!b.truncated.contains_key("dns"));
}

#[test]
fn overlong_windows_are_clamped_to_24_hours() {
    let now = 1_760_200_000;
    let b = build(
        &meta(now - 200_000, now),
        Sections::default(),
        &Health::default(),
        BATCH_CAP,
    );
    let s = body(&b, now);
    assert!(
        s.contains(&format!(r#""window_start":{}"#, now - 86_400)),
        "{s}"
    );
    assert!(s.contains(&format!(r#""window_end":{now}"#)));
}

#[test]
fn split_requested_option_lines_accumulate() {
    let lines = [
        "Oct 20 14:00:00 dnsmasq-dhcp[5]: 77 DHCPREQUEST(br-lan) 192.168.1.50 c2:11:22:33:44:01",
        "Oct 20 14:00:00 dnsmasq-dhcp[5]: 77 requested options: 1:netmask, 3:router, 6:dns-server,",
        "Oct 20 14:00:00 dnsmasq-dhcp[5]: 77 requested options: 15:domain-name, 28:broadcast",
        "Oct 20 14:00:00 dnsmasq-dhcp[5]: 77 DHCPACK(br-lan) 192.168.1.50 c2:11:22:33:44:01 Pixel",
    ];
    let mut a = DhcpAssembler::default();
    let mut leases: Vec<_> = lines
        .iter()
        .filter_map(|l| parse_line(l))
        .flat_map(|e| a.feed(&e))
        .collect();
    leases.extend(a.break_context());
    let lease = leases.pop().unwrap();
    assert_eq!(lease.opt55, vec![1, 3, 6, 15, 28]);
}

#[test]
fn scoped_ipv6_clients_are_attributed() {
    let mut c = DnsCorrelator::default();
    for l in [
        "Oct 20 14:00:04 dnsmasq[1]: 4 fe80::1c2d:3e4f:5a6b:7c8d%br-lan/51515 query[A] x.test from fe80::1c2d:3e4f:5a6b:7c8d%br-lan",
        "Oct 20 14:00:04 dnsmasq[1]: 4 fe80::1c2d:3e4f:5a6b:7c8d%br-lan/51515 reply x.test is 198.51.100.7",
    ] {
        c.feed(&parse_line(l).expect(l), 9);
    }
    let mut map = HashMap::new();
    map.insert("fe80::1c2d:3e4f:5a6b:7c8d".to_string(), MAC.to_string());
    let q = c.take_ready(&map);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].answer_ip.as_deref(), Some("198.51.100.7"));
}
