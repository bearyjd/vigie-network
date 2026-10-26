//! Fix round 5 for the DHCP option-order parser: any ACK of a MAC supersedes that MAC's held
//! blocks, one stray line (unparsed, or another process's) never costs a stored fingerprint or
//! publishes a block mid-list, and an age-out is recoverable by a fresh packet of the same MAC.
//! All data is synthetic (documentation ranges, locally administered MACs).

use vigie_agent::dnsmasq::{parse_line_pid, DhcpAssembler};
use vigie_agent::model::Lease;
use vigie_agent::window::Window;

const A: &str = "02:00:00:00:00:01";
const B: &str = "02:00:00:00:00:02";
const M: &str = "02:00:00:00:00:0e";
const FULL: [u8; 4] = [1, 3, 6, 15];

fn lp(pid: u32, rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[{pid}]: {rest}")
}
fn range(pid: u32, x: u32) -> String {
    lp(
        pid,
        &format!("{x} available DHCP range: 192.0.2.10 -- 192.0.2.50"),
    )
}
fn vendor(pid: u32, x: u32, v: &str) -> String {
    lp(pid, &format!("{x} vendor class: {v}"))
}
fn name(pid: u32, x: u32, v: &str) -> String {
    lp(pid, &format!("{x} client provides name: {v}"))
}
fn request(pid: u32, x: u32, ip: &str, mac: &str) -> String {
    lp(pid, &format!("{x} DHCPREQUEST(br-lan) {ip} {mac}"))
}
fn ack(pid: u32, x: u32, ip: &str, mac: &str, host: &str) -> String {
    lp(pid, &format!("{x} DHCPACK(br-lan) {ip} {mac} {host}"))
}
fn opts(pid: u32, x: u32, list: &str) -> String {
    lp(pid, &format!("{x} requested options: {list}"))
}
/// A line of a foreign process that no parser recognises.
fn noise() -> String {
    "Oct 20 14:00:00 dnsmasq[789]: 55 192.0.2.99/5353 reply x.test is NXDOMAIN".to_string()
}
fn feed(a: &mut DhcpAssembler, lines: &[String]) -> Vec<Lease> {
    let mut out = Vec::new();
    for s in lines {
        match parse_line_pid(s) {
            Some((pid, ev)) => out.extend(a.feed_pid(pid, &ev)),
            None => a.break_context(),
        }
    }
    out
}
fn close(a: &mut DhcpAssembler, out: &mut Vec<Lease>) {
    out.extend(a.end_poll());
    out.extend(a.end_poll());
}
type Fp = Vec<(Vec<u8>, Option<String>)>;
fn fp(v: &[Lease], mac: &str) -> Fp {
    v.iter()
        .filter(|l| l.mac == mac && (!l.opt55.is_empty() || l.opt60.is_some()))
        .map(|l| (l.opt55.clone(), l.opt60.clone()))
        .collect()
}
fn full_va() -> Fp {
    vec![(FULL.to_vec(), Some("VA".to_string()))]
}
fn clean_a(pid: u32, x: u32) -> Vec<String> {
    vec![
        range(pid, x),
        vendor(pid, x, "VA"),
        name(pid, x, "ha"),
        request(pid, x, "192.0.2.10", A),
        ack(pid, x, "192.0.2.10", A, "ha"),
        opts(pid, x, "1:netmask, 3:router"),
        opts(pid, x, "6:dns-server, 15:domain-name"),
    ]
}
/// The pair the window stores for A after a clean lease and then `renew` fed on top of it.
fn stored_after(renew: &[String]) -> (Vec<u8>, Option<String>) {
    let mut a = DhcpAssembler::default();
    let mut w = Window::default();
    let mut out = feed(&mut a, &clean_a(100, 1));
    close(&mut a, &mut out);
    for l in out {
        w.add_lease(l);
    }
    w.take();
    let mut out = feed(&mut a, renew);
    close(&mut a, &mut out);
    for l in out {
        w.add_lease(l);
    }
    let s = w.take();
    let l = s.leases.iter().find(|l| l.mac == A).cloned().unwrap();
    (l.opt55, l.opt60)
}

// ---- R5-4: any ACK of the same MAC supersedes its held blocks ----

fn held_a_block() -> Vec<String> {
    let mut lines = clean_a(100, 2);
    lines.push(request(200, 5, "192.0.2.20", M));
    lines.push(request(200, 5, "192.0.2.20", A));
    lines
}

#[test]
fn r5_unverified_newer_ack_of_the_same_mac_supersedes_the_held_block() {
    let mut lines = held_a_block();
    lines.push(ack(200, 5, "192.0.2.20", A, "ha"));
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    let last = out.iter().rfind(|l| l.mac == A).unwrap();
    assert_eq!(last.ip, "192.0.2.20", "{out:?}");
    assert!(fp(&out, A).is_empty(), "{out:?}");
    assert_eq!(a.take_counts().get("dhcp_block_superseded"), Some(&1));
}

#[test]
fn r5_unverified_ack_of_another_mac_supersedes_nothing() {
    let mut lines = clean_a(100, 2);
    lines.push(request(200, 5, "192.0.2.20", A));
    lines.push(request(200, 5, "192.0.2.20", B));
    lines.push(ack(200, 5, "192.0.2.20", B, "hb"));
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full_va(), "{out:?}");
    assert!(a.take_counts().is_empty());
}

#[test]
fn r5_unverified_ack_at_the_same_ip_of_another_mac_supersedes_nothing() {
    let mut lines = clean_a(100, 2);
    lines.push(request(200, 5, "192.0.2.10", A));
    lines.push(request(200, 5, "192.0.2.10", B));
    lines.push(ack(200, 5, "192.0.2.10", B, "hb"));
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full_va(), "{out:?}");
}

// ---- R5-10: one stray line never costs a stored fingerprint ----

#[test]
fn r5_one_unparsed_line_at_each_boundary_keeps_the_stored_pair() {
    for k in 0..=7 {
        let mut renew = clean_a(100, 2);
        renew.insert(k, noise());
        let (o, v) = stored_after(&renew);
        assert_eq!(
            (o, v.as_deref()),
            (FULL.to_vec(), Some("VA")),
            "noise at {k}"
        );
    }
}

#[test]
fn r5_other_pid_marker_inside_a_packet_keeps_the_stored_pair() {
    let mut renew = clean_a(100, 2);
    renew.insert(2, range(200, 9));
    let (o, v) = stored_after(&renew);
    assert_eq!((o, v.as_deref()), (FULL.to_vec(), Some("VA")));
}

#[test]
fn r5_other_pid_request_between_old_order_option_lines_keeps_the_whole_list() {
    let lines = vec![
        request(100, 2, "192.0.2.10", A),
        vendor(100, 2, "VA"),
        opts(100, 2, "1:netmask, 3:router"),
        request(200, 9, "192.0.2.11", B),
        opts(100, 2, "6:dns-server, 15:domain-name"),
        ack(100, 2, "192.0.2.10", A, "ha"),
    ];
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full_va(), "{out:?}");
}

#[test]
fn r5_an_unparsed_line_does_not_publish_a_block_mid_list() {
    let mut lines = clean_a(100, 2);
    lines.truncate(6); // first options line only
    lines.push(noise());
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &lines);
    assert!(fp(&out, A).is_empty(), "published mid-list: {out:?}");
    out.extend(feed(
        &mut a,
        &[opts(100, 2, "6:dns-server, 15:domain-name")],
    ));
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full_va(), "{out:?}");
}

#[test]
fn r5_a_foreign_pid_line_does_not_publish_a_block() {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &clean_a(100, 2));
    out.extend(feed(
        &mut a,
        &[lp(200, "9 next server: 192.0.2.1"), noise()],
    ));
    assert!(fp(&out, A).is_empty(), "{out:?}");
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full_va(), "{out:?}");
}

// ---- R5-5: stale (age-out) is recoverable, a foreign taint is not ----

fn aged_request(x: u32, mac: &str) -> (DhcpAssembler, Vec<Lease>) {
    let mut a = DhcpAssembler::default();
    let mut out = feed(
        &mut a,
        &[
            range(100, x),
            vendor(100, x, "VA"),
            request(100, x, "192.0.2.10", mac),
        ],
    );
    close(&mut a, &mut out);
    (a, out)
}

#[test]
fn r5_a_complete_retransmission_after_an_age_out_is_published() {
    let (mut a, mut out) = aged_request(3, A);
    out.extend(feed(&mut a, &clean_a(100, 3)));
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full_va(), "{out:?}");
}

#[test]
fn r5_a_retransmission_from_another_mac_after_an_age_out_is_denied() {
    let (mut a, mut out) = aged_request(3, B);
    out.extend(feed(&mut a, &clean_a(100, 3)));
    close(&mut a, &mut out);
    assert!(fp(&out, A).is_empty(), "{out:?}");
}

#[test]
fn r5_a_foreign_mac_taint_survives_a_later_marker_of_the_first_mac() {
    let mut a = DhcpAssembler::default();
    let mut out = feed(
        &mut a,
        &[
            request(100, 3, "192.0.2.10", B),
            request(100, 3, "192.0.2.10", M),
        ],
    );
    close(&mut a, &mut out);
    out.extend(feed(&mut a, &clean_a(100, 3)));
    close(&mut a, &mut out);
    assert!(fp(&out, A).is_empty(), "{out:?}");
}

#[test]
fn k38_aged_ctx_of_an_evicted_entry_leaves_a_tainted_stub() {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &[request(100, 1, "192.0.2.10", A)]);
    let rel: Vec<String> = (0..256)
        .map(|i| {
            lp(
                200,
                &format!("{} DHCPRELEASE(br-lan) 192.0.2.99 {M}", 1000 + i),
            )
        })
        .collect();
    out.extend(feed(&mut a, &rel));
    close(&mut a, &mut out);
    out.extend(feed(&mut a, &clean_a(100, 1)));
    close(&mut a, &mut out);
    assert!(fp(&out, A).is_empty(), "{out:?}");
}

// ---- per-pid slots are bounded: past the cap the oldest preamble goes stale ----

#[test]
fn r5_a_preamble_evicted_by_the_slot_cap_publishes_nothing_for_its_entry() {
    let mut a = DhcpAssembler::default();
    let mut lines = vec![range(100, 7), vendor(100, 7, "VA")];
    // Four more processes open a preamble: the fifth slot evicts pid 100's.
    lines.extend((1..=4).map(|i| range(200 + i, 9)));
    lines.extend([
        request(100, 7, "192.0.2.10", A),
        ack(100, 7, "192.0.2.10", A, "ha"),
        opts(100, 7, "1:netmask"),
    ]);
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    assert!(fp(&out, A).is_empty(), "{out:?}");
}
