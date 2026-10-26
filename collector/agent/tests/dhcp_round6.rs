//! Fix round 6 for the DHCP option-order parser: a context that collected options and is then
//! displaced by anything that does not continue it makes its entry stale (no truncated list is
//! ever published, the stored pair stays); a repeated packet-start marker and an unparsed line
//! before any option was collected cost nothing. All data is synthetic.

use vigie_agent::dnsmasq::{parse_line_pid, DhcpAssembler};
use vigie_agent::model::Lease;
use vigie_agent::window::Window;

const A: &str = "02:00:00:00:00:01";
const B: &str = "02:00:00:00:00:02";
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
fn tags(pid: u32, x: u32) -> String {
    lp(pid, &format!("{x} tags: br-lan"))
}
fn fwd(pid: u32) -> String {
    format!("Oct 20 14:00:00 dnsmasq[{pid}]: forwarded x.test to 192.0.2.1")
}
fn query(pid: u32) -> String {
    format!("Oct 20 14:00:00 dnsmasq[{pid}]: 55 192.0.2.99/5353 query[A] x.test from 192.0.2.99")
}
fn offer(pid: u32) -> String {
    lp(pid, "9 DHCPOFFER(br-lan) 192.0.2.30 02:00:00:00:00:09")
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
fn run(lines: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, lines);
    close(&mut a, &mut out);
    out
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
fn pre_a(pid: u32, x: u32) -> Vec<String> {
    vec![
        range(pid, x),
        vendor(pid, x, "VA"),
        name(pid, x, "ha"),
        request(pid, x, "192.0.2.10", A),
    ]
}
fn post_a(pid: u32, x: u32) -> Vec<String> {
    vec![
        tags(pid, x),
        ack(pid, x, "192.0.2.10", A, "ha"),
        opts(pid, x, "1:netmask, 3:router"),
        opts(pid, x, "6:dns-server, 15:domain-name"),
    ]
}
/// The pair the window stores for A after a clean lease and then `renew` fed on top of it.
fn stored_after(renew: &[String]) -> (Vec<u8>, Option<String>) {
    let mut a = DhcpAssembler::default();
    let mut w = Window::default();
    let mut clean = pre_a(100, 1);
    clean.extend(post_a(100, 1));
    let mut out = feed(&mut a, &clean);
    close(&mut a, &mut out);
    out.into_iter().for_each(|l| w.add_lease(l));
    w.take();
    let mut out = feed(&mut a, renew);
    close(&mut a, &mut out);
    out.into_iter().for_each(|l| w.add_lease(l));
    let l = w.take().leases.into_iter().find(|l| l.mac == A).unwrap();
    (l.opt55, l.opt60)
}
fn stored_full() -> (Vec<u8>, Option<String>) {
    (FULL.to_vec(), Some("VA".into()))
}

// ---- CODEX-1: another packet's marker displaces a context that collected options ----

fn codex1_log() -> Vec<String> {
    vec![
        request(100, 1, "192.0.2.10", A),
        vendor(100, 1, "VA"),
        opts(100, 1, "1:netmask, 3:router"),
        range(100, 2),
        request(100, 2, "192.0.2.11", B),
        opts(100, 1, "6:dns-server, 15:domain-name"),
        ack(100, 1, "192.0.2.10", A, "ha"),
    ]
}

#[test]
fn r6_codex1_displaced_context_publishes_no_truncated_list() {
    let out = run(&codex1_log());
    assert!(fp(&out, A).is_empty(), "{:?}", fp(&out, A));
}

#[test]
fn r6_codex1_stored_complete_pair_is_not_replaced() {
    assert_eq!(stored_after(&codex1_log()), stored_full());
}

// ---- OPUS-L2: any same-process line that does not continue the context stales it ----

#[test]
fn r6_l2_same_pid_query_or_offer_between_option_lines_publishes_nothing() {
    for mid in [query(100), offer(100)] {
        let mut l = pre_a(100, 7);
        l.push(opts(100, 7, "1:netmask, 3:router"));
        l.push(mid.clone());
        l.push(opts(100, 7, "6:dns-server, 15:domain-name"));
        l.push(ack(100, 7, "192.0.2.10", A, "ha"));
        assert!(fp(&run(&l), A).is_empty(), "{mid}");
        assert_eq!(stored_after(&l[..]), stored_full(), "{mid}");
    }
}

#[test]
fn r6_old_order_matching_ack_still_publishes_the_whole_list() {
    let mut l = pre_a(100, 7);
    l.push(opts(100, 7, "1:netmask, 3:router"));
    l.push(opts(100, 7, "6:dns-server, 15:domain-name"));
    l.push(ack(100, 7, "192.0.2.10", A, "ha"));
    assert_eq!(fp(&run(&l), A), full_va());
}

// ---- OPUS-M1: a repeated marker before vendor/name replaces the preamble ----

#[test]
fn r6_m1_two_range_lines_for_one_xid_keep_the_fingerprint() {
    let mut l = vec![range(100, 7)];
    l.extend(pre_a(100, 7));
    l.extend(post_a(100, 7));
    assert_eq!(fp(&run(&l), A), full_va(), "{l:?}");
}

#[test]
fn r6_m1_marker_after_vendor_still_drops_the_preamble() {
    let mut l = vec![range(100, 7), vendor(100, 7, "EVIL"), range(100, 7)];
    l.extend(pre_a(100, 7));
    l.extend(post_a(100, 7));
    assert!(fp(&run(&l), A)
        .iter()
        .all(|f| f.1.as_deref() != Some("EVIL")));
}

// ---- OPUS-M2: an unparsed line costs only contexts that collected options ----

#[test]
fn r6_m2_unparsed_line_between_request_and_ack_keeps_the_fingerprint() {
    let mut l = pre_a(100, 7);
    l.push(fwd(999));
    l.extend(post_a(100, 7));
    assert_eq!(fp(&run(&l), A), full_va(), "{l:?}");
}

#[test]
fn r6_m2_old_order_unparsed_line_before_options_ends_vendor_only() {
    let mut l = pre_a(100, 7);
    l.push(fwd(999));
    l.push(opts(100, 7, "1:netmask, 3:router"));
    l.push(opts(100, 7, "6:dns-server, 15:domain-name"));
    l.push(ack(100, 7, "192.0.2.10", A, "ha"));
    let f = fp(&run(&l), A);
    assert!(f.iter().all(|x| x.0.is_empty()), "no truncated list: {f:?}");
    assert_eq!(stored_after(&l), stored_full());
}

#[test]
fn r6_m2_unparsed_line_between_option_lines_publishes_nothing() {
    let mut l = pre_a(100, 7);
    l.push(opts(100, 7, "1:netmask, 3:router"));
    l.push(fwd(999));
    l.push(opts(100, 7, "6:dns-server, 15:domain-name"));
    l.push(ack(100, 7, "192.0.2.10", A, "ha"));
    assert!(fp(&run(&l), A).is_empty());
}

// ---- OPUS-L1: killers for the stale-entry and cap-eviction rules ----

#[test]
fn k_n18_stale_entry_publishes_no_old_order_options() {
    let mut l = pre_a(100, 7);
    l.push(opts(100, 7, "1:netmask, 3:router"));
    l.push(fwd(999));
    l.push(opts(100, 7, "6:dns-server, 15:domain-name"));
    l.push(ack(100, 7, "192.0.2.10", A, "ha"));
    assert!(fp(&run(&l), A).is_empty());
}

#[test]
fn k_n22_evicted_ctx_publishes_no_truncated_list() {
    let mut l = pre_a(1, 7);
    l.push(opts(1, 7, "1:netmask, 3:router"));
    for p in 2..=5u32 {
        l.push(request(p, 7, &format!("192.0.2.{}", 20 + p), B));
    }
    l.push(opts(1, 7, "6:dns-server, 15:domain-name"));
    l.push(ack(1, 7, "192.0.2.10", A, "ha"));
    assert!(fp(&run(&l), A).is_empty(), "{:?}", fp(&run(&l), A));
}

// ---- Codex re-check: options retained across a repeated same-key REQUEST ----

fn repeated_request_log(mid: String) -> Vec<String> {
    vec![
        request(123, 1, "192.0.2.10", A),
        vendor(123, 1, "VA"),
        opts(123, 1, "1:netmask, 3:router"),
        request(123, 1, "192.0.2.10", A),
        mid,
        opts(123, 1, "6:dns-server, 15:domain-name"),
        ack(123, 1, "192.0.2.10", A, "ha"),
    ]
}

#[test]
fn r6_repeated_request_keeps_the_retained_prefix_unpublished_after_an_unparsed_line() {
    let out = run(&repeated_request_log(fwd(999)));
    assert!(fp(&out, A).is_empty(), "{:?}", fp(&out, A));
}

#[test]
fn r6_repeated_request_keeps_the_retained_prefix_unpublished_after_a_query() {
    let out = run(&repeated_request_log(query(123)));
    assert!(fp(&out, A).is_empty(), "{:?}", fp(&out, A));
}

#[test]
fn r6_repeated_request_without_interruption_replaces_the_retained_list() {
    let mut l = repeated_request_log(opts(123, 1, "1:netmask, 3:router"));
    l.retain(|s| !s.contains("tags"));
    assert_eq!(fp(&run(&l), A), full_va());
}
