//! Fix round 2 for the DHCP option-order parser: lines of another dnsmasq process never end a
//! held block, the wrong-MAC scenarios stay safe, and the guards that earlier mutants slipped past.
//! All data is synthetic (documentation ranges, locally administered MACs).

use vigie_agent::dnsmasq::{parse_line_pid, DhcpAssembler};
use vigie_agent::model::Lease;

const A: &str = "02:00:00:00:00:01";
const B: &str = "02:00:00:00:00:02";

fn lp(pid: u32, rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[{pid}]: {rest}")
}
fn head(pid: u32, x: u32, mac: &str, v: &str) -> Vec<String> {
    vec![
        lp(
            pid,
            &format!("{x} available DHCP range: 192.0.2.10 -- 192.0.2.50"),
        ),
        lp(pid, &format!("{x} vendor class: {v}")),
        lp(pid, &format!("{x} DHCPREQUEST(br-lan) 192.0.2.10 {mac}")),
        lp(pid, &format!("{x} DHCPACK(br-lan) 192.0.2.10 {mac}")),
    ]
}
fn opts(pid: u32, x: u32, list: &str) -> String {
    lp(pid, &format!("{x} requested options: {list}"))
}
fn tags(pid: u32, x: u32) -> String {
    lp(pid, &format!("{x} tags: br-lan"))
}
fn dns_query(pid: u32) -> String {
    lp(
        pid,
        "9 192.0.2.99/5353 query[A] example.test from 192.0.2.99",
    )
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
/// One stream, then the stream ends and the block is closed by two polls and a break.
fn run(lines: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, lines);
    out.extend(a.end_poll());
    out.extend(a.end_poll());
    out
}
/// The option lists of the leases that carry a fingerprint.
fn fps(v: &[Lease]) -> Vec<Vec<u8>> {
    v.iter()
        .filter(|l| !l.opt55.is_empty())
        .map(|l| l.opt55.clone())
        .collect()
}
fn lease_of(all: &[Lease], mac: &str) -> Lease {
    all.iter()
        .rev()
        .find(|x| x.mac == mac)
        .cloned()
        .expect("lease")
}

// ---- M2: another process' lines pass through the held block ----

#[test]
fn a_line_of_another_pid_between_option_lines_does_not_truncate_the_list() {
    let mut lines = head(100, 7, A, "v");
    lines.push(opts(100, 7, "1:netmask, 3:router"));
    lines.push(dns_query(200));
    lines.push(opts(100, 7, "6:dns-server, 15:domain-name"));
    assert_eq!(fps(&run(&lines)), vec![vec![1, 3, 6, 15]]);
}

#[test]
fn a_line_of_another_pid_between_ack_and_options_keeps_the_block() {
    let mut lines = head(100, 7, A, "v");
    lines.push(dns_query(200));
    lines.push(opts(100, 7, "1:netmask, 3:router"));
    let got = run(&lines);
    assert_eq!(fps(&got), vec![vec![1, 3]]);
    assert_eq!(lease_of(&got, A).opt60.as_deref(), Some("v"));
}

#[test]
fn a_line_of_another_pid_inside_the_preamble_keeps_vendor_and_name() {
    let lines = vec![
        lp(100, "7 available DHCP range: 192.0.2.10 -- 192.0.2.50"),
        lp(100, "7 vendor class: v"),
        dns_query(200),
        lp(100, &format!("7 DHCPREQUEST(br-lan) 192.0.2.10 {A}")),
        lp(100, &format!("7 DHCPACK(br-lan) 192.0.2.10 {A}")),
        opts(100, 7, "1:netmask"),
    ];
    assert_eq!(lease_of(&run(&lines), A).opt60.as_deref(), Some("v"));
}

#[test]
fn a_line_of_another_pid_inside_the_old_order_context_keeps_the_attach() {
    let lines = vec![
        lp(100, &format!("7 DHCPREQUEST(br-lan) 192.0.2.10 {A}")),
        dns_query(200),
        opts(100, 7, "1:netmask, 3:router"),
        lp(100, &format!("7 DHCPACK(br-lan) 192.0.2.10 {A}")),
    ];
    assert_eq!(lease_of(&run(&lines), A).opt55, vec![1, 3]);
}

#[test]
fn a_held_block_of_another_pid_is_still_closed_by_the_second_poll() {
    let mut a = DhcpAssembler::default();
    let mut lines = head(100, 7, A, "v");
    lines.push(opts(100, 7, "1:netmask, 3:router"));
    lines.push(dns_query(200));
    let mut out = feed(&mut a, &lines);
    assert!(a.end_poll().is_empty());
    out.extend(a.end_poll());
    assert_eq!(fps(&out), vec![vec![1, 3]]);
}

#[test]
fn an_ack_of_another_pid_never_hands_its_options_to_the_held_block() {
    // Same serial in two processes: nothing of one may reach the other.
    let mut lines = head(100, 7, A, "vend-a");
    lines.extend(head(200, 7, B, "vend-b"));
    lines.push(opts(100, 7, "3:router"));
    let got = run(&lines);
    let b = lease_of(&got, B);
    assert!(
        !b.opt55.contains(&3) && b.opt60.as_deref() != Some("vend-a"),
        "{b:?}"
    );
}

// ---- wrong-MAC safety (reviewer scenarios W1-W6) ----

fn check(out: &[Lease]) {
    for l in out {
        if l.mac == A {
            assert!(
                !l.opt55.contains(&42) && l.opt60.as_deref() != Some("vend-b"),
                "{l:?}"
            );
        }
        if l.mac == B {
            assert!(
                !l.opt55.contains(&3) && l.opt60.as_deref() != Some("vend-a"),
                "{l:?}"
            );
        }
    }
}

#[test]
fn w1_ack_a_ack_b_then_a_options() {
    let mut v = head(1, 10, A, "vend-a");
    v.extend(head(1, 11, B, "vend-b"));
    v.push(opts(1, 10, "3:router"));
    check(&run(&v));
}

#[test]
fn w2_b_reuses_the_serial_of_a_after_the_ack() {
    let mut v = head(1, 10, A, "vend-a");
    v.extend(head(1, 10, B, "vend-b"));
    v.push(opts(1, 10, "42:x"));
    check(&run(&v));
}

#[test]
fn w2b_b_request_on_the_serial_then_options_then_a_ack() {
    let mut v = head(1, 10, A, "vend-a");
    v.push(lp(1, &format!("10 DHCPREQUEST(br-lan) 192.0.2.10 {B}")));
    v.push(opts(1, 10, "42:x"));
    v.push(lp(1, &format!("10 DHCPACK(br-lan) 192.0.2.10 {A}")));
    v.push(opts(1, 10, "42:x"));
    check(&run(&v));
}

#[test]
fn w3_a_non_lease_verb_between_ack_and_options() {
    for verb in [
        "DHCPNAK(br-lan) 192.0.2.10",
        "DHCPRELEASE(br-lan) 192.0.2.10 02:00:00:00:00:02",
        "DHCPINFORM(br-lan) 192.0.2.10 02:00:00:00:00:02",
        "DHCPDECLINE(br-lan) 192.0.2.10 02:00:00:00:00:02",
    ] {
        let mut v = head(1, 10, A, "vend-a");
        v.push(lp(1, &format!("10 {verb}")));
        v.push(opts(1, 10, "42:x"));
        let got = run(&v);
        check(&got);
        assert!(fps(&got).is_empty(), "{verb}: {got:?}");
    }
}

#[test]
fn w4_a_tainted_ack_while_a_block_is_open() {
    let mut v = head(1, 10, A, "vend-a");
    v.push(lp(1, &format!("11 DHCPACK(br-lan) 192.0.2.11 {B}")));
    v.push(opts(1, 11, "42:x"));
    v.push(opts(1, 10, "42:x"));
    check(&run(&v));
}

#[test]
fn w5_old_order_options_then_the_ack_of_another_mac() {
    let v = vec![
        lp(1, &format!("10 DHCPREQUEST(br-lan) 192.0.2.10 {A}")),
        opts(1, 10, "3:router"),
        lp(1, "10 vendor class: vend-a"),
        lp(1, &format!("10 DHCPACK(br-lan) 192.0.2.10 {B}")),
    ];
    let got = run(&v);
    check(&got);
    assert!(fps(&got).is_empty(), "{got:?}");
}

// ---- L3: stale order keys do not evict live entries (mutant M35) ----

#[test]
fn acked_transactions_do_not_evict_a_live_one_early() {
    let mut a = DhcpAssembler::default();
    let mut lines = vec![
        lp(1, &format!("1 DHCPREQUEST(br-lan) 192.0.2.10 {A}")),
        opts(1, 1, "3:router"),
    ];
    // 200 finished transactions, then 60 more open ones: only 61 are live, far below the cap.
    for x in 1000..1200 {
        lines.push(lp(1, &format!("{x} DHCPREQUEST(br-lan) 192.0.2.11 {B}")));
        lines.push(lp(1, &format!("{x} DHCPACK(br-lan) 192.0.2.11 {B}")));
    }
    for x in 2000..2060 {
        lines.push(lp(1, &format!("{x} DHCPREQUEST(br-lan) 192.0.2.11 {B}")));
    }
    lines.push(lp(1, &format!("1 DHCPACK(br-lan) 192.0.2.10 {A}")));
    let got = feed(&mut a, &lines);
    assert_eq!(lease_of(&got, A).opt55, vec![3]);
}

// ---- L4: tags keep the post-ACK block open (M14); a gap clears every context (M18) ----

#[test]
fn a_tags_line_inside_the_post_ack_block_keeps_it_open() {
    let mut lines = head(1, 7, A, "v");
    lines.push(opts(1, 7, "1:netmask"));
    lines.push(tags(1, 7));
    lines.push(opts(1, 7, "3:router"));
    let got = run(&lines);
    assert_eq!(fps(&got), vec![vec![1, 3]]);
    assert_eq!(lease_of(&got, A).opt60.as_deref(), Some("v"));
}

#[test]
fn a_gap_after_the_request_detaches_older_order_options() {
    let mut a = DhcpAssembler::default();
    let mut out = feed(
        &mut a,
        &[lp(1, &format!("7 DHCPREQUEST(br-lan) 192.0.2.10 {A}"))],
    );
    a.lose_context();
    out.extend(feed(
        &mut a,
        &[
            opts(1, 7, "3:router"),
            lp(1, &format!("7 DHCPACK(br-lan) 192.0.2.10 {A}")),
        ],
    ));
    out.extend(a.end_poll());
    out.extend(a.end_poll());
    assert!(fps(&out).is_empty(), "{out:?}");
}

#[test]
fn a_gap_inside_the_post_ack_block_discards_it_unpublished() {
    let mut a = DhcpAssembler::default();
    let mut lines = head(1, 7, A, "v");
    lines.push(opts(1, 7, "1:netmask"));
    let mut out = feed(&mut a, &lines);
    a.lose_context();
    out.extend(feed(&mut a, &[opts(1, 7, "3:router")]));
    out.extend(a.end_poll());
    out.extend(a.end_poll());
    assert!(fps(&out).is_empty(), "{out:?}");
}

#[test]
fn a_gap_inside_the_preamble_drops_the_vendor() {
    let mut a = DhcpAssembler::default();
    let mut out = feed(
        &mut a,
        &[
            lp(1, "7 available DHCP range: 192.0.2.10 -- 192.0.2.50"),
            lp(1, "7 vendor class: v"),
        ],
    );
    a.lose_context();
    out.extend(feed(
        &mut a,
        &[
            lp(1, &format!("7 DHCPREQUEST(br-lan) 192.0.2.10 {A}")),
            lp(1, &format!("7 DHCPACK(br-lan) 192.0.2.10 {A}")),
            opts(1, 7, "1:netmask"),
        ],
    ));
    out.extend(a.end_poll());
    out.extend(a.end_poll());
    assert!(out.iter().all(|l| l.opt60.is_none()), "{out:?}");
}
