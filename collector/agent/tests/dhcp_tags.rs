//! F1: dnsmasq logs `<xid> tags: <iface>` between the packet line and `requested options:`.
//! The line is neutral: it keeps the attach context of the same xid and never creates one.

use std::collections::{BTreeSet, HashMap};
use vigie_agent::dnsmasq::{parse_line, DhcpAssembler};
use vigie_agent::model::Lease;

const MAC: &str = "c2:11:22:33:44:01";

fn l(rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[5023]: {rest}")
}

/// Mirrors `Agent::poll_log`: unparsed lines break the attach context.
fn run(lines: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out = Vec::new();
    for s in lines {
        match parse_line(s) {
            Some(ev) => out.extend(a.feed(&ev)),
            None => out.extend(a.break_context()),
        }
    }
    out.extend(a.break_context());
    out
}

fn req(x: u32) -> String {
    l(&format!("{x} DHCPREQUEST(br-lan) 192.168.1.50 {MAC}"))
}
fn tags(x: u32) -> String {
    l(&format!("{x} tags: br-lan"))
}
fn opts(x: u32) -> String {
    l(&format!(
        "{x} requested options: 1:netmask, 3:router, 6:dns-server"
    ))
}
fn vendor(x: u32) -> String {
    l(&format!("{x} vendor class: android-dhcp-14"))
}
fn ack(x: u32) -> String {
    l(&format!("{x} DHCPACK(br-lan) 192.168.1.50 {MAC} Pixel"))
}

fn one(lines: &[String]) -> Lease {
    let got = run(lines);
    assert_eq!(got.len(), 1);
    got.into_iter().next().unwrap()
}

fn assert_full(v: &Lease) {
    assert_eq!(v.opt55, vec![1, 3, 6]);
    assert_eq!(v.opt60.as_deref(), Some("android-dhcp-14"));
}

fn assert_empty(v: &Lease) {
    assert!(v.opt55.is_empty(), "{:?}", v.opt55);
    assert_eq!(v.opt60, None);
}

#[test]
fn real_dnsmasq_order_yields_the_fingerprint() {
    assert_full(&one(&[req(7), tags(7), opts(7), vendor(7), ack(7)]));
}

#[test]
fn tags_with_a_different_xid_breaks_context() {
    assert_empty(&one(&[req(7), tags(8), opts(7), vendor(7), ack(7)]));
}

#[test]
fn two_tags_lines_keep_context() {
    assert_full(&one(&[
        req(7),
        tags(7),
        tags(7),
        opts(7),
        vendor(7),
        ack(7),
    ]));
}

#[test]
fn tags_after_options_keeps_context() {
    assert_full(&one(&[req(7), opts(7), tags(7), vendor(7), ack(7)]));
}

#[test]
fn tags_alone_creates_no_context() {
    assert_empty(&one(&[tags(7), opts(7), vendor(7), ack(7)]));
    // a context that ended (ACK of another xid) is not revived by tags
    let got = run(&[req(6), ack(6), tags(7), opts(7), vendor(7), ack(7)]);
    assert_eq!(got.len(), 2);
    assert_empty(&got[1]);
}

#[test]
fn tags_after_a_dns_line_does_not_reopen_a_context() {
    let dns = l("7 192.168.1.9/5353 query[A] x.test from 192.168.1.9");
    let lines = [req(7), dns, tags(7), opts(7), vendor(7), ack(7)];
    assert_empty(&one(&lines));
}

#[test]
fn tags_after_an_unparsed_line_does_not_reopen_a_context() {
    let junk = l("7 some unknown line");
    let lines = [req(7), junk, tags(7), opts(7), vendor(7), ack(7)];
    assert_empty(&one(&lines));
}

#[test]
fn tags_value_length_and_charset_do_not_matter() {
    // The tag value is never used, so a router with many or non-ASCII tags keeps its fingerprints.
    for value in [
        "a".repeat(500),
        "a".repeat(1024),
        "br-lan caf\u{e9} \u{4e2d}\u{6587}".into(),
    ] {
        let t = l(&format!("7 tags: {value}"));
        assert_full(&one(&[req(7), t, opts(7), vendor(7), ack(7)]));
    }
    // a long tags line of ANOTHER xid still breaks the context
    let other = l(&format!("8 tags: {}", "a".repeat(500)));
    assert_empty(&one(&[req(7), other, opts(7), vendor(7), ack(7)]));
}

#[test]
fn control_char_or_over_1024_char_tags_line_is_unparsed_and_breaks_context() {
    let long = l(&format!("7 tags: {}", "a".repeat(1025)));
    assert_empty(&one(&[req(7), long, opts(7), vendor(7), ack(7)]));
    for ctl in [
        "7 tags: br\u{1b}[0m",
        "7 tags: br\u{7f}",
        "7 tags: a\tb",
        "7 tags: a\u{85}b",
    ] {
        assert_empty(&one(&[req(7), l(ctl), opts(7), vendor(7), ack(7)]));
    }
}

#[test]
fn boundary_verbs_still_taint_after_tags() {
    let lines = [
        req(7),
        tags(7),
        l("7 DHCPINFORM(br-lan) 192.168.1.66 de:ad:be:ef:00:01"),
        tags(7),
        l("7 requested options: 99:evil"),
        l("7 vendor class: evil"),
        ack(7),
    ];
    assert_empty(&one(&lines));
}

#[test]
fn unparsed_or_dns_line_after_tags_still_breaks_context() {
    let junk = l("7 some unknown line");
    assert_empty(&one(&[req(7), tags(7), junk, opts(7), vendor(7), ack(7)]));
    let dns = l("7 192.168.1.9/5353 query[A] x.test from 192.168.1.9");
    assert_empty(&one(&[req(7), tags(7), dns, opts(7), vendor(7), ack(7)]));
}

#[test]
fn forged_prefix_in_vendor_class_stays_in_value_after_tags() {
    let forged = l("7 vendor class: x Oct 20 14:00:00 dnsmasq-dhcp[1]: 7 DHCPACK(br-lan) 1.2.3.4 aa:bb:cc:dd:ee:ff");
    let got = run(&[req(7), tags(7), opts(7), forged, ack(7)]);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].mac, MAC);
}

#[test]
fn p0_sample_yields_fingerprints_for_every_device() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/p0/dnsmasq-dhcp-sample.log"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let leases = run(&lines);
    // Independent expectation read straight from the text, per xid.
    let mut has_opts: HashMap<String, bool> = HashMap::new();
    let mut vend: HashMap<String, String> = HashMap::new();
    let mut acks: Vec<(String, String)> = Vec::new();
    for line in &lines {
        let msg = line.split("]: ").nth(1).unwrap();
        let (xid, rest) = msg.split_once(' ').unwrap();
        if rest.starts_with("requested options:") {
            has_opts.insert(xid.into(), true);
        }
        if let Some(v) = rest.strip_prefix("vendor class:") {
            vend.insert(xid.into(), v.trim().into());
        }
        if rest.starts_with("DHCPACK(") {
            let t: Vec<&str> = rest.split_whitespace().collect();
            acks.push((xid.to_string(), t[2].to_string()));
        }
    }
    assert!(acks.len() >= 7);
    assert_eq!(leases.len(), acks.len());
    for (lease, (xid, mac)) in leases.iter().zip(&acks) {
        assert_eq!(&lease.mac, mac);
        assert_eq!(
            !lease.opt55.is_empty(),
            has_opts.contains_key(xid),
            "opt55 of {mac}"
        );
        assert_eq!(lease.opt60.as_ref(), vend.get(xid), "opt60 of {mac}");
    }
    let macs: BTreeSet<_> = leases.iter().map(|x| x.mac.clone()).collect();
    for m in &macs {
        assert!(
            leases.iter().any(|x| &x.mac == m && !x.opt55.is_empty()),
            "{m}"
        );
    }
    assert!(leases.iter().filter(|x| x.opt60.is_some()).count() >= 3);
}
