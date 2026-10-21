//! Re-review item 1: the DHCP log is a sequential stream. Option/vendor/name lines carry the
//! serial (xid) the CLIENT chose, so they attach only to the packet line that immediately
//! precedes them (same xid, nothing in between). MAC-less verbs (INFORM, RELEASE, DECLINE, NAK)
//! are context boundaries that also poison the xid.

use vigie_agent::dnsmasq::{parse_line, DhcpAssembler};
use vigie_agent::model::Lease;

const ATT: &str = "de:ad:be:ef:00:01";
const VIC: &str = "c2:11:22:33:44:01";
const VIC2: &str = "c2:11:22:33:44:02";

fn l(rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[5023]: {rest}")
}

fn run(lines: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out = Vec::new();
    for s in lines {
        match parse_line(s) {
            Some(ev) => out.extend(a.feed(&ev)),
            None => a.break_context(),
        }
    }
    out
}

fn evil_inform(xid: u32) -> Vec<String> {
    vec![
        l(&format!("{xid} DHCPINFORM(br-lan) 192.168.1.66 {ATT}")),
        l(&format!(
            "{xid} requested options: 1:netmask, 3:router, 99:evil"
        )),
        l(&format!("{xid} vendor class: evil")),
        l(&format!("{xid} client provides name: evil-host")),
    ]
}

fn assert_clean(v: &Lease) {
    assert_eq!(v.mac, VIC);
    assert!(v.opt55.is_empty(), "attacker opt55: {:?}", v.opt55);
    assert_eq!(v.opt60, None);
    assert_eq!(v.hostname, None);
}

#[test]
fn inform_with_same_xid_after_discover_cannot_poison_the_victim() {
    let mut lines = vec![l(&format!("1 DHCPDISCOVER(br-lan) {VIC}"))];
    lines.extend(evil_inform(1));
    lines.push(l(&format!("1 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")));
    lines.push(l(&format!("1 DHCPACK(br-lan) 192.168.1.50 {VIC}")));
    let got = run(&lines);
    assert_eq!(got.len(), 1);
    assert_clean(&got[0]);
}

#[test]
fn inform_between_request_and_ack_cannot_poison_the_victim() {
    let mut lines = vec![l(&format!("2 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}"))];
    lines.extend(evil_inform(2));
    lines.push(l(&format!("2 DHCPACK(br-lan) 192.168.1.50 {VIC}")));
    let got = run(&lines);
    assert_eq!(got.len(), 1);
    assert_clean(&got[0]);
}

#[test]
fn other_macless_verbs_are_boundaries_too() {
    for verb in ["DHCPRELEASE", "DHCPDECLINE", "DHCPNAK"] {
        let lines = vec![
            l(&format!("3 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
            l(&format!("3 {verb}(br-lan) 192.168.1.66 {ATT}")),
            l("3 vendor class: evil"),
            l("3 client provides name: evil-host"),
            l(&format!("3 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
        ];
        let got = run(&lines);
        assert_eq!(got.len(), 1, "{verb}");
        assert_clean(&got[0]);
    }
}

#[test]
fn offer_is_a_boundary() {
    let lines = vec![
        l(&format!("4 DHCPDISCOVER(br-lan) {VIC}")),
        l(&format!("4 DHCPOFFER(br-lan) 192.168.1.50 {VIC}")),
        l("4 vendor class: after-offer"),
        l(&format!("4 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    assert_clean(&run(&lines)[0]);
}

#[test]
fn a_foreign_line_between_request_and_options_detaches_them() {
    let lines = vec![
        l(&format!("5 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        "Oct 20 14:00:00 dnsmasq[1]: 77 192.168.1.9/5353 query[A] a.test from 192.168.1.9".into(),
        l("5 vendor class: late"),
        l(&format!("5 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    assert_clean(&run(&lines)[0]);
    // An unparsed line (noise, or something we do not understand) also ends the context.
    let lines = vec![
        l(&format!("5 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l("some unknown line"),
        l("5 vendor class: late"),
        l(&format!("5 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    assert_clean(&run(&lines)[0]);
}

#[test]
fn an_option_line_for_another_xid_does_not_attach() {
    let lines = vec![
        l(&format!("6 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l("999 vendor class: other-xid"),
        l(&format!("6 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    assert_clean(&run(&lines)[0]);
}

#[test]
fn interleaved_transactions_never_cross_attribute() {
    let lines = vec![
        l(&format!("10 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l(&format!("11 DHCPREQUEST(br-lan) 192.168.1.51 {VIC2}")),
        l("10 vendor class: vic-class"),
        l("11 vendor class: vic2-class"),
        l(&format!("10 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
        l(&format!("11 DHCPACK(br-lan) 192.168.1.51 {VIC2}")),
    ];
    let got = run(&lines);
    assert_eq!(got.len(), 2);
    for v in &got {
        // Interleaving is not how dnsmasq logs; what must hold is that nothing is mis-assigned.
        assert!(
            v.opt60.is_none()
                || (v.mac == VIC && v.opt60.as_deref() == Some("vic-class"))
                || (v.mac == VIC2 && v.opt60.as_deref() == Some("vic2-class")),
            "{v:?}"
        );
    }
    assert_eq!(
        got[0].opt60, None,
        "the 10 line was detached by the 11 request"
    );
}

#[test]
fn legitimate_xid_reuse_after_reboot_gets_fresh_fingerprints() {
    let tx = |class: &str, opts: &str| {
        vec![
            l(&format!("7 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
            l(&format!("7 requested options: {opts}")),
            l(&format!("7 vendor class: {class}")),
            l(&format!("7 DHCPACK(br-lan) 192.168.1.50 {VIC} Pixel")),
        ]
    };
    let mut lines = tx("android-1", "1:netmask, 3:router");
    lines.extend(tx("android-2", "6:dns-server"));
    let got = run(&lines);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].opt60.as_deref(), Some("android-1"));
    assert_eq!(got[0].opt55, vec![1, 3]);
    assert_eq!(got[1].opt60.as_deref(), Some("android-2"));
    assert_eq!(got[1].opt55, vec![6], "no carry-over from the first boot");
}

#[test]
fn normal_dnsmasq_sequence_still_fingerprints() {
    let lines = vec![
        l(&format!("8 DHCPDISCOVER(br-lan) {VIC}")),
        l("8 requested options: 1:netmask, 3:router"),
        l("8 vendor class: android-dhcp-14"),
        l(&format!("8 DHCPOFFER(br-lan) 192.168.1.50 {VIC}")),
        l(&format!("8 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l("8 requested options: 1:netmask, 3:router"),
        l("8 vendor class: android-dhcp-14"),
        l("8 client provides name: Pixel"),
        l(&format!("8 DHCPACK(br-lan) 192.168.1.50 {VIC} Pixel")),
    ];
    let v = &run(&lines)[0];
    assert_eq!(v.opt60.as_deref(), Some("android-dhcp-14"));
    assert_eq!(
        v.opt55,
        vec![1, 3],
        "DISCOVER and REQUEST lists are not concatenated"
    );
    assert_eq!(v.hostname.as_deref(), Some("Pixel"));
}

#[test]
fn a_new_discover_for_the_same_mac_resets_the_entry() {
    let lines = vec![
        l(&format!("9 DHCPDISCOVER(br-lan) {VIC}")),
        l("9 requested options: 1:netmask, 3:router"),
        l("9 vendor class: first"),
        l("9 client provides name: first-host"),
        l(&format!("9 DHCPDISCOVER(br-lan) {VIC}")),
        l("9 requested options: 1:netmask, 3:router"),
        l(&format!("9 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    let v = &run(&lines)[0];
    assert_eq!(v.opt55, vec![1, 3], "no [1,3,1,3]");
    assert_eq!(v.opt60, None, "stale vendor class reset");
    assert_eq!(v.hostname, None, "stale name reset");
}

#[test]
fn split_option_lists_in_one_context_still_accumulate() {
    let lines = vec![
        l(&format!("12 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l("12 requested options: 1:netmask, 3:router,"),
        l("12 requested options: 15:domain-name, 28:broadcast"),
        l(&format!("12 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    assert_eq!(run(&lines)[0].opt55, vec![1, 3, 15, 28]);
}

#[test]
fn one_mac_with_two_interleaved_xids_keeps_the_lines_apart() {
    let lines = vec![
        l(&format!("20 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l(&format!("21 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l("20 vendor class: belongs-to-20"),
        l(&format!("20 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
        l(&format!("21 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    let got = run(&lines);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].opt60, None, "context was 21 when the 20 line came");
    assert_eq!(got[1].opt60, None);
}

#[test]
fn a_tainted_xid_stays_unfingerprinted_even_for_the_matching_mac() {
    for verb in ["DHCPINFORM", "DHCPRELEASE", "DHCPDECLINE", "DHCPNAK"] {
        let lines = vec![
            l(&format!("22 {verb}(br-lan) 192.168.1.66 {ATT}")),
            l(&format!("22 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
            l("22 vendor class: victim-own-but-untrusted"),
            l(&format!("22 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
        ];
        assert_clean(&run(&lines)[0]);
    }
}
