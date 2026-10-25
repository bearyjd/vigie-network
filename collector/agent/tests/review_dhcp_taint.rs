//! Security review item 1: DHCP fingerprint poisoning via serial (xid) collision.
//! Lines of different transactions that share a serial must never be merged into one lease.

use vigie_agent::dnsmasq::{parse_line, DhcpAssembler};
use vigie_agent::model::Lease;

const ATT: &str = "de:ad:be:ef:00:01";
const VIC: &str = "c2:11:22:33:44:01";

fn l(rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[5023]: {rest}")
}

fn feed_all(lines: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out: Vec<Lease> = lines
        .iter()
        .filter_map(|s| parse_line(s))
        .flat_map(|ev| a.feed(&ev))
        .collect();
    out.extend(a.break_context());
    out
}

#[test]
fn attacker_cannot_poison_victim_fingerprint_with_same_xid() {
    let lines = [
        l(&format!("1000 DHCPREQUEST(br-lan) 192.168.1.66 {ATT}")),
        l("1000 requested options: 1:netmask, 3:router, 6:dns-server"),
        l("1000 vendor class: evil-class"),
        l("1000 client provides name: evil-host"),
        l(&format!("1000 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l(&format!("1000 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    let leases = feed_all(&lines);
    assert_eq!(leases.len(), 1);
    let v = &leases[0];
    assert_eq!(v.mac, VIC);
    assert!(v.opt55.is_empty(), "attacker opt55 must not reach victim");
    assert_eq!(v.opt60, None, "attacker vendor class must not reach victim");
    assert_eq!(v.hostname, None, "attacker hostname must not reach victim");
}

#[test]
fn victim_ack_alone_does_not_consume_attackers_request_fingerprint() {
    // Attacker request with the same xid, victim's ACK arrives without its own request line.
    let lines = [
        l(&format!("2000 DHCPREQUEST(br-lan) 192.168.1.66 {ATT}")),
        l("2000 vendor class: evil-class"),
        l("2000 client provides name: evil-host"),
        l(&format!("2000 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    let leases = feed_all(&lines);
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].opt60, None);
    assert_eq!(leases[0].hostname, None);
}

#[test]
fn options_lines_after_a_taint_are_ignored() {
    let lines = [
        l(&format!("3000 DHCPREQUEST(br-lan) 192.168.1.66 {ATT}")),
        l(&format!("3000 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l("3000 vendor class: late-evil"),
        l(&format!("3000 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    assert_eq!(feed_all(&lines)[0].opt60, None);
}

#[test]
fn same_mac_retry_with_same_xid_keeps_its_fingerprint() {
    let lines = [
        l(&format!("4000 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l("4000 vendor class: android-dhcp-14"),
        l(&format!(
            "4000 DHCPREQUEST(br-lan) 192.168.1.50 {}",
            VIC.to_uppercase()
        )),
        l("4000 requested options: 1:netmask, 3:router"),
        l(&format!("4000 DHCPACK(br-lan) 192.168.1.50 {VIC} Pixel")),
    ];
    let v = &feed_all(&lines)[0];
    assert_eq!(v.opt60.as_deref(), Some("android-dhcp-14"));
    assert_eq!(v.opt55, vec![1, 3]);
    assert_eq!(v.hostname.as_deref(), Some("Pixel"));
}

#[test]
fn fingerprint_without_any_request_line_is_not_trusted() {
    let lines = [
        l("5000 vendor class: orphan"),
        l(&format!("5000 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    assert_eq!(feed_all(&lines)[0].opt60, None);
}

// A taint must not depend on the final ACK check: here the ACK is for the FIRST request's MAC, so
// only the sticky taint (set when the second MAC appeared) keeps the foreign lines out.

#[test]
fn second_mac_on_the_serial_taints_even_when_the_ack_is_for_the_first_mac() {
    let lines = [
        l(&format!("6000 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l("6000 vendor class: victim-class"),
        l(&format!("6000 DHCPREQUEST(br-lan) 192.168.1.66 {ATT}")),
        l(&format!("6000 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    let v = &feed_all(&lines)[0];
    assert_eq!(v.mac, VIC);
    assert_eq!(
        v.opt60, None,
        "lines that may belong to another MAC are dropped for both"
    );
}

#[test]
fn lines_after_a_taint_are_ignored_for_every_kind() {
    for (kind, line) in [
        ("vendor", "7000 vendor class: late"),
        ("opt55", "7000 requested options: 1:netmask, 3:router"),
        ("name", "7000 client provides name: late-host"),
    ] {
        let lines = [
            l(&format!("7000 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
            l(&format!("7000 DHCPREQUEST(br-lan) 192.168.1.66 {ATT}")),
            l(line),
            l(&format!("7000 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
        ];
        let v = &feed_all(&lines)[0];
        assert_eq!(v.opt60, None, "{kind}");
        assert!(v.opt55.is_empty(), "{kind}");
        assert_eq!(v.hostname, None, "{kind}");
    }
}

#[test]
fn fingerprint_lines_that_precede_the_request_are_not_attributed_to_it() {
    let lines = [
        l("8000 vendor class: before-any-request"),
        l(&format!("8000 DHCPREQUEST(br-lan) 192.168.1.50 {VIC}")),
        l(&format!("8000 DHCPACK(br-lan) 192.168.1.50 {VIC}")),
    ];
    assert_eq!(feed_all(&lines)[0].opt60, None);
}
