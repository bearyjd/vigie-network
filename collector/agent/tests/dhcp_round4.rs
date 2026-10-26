//! Fix round 4 for the DHCP option-order parser: ageing is by inactivity (any matching line of
//! the block resets it), an entry whose preamble/context genuinely aged out is unusable (the
//! window keeps its stored pair), an interrupted marked retry inherits nothing, and held blocks
//! are superseded by a verified ACK for the same MAC or the same address only.
//! All data is synthetic (documentation ranges, locally administered MACs).

use vigie_agent::dnsmasq::{parse_line_pid, DhcpAssembler};
use vigie_agent::model::Lease;

const A: &str = "02:00:00:00:00:01";
const B: &str = "02:00:00:00:00:02";

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
fn polls(a: &mut DhcpAssembler, n: usize) -> Vec<Lease> {
    (0..n).flat_map(|_| a.end_poll()).collect()
}
fn close(a: &mut DhcpAssembler, out: &mut Vec<Lease>) {
    out.extend(polls(a, 2));
}
type Fp = Vec<(Vec<u8>, Option<String>)>;
/// (options, vendor class) of every publication of `mac` that carries a fingerprint.
fn fp(v: &[Lease], mac: &str) -> Fp {
    v.iter()
        .filter(|l| l.mac == mac && (!l.opt55.is_empty() || l.opt60.is_some()))
        .map(|l| (l.opt55.clone(), l.opt60.clone()))
        .collect()
}
fn full(opts: &[u8], v: &str) -> Fp {
    vec![(opts.to_vec(), Some(v.to_string()))]
}

// ---- OPUS-F1 / CODEX-1: inactivity ageing ----

/// Runs `before` lines, `gap` EOF polls, then `after` lines, and closes everything.
fn with_gap(before: &[String], gap: usize, after: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, before);
    out.extend(polls(&mut a, gap));
    out.extend(feed(&mut a, after));
    close(&mut a, &mut out);
    out
}

#[test]
fn k15_pre_dies_at_exactly_two_eof_polls() {
    let before = [range(100, 7), vendor(100, 7, "v")];
    let after = [
        request(100, 7, "192.0.2.10", A),
        ack(100, 7, "192.0.2.10", A, "h"),
        opts(100, 7, "1:netmask"),
    ];
    assert_eq!(fp(&with_gap(&before, 1, &after), A), full(&[1], "v"));
    assert_eq!(fp(&with_gap(&before, 2, &after), A), Fp::new());
}

#[test]
fn k14_ctx_dies_at_exactly_two_eof_polls() {
    let before = [request(100, 7, "192.0.2.10", A)];
    let after = [opts(100, 7, "1:netmask"), ack(100, 7, "192.0.2.10", A, "h")];
    assert_eq!(fp(&with_gap(&before, 1, &after), A), vec![(vec![1], None)]);
    assert_eq!(fp(&with_gap(&before, 2, &after), A), Fp::new());
}

#[test]
fn a_matching_line_resets_the_preamble_age() {
    let mut a = DhcpAssembler::default();
    let mut out = Vec::new();
    for step in [range(100, 7), vendor(100, 7, "v"), tags(100, 7)] {
        out.extend(feed(&mut a, &[step]));
        out.extend(polls(&mut a, 1));
    }
    out.extend(feed(
        &mut a,
        &[
            request(100, 7, "192.0.2.10", A),
            ack(100, 7, "192.0.2.10", A, "h"),
            opts(100, 7, "1:netmask"),
        ],
    ));
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full(&[1], "v"), "{out:?}");
}

#[test]
fn a_matching_line_resets_the_context_age() {
    let mut a = DhcpAssembler::default();
    let mut out = Vec::new();
    for step in [request(100, 7, "192.0.2.10", A), tags(100, 7), tags(100, 7)] {
        out.extend(feed(&mut a, &[step]));
        out.extend(polls(&mut a, 1));
    }
    out.extend(feed(
        &mut a,
        &[opts(100, 7, "1:netmask"), ack(100, 7, "192.0.2.10", A, "h")],
    ));
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), vec![(vec![1], None)], "{out:?}");
}

#[test]
fn a_list_written_across_three_polls_is_whole() {
    // CODEX-1 repro: poll 1 up to the ACK, polls 2 and 3 one options line each.
    let mut a = DhcpAssembler::default();
    let mut out = feed(
        &mut a,
        &[
            range(100, 7),
            vendor(100, 7, "v"),
            request(100, 7, "192.0.2.10", A),
            ack(100, 7, "192.0.2.10", A, "h"),
        ],
    );
    out.extend(polls(&mut a, 1));
    out.extend(feed(&mut a, &[opts(100, 7, "1:netmask, 3:router")]));
    out.extend(polls(&mut a, 1));
    out.extend(feed(
        &mut a,
        &[opts(100, 7, "6:dns-server, 15:domain-name")],
    ));
    out.extend(polls(&mut a, 1));
    out.extend(feed(&mut a, &[lp(100, "7 next server: 192.0.2.1")]));
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full(&[1, 3, 6, 15], "v"), "{out:?}");
}

#[test]
fn an_aged_out_preamble_publishes_no_fingerprint_for_that_serial() {
    // The vendor-less pair must never reach the window (it would overwrite a stored one).
    let before = [range(100, 7), vendor(100, 7, "v")];
    let after = [
        request(100, 7, "192.0.2.10", A),
        ack(100, 7, "192.0.2.10", A, "h"),
        opts(100, 7, "1:netmask, 3:router"),
    ];
    let out = with_gap(&before, 3, &after);
    assert!(
        out.iter().all(|l| l.opt55.is_empty() && l.opt60.is_none()),
        "{out:?}"
    );
    assert!(
        out.iter()
            .any(|l| l.mac == A && l.hostname.as_deref() == Some("h")),
        "{out:?}"
    );
}

#[test]
fn a_poll_that_stopped_at_its_budget_ages_nothing() {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &[range(100, 7), vendor(100, 7, "v")]);
    for _ in 0..4 {
        out.extend(a.end_poll_at(false));
    }
    out.extend(feed(
        &mut a,
        &[
            request(100, 7, "192.0.2.10", A),
            ack(100, 7, "192.0.2.10", A, "h"),
            opts(100, 7, "1:netmask"),
        ],
    ));
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full(&[1], "v"), "{out:?}");
}

// ---- CODEX-2: an interrupted marked retry inherits nothing ----

#[test]
fn an_interrupted_marked_retry_does_not_inherit_the_previous_attempt() {
    let lines = [
        range(100, 7),
        vendor(100, 7, "OLD"),
        lp(100, "7 client provides name: OLD-HOST"),
        request(100, 7, "192.0.2.10", A),
        range(100, 7),
        vendor(100, 7, "NEW"),
        lp(100, "7 user class: unrecognised"),
        request(100, 7, "192.0.2.10", A),
        lp(100, "7 DHCPACK(br-lan) 192.0.2.10 02:00:00:00:00:01"),
        opts(100, 7, "6:dns-server"),
    ];
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    assert!(
        out.iter()
            .all(|l| l.hostname.is_none() && l.opt60.as_deref() != Some("OLD")),
        "{out:?}"
    );
    // The unrecognised line between marker and request leaves the entry stale: nothing is
    // published for it (a vendor-less list would overwrite the stored pair).
    assert!(fp(&out, A).is_empty(), "{out:?}");
}

// ---- OPUS-F2 / F4: superseding ----

fn held_a(ip_b: &str, ack_b: String) -> (DhcpAssembler, Vec<Lease>) {
    let mut a = DhcpAssembler::default();
    let mut lines = vec![
        range(100, 7),
        vendor(100, 7, "vend-a"),
        request(100, 7, "192.0.2.10", A),
        ack(100, 7, "192.0.2.10", A, "ha"),
        opts(100, 7, "1:netmask"),
        request(200, 9, ip_b, B),
    ];
    lines.push(ack_b);
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    (a, out)
}

#[test]
fn a_verified_ack_of_another_mac_for_the_same_ip_supersedes_the_block() {
    let (mut a, out) = held_a("192.0.2.10", ack(200, 9, "192.0.2.10", B, "hb"));
    assert_eq!(fp(&out, A), Fp::new(), "{out:?}");
    assert_eq!(a.take_counts().get("dhcp_block_superseded"), Some(&1));
}

#[test]
fn a_verified_ack_for_another_ip_leaves_the_block_alone() {
    let (mut a, out) = held_a("192.0.2.11", ack(200, 9, "192.0.2.11", B, "hb"));
    assert_eq!(fp(&out, A), full(&[1], "vend-a"), "{out:?}");
    assert_eq!(a.take_counts().get("dhcp_block_superseded"), None);
}

#[test]
fn an_unverified_ack_never_supersedes_a_block() {
    // pid 200 ACKs another MAC (B) at the same IP with no matching REQUEST on its serial: tainted.
    let mut a = DhcpAssembler::default();
    let mut lines = vec![
        range(100, 7),
        vendor(100, 7, "vend-a"),
        request(100, 7, "192.0.2.10", A),
        ack(100, 7, "192.0.2.10", A, "ha"),
        opts(100, 7, "1:netmask"),
    ];
    lines.push(ack(200, 9, "192.0.2.10", B, "x"));
    lines.push(request(200, 11, "192.0.2.10", A));
    lines.push(ack(200, 11, "192.0.2.10", B, "y"));
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full(&[1], "vend-a"), "{out:?}");
    assert_eq!(a.take_counts().get("dhcp_block_superseded"), None);
}

// ---- OPUS-F3: options logged after a DISCOVER are dropped by a marked REQUEST ----

#[test]
fn a_marked_request_drops_options_logged_after_the_discover() {
    let disc = lp(100, "7 DHCPDISCOVER(br-lan) 02:00:00:00:00:01");
    let lines = [
        disc,
        opts(100, 7, "1:netmask"),
        range(100, 7),
        vendor(100, 7, "v"),
        request(100, 7, "192.0.2.10", A),
        ack(100, 7, "192.0.2.10", A, "h"),
    ];
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    // Dropped, never misattributed: only the marked packet's own vendor survives.
    assert_eq!(
        fp(&out, A),
        vec![(vec![], Some("v".to_string()))],
        "{out:?}"
    );
}

// ---- OPUS-M21: an unparsed line publishes every held block ----

#[test]
fn an_unparsed_line_publishes_no_held_block_they_age_out_instead() {
    let mut a = DhcpAssembler::default();
    let mut lines = vec![
        range(100, 7),
        vendor(100, 7, "va"),
        request(100, 7, "192.0.2.10", A),
        ack(100, 7, "192.0.2.10", A, "ha"),
        opts(100, 7, "1:netmask"),
        range(200, 8),
        vendor(200, 8, "vb"),
        request(200, 8, "192.0.2.11", B),
        ack(200, 8, "192.0.2.11", B, "hb"),
        opts(200, 8, "3:router"),
    ];
    lines.push("this line is not dnsmasq".to_string());
    let mut out = feed(&mut a, &lines);
    assert!(fp(&out, A).is_empty() && fp(&out, B).is_empty(), "{out:?}");
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), full(&[1], "va"), "{out:?}");
    assert_eq!(fp(&out, B), full(&[3], "vb"), "{out:?}");
}

#[test]
fn an_attached_options_line_resets_the_context_age() {
    let mut a = DhcpAssembler::default();
    let mut out = Vec::new();
    for step in [
        request(100, 7, "192.0.2.10", A),
        opts(100, 7, "1:netmask"),
        opts(100, 7, "3:router"),
    ] {
        out.extend(feed(&mut a, &[step]));
        out.extend(polls(&mut a, 1));
    }
    out.extend(feed(&mut a, &[ack(100, 7, "192.0.2.10", A, "h")]));
    close(&mut a, &mut out);
    assert_eq!(fp(&out, A), vec![(vec![1, 3], None)], "{out:?}");
}
