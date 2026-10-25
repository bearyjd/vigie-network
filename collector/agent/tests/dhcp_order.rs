//! Real dnsmasq order (log-dhcp): `available DHCP range` opens a packet, then `vendor class` and
//! `client provides name` come BEFORE the `DHCPREQUEST`, and `requested options` lines come AFTER
//! the `DHCPACK`. All data here is synthetic (documentation ranges, locally administered MACs).

use std::fs;
use vigie_agent::dnsmasq::{parse_line, DhcpAssembler};
use vigie_agent::model::{Lease, Sections};
use vigie_agent::tail::Tail;
use vigie_agent::window::Window;

const A: &str = "02:00:00:00:00:01";
const B: &str = "02:00:00:00:00:02";

fn l(rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[123]: {rest}")
}
fn range(x: u32) -> String {
    l(&format!(
        "{x} available DHCP range: 192.0.2.10 -- 192.0.2.50"
    ))
}
fn vendor(x: u32, v: &str) -> String {
    l(&format!("{x} vendor class: {v}"))
}
fn name(x: u32, n: &str) -> String {
    l(&format!("{x} client provides name: {n}"))
}
fn req(x: u32, mac: &str) -> String {
    l(&format!("{x} DHCPREQUEST(br-lan) 192.0.2.10 {mac}"))
}
fn ack(x: u32, mac: &str) -> String {
    l(&format!("{x} DHCPACK(br-lan) 192.0.2.10 {mac}"))
}
fn opts(x: u32, list: &str) -> String {
    l(&format!("{x} requested options: {list}"))
}
fn dns(x: u32) -> String {
    l(&format!(
        "{x} 192.0.2.9/5353 query[A] x.test from 192.0.2.9"
    ))
}

/// Mirrors `Agent::poll_log`: unparsed lines break the attach context.
fn run(lines: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, lines);
    // End of the stream finishes a block that is still open.
    out.extend(a.break_context());
    out
}
fn feed(a: &mut DhcpAssembler, lines: &[String]) -> Vec<Lease> {
    let mut out = Vec::new();
    for s in lines {
        match parse_line(s) {
            Some(ev) => out.extend(a.feed(&ev)),
            None => out.extend(a.break_context()),
        }
    }
    out
}
fn last(lines: &[String]) -> Lease {
    run(lines).pop().expect("a lease")
}
fn packet(x: u32, mac: &str, v: &str, o: &str) -> Vec<String> {
    vec![
        range(x),
        vendor(x, v),
        name(x, "host-a"),
        req(x, mac),
        ack(x, mac),
        opts(x, o),
    ]
}

#[test]
fn captured_order_fixture_yields_the_full_fingerprint() {
    let text = fs::read_to_string("tests/fixtures/dhcp-actual-order.synthetic.log").unwrap();
    let lines: Vec<String> = text.lines().map(String::from).collect();
    let got = run(&lines);
    let fin = got.last().expect("lease");
    assert_eq!(fin.mac, A);
    assert_eq!(fin.opt55, vec![1, 3, 6, 15]);
    assert_eq!(fin.opt60.as_deref(), Some("fixture-vendor"));
    assert_eq!(fin.hostname.as_deref(), Some("fixture-client"));
}

// Superseded: the old test expected the ACK to publish (no options, vendor) and then an
// update per options line. That truncated/empty-first publication is the bug fixed in round 1.
#[test]
fn ack_publishes_no_fingerprint_and_the_finished_block_publishes_it_once() {
    let got = run(&packet(1, A, "v", "1:netmask, 3:router"));
    assert_eq!(got.len(), 2);
    assert!(
        got[0].opt55.is_empty() && got[0].opt60.is_none(),
        "{:?}",
        got[0]
    );
    assert_eq!(got[1].opt55, vec![1, 3]);
    assert_eq!(got[1].opt60.as_deref(), Some("v"));
}

#[test]
fn split_polls_and_window_flush_around_ack_and_options() {
    let lines = packet(1, A, "v", "1:netmask, 3:router");
    let mut asm = DhcpAssembler::default();
    let mut win = Window::default();
    for l in feed(&mut asm, &lines[..5]) {
        win.add_lease(l);
    }
    // End of the first poll: the block is held, nothing partial is published.
    assert!(asm.end_poll().is_empty());
    let first: Sections = win.take();
    assert_eq!(first.leases.len(), 1);
    assert!(first.leases[0].opt55.is_empty() && first.leases[0].opt60.is_none());
    for l in feed(&mut asm, &lines[5..]) {
        win.add_lease(l);
    }
    // The options line restarted the block's idle count: it closes after two quiet polls.
    assert!(asm.end_poll().is_empty());
    for l in asm.end_poll() {
        win.add_lease(l);
    }
    let second = win.take();
    assert_eq!(second.leases.len(), 1);
    assert_eq!(second.leases[0].opt55, vec![1, 3]);
    assert_eq!(second.leases[0].opt60.as_deref(), Some("v"));
}

#[test]
fn window_replaces_the_pair_as_one_unit() {
    let mut win = Window::default();
    win.add_lease(Lease::new(A, "192.0.2.10", None, &[9, 9], Some("old")).unwrap());
    for l in run(&packet(1, A, "new", "1:netmask")) {
        win.add_lease(l);
    }
    let s = win.take();
    assert_eq!(s.leases.len(), 1);
    assert_eq!(s.leases[0].opt55, vec![1]);
    assert_eq!(s.leases[0].opt60.as_deref(), Some("new"));
}

#[test]
fn json_carries_opt55_and_opt60_of_the_final_lease() {
    let mut out = String::new();
    last(&packet(1, A, "v", "1:netmask, 3:router")).write(&mut out);
    assert!(out.contains("\"opt55\":[1,3]"), "{out}");
    assert!(out.contains("\"opt60\":\"v\""), "{out}");
}

#[test]
fn multiline_options_keep_exact_order_and_cap_at_64() {
    let list = |r: std::ops::Range<u32>| r.map(|n| format!("{n}:x")).collect::<Vec<_>>().join(", ");
    let mut lines = packet(1, A, "v", &list(10..40));
    lines.push(opts(1, &list(40..80)));
    lines.push(opts(1, &list(80..90)));
    let fin = last(&lines);
    let want: Vec<u8> = (10..74).collect();
    assert_eq!(fin.opt55, want);
}

#[test]
fn vendor_and_name_are_optional() {
    let bare = vec![range(1), req(1, A), ack(1, A), opts(1, "1:netmask")];
    let f = last(&bare);
    assert_eq!((f.opt55.clone(), f.opt60.clone()), (vec![1], None));
    let only_name = vec![range(2), name(2, "n"), req(2, A), ack(2, A)];
    assert_eq!(last(&only_name).hostname.as_deref(), Some("n"));
    let only_vendor = vec![range(3), vendor(3, "v"), req(3, A), ack(3, A)];
    assert_eq!(last(&only_vendor).opt60.as_deref(), Some("v"));
}

#[test]
fn reused_xid_across_clients_never_leaks_evidence() {
    let mut lines = packet(1, A, "vendor-a", "1:netmask");
    // Client B reuses xid 1 and has no marker, vendor or name of its own.
    lines.extend([req(1, B), ack(1, B)]);
    let got = run(&lines);
    let b = got.last().unwrap();
    assert_eq!(b.mac, B);
    assert_eq!(b.opt60, None);
    assert_eq!(b.hostname, None);
    assert!(b.opt55.is_empty());
    // Options after B's ACK belong to B's own ACK, not A's.
    lines.push(opts(1, "6:dns-server"));
    let fin = run(&lines).pop().unwrap();
    assert_eq!((fin.mac.as_str(), fin.opt55.clone()), (B, vec![6]));
}

#[test]
fn interleaved_clients_do_not_cross_attribute() {
    let lines = vec![
        range(1),
        vendor(1, "vendor-a"),
        range(2),
        vendor(2, "vendor-b"),
        req(1, A),
        req(2, B),
        ack(1, A),
        ack(2, B),
        opts(2, "6:dns-server"),
    ];
    for lease in run(&lines) {
        assert_ne!(lease.opt60.as_deref(), Some("vendor-a"), "{lease:?}");
        if lease.mac == A {
            assert!(lease.opt55.is_empty(), "{lease:?}");
        }
    }
}

#[test]
fn orphan_and_mismatched_acks_attach_nothing() {
    let orphan = run(&[range(1), vendor(1, "v"), ack(1, A), opts(1, "1:netmask")]);
    assert_eq!(orphan.len(), 1);
    assert!(orphan[0].opt55.is_empty() && orphan[0].opt60.is_none());
    let lines = [
        range(2),
        vendor(2, "v"),
        req(2, A),
        ack(2, B),
        opts(2, "1:netmask"),
    ];
    let got = run(&lines);
    assert_eq!(got.len(), 1);
    assert!(got[0].opt55.is_empty() && got[0].opt60.is_none());
}

#[test]
fn foreign_boundaries_discard_the_preamble() {
    let injected = format!("junk {}", vendor(1, "v"));
    let foreign: Vec<String> = vec![
        dns(1),
        l("1 some unknown line"),
        injected,
        l("2 tags: br-lan"),
        l("2 DHCPOFFER(br-lan) 192.0.2.11 02:00:00:00:00:09"),
        l("2 DHCPNAK(br-lan) 192.0.2.11 02:00:00:00:00:09"),
        vendor(2, "other"),
        range(2),
    ];
    for f in foreign {
        let lines = [range(1), vendor(1, "v"), f.clone(), req(1, A), ack(1, A)];
        assert_eq!(last(&lines).opt60, None, "{f}");
    }
}

#[test]
fn foreign_boundaries_end_the_post_ack_context() {
    let foreign = [
        dns(1),
        l("1 some unknown line"),
        l("2 tags: br-lan"),
        opts(2, "9:x"),
        range(1),
        vendor(1, "v2"),
        l("1 DHCPOFFER(br-lan) 192.0.2.11 02:00:00:00:00:09"),
        req(1, B),
    ];
    for f in foreign {
        let mut lines = packet(1, A, "v", "1:netmask");
        lines.extend([f.clone(), opts(1, "7:x")]);
        let fin = last(&lines);
        assert_eq!(fin.mac, A, "{f}");
        assert!(!fin.opt55.contains(&7) && !fin.opt55.contains(&9), "{f}");
    }
}

#[test]
fn packet_generations_do_not_mix() {
    let mut lines = packet(1, A, "gen1", "1:netmask, 2:x");
    lines.extend([range(1), vendor(1, "gen2"), req(1, A), ack(1, A)]);
    lines.push(opts(1, "3:router"));
    let fin = last(&lines);
    assert_eq!(
        (fin.opt55.clone(), fin.opt60.as_deref()),
        (vec![3], Some("gen2"))
    );
    // Options after the next packet's marker are not attached to the earlier ACK.
    let mut late = packet(1, A, "g", "1:netmask");
    late.extend([range(1), opts(1, "5:x")]);
    assert_eq!(last(&late).opt55, vec![1]);
}

#[test]
fn a_second_ack_for_the_same_packet_does_not_reopen_options() {
    let mut lines = packet(1, A, "v", "1:netmask");
    lines.extend([ack(1, A), opts(1, "8:x")]);
    // The duplicate ACK has no request: unverified, so nothing attaches to it.
    let fin = last(&lines);
    assert!(!fin.opt55.contains(&8), "{fin:?}");
}

#[test]
fn bounded_memory_over_a_long_replay() {
    let mut a = DhcpAssembler::default();
    let mut n = 0usize;
    for i in 0..20_000u32 {
        let mac = format!("02:00:00:00:{:02x}:{:02x}", (i >> 8) & 0xff, i & 0xff);
        n += feed(&mut a, &packet(i + 1, &mac, "v", "1:netmask")).len();
        // Unterminated packets must not pile up either. (Their first line finishes the
        // previous packet's block, which is counted here.)
        n += feed(
            &mut a,
            &[
                range(i + 100_000),
                vendor(i + 100_000, "x"),
                req(i + 100_000, &mac),
            ],
        )
        .len();
    }
    assert_eq!(n, 40_000);
    assert!(format!("{a:?}").len() < 100_000);
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("vigie-order-{}-{tag}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    d.join("dnsmasq.log")
}
fn poll_into(t: &mut Tail, a: &mut DhcpAssembler) -> Vec<Lease> {
    let mut out = Vec::new();
    for line in t.poll_with_gaps().unwrap() {
        match line {
            Some(s) => out.extend(feed(a, &[s])),
            None => a.lose_context(),
        }
    }
    out
}

#[test]
fn truncation_between_ack_and_options_does_not_join() {
    let path = tmp("trunc");
    fs::write(&path, "").unwrap();
    let mut t = Tail::new(path.clone());
    let mut a = DhcpAssembler::default();
    poll_into(&mut t, &mut a);
    let mut head = packet(1, A, "v", "1:netmask");
    head.truncate(5);
    fs::write(&path, head.join("\n") + "\n").unwrap();
    assert_eq!(poll_into(&mut t, &mut a).len(), 1);
    // Truncate and refill with a line that reuses the xid.
    fs::write(&path, opts(1, "9:evil") + "\n").unwrap();
    assert!(poll_into(&mut t, &mut a).is_empty());
}

#[test]
fn overlong_line_between_ack_and_options_breaks_the_context() {
    let path = tmp("long");
    fs::write(&path, "").unwrap();
    let mut t = Tail::new(path.clone());
    let mut a = DhcpAssembler::default();
    poll_into(&mut t, &mut a);
    let mut lines = packet(1, A, "v", "1:netmask");
    let tail_line = lines.pop().unwrap();
    lines.push(format!("{}{}", l("1 vendor class: "), "z".repeat(5000)));
    lines.push(tail_line);
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    let got = poll_into(&mut t, &mut a);
    assert_eq!(got.len(), 1, "{got:?}");
}
