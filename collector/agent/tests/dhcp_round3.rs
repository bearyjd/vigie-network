//! Fix round 3 for the DHCP option-order parser: one held block per dnsmasq process, newer
//! leases are never overwritten by an older block, a gap clears everything pending, marked
//! retries do not mix generations, and polls that stopped at their byte budget do not age
//! anything. All data is synthetic (documentation ranges, locally administered MACs).

use vigie_agent::dnsmasq::{parse_line_pid, DhcpAssembler};
use vigie_agent::model::Lease;

const A: &str = "02:00:00:00:00:01";
const B: &str = "02:00:00:00:00:02";
const C: &str = "02:00:00:00:00:03";

fn lp(pid: u32, rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[{pid}]: {rest}")
}
fn range(pid: u32, x: u32) -> String {
    lp(
        pid,
        &format!("{x} available DHCP range: 192.0.2.10 -- 192.0.2.50"),
    )
}
fn request(pid: u32, x: u32, ip: &str, mac: &str) -> String {
    lp(pid, &format!("{x} DHCPREQUEST(br-lan) {ip} {mac}"))
}
fn ack(pid: u32, x: u32, ip: &str, mac: &str, host: &str) -> String {
    lp(pid, &format!("{x} DHCPACK(br-lan) {ip} {mac} {host}"))
}
/// One address per dnsmasq process: a verified ACK for an address supersedes the blocks held
/// for it, so packets of different devices must not share one.
fn head(pid: u32, x: u32, mac: &str, v: &str) -> Vec<String> {
    let ip = format!("192.0.2.{}", 10 + pid % 97);
    vec![
        range(pid, x),
        lp(pid, &format!("{x} vendor class: {v}")),
        request(pid, x, &ip, mac),
        lp(pid, &format!("{x} DHCPACK(br-lan) {ip} {mac}")),
    ]
}
fn opts(pid: u32, x: u32, list: &str) -> String {
    lp(pid, &format!("{x} requested options: {list}"))
}
fn feed(a: &mut DhcpAssembler, lines: &[String]) -> Vec<Lease> {
    let mut out = Vec::new();
    for s in lines {
        match parse_line_pid(s) {
            Some((pid, ev)) => out.extend(a.feed_pid(pid, &ev)),
            None => out.extend(a.break_context()),
        }
    }
    out
}
fn close(a: &mut DhcpAssembler, out: &mut Vec<Lease>) {
    out.extend(a.end_poll());
    out.extend(a.end_poll());
    out.extend(a.break_context());
}
fn run(lines: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, lines);
    close(&mut a, &mut out);
    out
}
/// (options, vendor class) of every publication of `mac` that carries a fingerprint.
fn fp(v: &[Lease], mac: &str) -> Vec<(Vec<u8>, Option<String>)> {
    v.iter()
        .filter(|l| l.mac == mac && (!l.opt55.is_empty() || l.opt60.is_some()))
        .map(|l| (l.opt55.clone(), l.opt60.clone()))
        .collect()
}
fn dns_query(pid: u32) -> String {
    format!(
        "Oct 20 14:00:00 dnsmasq[{pid}]: 9 192.0.2.99/5353 query[A] example.test from 192.0.2.99"
    )
}

// ---- OPUS-M1: one held block per pid ----

#[test]
fn p1_a_foreign_ack_does_not_drop_a_complete_held_block() {
    let mut lines = head(100, 7, A, "vend-a");
    lines.push(opts(100, 7, "1:netmask, 3:router, 6:dns-server"));
    lines.extend(head(200, 9, C, "attacker"));
    let out = run(&lines);
    assert_eq!(
        fp(&out, A),
        vec![(vec![1, 3, 6], Some("vend-a".into()))],
        "{out:?}"
    );
}

#[test]
fn p1b_a_flood_of_foreign_acks_does_not_starve_the_fingerprints() {
    let mut a = DhcpAssembler::default();
    let mut out = Vec::new();
    for i in 0..20u32 {
        let mac = format!("02:00:00:00:01:{i:02x}");
        let mut l = head(100, 1000 + i, &mac, "v");
        l.push(opts(100, 1000 + i, "1:netmask, 3:router"));
        l.extend(head(200, 5000 + i, C, "attacker"));
        out.extend(feed(&mut a, &l));
        close(&mut a, &mut out);
    }
    let n = out
        .iter()
        .filter(|l| l.mac != C && !l.opt55.is_empty())
        .count();
    assert_eq!(n, 20, "{out:?}");
}

#[test]
fn p4_three_pids_hold_their_blocks_at_once() {
    let mut lines = head(100, 7, A, "vend-a");
    lines.push(request(200, 8, "192.0.2.11", B));
    lines.push(range(300, 9));
    lines.push(opts(100, 7, "1:netmask"));
    lines.push(opts(200, 8, "42:x"));
    lines.push(lp(300, "9 vendor class: vend-c"));
    lines.push(request(300, 9, "192.0.2.12", C));
    lines.push(ack(200, 8, "192.0.2.11", B, "bee"));
    lines.push(ack(300, 9, "192.0.2.12", C, "cee"));
    lines.push(opts(300, 9, "6:dns-server"));
    let out = run(&lines);
    assert_eq!(
        fp(&out, A),
        vec![(vec![1], Some("vend-a".into()))],
        "{out:?}"
    );
    assert_eq!(fp(&out, B), vec![(vec![42], None)], "{out:?}");
    assert_eq!(
        fp(&out, C),
        vec![(vec![6], Some("vend-c".into()))],
        "{out:?}"
    );
}

#[test]
fn a_held_block_continues_across_a_foreign_ack_without_truncation() {
    let mut lines = head(100, 7, A, "vend-a");
    lines.push(opts(100, 7, "1:netmask, 3:router"));
    lines.extend(head(200, 9, C, "other"));
    lines.push(opts(100, 7, "6:dns-server, 15:domain-name"));
    let out = run(&lines);
    assert_eq!(
        fp(&out, A),
        vec![(vec![1, 3, 6, 15], Some("vend-a".into()))],
        "{out:?}"
    );
}

#[test]
fn k17_an_evicted_block_is_dropped_never_published_truncated() {
    let mut a = DhcpAssembler::default();
    let mut lines = Vec::new();
    for i in 0..5u32 {
        let mac = format!("02:00:00:00:02:{i:02x}");
        lines.extend(head(100 + i, 1, &mac, "v"));
        lines.push(opts(100 + i, 1, "1:netmask"));
    }
    let mut out = feed(&mut a, &lines);
    close(&mut a, &mut out);
    let published = out.iter().filter(|l| !l.opt55.is_empty()).count();
    assert_eq!(published, 4, "{out:?}");
    assert!(
        out.iter()
            .filter(|l| l.mac == "02:00:00:00:02:00")
            .all(|l| l.opt55.is_empty()),
        "{out:?}"
    );
    assert_eq!(a.take_counts().get("dhcp_block_evicted"), Some(&1));
}

// ---- CODEX-1: a deferred block never overwrites a newer lease ----

#[test]
fn a_held_block_never_republishes_an_older_lease_over_a_newer_ack() {
    let lines = vec![
        request(100, 1, "192.0.2.10", A),
        ack(100, 1, "192.0.2.10", A, "old-host"),
        opts(100, 1, "1:netmask, 3:router"),
        request(200, 5, "192.0.2.20", A),
        ack(200, 5, "192.0.2.20", A, "new-host"),
        lp(100, "1 tags: end"),
    ];
    let mut a = DhcpAssembler::default();
    let out = {
        let mut o = feed(&mut a, &lines);
        close(&mut a, &mut o);
        o
    };
    let mine: Vec<&Lease> = out.iter().filter(|l| l.mac == A).collect();
    let last = mine.last().expect("lease");
    assert_eq!(
        (last.ip.as_str(), last.hostname.as_deref()),
        ("192.0.2.20", Some("new-host")),
        "{out:?}"
    );
    assert_eq!(a.take_counts().get("dhcp_block_superseded"), Some(&1));
}

// ---- CODEX-2: a gap clears the pending pre-ACK fields too ----

#[test]
fn a_gap_between_request_and_ack_drops_the_pending_preamble() {
    let mut a = DhcpAssembler::default();
    let mut out = feed(
        &mut a,
        &[
            range(100, 7),
            lp(100, "7 vendor class: stale-v"),
            lp(100, "7 client provides name: stale-n"),
            request(100, 7, "192.0.2.10", A),
        ],
    );
    a.lose_context();
    out.extend(feed(
        &mut a,
        &[ack(100, 7, "192.0.2.10", A, "x"), opts(100, 7, "42:x")],
    ));
    close(&mut a, &mut out);
    assert!(fp(&out, A).is_empty(), "{out:?}");
    assert!(out.iter().all(|l| l.opt55.is_empty()), "{out:?}");
}

#[test]
fn a_gap_after_pre_ack_options_drops_the_possibly_truncated_list() {
    let mut a = DhcpAssembler::default();
    let mut out = feed(
        &mut a,
        &[request(100, 7, "192.0.2.10", A), opts(100, 7, "1:netmask")],
    );
    a.lose_context();
    out.extend(feed(&mut a, &[ack(100, 7, "192.0.2.10", A, "x")]));
    close(&mut a, &mut out);
    assert!(fp(&out, A).is_empty(), "{out:?}");
}

// ---- CODEX-4 (assembler side): only polls that reached the end of the log age a block ----

#[test]
fn polls_that_stopped_at_their_budget_do_not_age_a_block() {
    let mut a = DhcpAssembler::default();
    let mut lines = head(100, 7, A, "v");
    lines.push(opts(100, 7, "1:netmask, 3:router"));
    let mut out = feed(&mut a, &lines);
    for _ in 0..5 {
        out.extend(a.end_poll_at(false));
    }
    assert!(out.iter().all(|l| l.opt55.is_empty()), "{out:?}");
    out.extend(feed(&mut a, &[opts(100, 7, "6:dns-server")]));
    assert!(a.end_poll_at(true).is_empty());
    out.extend(a.end_poll_at(true));
    assert_eq!(fp(&out, A), vec![(vec![1, 3, 6], Some("v".into()))]);
}

// ---- CODEX-5: a marked retry starts from nothing ----

#[test]
fn a_marked_retry_clears_the_options_of_the_earlier_attempt() {
    let lines = vec![
        request(100, 7, "192.0.2.10", A),
        opts(100, 7, "1:netmask"),
        range(100, 7),
        lp(100, "7 vendor class: new-v"),
        request(100, 7, "192.0.2.10", A),
        ack(100, 7, "192.0.2.10", A, "h"),
        opts(100, 7, "6:dns-server"),
    ];
    let out = run(&lines);
    let mine: Vec<&Lease> = out.iter().filter(|l| l.mac == A).collect();
    assert_eq!(mine.len(), 2, "{out:?}");
    assert!(
        mine[0].opt55.is_empty() && mine[0].opt60.is_none(),
        "{out:?}"
    );
    assert_eq!(
        (mine[1].opt55.clone(), mine[1].opt60.as_deref()),
        (vec![6], Some("new-v")),
        "{out:?}"
    );
}

// ---- OPUS-L1: held pre/ctx age on EOF polls only ----

#[test]
fn an_old_order_context_ages_out_after_two_eof_polls() {
    let run_with = |eof: bool| {
        let mut a = DhcpAssembler::default();
        let mut out = feed(&mut a, &[request(100, 7, "192.0.2.10", A)]);
        for _ in 0..3 {
            out.extend(a.end_poll_at(eof));
        }
        out.extend(feed(
            &mut a,
            &[opts(100, 7, "1:netmask"), ack(100, 7, "192.0.2.10", A, "h")],
        ));
        close(&mut a, &mut out);
        out
    };
    assert!(run_with(true).iter().all(|l| l.opt55.is_empty()));
    assert!(run_with(false).iter().any(|l| l.opt55 == vec![1]));
}

#[test]
fn a_preamble_ages_out_after_two_eof_polls() {
    let run_with = |eof: bool| {
        let mut a = DhcpAssembler::default();
        let mut out = feed(&mut a, &[range(100, 7), lp(100, "7 vendor class: v")]);
        for _ in 0..3 {
            out.extend(a.end_poll_at(eof));
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
        out
    };
    assert!(run_with(true).iter().all(|l| l.opt60.is_none()));
    assert!(run_with(false)
        .iter()
        .any(|l| l.opt60.as_deref() == Some("v")));
}

// ---- killers for earlier surviving mutants ----

#[test]
fn k08_own_new_ctx_wins_over_a_held_foreign_ctx() {
    let lines = vec![
        request(100, 7, "192.0.2.10", A),
        request(200, 8, "192.0.2.11", B),
        opts(200, 8, "1:netmask, 3:router"),
        ack(200, 8, "192.0.2.11", B, "h"),
    ];
    let out = run(&lines);
    assert_eq!(
        fp(&out, B).first().map(|x| x.0.clone()),
        Some(vec![1, 3]),
        "{out:?}"
    );
}

#[test]
fn k09_own_new_preamble_wins_over_a_held_foreign_one() {
    let mut lines = vec![range(100, 7)];
    lines.extend(head(200, 8, B, "vend-b"));
    lines.push(opts(200, 8, "1:netmask"));
    let out = run(&lines);
    assert_eq!(
        fp(&out, B),
        vec![(vec![1], Some("vend-b".into()))],
        "{out:?}"
    );
}

#[test]
fn k29_foreign_ack_inside_old_order_ctx_keeps_the_attach() {
    let lines = vec![
        request(100, 7, "192.0.2.10", A),
        request(200, 9, "192.0.2.12", C),
        request(100, 7, "192.0.2.10", A),
        ack(200, 9, "192.0.2.12", C, "c"),
        opts(100, 7, "1:netmask, 3:router"),
        ack(100, 7, "192.0.2.10", A, "a"),
    ];
    let out = run(&lines);
    assert_eq!(
        fp(&out, A).first().map(|x| x.0.clone()),
        Some(vec![1, 3]),
        "{out:?}"
    );
}

#[test]
fn a_query_of_another_pid_keeps_the_whole_list() {
    let mut lines = head(100, 7, A, "v");
    lines.push(opts(100, 7, "1:netmask, 3:router"));
    lines.push(dns_query(456));
    lines.push(opts(100, 7, "6:dns-server, 15:domain-name"));
    assert_eq!(
        fp(&run(&lines), A),
        vec![(vec![1, 3, 6, 15], Some("v".into()))]
    );
}
