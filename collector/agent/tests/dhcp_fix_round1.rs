//! Fix round 1 for the DHCP option-order parser: one publication of the post-ACK fingerprint
//! (no truncated or empty-first lists), joins keyed on (pid, serial), and the safe drops.
//! All data is synthetic (documentation ranges, locally administered MACs).

use vigie_agent::dnsmasq::{parse_line, parse_line_pid, DhcpAssembler, LogEvent};
use vigie_agent::model::Lease;
use vigie_agent::window::Window;

const A: &str = "02:00:00:00:00:01";
const B: &str = "02:00:00:00:00:02";

fn lp(pid: u32, rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[{pid}]: {rest}")
}
fn l(rest: &str) -> String {
    lp(123, rest)
}
fn range(x: u32) -> String {
    l(&format!(
        "{x} available DHCP range: 192.0.2.10 -- 192.0.2.50"
    ))
}
fn vendor(x: u32, v: &str) -> String {
    l(&format!("{x} vendor class: {v}"))
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
/// One stream, then the end of the stream finishes a block that is still open.
fn run(lines: &[String]) -> Vec<Lease> {
    let mut a = DhcpAssembler::default();
    let mut out = feed(&mut a, lines);
    out.extend(a.break_context());
    out
}
fn head(x: u32, mac: &str, v: &str) -> Vec<String> {
    vec![range(x), vendor(x, v), req(x, mac), ack(x, mac)]
}
fn no_fp(lease: &Lease) -> bool {
    lease.opt55.is_empty() && lease.opt60.is_none()
}

// ---- CODEX-H2 / OPUS-4: one publication, never truncated, never empty-first ----

#[test]
fn a_window_flush_after_the_ack_keeps_an_existing_complete_pair() {
    let mut win = Window::default();
    win.add_lease(Lease::new(A, "192.0.2.10", None, &[1, 3, 6, 15], Some("v")).unwrap());
    win.take();
    let mut a = DhcpAssembler::default();
    for lease in feed(&mut a, &head(1, A, "v")) {
        win.add_lease(lease);
    }
    let got = win.take();
    assert_eq!(got.leases.len(), 1);
    assert_eq!(got.leases[0].opt55, vec![1, 3, 6, 15]);
    assert_eq!(got.leases[0].opt60.as_deref(), Some("v"));
}

#[test]
fn a_gap_before_the_options_leaves_an_existing_pair_alone() {
    let mut win = Window::default();
    win.add_lease(Lease::new(A, "192.0.2.10", None, &[1, 3, 6, 15], Some("v")).unwrap());
    let mut a = DhcpAssembler::default();
    for lease in feed(&mut a, &head(1, A, "v")) {
        win.add_lease(lease);
    }
    a.lose_context();
    assert!(a.end_poll().is_empty() && a.end_poll().is_empty());
    let got = win.take();
    assert_eq!(got.leases[0].opt55, vec![1, 3, 6, 15]);
}

#[test]
fn a_flush_between_option_lines_never_publishes_a_truncated_list() {
    let mut a = DhcpAssembler::default();
    let mut win = Window::default();
    let mut lines = head(1, A, "v");
    lines.push(opts(1, "1:netmask, 3:router"));
    for lease in feed(&mut a, &lines) {
        win.add_lease(lease);
    }
    assert!(a.end_poll().is_empty());
    let flushed = win.take();
    assert!(flushed.leases.iter().all(no_fp), "{:?}", flushed.leases);
    let mut all = feed(&mut a, &[opts(1, "6:dns-server, 15:domain-name")]);
    all.extend(a.end_poll());
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].opt55, vec![1, 3, 6, 15]);
    assert_eq!(all[0].opt60.as_deref(), Some("v"));
}

#[test]
fn a_gap_in_the_middle_of_the_block_publishes_nothing() {
    let mut a = DhcpAssembler::default();
    let mut lines = head(1, A, "v");
    lines.push(opts(1, "1:netmask, 3:router"));
    let mut got = feed(&mut a, &lines);
    a.lose_context();
    got.extend(feed(&mut a, &[opts(1, "6:dns-server")]));
    got.extend(a.end_poll());
    got.extend(a.end_poll());
    got.extend(a.break_context());
    assert_eq!(got.len(), 1, "only the ACK lease: {got:?}");
    assert!(no_fp(&got[0]));
}

#[test]
fn a_block_open_on_a_quiet_log_closes_after_one_more_poll() {
    let mut a = DhcpAssembler::default();
    let mut lines = head(1, A, "v");
    lines.push(opts(1, "1:netmask"));
    assert_eq!(feed(&mut a, &lines).len(), 1, "the ACK lease only");
    assert!(a.end_poll().is_empty(), "held through the first poll end");
    let closed = a.end_poll();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].opt55, vec![1]);
    assert!(a.end_poll().is_empty(), "published once");
    assert!(a.break_context().is_empty());
}

#[test]
fn a_vendor_only_block_publishes_the_vendor_when_it_closes() {
    let mut a = DhcpAssembler::default();
    assert_eq!(feed(&mut a, &head(1, A, "v")).len(), 1);
    a.end_poll();
    let closed = a.end_poll();
    assert_eq!(closed.len(), 1);
    assert!(closed[0].opt55.is_empty());
    assert_eq!(closed[0].opt60.as_deref(), Some("v"));
}

#[test]
fn a_new_mac_gets_its_full_pair_in_one_lease_and_none_before() {
    let mut lines = head(1, B, "vendor-b");
    lines.extend([opts(1, "1:netmask"), opts(1, "3:router")]);
    let got = run(&lines);
    assert_eq!(got.len(), 2);
    assert!(no_fp(&got[0]), "ACK lease carries nothing to first-win on");
    assert_eq!(got[1].opt55, vec![1, 3]);
    assert_eq!(got[1].opt60.as_deref(), Some("vendor-b"));
    assert_eq!((got[1].mac.as_str(), got[1].ip.as_str()), (B, "192.0.2.10"));
}

#[test]
fn json_shape_of_the_leases_is_unchanged() {
    let got = run(&[
        range(1),
        vendor(1, "v"),
        req(1, A),
        ack(1, A),
        opts(1, "1:netmask"),
    ]);
    let (mut first, mut second) = (String::new(), String::new());
    got[0].write(&mut first);
    got[1].write(&mut second);
    let pre = format!("{{\"mac\":\"{A}\",\"ip\":\"192.0.2.10\",\"hostname\":null,");
    assert_eq!(first, format!("{pre}\"opt55\":[],\"opt60\":null}}"));
    assert_eq!(second, format!("{pre}\"opt55\":[1],\"opt60\":\"v\"}}"));
}

// ---- OPUS-3: lines of different dnsmasq processes are never joined ----

#[test]
fn pid_is_parsed_from_the_syslog_prefix() {
    let (pid, ev) = parse_line_pid(&lp(4242, "7 tags: br-lan")).unwrap();
    assert_eq!((pid, ev), (4242, LogEvent::DhcpTags { id: "7".into() }));
    assert!(parse_line(&lp(4242, "7 tags: br-lan")).is_some());
}

#[test]
fn a_preamble_of_one_pid_never_reaches_the_request_of_another() {
    let got = run(&[
        lp(100, "5 available DHCP range: 192.0.2.10 -- 192.0.2.50"),
        lp(100, "5 vendor class: victim-vendor"),
        lp(200, &format!("5 DHCPREQUEST(br-lan) 192.0.2.10 {B}")),
        lp(200, &format!("5 DHCPACK(br-lan) 192.0.2.10 {B}")),
    ]);
    assert!(got.iter().all(|x| x.opt60.is_none()), "{got:?}");
}

#[test]
fn post_ack_options_of_another_pid_do_not_attach() {
    let got = run(&[
        range(5),
        req(5, A),
        ack(5, A),
        lp(200, "5 requested options: 1,121"),
    ]);
    assert!(got.iter().all(|x| x.opt55.is_empty()), "{got:?}");
}

#[test]
fn two_pids_may_reuse_one_serial_without_tainting_each_other() {
    let mut lines = head(5, A, "va");
    lines.extend([
        lp(200, "5 available DHCP range: 192.0.2.10 -- 192.0.2.50"),
        lp(200, "5 vendor class: vb"),
        lp(200, &format!("5 DHCPREQUEST(br-lan) 192.0.2.10 {B}")),
        lp(200, &format!("5 DHCPACK(br-lan) 192.0.2.10 {B}")),
        lp(200, "5 requested options: 3"),
    ]);
    let got = run(&lines);
    let b = got.iter().rfind(|x| x.mac == B).unwrap();
    assert_eq!((b.opt55.clone(), b.opt60.as_deref()), (vec![3], Some("vb")));
}

// ---- OPUS-6: lines we do not recognise drop the fingerprint, never leak it ----

#[test]
fn a_user_class_line_between_vendor_and_request_drops_the_preamble() {
    let got = run(&[
        range(1),
        vendor(1, "v"),
        l("1 user class: ignored"),
        req(1, A),
        ack(1, A),
    ]);
    assert!(got.iter().all(no_fp), "{got:?}");
}

#[test]
fn an_available_subnet_line_is_not_a_packet_start() {
    let got = run(&[
        l("1 available DHCP subnet: 192.0.2.0/255.255.255.0"),
        vendor(1, "v"),
        req(1, A),
        ack(1, A),
    ]);
    assert!(got.iter().all(no_fp), "{got:?}");
}

// ---- surviving mutants ----

#[test]
fn m01_a_marker_text_inside_a_value_is_still_that_lines_own_kind() {
    let v = vendor(1, "x available DHCP range: y");
    assert!(matches!(parse_line(&v), Some(LogEvent::DhcpVendor { .. })));
}

#[test]
fn m02_the_marker_value_is_bounded_and_control_free() {
    let long = l(&format!("1 available DHCP range: {}", "a".repeat(1100)));
    assert_eq!(parse_line(&long), None);
    assert_eq!(parse_line(&l("1 available DHCP range: a\u{7}b")), None);
}

#[test]
fn m08_a_marked_packet_of_a_foreign_mac_never_reaches_the_owner() {
    let got = run(&[
        req(1, A),
        range(1),
        vendor(1, "b-vendor"),
        req(1, B),
        ack(1, A),
    ]);
    assert!(got.iter().all(|x| x.opt60.is_none()), "{got:?}");
}

#[test]
fn m09_a_marked_retry_without_vendor_inherits_nothing() {
    let got = run(&[
        range(1),
        vendor(1, "v1"),
        req(1, A),
        range(1),
        req(1, A),
        ack(1, A),
    ]);
    assert!(got.iter().all(|x| x.opt60.is_none()), "{got:?}");
}

#[test]
fn m11_the_first_post_ack_line_replaces_an_older_list() {
    let got = run(&[req(1, A), opts(1, "1:a"), ack(1, A), opts(1, "3:b")]);
    assert_eq!(got.last().unwrap().opt55, vec![3]);
}

#[test]
fn m17_a_packet_start_ends_the_request_context() {
    let got = run(&[req(1, A), range(2), vendor(1, "x"), ack(1, A)]);
    assert!(got.iter().all(|x| x.opt60.is_none()), "{got:?}");
}

#[test]
fn m18_a_tags_line_inside_the_preamble_keeps_it() {
    let lines = [
        range(1),
        l("1 tags: br-lan"),
        vendor(1, "v"),
        req(1, A),
        ack(1, A),
    ];
    let got = run(&lines);
    assert_eq!(got.last().unwrap().opt60.as_deref(), Some("v"));
}

// ---- the window never shrinks a complete pair through the options-less close ----

#[test]
fn a_vendor_only_close_does_not_shrink_a_stored_pair_of_the_same_vendor() {
    let mut win = Window::default();
    win.add_lease(Lease::new(A, "192.0.2.10", None, &[1, 3], Some("v")).unwrap());
    let mut a = DhcpAssembler::default();
    let mut got = feed(&mut a, &head(1, A, "v"));
    got.extend(a.break_context());
    assert_eq!(got.len(), 2);
    for lease in got {
        win.add_lease(lease);
    }
    let s = win.take();
    assert_eq!(s.leases[0].opt55, vec![1, 3]);
    assert_eq!(s.leases[0].opt60.as_deref(), Some("v"));
}

#[test]
fn a_different_vendor_class_still_replaces_the_pair_as_one_unit() {
    let mut win = Window::default();
    win.add_lease(Lease::new(A, "192.0.2.10", None, &[1, 3], Some("old")).unwrap());
    win.add_lease(Lease::new(A, "192.0.2.10", None, &[], Some("new")).unwrap());
    let s = win.take();
    assert!(s.leases[0].opt55.is_empty());
    assert_eq!(s.leases[0].opt60.as_deref(), Some("new"));
}
