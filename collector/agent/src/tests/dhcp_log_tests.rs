//! Log-to-window tests through the real `Agent::poll_log` path (tail, assembler, window).
//! All data is synthetic (documentation ranges, locally administered MACs).

use super::*;
use std::fs;
use std::path::Path;

const MAC_A: &str = "02:00:00:00:00:01";
const MAC_B: &str = "02:00:00:00:00:02";

fn l(rest: &str) -> String {
    format!("Oct 20 14:00:00 dnsmasq-dhcp[123]: {rest}\n")
}
fn packet(x: u32, mac: &str, vendor: &str) -> String {
    [
        format!("{x} available DHCP range: 192.0.2.10 -- 192.0.2.50"),
        format!("{x} vendor class: {vendor}"),
        format!("{x} DHCPREQUEST(br-lan) 192.0.2.10 {mac}"),
        format!("{x} DHCPACK(br-lan) 192.0.2.10 {mac}"),
    ]
    .iter()
    .map(|s| l(s))
    .collect()
}
fn opts(x: u32, list: &str) -> String {
    l(&format!("{x} requested options: {list}"))
}
/// The leases waiting in the window (the identity push is gated off in these tests).
fn leases(a: &mut Agent) -> Vec<Lease> {
    a.window.take_identity().leases
}
fn lease_of(all: &[Lease], mac: &str) -> Lease {
    all.iter().find(|x| x.mac == mac).cloned().expect("lease")
}
fn rotate(path: &Path, to: &str, new_content: &str) {
    fs::rename(path, path.with_extension(to)).unwrap();
    fs::write(path, new_content).unwrap();
}

#[test]
fn two_rotations_between_polls_never_attach_options_to_the_old_mac() {
    let (mut a, path) = log_agent("h1");
    append(&path, &packet(1, MAC_A, "vendor-a"));
    a.poll_log(1);
    // An intermediate file holds a whole packet of another client, then a second rotation.
    rotate(
        &path,
        "2",
        &(packet(2, MAC_B, "vendor-b") + &opts(2, "3:router")),
    );
    rotate(&path, "1", &opts(1, "6:dns-server, 15:domain-name"));
    a.poll_log(2);
    a.poll_log(3);
    let all = leases(&mut a);
    let lease = lease_of(&all, MAC_A);
    assert!(lease.opt55.is_empty(), "{lease:?}");
    assert_eq!(lease.opt60, None);
    assert!(all.iter().all(|x| !x.opt55.contains(&6)), "{all:?}");
    for ext in ["1", "2"] {
        fs::remove_file(path.with_extension(ext)).ok();
    }
    fs::remove_file(path).ok();
}

#[test]
fn an_overlong_line_between_ack_and_options_leaves_the_fingerprint_empty() {
    let (mut a, path) = log_agent("m19");
    append(&path, &packet(1, MAC_A, "vendor-a"));
    append(&path, &format!("{}\n", "z".repeat(5000)));
    append(&path, &opts(1, "1:netmask, 3:router"));
    a.poll_log(1);
    a.poll_log(2);
    a.poll_log(3);
    let lease = lease_of(&leases(&mut a), MAC_A);
    assert!(lease.opt55.is_empty(), "{lease:?}");
    assert_eq!(lease.opt60, None);
    fs::remove_file(path).ok();
}

#[test]
fn a_complete_block_is_published_once_by_an_unparsed_line_or_the_second_poll() {
    let (mut a, path) = log_agent("close");
    append(
        &path,
        &(packet(1, MAC_A, "vendor-a") + &opts(1, "1:netmask, 3:router")),
    );
    a.poll_log(1);
    let first = lease_of(&leases(&mut a), MAC_A);
    assert!(first.opt55.is_empty() && first.opt60.is_none(), "{first:?}");
    a.poll_log(2);
    let closed = lease_of(&leases(&mut a), MAC_A);
    assert_eq!(closed.opt55, vec![1, 3]);
    assert_eq!(closed.opt60.as_deref(), Some("vendor-a"));
    // A foreign line after the options finishes the block within the same poll.
    append(
        &path,
        &(packet(2, MAC_B, "vendor-b") + &opts(2, "6:dns-server")),
    );
    append(&path, "not a dnsmasq line\n");
    a.poll_log(3);
    let b = lease_of(&leases(&mut a), MAC_B);
    assert_eq!(
        (b.opt55.clone(), b.opt60.as_deref()),
        (vec![6], Some("vendor-b"))
    );
    fs::remove_file(path).ok();
}

/// A path that names itself: every stat of it fails with ELOOP, also for root.
fn break_path(path: &Path) {
    std::os::unix::fs::symlink(path, path).unwrap();
}
fn mend_path(path: &Path, content: &str) {
    fs::remove_file(path).unwrap();
    fs::write(path, content).unwrap();
}
fn drop_count(a: &mut Agent, kind: &str) -> u64 {
    a.window
        .take_with_drops()
        .1
        .get(kind)
        .copied()
        .unwrap_or_default()
}

#[test]
fn a_failed_poll_never_publishes_the_held_block_ahead_of_the_pending_gap() {
    let (mut a, path) = log_agent("errpoll");
    append(
        &path,
        &(packet(1, MAC_A, "vendor-a") + &opts(1, "1:netmask, 3:router")),
    );
    a.poll_log(1);
    // The continuation lands in the rotated-to file, which cannot be reached right now.
    fs::rename(&path, path.with_extension("1")).unwrap();
    break_path(&path);
    a.poll_log(2);
    assert_eq!(
        drop_count(&mut a, "tail_open_failed"),
        1,
        "poll 2 must fail"
    );
    mend_path(&path, &opts(1, "6:dns-server"));
    a.poll_log(3);
    a.poll_log(4);
    let all = leases(&mut a);
    assert!(all.iter().all(|x| x.opt55.is_empty()), "{all:?}");
    assert!(all.iter().all(|x| x.opt60.is_none()), "{all:?}");
    fs::remove_file(path.with_extension("1")).ok();
    fs::remove_file(path).ok();
}

#[test]
fn a_suppressed_tail_error_never_lets_a_truncated_block_publish() {
    let (mut a, path) = log_agent("suppressed");
    append(&path, &packet(1, MAC_A, "vendor-a"));
    a.poll_log(1);
    append(&path, &opts(1, "1:netmask, 3:router"));
    fs::rename(&path, path.with_extension("1")).unwrap();
    break_path(&path);
    // The old file is drained, the rotation stat fails: the lines come back, the failure is
    // only counted, and the list may continue in the file that cannot be reached yet.
    a.poll_log(2);
    mend_path(&path, &opts(1, "6:dns-server, 15:domain-name"));
    a.poll_log(3);
    a.poll_log(4);
    let all = leases(&mut a);
    assert!(all.iter().all(|x| x.opt55.is_empty()), "{all:?}");
    fs::remove_file(path.with_extension("1")).ok();
    fs::remove_file(path).ok();
}

#[test]
fn a_poll_that_stopped_at_its_byte_budget_does_not_close_the_block() {
    let (mut a, path) = log_agent("budget");
    let query =
        "Oct 20 14:00:00 dnsmasq[456]: 9 192.0.2.99/5353 query[A] example.test from 192.0.2.99\n";
    let n = 2 * vigie_agent::tail::MAX_POLL_BYTES as usize / query.len() + 2000;
    let mut stream = packet(1, MAC_A, "vendor-a") + &opts(1, "1:netmask, 3:router");
    stream += &query.repeat(n);
    stream += &opts(1, "6:dns-server, 15:domain-name");
    append(&path, &stream);
    for t in 1..=4 {
        a.poll_log(t);
    }
    let lease = lease_of(&leases(&mut a), MAC_A);
    assert_eq!(lease.opt55, vec![1, 3, 6, 15], "{lease:?}");
    assert_eq!(lease.opt60.as_deref(), Some("vendor-a"));
    fs::remove_file(path).ok();
}

#[test]
fn a_query_of_another_pid_through_poll_log_keeps_the_whole_list() {
    let (mut a, path) = log_agent("k27");
    append(
        &path,
        &(packet(1, MAC_A, "vendor-a") + &opts(1, "1:netmask, 3:router")),
    );
    append(
        &path,
        "Oct 20 14:00:00 dnsmasq[456]: 9 192.0.2.99/5353 query[A] example.test from 192.0.2.99\n",
    );
    append(&path, &opts(1, "6:dns-server, 15:domain-name"));
    a.poll_log(1);
    a.poll_log(2);
    let lease = lease_of(&leases(&mut a), MAC_A);
    assert_eq!(lease.opt55, vec![1, 3, 6, 15], "{lease:?}");
    fs::remove_file(path).ok();
}

#[test]
fn a_failed_open_never_turns_the_tail_of_a_torn_line_into_a_lease() {
    use std::os::unix::net::UnixListener;
    let (mut a, path) = log_agent("tornopen");
    append(
        &path,
        "Oct 20 14:00:00 dnsmasq-dhcp[123]: 5 vendor class: zz",
    );
    a.poll_log(1);
    // The new file at the path cannot be opened (a socket: ENXIO, also for root).
    fs::rename(&path, path.with_extension("1")).unwrap();
    let sock = UnixListener::bind(&path).unwrap();
    a.poll_log(2);
    // The writer finishes the torn line in the renamed file.
    append(
        &path.with_extension("1"),
        &l(&format!("9 DHCPACK(br-lan) 192.0.2.77 {MAC_B}")),
    );
    drop(sock);
    mend_path(&path, "");
    a.poll_log(3);
    a.poll_log(4);
    let all = leases(&mut a);
    assert!(all.iter().all(|x| x.mac != MAC_B), "forged lease: {all:?}");
    fs::remove_file(path.with_extension("1")).ok();
    fs::remove_file(path).ok();
}

#[test]
fn k32_dhcp_counters_reach_the_window() {
    let (mut a, path) = log_agent("k32");
    let line = |pid: u32, rest: &str| format!("Oct 20 14:00:00 dnsmasq-dhcp[{pid}]: {rest}\n");
    let mac = "02:00:00:00:00:01";
    let mut text = String::new();
    for (pid, x) in [(100, 7), (200, 8)] {
        text += &line(pid, &format!("{x} DHCPREQUEST(br-lan) 192.0.2.10 {mac}"));
        text += &line(pid, &format!("{x} DHCPACK(br-lan) 192.0.2.10 {mac}"));
    }
    append(&path, &text);
    a.poll_log(1);
    let drops = a.window.take_with_drops().1;
    std::fs::remove_file(path).ok();
    assert_eq!(drops.get("dhcp_block_superseded"), Some(&1), "{drops:?}");
}
