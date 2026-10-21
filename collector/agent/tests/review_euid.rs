//! Re-review item 4: the agent refuses to run as root (euid 0) unless `--allow-root` is given.
//! The decision is a pure function over the text of /proc/self/status.

use vigie_agent::procstat::{parse_euid, root_refusal};

fn status(uids: &str) -> String {
    format!("Name:\tvigie-collector\nUmask:\t0022\nUid:\t{uids}\nGid:\t6700\t6700\t6700\t6700\n")
}

#[test]
fn effective_uid_is_the_second_field() {
    assert_eq!(parse_euid(&status("1000\t0\t0\t0")), Some(0));
    assert_eq!(parse_euid(&status("0\t6700\t6700\t6700")), Some(6700));
    assert_eq!(parse_euid("Name:\tx\n"), None);
    assert_eq!(parse_euid("Uid:\t0\n"), None);
    assert_eq!(parse_euid("Uid:\t0\tx\t0\t0\n"), None);
    assert_eq!(parse_euid(""), None);
}

#[test]
fn root_is_refused_without_the_explicit_flag() {
    let root = status("0\t0\t0\t0");
    let msg = root_refusal(Some(&root), false).expect("must refuse");
    assert!(
        msg.contains("root") && msg.contains("--allow-root"),
        "{msg}"
    );
    assert_eq!(root_refusal(Some(&root), true), None, "explicit opt-in");
}

#[test]
fn effective_root_is_refused_even_with_a_nonzero_real_uid() {
    assert!(root_refusal(Some(&status("1000\t0\t0\t0")), false).is_some());
}

#[test]
fn the_dedicated_user_is_accepted() {
    assert_eq!(
        root_refusal(Some(&status("6700\t6700\t6700\t6700")), false),
        None
    );
}

#[test]
fn an_unreadable_or_unparseable_status_fails_closed() {
    assert!(root_refusal(None, false).is_some());
    assert!(root_refusal(Some("garbage"), false).is_some());
    assert_eq!(root_refusal(None, true), None);
}
