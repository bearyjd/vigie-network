//! Property test: the actual-order fixture is replayed through the real `Agent::poll_log` split
//! at every one of the 512 line-boundary patterns, with and without one idle poll (a poll that
//! finds no new line) after any line. Synthetic data only.
//!
//! Expected outcome by where the idle poll falls (line numbers are 0-based fixture lines):
//! - none, or after a line >= 7: the unsplit result (full list + vendor);
//! - 0..=4 (the preamble / old-order context goes quiet for two EOF polls): the pending entry
//!   is dropped as unusable, so NO fingerprint is published at all (the window keeps whatever
//!   pair it stored) and never a vendor-less or truncated one;
//! - 5 (block stalls straight after the ACK): the documented post-ACK limit, options-less;
//! - 6 (block stalls mid-list): the documented post-ACK limit, the truncated list `[1, 3]`.
use super::*;
use vigie_agent::model::Lease;

const FIX: &str = include_str!("../../tests/fixtures/dhcp-actual-order.synthetic.log");
const FULL: [u8; 4] = [1, 3, 6, 15];
const VENDOR: &str = "fixture-vendor";

fn lines() -> Vec<String> {
    FIX.lines().map(|l| format!("{l}\n")).collect()
}

/// Lines appended before each poll for split `mask` (bit i set: poll after line i) and an
/// optional idle poll after line `idle`.
fn schedule(mask: u32, idle: Option<usize>) -> Vec<Vec<String>> {
    let ls = lines();
    let (mut out, mut cur) = (Vec::new(), Vec::new());
    for (i, l) in ls.iter().enumerate() {
        cur.push(l.clone());
        if i + 1 == ls.len() || (mask >> i) & 1 == 1 || idle == Some(i) {
            out.push(std::mem::take(&mut cur));
        }
        if idle == Some(i) {
            out.push(Vec::new());
        }
    }
    out
}

/// Plays `sched` (then three closing polls) and returns every lease the window published.
fn play(a: &mut Agent, path: &std::path::Path, sched: &[Vec<String>], t0: u64) -> Vec<Lease> {
    let mut out = Vec::new();
    for (t, chunk) in sched.iter().enumerate() {
        append(path, &chunk.concat());
        a.poll_log(t0 + t as u64);
        out.extend(a.window.take_identity().leases);
    }
    for t in 0..3 {
        a.poll_log(t0 + 100 + t);
        out.extend(a.window.take_identity().leases);
    }
    out
}

/// Publications that carry a fingerprint, as (options, vendor).
fn fps(v: &[Lease]) -> Vec<(Vec<u8>, Option<String>)> {
    v.iter()
        .filter(|l| !l.opt55.is_empty() || l.opt60.is_some())
        .map(|l| (l.opt55.clone(), l.opt60.clone()))
        .collect()
}

fn expected(idle: Option<usize>) -> Vec<(Vec<u8>, Option<String>)> {
    let v = Some(VENDOR.to_string());
    match idle {
        Some(0..=4) => vec![],
        Some(5) => vec![(vec![], v)],
        Some(6) => vec![(vec![1, 3], v)],
        _ => vec![(FULL.to_vec(), v)],
    }
}

fn idles() -> impl Iterator<Item = Option<usize>> {
    std::iter::once(None).chain((0..lines().len()).map(Some))
}

#[test]
fn prop_split_every_boundary() {
    let n = lines().len();
    assert_eq!(n, 10);
    let mut bad = Vec::new();
    for mask in 0..(1u32 << (n - 1)) {
        for idle in idles() {
            let (mut a, path) = log_agent(&format!("prop-{mask}-{idle:?}"));
            let got = play(&mut a, &path, &schedule(mask, idle), 1);
            std::fs::remove_file(path).ok();
            if fps(&got) != expected(idle)
                || got
                    .iter()
                    .any(|l| l.hostname.as_deref() != Some("fixture-client"))
            {
                bad.push(format!("mask={mask:09b} idle={idle:?} got={:?}", fps(&got)));
            }
        }
    }
    let busy = bad
        .iter()
        .filter(|b| b.ends_with("None") || b.contains("idle=None"))
        .count();
    assert!(
        bad.is_empty(),
        "{} mismatches ({busy} with a new line in every poll), first: {:?}",
        bad.len(),
        &bad[..bad.len().min(3)]
    );
}

#[test]
fn prop_renew_split_keeps_the_stored_pair() {
    let mut bad = Vec::new();
    for mask in 0..(1u32 << 9) {
        for idle in idles().filter(|i| *i != Some(6)) {
            let (mut a, path) = log_agent(&format!("renew-{mask}-{idle:?}"));
            append(&path, FIX);
            for t in 1..=3 {
                a.poll_log(t);
            }
            let first = a.window.take_identity().leases;
            assert_eq!(fps(&first), vec![(FULL.to_vec(), Some(VENDOR.to_string()))]);
            // Renewal (serial 2): the stored pair must survive whatever the poll pattern.
            let renew: Vec<String> = lines()
                .iter()
                .map(|l| l.replacen(": 1 ", ": 2 ", 1))
                .collect();
            let sched: Vec<Vec<String>> = {
                let mut s = schedule(mask, idle);
                let mut it = renew.into_iter();
                for chunk in s.iter_mut() {
                    *chunk = chunk.iter().map(|_| it.next().unwrap()).collect();
                }
                s
            };
            let got = play(&mut a, &path, &sched, 10);
            std::fs::remove_file(path).ok();
            let last = got.iter().rfind(|l| l.mac == "02:00:00:00:00:01");
            let ok = last.is_some_and(|l| l.opt55 == FULL && l.opt60.as_deref() == Some(VENDOR));
            if !ok {
                bad.push(format!("mask={mask:09b} idle={idle:?} last={last:?}"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} lost the stored pair, first: {:?}",
        bad.len(),
        &bad[..bad.len().min(5)]
    );
}
