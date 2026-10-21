//! The server rejects a whole batch whose `truncated` map has more than 16 keys. The builder
//! already emits up to 15 of its own; the source wiring adds more, so the builder must cap.

use std::collections::BTreeMap;
use vigie_agent::builder::{build_with_drops, BATCH_CAP};
use vigie_agent::model::{Health, Meta, Sections};

fn meta() -> Meta {
    Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq: 1,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: 1_760_000_000,
        window_end: 1_760_000_060,
    }
}

fn drops(n: usize) -> BTreeMap<String, u64> {
    (0..n)
        .map(|i| (format!("drop_{}", (b'a' + i as u8) as char), i as u64 + 1))
        .collect()
}

fn build(d: &BTreeMap<String, u64>) -> vigie_agent::builder::Built {
    build_with_drops(
        &meta(),
        Sections::default(),
        &Health::default(),
        BATCH_CAP,
        d,
    )
}

#[test]
fn truncated_never_exceeds_sixteen_keys_and_conserves_counts() {
    let mut d = drops(24);
    d.insert("source_flags".into(), 0b1010);
    let sum: u64 = d
        .iter()
        .filter(|(k, _)| *k != "source_flags")
        .map(|(_, v)| *v)
        .sum();
    let b = build(&d);
    assert!(b.truncated.len() <= 16, "{} keys", b.truncated.len());
    assert_eq!(
        b.truncated.get("source_flags"),
        Some(&0b1010),
        "bitmask kept verbatim"
    );
    let kept: u64 = b
        .truncated
        .iter()
        .filter(|(k, _)| *k != "source_flags")
        .map(|(_, v)| *v)
        .sum();
    assert_eq!(kept, sum, "overflow keys are summed, not lost");
    let text = String::from_utf8(b.encoded.body(1_760_000_061, 0)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(v["truncated"].as_object().unwrap().len() <= 16);
}

#[test]
fn the_largest_counts_keep_their_own_key() {
    let d = drops(24);
    let b = build(&d);
    assert_eq!(b.truncated.get("drop_x"), Some(&24), "largest kept by name");
    assert!(!b.truncated.contains_key("drop_a"), "smallest merged");
    assert!(b.truncated.contains_key("truncated_other"));
}

#[test]
fn under_the_cap_nothing_is_merged() {
    let d = drops(10);
    assert_eq!(build(&d).truncated, d);
}

#[test]
fn exactly_sixteen_keys_is_left_alone() {
    let d = drops(16);
    assert_eq!(build(&d).truncated, d);
}
