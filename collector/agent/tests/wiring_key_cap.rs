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

#[test]
fn ct_unmapped_flows_is_reported_when_there_is_room() {
    let mut d = drops(5);
    d.insert("ct_unmapped_flows".into(), 3);
    assert_eq!(build(&d).truncated, d);
}

#[test]
fn ct_unmapped_flows_is_the_first_key_merged_even_when_it_is_the_largest() {
    // 14 other keys plus source_flags, ct_unmapped_bytes and ct_unmapped_flows: 17 keys, so two
    // rows must merge. Flows is the companion of ct_unmapped_bytes, so it yields before any other
    // key whatever its count; the second is then the smallest count (drop_a = 1).
    let mut d = drops(14);
    d.insert("source_flags".into(), 5);
    d.insert("ct_unmapped_bytes".into(), 2);
    d.insert("ct_unmapped_flows".into(), 1_000_000);
    let b = build(&d);
    assert_eq!(b.truncated.len(), 16, "{:?}", b.truncated);
    assert!(!b.truncated.contains_key("ct_unmapped_flows"));
    assert!(!b.truncated.contains_key("drop_a"));
    assert_eq!(b.truncated.get("ct_unmapped_bytes"), Some(&2), "bytes kept");
    assert_eq!(b.truncated.get("drop_b"), Some(&2));
    assert_eq!(b.truncated.get("source_flags"), Some(&5));
    assert_eq!(b.truncated["truncated_other"], 1_000_001);
}
