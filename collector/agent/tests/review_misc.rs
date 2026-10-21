//! Security review items 7 (urgent table eviction) and 8 (duplicate must not acknowledge drops).

use vigie_agent::model::*;
use vigie_agent::sender::*;
use vigie_agent::urgent::{Urgent, MAX_TRACKED_MACS, MIN_INTERVAL_MS};

fn mac_n(n: usize) -> String {
    format!(
        "02:00:00:{:02x}:{:02x}:{:02x}",
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff
    )
}

#[test]
fn urgent_table_evicts_the_oldest_instead_of_disabling_itself() {
    let mut u = Urgent::new();
    let mut t = 0u64;
    for n in 0..MAX_TRACKED_MACS {
        u.on_lease(&mac_n(n), t);
        t += MIN_INTERVAL_MS;
    }
    // Table is full. A brand new MAC must still trigger an urgent push.
    t += MIN_INTERVAL_MS;
    assert!(
        u.on_lease(&mac_n(MAX_TRACKED_MACS + 1), t),
        "new MAC after the table filled"
    );
    // The oldest entry was evicted, so it counts as new again; a recent one does not.
    t += MIN_INTERVAL_MS;
    assert!(u.on_lease(&mac_n(0), t), "oldest MAC was evicted");
    t += MIN_INTERVAL_MS;
    assert!(
        !u.on_lease(&mac_n(MAX_TRACKED_MACS - 1), t),
        "recent MAC still tracked"
    );
}

fn enc(seq: u64) -> EncodedBatch {
    let meta = Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq,
        batch_id: format!("01927f3e-8a1b-7c2d-9e4f-{seq:012x}"),
        window_start: 1_760_100_000 - 60,
        window_end: 1_760_100_000,
    };
    encode(
        &meta,
        &Sections::default(),
        &std::collections::BTreeMap::new(),
        &Health::default(),
    )
}

struct Reply(&'static str);
impl Transport for Reply {
    fn post(&mut self, _h: &Headers, _b: &[u8]) -> Result<HttpReply, TransportError> {
        Ok(HttpReply {
            status: 200,
            date: None,
            body: self.0.as_bytes().to_vec(),
        })
    }
}

fn engine() -> Engine {
    Engine::new(
        Identity {
            collector_id: "c1".into(),
            key_id: "k1".into(),
            boot_id: "boot1".into(),
        },
        vec![7; 32],
        1_760_000_000,
        1024 * 1024,
    )
}

#[test]
fn duplicate_ack_does_not_subtract_the_retrys_dropped_value() {
    let mut e = engine();
    e.spool.note_dropped(3);
    e.enqueue(enc(1));
    assert_eq!(
        e.tick(&mut Reply(r#"{"duplicate":true}"#), 1_760_100_000, 10, 1),
        Tick::Sent { duplicate: true }
    );
    assert_eq!(
        e.spool.dropped_unreported(),
        3,
        "not acknowledged, will be reported again"
    );
}

#[test]
fn a_fresh_ack_subtracts_exactly_what_it_carried() {
    let mut e = engine();
    e.spool.note_dropped(3);
    e.enqueue(enc(1));
    assert_eq!(
        e.tick(&mut Reply(r#"{"duplicate":false}"#), 1_760_100_000, 10, 1),
        Tick::Sent { duplicate: false }
    );
    assert_eq!(e.spool.dropped_unreported(), 0);
}

// ---- item 9: no weak-randomness fallback ----

#[test]
fn random_fails_hard_when_the_source_is_unavailable_or_short() {
    use vigie_agent::runtime::random_from;
    assert!(random_from::<16>(std::path::Path::new("/nonexistent/urandom")).is_err());
    let short = std::env::temp_dir().join(format!("vigie-short-{}", std::process::id()));
    std::fs::write(&short, [1u8; 4]).unwrap();
    assert!(
        random_from::<16>(&short).is_err(),
        "a short read is an error, never padded"
    );
    std::fs::remove_file(&short).unwrap();
    let a = random_from::<16>(std::path::Path::new("/dev/urandom")).unwrap();
    let b = random_from::<16>(std::path::Path::new("/dev/urandom")).unwrap();
    assert_ne!(a, b);
}

#[test]
fn runtime_source_has_no_clock_seeded_fallback() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/runtime.rs")).unwrap();
    assert!(
        !src.contains("x << 13"),
        "xorshift fallback must stay removed"
    );
}
