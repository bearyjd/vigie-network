//! Security review item 5: no windows are built from an unverified wall clock; an NTP step
//! before the first server contact must not lose or mis-time data; stale 422s are counted.

use std::collections::BTreeMap;

use vigie_agent::builder::{build, BATCH_CAP};
use vigie_agent::model::*;
use vigie_agent::sender::*;
use vigie_agent::syncstate::{FlushPlan, SyncState};
use vigie_agent::window::{Window, WindowClock};

const BUILD_TS: u64 = 1_760_000_000;
const BOOT_WALL: u64 = 1_760_000_100; // sysfixtime-style stale clock, just after the build date
const MAC: &str = "aa:bb:cc:dd:ee:01";

fn engine() -> Engine {
    Engine::new(
        Identity {
            collector_id: "c1".into(),
            key_id: "k1".into(),
            boot_id: "boot1".into(),
        },
        vec![7; 32],
        BUILD_TS,
        1024 * 1024,
    )
}

fn meta(seq: u64, start: u64, end: u64) -> Meta {
    Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq,
        batch_id: format!("01927f3e-8a1b-7c2d-9e4f-{seq:012x}"),
        window_start: start,
        window_end: end,
    }
}

struct Reply(u16, Option<u64>, &'static str);

impl Transport for Reply {
    fn post(&mut self, _h: &Headers, _b: &[u8]) -> Result<HttpReply, TransportError> {
        Ok(HttpReply {
            status: self.0,
            date: self.1,
            body: self.2.as_bytes().to_vec(),
        })
    }
}

#[test]
fn nothing_is_built_before_a_server_date_and_the_probe_gets_one() {
    let s = SyncState::new();
    assert!(!s.is_synced());
    assert_eq!(
        s.plan(true),
        FlushPlan::Probe,
        "sane-looking clock is not enough"
    );
    assert_eq!(s.plan(false), FlushPlan::Probe);
}

#[test]
fn urgent_pushes_need_a_synced_and_sane_clock() {
    let mut s = SyncState::new();
    assert!(!s.allow_identity_push(true), "no server Date yet");
    s.observe(true, 5_000, 10);
    assert!(s.allow_identity_push(true));
    assert!(
        !s.allow_identity_push(false),
        "clock disagrees with the server"
    );
}

#[test]
fn after_first_date_windows_are_built_unless_the_clock_is_off() {
    let mut s = SyncState::new();
    assert_eq!(s.observe(false, 5_000, 10), None, "no Date yet");
    assert!(!s.is_synced());
    assert_eq!(
        s.observe(true, 5_000, 10),
        Some(4_990),
        "wall - mono offset"
    );
    assert!(s.is_synced());
    assert_eq!(s.observe(true, 6_000, 20), None, "reported once");
    assert_eq!(s.plan(true), FlushPlan::Build);
    assert_eq!(
        s.plan(false),
        FlushPlan::Hold,
        "a later step holds, as before"
    );
}

#[test]
fn provisional_rows_carry_monotonic_stamps_then_wall_stamps() {
    let mut s = SyncState::new();
    assert_eq!(s.stamp(1_760_000_555, 42), 42);
    s.observe(true, 1_760_000_555, 42);
    assert_eq!(s.stamp(1_760_000_600, 87), 1_760_000_600);
}

#[test]
fn ntp_step_before_first_contact_keeps_rows_correctly_timed() {
    let mut sync = SyncState::new();
    let mut win = Window::default();
    let mut eng = engine();
    let q =
        |ts: u64, n: u32| DnsQuery::new(ts, MAC, &format!("n{n}.example.com"), "A", None).unwrap();
    // Three queries read before NTP stepped the clock (wall = BOOT_WALL + mono).
    for (n, mono) in [5u64, 20, 50].into_iter().enumerate() {
        win.add_dns(q(sync.stamp(BOOT_WALL + mono, mono), n as u32));
    }
    // NTP steps the wall clock forward by five days; first flush attempt at mono 61.
    let (mono, real_wall) = (61u64, BOOT_WALL + 5 * 86_400 + 61);
    assert_eq!(
        sync.plan(eng.gate.is_sane(real_wall, mono)),
        FlushPlan::Probe
    );
    assert_eq!(
        win.dns_count(),
        3,
        "window kept, not built from a stepped clock"
    );

    // Probe: an empty batch gets us a Date even if the server rejects it.
    let probe = encode(
        &meta(1, real_wall, real_wall),
        &Sections::default(),
        &BTreeMap::new(),
        &Health::default(),
    );
    eng.enqueue(probe);
    let mut t = Reply(422, Some(real_wall), "{\"error\":\"invalid_batch\"}");
    eng.tick(&mut t, real_wall, mono, 0);
    let offset = sync
        .observe(eng.gate.has_server_date(), real_wall, mono)
        .expect("Date observed");
    win.rebase_dns(offset);
    assert_eq!(
        sync.plan(eng.gate.is_sane(real_wall, mono)),
        FlushPlan::Build
    );

    let clock = WindowClock::new(0);
    let start = clock.start(real_wall, mono);
    let (sections, drops) = win.take_with_drops();
    let b = build(
        &meta(2, start, real_wall),
        sections,
        &Health::default(),
        BATCH_CAP,
    );
    assert!(drops.is_empty());
    assert!(
        b.truncated.is_empty(),
        "no row fell outside the window: {:?}",
        b.truncated
    );
    let body = String::from_utf8(b.encoded.body(real_wall, 0)).unwrap();
    for mono_row in [5u64, 20, 50] {
        let want = real_wall - (mono - mono_row);
        assert!(
            body.contains(&format!("\"ts\":{want}")),
            "row {mono_row} re-timed to {want}"
        );
    }
}

// ---- stale 422 ----

fn stale_batch(window_end: u64) -> EncodedBatch {
    encode(
        &meta(9, window_end - 60, window_end),
        &Sections::default(),
        &BTreeMap::new(),
        &Health::default(),
    )
}

#[test]
fn a_422_for_a_window_older_than_the_spool_age_is_counted_as_stale() {
    let mut eng = engine();
    let now = BUILD_TS + 10 * 86_400;
    eng.enqueue(stale_batch(now - 2 * 86_400));
    let mut t = Reply(422, None, "{\"error\":\"invalid_batch\"}");
    assert_eq!(eng.tick(&mut t, now, 1, 0), Tick::DiscardedStale);
    assert_eq!(eng.dropped_stale, 1);
    assert_eq!(
        eng.spool.dropped_unreported(),
        1,
        "the server is still told one batch was lost"
    );
    assert_eq!(eng.spool.len(), 0);
}

#[test]
fn a_422_for_a_fresh_window_is_a_plain_discard() {
    let mut eng = engine();
    let now = BUILD_TS + 10 * 86_400;
    eng.enqueue(stale_batch(now - 60));
    let mut t = Reply(422, None, "{\"error\":\"invalid_batch\"}");
    assert_eq!(eng.tick(&mut t, now, 1, 0), Tick::Discarded(422));
    assert_eq!(eng.dropped_stale, 0);
}
