use std::collections::BTreeMap;

use vigie_agent::backoff::Backoff;
use vigie_agent::model::*;
use vigie_agent::sender::*;
use vigie_agent::sign;
use vigie_agent::spool::Spool;
use vigie_agent::timegate::TimeGate;
use vigie_agent::urgent::Urgent;

const BUILD_TS: u64 = 1_760_000_000;
const NOW: u64 = 1_760_100_000;
const KEY: [u8; 32] = [7; 32];

fn enc(seq: u64, pad: usize) -> EncodedBatch {
    let meta = Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq,
        batch_id: format!("01927f3e-8a1b-7c2d-9e4f-{seq:012x}"),
        window_start: NOW - 60,
        window_end: NOW,
    };
    let mut s = Sections::default();
    if pad > 0 {
        s.leases.push(
            Lease::new(
                "aa:bb:cc:dd:ee:01",
                "10.0.0.1",
                Some(&"h".repeat(pad)),
                &[],
                None,
            )
            .unwrap(),
        );
    }
    encode(&meta, &s, &BTreeMap::new(), &Health::default())
}

fn engine() -> Engine {
    Engine::new(
        Identity {
            collector_id: "c1".into(),
            key_id: "k1".into(),
            boot_id: "boot1".into(),
        },
        KEY.to_vec(),
        BUILD_TS,
        1024 * 1024,
    )
}

struct Fake {
    replies: Vec<Result<HttpReply, TransportError>>,
    calls: Vec<(Headers, Vec<u8>)>,
}

impl Fake {
    fn new(replies: Vec<Result<HttpReply, TransportError>>) -> Self {
        Self {
            replies,
            calls: vec![],
        }
    }
}

impl Transport for Fake {
    fn post(&mut self, h: &Headers, body: &[u8]) -> Result<HttpReply, TransportError> {
        self.calls.push((h.clone(), body.to_vec()));
        self.replies.remove(0)
    }
}

fn reply(status: u16, body: &str) -> Result<HttpReply, TransportError> {
    Ok(HttpReply {
        status,
        date: None,
        body: body.as_bytes().to_vec(),
    })
}

// ---- spool ----

#[test]
fn spool_drops_oldest_and_counts() {
    let one = enc(1, 1000).len();
    let mut sp = Spool::new(one * 3 + 10);
    for seq in 1..=5 {
        sp.push(enc(seq, 1000));
    }
    assert_eq!(sp.len(), 3);
    assert!(sp.bytes() <= one * 3 + 10);
    assert_eq!(sp.dropped_unreported(), 2);
    assert_eq!(
        sp.pop_front().unwrap().seq,
        3,
        "oldest were dropped, order kept"
    );
    assert_eq!(sp.pop_front().unwrap().seq, 4);
    sp.mark_reported(2);
    assert_eq!(sp.dropped_unreported(), 0);
}

#[test]
fn spool_cap_is_one_mebibyte() {
    assert_eq!(vigie_agent::spool::SPOOL_CAP, 1_048_576);
}

// ---- backoff ----

#[test]
fn backoff_grows_exponentially_with_jitter_and_caps_at_five_minutes() {
    let mut b = Backoff::default();
    let d1 = b.next_delay_s(u64::MAX);
    assert_eq!(d1, 5, "first delay with max jitter is the base");
    let d2 = b.next_delay_s(u64::MAX);
    assert_eq!(d2, 10);
    let mut b = Backoff::default();
    assert_eq!(
        b.next_delay_s(0),
        3,
        "min jitter is half the delay (rounded up)"
    );
    assert_eq!(b.next_delay_s(0), 5);
    let mut b = Backoff::default();
    let mut last = 0;
    for _ in 0..200 {
        last = b.next_delay_s(u64::MAX);
        assert!(last <= 300);
    }
    assert_eq!(last, 300, "capped at exactly 5 minutes");
    let mut b = Backoff::default();
    for _ in 0..200 {
        assert!(b.next_delay_s(0) >= 150 || b.attempts() < 7);
    }
    b.reset();
    assert_eq!(b.next_delay_s(u64::MAX), 5);
}

// ---- time gate ----

#[test]
fn time_gate_holds_before_build_date_and_on_server_skew() {
    let mut g = TimeGate::new(BUILD_TS);
    assert!(
        !g.is_sane(BUILD_TS - 1, 0),
        "clock before build date (no RTC boot)"
    );
    assert!(g.is_sane(BUILD_TS, 0));
    assert!(!g.is_sane((1 << 40) + 1, 0), "implausibly far future");
    g.observe_server_date(NOW, 100);
    assert!(g.is_sane(NOW + 200, 100));
    assert!(g.is_sane(NOW - 240, 100));
    assert!(!g.is_sane(NOW + 241, 100));
    assert!(!g.is_sane(NOW - 241, 100));
    // 1000 monotonic seconds later the server is expected to be 1000 s ahead.
    assert!(g.is_sane(NOW + 1000, 1100));
    assert!(!g.is_sane(NOW, 1100));
}

// ---- urgent ----

#[test]
fn urgent_push_only_for_new_macs_and_rate_limited() {
    let mut u = Urgent::new();
    u.prime(["aa:aa:aa:aa:aa:01"]);
    assert!(!u.on_lease("aa:aa:aa:aa:aa:01", 1_000), "known at startup");
    assert!(u.on_lease("aa:aa:aa:aa:aa:02", 10_000), "new mac");
    assert!(!u.on_lease("aa:aa:aa:aa:aa:02", 10_001), "no longer new");
    assert!(
        !u.on_lease("aa:aa:aa:aa:aa:03", 14_999),
        "rate limited (< 5 s)"
    );
    assert!(!u.take_pending(14_999));
    assert!(u.take_pending(15_000), "pending push released at 5 s");
    assert!(!u.take_pending(20_001), "only once");
    assert!(u.on_lease("aa:aa:aa:aa:aa:04", 20_001));
}

// ---- engine ----

#[test]
fn success_pops_batch_resets_backoff_and_reports_drops() {
    let mut e = engine();
    e.spool.note_dropped(3);
    e.enqueue(enc(1, 0));
    let mut t = Fake::new(vec![reply(200, r#"{"duplicate":false}"#)]);
    assert_eq!(e.tick(&mut t, NOW, 10, 1), Tick::Sent { duplicate: false });
    assert!(e.spool.is_empty());
    assert_eq!(e.spool.dropped_unreported(), 0);
    let body = String::from_utf8(t.calls[0].1.clone()).unwrap();
    assert!(
        body.ends_with(&format!(r#""sent_ts":{NOW},"dropped_batches":3}}"#)),
        "{body}"
    );
}

#[test]
fn duplicate_true_counts_as_success() {
    let mut e = engine();
    e.spool.note_dropped(1);
    e.enqueue(enc(1, 0));
    e.backoff.next_delay_s(0);
    let mut t = Fake::new(vec![reply(200, r#"{"duplicate":true}"#)]);
    assert_eq!(e.tick(&mut t, NOW, 10, 1), Tick::Sent { duplicate: true });
    assert!(
        e.spool.is_empty(),
        "lost-ACK retry must not be re-sent forever"
    );
    assert_eq!(
        e.spool.dropped_unreported(),
        1,
        "a duplicate does not acknowledge the retry's dropped_batches"
    );
    assert_eq!(e.backoff.attempts(), 0);
}

#[test]
fn failures_back_off_keep_batch_and_restamp_sent_ts() {
    let mut e = engine();
    e.enqueue(enc(1, 0));
    let mut t = Fake::new(vec![
        reply(503, ""),
        Err(TransportError("down".into())),
        reply(200, "{}"),
    ]);
    let Tick::Retry {
        status: Some(503),
        delay_s,
    } = e.tick(&mut t, NOW, 100, u64::MAX)
    else {
        panic!("expected retry")
    };
    assert_eq!(delay_s, 5);
    assert_eq!(
        e.tick(&mut t, NOW + 4, 104, 0),
        Tick::Waiting,
        "before the backoff expires"
    );
    assert_eq!(t.calls.len(), 1);
    let Tick::Retry {
        status: None,
        delay_s,
    } = e.tick(&mut t, NOW + 5, 105, u64::MAX)
    else {
        panic!("expected retry")
    };
    assert_eq!(delay_s, 10);
    assert_eq!(e.spool.len(), 1, "batch kept across failures");
    assert_eq!(
        e.tick(&mut t, NOW + 15, 115, 0),
        Tick::Sent { duplicate: false }
    );
    let (h0, b0) = &t.calls[0];
    let (h2, b2) = &t.calls[2];
    assert_eq!(
        (h0.batch_id.as_str(), h0.seq.as_str()),
        (h2.batch_id.as_str(), h2.seq.as_str())
    );
    assert_eq!(h0.sent_ts, NOW.to_string());
    assert_eq!(
        h2.sent_ts,
        (NOW + 15).to_string(),
        "sent_ts is stamped per attempt"
    );
    assert_ne!(b0, b2);
}

#[test]
fn rejected_batches_are_discarded_and_counted() {
    for status in [409u16, 413, 422] {
        let mut e = engine();
        e.enqueue(enc(1, 0));
        e.enqueue(enc(2, 0));
        let mut t = Fake::new(vec![reply(status, ""), reply(200, "{}")]);
        assert_eq!(e.tick(&mut t, NOW, 10, 1), Tick::Discarded(status));
        assert_eq!(e.spool.len(), 1);
        assert_eq!(e.spool.dropped_unreported(), 1);
        assert_eq!(e.tick(&mut t, NOW, 10, 1), Tick::Sent { duplicate: false });
        let body = String::from_utf8(t.calls[1].1.clone()).unwrap();
        assert!(body.ends_with(r#""dropped_batches":1}"#), "{body}");
    }
}

#[test]
fn transient_statuses_retry() {
    for status in [400u16, 401, 429, 500, 502, 503, 504] {
        let mut e = engine();
        e.enqueue(enc(1, 0));
        let mut t = Fake::new(vec![reply(status, "")]);
        assert!(
            matches!(e.tick(&mut t, NOW, 10, 1), Tick::Retry { status: Some(s), .. } if s == status)
        );
        assert_eq!(e.spool.len(), 1, "status {status}");
        assert_eq!(e.spool.dropped_unreported(), 0);
    }
}

#[test]
fn holds_sending_while_clock_is_not_sane() {
    let mut e = engine();
    e.enqueue(enc(1, 0));
    let mut t = Fake::new(vec![reply(200, "{}")]);
    assert_eq!(e.tick(&mut t, BUILD_TS - 5, 10, 1), Tick::Held);
    assert!(t.calls.is_empty());
    assert_eq!(e.tick(&mut t, NOW, 11, 1), Tick::Sent { duplicate: false });
}

#[test]
fn server_date_skew_holds_sending() {
    let mut e = engine();
    e.enqueue(enc(1, 0));
    let mut t = Fake::new(vec![Ok(HttpReply {
        status: 400,
        date: Some(NOW + 3600),
        body: vec![],
    })]);
    assert!(matches!(
        e.tick(&mut t, NOW, 10, 1),
        Tick::Retry {
            status: Some(400),
            ..
        }
    ));
    assert_eq!(
        e.tick(&mut t, NOW + 1000, 1000, 1),
        Tick::Held,
        "clock disagrees with server Date"
    );
    assert_eq!(t.calls.len(), 1);
}

#[test]
fn signature_header_verifies_over_the_exact_body_sent() {
    let mut e = engine();
    e.enqueue(enc(9, 10));
    let mut t = Fake::new(vec![reply(200, "{}")]);
    e.tick(&mut t, NOW, 10, 1);
    let (h, body) = &t.calls[0];
    let env = sign::Envelope {
        collector_id: &h.collector_id,
        key_id: &h.key_id,
        boot_id: &h.boot_id,
        seq: h.seq.parse().unwrap(),
        sent_ts: h.sent_ts.parse().unwrap(),
        batch_id: &h.batch_id,
    };
    assert_eq!(h.signature, sign::sign(&KEY, &env, body));
    assert!(String::from_utf8_lossy(body).contains(&format!(r#""sent_ts":{}"#, h.sent_ts)));
    assert_eq!(h.seq, "9");
}
