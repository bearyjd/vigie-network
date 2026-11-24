//! The window cut against reader events that land between the final pump and the flush.
//! Each test replays one interleaving deterministically through injected channels, doing to
//! `CtShared` exactly what the reader does at that point.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;

use vigie_agent::builder::{build_with_drops, BATCH_CAP};
use vigie_agent::ctparse::{Kind, Record, Snapshot};
use vigie_agent::ctsock::CtShared;
use vigie_agent::model::{Health, Meta, Proto};
use vigie_agent::window::Window;
use vigie_agent::wiring::{flag, Sources};

const A: &str = "aa:bb:cc:00:00:01";

struct Fake {
    tx: SyncSender<Snapshot>,
    ct: Arc<CtShared>,
    sources: Sources,
    table: HashMap<String, String>,
    w: Window,
    mono: u64,
}

fn fake() -> Fake {
    let (tx, rx) = sync_channel(8);
    let ct = Arc::new(CtShared::default());
    ct.connected.store(true, Ordering::Relaxed);
    Fake {
        tx,
        sources: Sources::from_parts(Some((rx, ct.clone())), None, 0),
        ct,
        table: [("192.168.8.10".to_string(), A.to_string())].into(),
        w: Window::default(),
        mono: 0,
    }
}

fn snap(transport_gap: bool) -> Snapshot {
    Snapshot {
        transport_gap,
        records: vec![Record {
            src: "192.168.8.10".parse().unwrap(),
            kind: Kind::Tuple,
            dst: Some("1.1.1.1".parse().unwrap()),
            dport: Some(443),
            proto: Proto::Tcp,
            bytes_up: 70,
            bytes_down: 1,
            flows: 1,
        }],
        ..Snapshot::default()
    }
}

#[derive(Debug, PartialEq)]
struct Flushed {
    socket_down: bool,
    rows: usize,
    ct_errors: u64,
}

impl Fake {
    /// The flush's final pump.
    fn pump(&mut self) {
        self.mono += 30;
        self.sources.pump(&mut self.w, &self.table, self.mono);
    }

    /// `finish_window` and the batch it yields.
    fn finish(&mut self) -> Flushed {
        self.mono += 30;
        self.sources.finish_window(&mut self.w, self.mono);
        let meta = Meta {
            collector_id: "c1".into(),
            key_id: "k1".into(),
            boot_id: "boot1".into(),
            seq: 1,
            batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
            window_start: 1_760_000_000,
            window_end: 1_760_000_060,
        };
        let (sections, drops) = self.w.take_with_drops();
        let b = build_with_drops(&meta, sections, &Health::default(), BATCH_CAP, &drops);
        let j: serde_json::Value =
            serde_json::from_slice(&b.encoded.body(1_760_000_061, 0)).unwrap();
        let t = &j["truncated"];
        Flushed {
            socket_down: t["source_flags"].as_u64().unwrap_or(0) & flag::CT_SOCKET_DOWN != 0,
            rows: j["conntrack"].as_array().map_or(0, Vec::len),
            ct_errors: t["ct_errors"].as_u64().unwrap_or(0),
        }
    }
}

fn clean(rows: usize) -> Flushed {
    Flushed {
        socket_down: false,
        rows,
        ct_errors: 0,
    }
}

/// P1-1: the socket was down at the final pump; the reader reconnects (latch, then
/// `connected`) before `finish_window` reads the socket state.
#[test]
fn a_reconnect_between_the_final_pump_and_the_flush_still_marks_the_window() {
    let mut f = fake();
    f.ct.connected.store(false, Ordering::Relaxed);
    f.pump();
    f.ct.interrupted.store(true, Ordering::Relaxed);
    f.ct.connected.store(true, Ordering::Relaxed);
    assert!(f.finish().socket_down, "the gap belongs to this window");
    f.pump();
    assert_eq!(f.finish(), clean(0), "and to this window only");
}

/// P1-2: a broken-sequence frame enqueued after the final drain travels with its own flag, so
/// its bytes and the flag land in the same window.
#[test]
fn a_flagged_frame_enqueued_after_the_final_drain_marks_the_window_that_counts_it() {
    let mut f = fake();
    f.pump();
    f.tx.send(snap(true)).unwrap();
    assert_eq!(f.finish(), clean(0), "its bytes are not in this window");
    f.pump();
    let next = f.finish();
    assert_eq!((next.socket_down, next.rows), (true, 1), "{next:?}");
    f.tx.send(snap(false)).unwrap();
    f.pump();
    assert_eq!(f.finish(), clean(1));
}

/// P2-4: a queue drop counted after the final pump is reported with bit 4 in the same window.
#[test]
fn a_queue_drop_after_the_final_pump_marks_the_same_window_as_its_counter() {
    let mut f = fake();
    f.pump();
    f.ct.dropped.fetch_add(1, Ordering::Relaxed);
    let got = f.finish();
    assert_eq!((got.socket_down, got.ct_errors), (true, 1), "{got:?}");
    f.pump();
    assert_eq!(f.finish(), clean(0), "one drop costs one window");
}
