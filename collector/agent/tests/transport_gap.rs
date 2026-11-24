//! Transport gaps through a real Unix socket: an interrupted helper connection, a lost queued
//! snapshot or a broken sequence must mark the window it falls in with `CT_SOCKET_DOWN`, even
//! when a healthy-looking frame arrives before the flush. The next clean window clears it.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use vigie_agent::builder::{build_with_drops, BATCH_CAP};
use vigie_agent::ctsock::{CtConfig, CtReader, CtShared, QUEUE};
use vigie_agent::model::{Health, Meta};
use vigie_agent::window::Window;
use vigie_agent::wiring::{flag, Sources};

const A: &str = "aa:bb:cc:00:00:01";
const RETRY_MS: u64 = 20;

struct Helper {
    /// None while the fake helper is down: its socket file is gone, so the reader cannot
    /// reconnect until the test binds it again (no wall-clock race with the retry delay).
    listener: Option<UnixListener>,
    path: PathBuf,
    shared: Arc<CtShared>,
    sources: Sources,
    table: HashMap<String, String>,
    mono: u64,
    w: Window,
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vigie-gap-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    d
}

fn bind(p: &PathBuf) -> UnixListener {
    let listener = UnixListener::bind(p).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

/// A listening fake helper and a reader that retries quickly.
fn helper(tag: &str) -> Helper {
    let p = tmpdir(tag).join("c.sock");
    let listener = Some(bind(&p));
    let me = std::fs::metadata("/proc/self").unwrap().uid();
    let cfg = CtConfig {
        backoff_base_ms: RETRY_MS,
        backoff_cap_ms: RETRY_MS,
        ..CtConfig::new(p.clone(), vec![0, me])
    };
    let ct = CtReader::spawn(cfg).unwrap();
    let shared = ct.shared.clone();
    Helper {
        listener,
        path: p,
        shared,
        sources: Sources::from_readers(Some(ct), None, 0),
        table: [("192.168.8.10".to_string(), A.to_string())].into(),
        mono: 0,
        w: Window::default(),
    }
}

/// A healthy frame; `None` is an old helper's frame without sequence metadata.
fn frame(seq: Option<u64>) -> String {
    let seq = seq.map_or(String::new(), |s| format!(r#""seq":{s},"#));
    format!(
        r#"{{"v":1,{seq}"ts":1,"interval_s":60,"records":[{{"src":"192.168.8.10","dst":"8.8.8.8","dport":53,"proto":"udp","bytes_up":70,"bytes_down":120,"flows":1}}]}}"#
    )
}

fn wait(what: &str, cond: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

impl Helper {
    /// Binds the socket again if the helper is down, then accepts the reader.
    fn accept(&mut self) -> UnixStream {
        let path = self.path.clone();
        let listener = self.listener.get_or_insert_with(|| bind(&path));
        let (conn, _) = listener.accept().unwrap();
        wait("connected", || {
            self.shared.connected.load(Ordering::Relaxed)
        });
        conn
    }

    /// Writes the frames and waits until the reader has parsed all of them.
    fn send(&self, conn: &mut UnixStream, seqs: &[Option<u64>]) {
        let before = self.shared.received.load(Ordering::Relaxed);
        for s in seqs {
            writeln!(conn, "{}", frame(*s)).unwrap();
        }
        let want = before + seqs.len() as u64;
        wait("frames received", || {
            self.shared.received.load(Ordering::Relaxed) >= want
        });
    }

    /// Takes the helper down (socket file removed, connection closed) and waits until the
    /// reader has noticed; it stays down until the next `accept`.
    fn hang_up(&mut self, conn: UnixStream) {
        self.listener = None;
        std::fs::remove_file(&self.path).unwrap();
        drop(conn);
        wait("disconnected", || {
            !self.shared.connected.load(Ordering::Relaxed)
        });
    }

    /// Flushes one window; returns its `truncated` map and A's uploaded bytes. `pump` false is the agent's Hold path: `finish_window` alone, queued frames stay queued.
    fn flush_with(&mut self, pump: bool) -> (serde_json::Value, u64) {
        self.mono += 60;
        if pump {
            self.pump_only();
        }
        self.sources.finish_window(&mut self.w, self.mono);
        let (sections, drops) = self.w.take_with_drops();
        let meta = Meta {
            collector_id: "c1".into(),
            key_id: "k1".into(),
            boot_id: "boot1".into(),
            seq: 1,
            batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
            window_start: 1_760_000_000,
            window_end: 1_760_000_060,
        };
        let b = build_with_drops(&meta, sections, &Health::default(), BATCH_CAP, &drops);
        let j: serde_json::Value =
            serde_json::from_slice(&b.encoded.body(1_760_000_061, 0)).unwrap();
        let up = j["conntrack"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter(|r| r["mac"] == A)
                    .map(|r| r["bytes_up"].as_u64().unwrap())
                    .sum()
            })
            .unwrap_or(0);
        (j["truncated"].clone(), up)
    }

    /// A pump of the open window between flushes (the agent's main loop does this).
    fn pump_only(&mut self) {
        self.sources.pump(&mut self.w, &self.table, self.mono);
    }

    /// Flushes and checks the window holds exactly `frames` frames' bytes and the given verdict.
    fn window(&mut self, frames: u64, degraded: bool, why: &str) -> serde_json::Value {
        self.window_with(true, frames, degraded, why)
    }

    fn window_with(
        &mut self,
        pump: bool,
        frames: u64,
        degraded: bool,
        why: &str,
    ) -> serde_json::Value {
        let (t, up) = self.flush_with(pump);
        assert_eq!(
            up,
            FRAME_UP * frames,
            "{why}: window membership of rows: {t}"
        );
        if degraded {
            assert_ne!(flags(&t) & flag::CT_SOCKET_DOWN, 0, "{why}: {t}");
        } else {
            assert!(t.get("source_flags").is_none(), "{why}: {t}");
        }
        t
    }
}

/// `bytes_up` of one frame (see `frame`).
const FRAME_UP: u64 = 70;

fn flags(t: &serde_json::Value) -> u64 {
    t.get("source_flags").and_then(|v| v.as_u64()).unwrap_or(0)
}

#[test]
fn a_reconnect_with_a_reprimed_sequence_before_the_flush_still_marks_the_window() {
    let mut h = helper("reprime");
    let mut c1 = h.accept();
    h.send(&mut c1, &[Some(1)]);
    let before = h.shared.attempts.load(Ordering::Relaxed);
    h.hang_up(c1);
    let mut c2 = h.accept();
    let refused = h.shared.attempts.load(Ordering::Relaxed) - before;
    h.send(&mut c2, &[Some(1)]);
    let t = h.window(2, true, "interrupted window looks healthy at flush time");
    assert_eq!(
        t["ct_errors"].as_u64().unwrap_or(0),
        refused,
        "only the refused reconnects count; a clean EOF stays out: {t}"
    );
    h.send(&mut c2, &[Some(2)]);
    h.window(1, false, "the next genuinely clean window clears it");
}

#[test]
fn a_reconnect_in_the_next_window_marks_that_window_too() {
    let mut h = helper("nextwin");
    let mut c1 = h.accept();
    h.send(&mut c1, &[Some(1)]);
    h.hang_up(c1);
    h.window(1, true, "down at flush time");
    assert!(
        !h.shared.connected.load(Ordering::Relaxed),
        "the helper is still down: the reconnect falls in the next window"
    );
    let mut c2 = h.accept();
    h.send(&mut c2, &[Some(1)]);
    h.window(1, true, "started down, recovered before the flush");
    h.send(&mut c2, &[Some(2)]);
    h.window(1, false, "ordinary recovery");
}

#[test]
fn the_first_connect_is_not_an_interruption() {
    let mut h = helper("first");
    let mut c = h.accept();
    h.send(&mut c, &[Some(500)]);
    h.window(1, false, "a running helper's first frame is a baseline");
    h.send(&mut c, &[Some(501)]);
    h.window(1, false, "and its successor is continuous");
}

#[test]
fn a_snapshot_lost_from_a_full_queue_marks_the_window() {
    let mut h = helper("queue");
    let mut c = h.accept();
    let seqs: Vec<Option<u64>> = (1..=QUEUE as u64 + 1).map(Some).collect();
    h.send(&mut c, &seqs);
    let t = h.window(QUEUE as u64, true, "queue loss");
    assert_eq!(t["ct_errors"], 1, "the drop counter keeps its meaning: {t}");
    h.send(&mut c, &[Some(QUEUE as u64 + 2)]);
    h.window(
        1,
        true,
        "the next delivered frame carries the drop (errs toward degrading)",
    );
    h.send(&mut c, &[Some(QUEUE as u64 + 3)]);
    h.window(1, false, "cleared after it");
}

#[test]
fn the_first_frame_after_a_reconnect_marks_the_window_that_counts_it() {
    let mut h = helper("firstafter");
    let mut c1 = h.accept();
    h.send(&mut c1, &[Some(1)]);
    h.window(1, false, "baseline");
    h.hang_up(c1);
    let mut c2 = h.accept();
    h.send(&mut c2, &[Some(1)]);
    h.window_with(
        false,
        0,
        true,
        "the reconnect is cut before its first frame drains",
    );
    h.window(1, true, "the first frame's counters may hold the gap");
    h.send(&mut c2, &[Some(2)]);
    h.window(1, false, "continuous after it");
}

#[test]
fn a_queue_drop_on_the_hold_path_marks_the_window_of_the_next_frame() {
    let mut h = helper("dropheld");
    let mut c = h.accept();
    let seqs: Vec<Option<u64>> = (1..=QUEUE as u64 + 1).map(Some).collect();
    h.send(&mut c, &seqs);
    h.window_with(false, 0, true, "held window: the drop's own window");
    h.pump_only();
    h.send(&mut c, &[Some(QUEUE as u64 + 2)]);
    let t = h.window(
        QUEUE as u64 + 1,
        true,
        "the frame after the drop carries it",
    );
    assert!(
        t.get("ct_errors").is_none(),
        "the drop was counted once: {t}"
    );
    h.send(&mut c, &[Some(QUEUE as u64 + 3)]);
    h.window(1, false, "then clean");
}

#[test]
fn a_queue_overflow_between_the_final_pump_and_the_cut_marks_the_next_frame_too() {
    let mut h = helper("dropcut");
    let mut c = h.accept();
    h.send(&mut c, &[Some(1)]);
    h.window(1, false, "baseline");
    h.pump_only();
    let seqs: Vec<Option<u64>> = (2..=QUEUE as u64 + 2).map(Some).collect();
    h.send(&mut c, &seqs);
    h.window_with(false, 0, true, "overflow after the final pump");
    h.pump_only();
    h.send(&mut c, &[Some(QUEUE as u64 + 3)]);
    h.window(
        QUEUE as u64 + 1,
        true,
        "queued frames plus the frame after the drop",
    );
    h.send(&mut c, &[Some(QUEUE as u64 + 4)]);
    h.window(1, false, "then clean");
}

/// One connection: a baseline window, the window with `second` (degraded or not), then a
/// window with `next` alone, which must be clean. Every window holds exactly its own frames.
fn sequence_case(
    tag: &str,
    first: &[Option<u64>],
    second: &[Option<u64>],
    degraded: bool,
    next: Option<u64>,
) {
    let mut h = helper(tag);
    let mut c = h.accept();
    h.send(&mut c, first);
    h.window(first.len() as u64, false, &format!("{tag}: baseline"));
    h.send(&mut c, second);
    h.window(second.len() as u64, degraded, tag);
    h.send(&mut c, &[next]);
    h.window(
        1,
        false,
        &format!("{tag}: the next continuous window is clean"),
    );
}

/// A helper-side loss (its queue was busy) is only revealed by the next frame: the window that
/// receives that frame is marked, not the earlier one, which was already flushed.
#[test]
fn a_sequence_gap_marks_the_window_of_the_frame_that_reveals_it() {
    sequence_case("gap", &[Some(1)], &[Some(3)], true, Some(4));
}

#[test]
fn a_duplicate_snapshot_marks_the_window() {
    sequence_case("dup", &[Some(1)], &[Some(1)], true, Some(2));
}

#[test]
fn a_reordered_snapshot_marks_its_window_without_rewinding_the_sequence() {
    sequence_case("reorder", &[Some(100)], &[Some(99)], true, Some(101));
}

#[test]
fn a_replay_of_the_high_water_frame_after_a_reorder_is_a_duplicate() {
    let mut h = helper("rereplay");
    let mut c = h.accept();
    h.send(&mut c, &[Some(100)]);
    h.window(1, false, "baseline");
    h.send(&mut c, &[Some(99)]);
    h.window(1, true, "reorder");
    h.send(&mut c, &[Some(100)]);
    h.window(
        1,
        true,
        "the high-water frame again is a duplicate, not continuous",
    );
    h.send(&mut c, &[Some(101)]);
    h.window(1, false, "continuous again");
}

#[test]
fn a_reset_on_one_connection_marks_the_window_and_rebaselines() {
    sequence_case("reset", &[Some(50_000)], &[Some(1)], true, Some(2));
}

#[test]
fn a_wrapped_sequence_is_judged_like_a_reset() {
    sequence_case("wrap", &[Some(u64::MAX)], &[Some(1)], true, Some(2));
}

#[test]
fn consecutive_sequences_stay_clean() {
    sequence_case(
        "steady",
        &[Some(1), Some(2)],
        &[Some(3), Some(4)],
        false,
        Some(5),
    );
}

#[test]
fn frames_without_sequence_metadata_are_never_judged() {
    sequence_case("noseq", &[None, None], &[None, None], false, None);
    sequence_case("mixed", &[Some(7)], &[None, Some(8)], false, Some(9));
}
