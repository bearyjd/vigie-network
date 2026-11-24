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
const RETRY_MS: u64 = 400;

struct Helper {
    listener: UnixListener,
    shared: Arc<CtShared>,
    sources: Sources,
    table: HashMap<String, String>,
    mono: u64,
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vigie-gap-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    d
}

/// A listening fake helper and a reader that retries after `RETRY_MS`: long enough that a test
/// sees the socket down and flushes before the reader reconnects into the listen backlog.
fn helper(tag: &str) -> Helper {
    let p = tmpdir(tag).join("c.sock");
    let listener = UnixListener::bind(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let me = std::fs::metadata("/proc/self").unwrap().uid();
    let cfg = CtConfig {
        backoff_base_ms: RETRY_MS,
        backoff_cap_ms: RETRY_MS,
        ..CtConfig::new(p, vec![0, me])
    };
    let ct = CtReader::spawn(cfg).unwrap();
    let shared = ct.shared.clone();
    Helper {
        listener,
        shared,
        sources: Sources::from_readers(Some(ct), None, 0),
        table: [("192.168.8.10".to_string(), A.to_string())].into(),
        mono: 0,
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
    fn accept(&self) -> UnixStream {
        let (conn, _) = self.listener.accept().unwrap();
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

    /// Closes the connection and waits until the reader has noticed.
    fn hang_up(&self, conn: UnixStream) {
        drop(conn);
        wait("disconnected", || {
            !self.shared.connected.load(Ordering::Relaxed)
        });
    }

    /// Pumps and flushes one window; returns its `truncated` map.
    fn flush(&mut self) -> serde_json::Value {
        self.mono += 60;
        let mut w = Window::default();
        self.sources.pump(&mut w, &self.table, self.mono);
        self.sources.finish_window(&mut w, self.mono);
        let (sections, drops) = w.take_with_drops();
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
        j["truncated"].clone()
    }
}

fn flags(t: &serde_json::Value) -> u64 {
    t.get("source_flags").and_then(|v| v.as_u64()).unwrap_or(0)
}

fn assert_degraded(t: &serde_json::Value, why: &str) {
    assert_ne!(flags(t) & flag::CT_SOCKET_DOWN, 0, "{why}: {t}");
}

fn assert_clean(t: &serde_json::Value, why: &str) {
    assert!(t.get("source_flags").is_none(), "{why}: {t}");
}

#[test]
fn a_reconnect_with_a_reprimed_sequence_before_the_flush_still_marks_the_window() {
    let mut h = helper("reprime");
    let mut c1 = h.accept();
    h.send(&mut c1, &[Some(1)]);
    h.hang_up(c1);
    let mut c2 = h.accept();
    h.send(&mut c2, &[Some(1)]);
    let t = h.flush();
    assert_degraded(&t, "interrupted window looks healthy at flush time");
    assert!(
        t.get("ct_errors").is_none(),
        "a clean EOF stays out of the error counter: {t}"
    );
    h.send(&mut c2, &[Some(2)]);
    assert_clean(&h.flush(), "the next genuinely clean window clears it");
}

#[test]
fn a_reconnect_in_the_next_window_marks_that_window_too() {
    let mut h = helper("nextwin");
    let mut c1 = h.accept();
    h.send(&mut c1, &[Some(1)]);
    h.hang_up(c1);
    assert_degraded(&h.flush(), "down at flush time");
    assert!(
        !h.shared.connected.load(Ordering::Relaxed),
        "precondition: the reconnect falls in the next window"
    );
    let mut c2 = h.accept();
    h.send(&mut c2, &[Some(1)]);
    assert_degraded(&h.flush(), "started down, recovered before the flush");
    h.send(&mut c2, &[Some(2)]);
    assert_clean(&h.flush(), "ordinary recovery");
}

#[test]
fn the_first_connect_is_not_an_interruption() {
    let mut h = helper("first");
    let mut c = h.accept();
    h.send(&mut c, &[Some(500)]);
    assert_clean(&h.flush(), "a running helper's first frame is a baseline");
    h.send(&mut c, &[Some(501)]);
    assert_clean(&h.flush(), "and its successor is continuous");
}

#[test]
fn a_snapshot_lost_from_a_full_queue_marks_the_window() {
    let mut h = helper("queue");
    let mut c = h.accept();
    let seqs: Vec<Option<u64>> = (1..=QUEUE as u64 + 1).map(Some).collect();
    h.send(&mut c, &seqs);
    let t = h.flush();
    assert_degraded(&t, "queue loss");
    assert_eq!(t["ct_errors"], 1, "the drop counter keeps its meaning: {t}");
    h.send(&mut c, &[Some(QUEUE as u64 + 2)]);
    assert_clean(&h.flush(), "cleared after the lossy window");
}

/// Each case runs on one connection: a baseline frame window, then the anomaly, then a clean
/// successor window.
fn sequence_case(tag: &str, first: &[Option<u64>], second: &[Option<u64>], degraded: bool) {
    let mut h = helper(tag);
    let mut c = h.accept();
    h.send(&mut c, first);
    assert_clean(&h.flush(), &format!("{tag}: baseline"));
    h.send(&mut c, second);
    let t = h.flush();
    if degraded {
        assert_degraded(&t, tag);
    } else {
        assert_clean(&t, tag);
    }
    let next = second.iter().rev().find_map(|s| *s).map(|s| s + 1);
    h.send(&mut c, &[next]);
    assert_clean(
        &h.flush(),
        &format!("{tag}: the next continuous window is clean"),
    );
}

#[test]
fn a_sequence_gap_on_one_connection_marks_the_window() {
    sequence_case("gap", &[Some(1)], &[Some(3)], true);
}

#[test]
fn a_duplicate_snapshot_marks_the_window() {
    sequence_case("dup", &[Some(1)], &[Some(1)], true);
}

#[test]
fn a_reordered_snapshot_marks_the_window() {
    sequence_case("reorder", &[Some(5)], &[Some(4)], true);
}

#[test]
fn a_reset_on_one_connection_marks_the_window() {
    sequence_case("reset", &[Some(50)], &[Some(1)], true);
}

#[test]
fn a_wrapped_sequence_is_judged_conservatively_like_a_reset() {
    sequence_case("wrap", &[Some(u64::MAX)], &[Some(1)], true);
}

#[test]
fn consecutive_sequences_stay_clean() {
    sequence_case("steady", &[Some(1), Some(2)], &[Some(3), Some(4)], false);
}

#[test]
fn frames_without_sequence_metadata_are_never_judged() {
    sequence_case("noseq", &[None, None], &[None, None], false);
    sequence_case("mixed", &[Some(7)], &[None, Some(8)], false);
}
