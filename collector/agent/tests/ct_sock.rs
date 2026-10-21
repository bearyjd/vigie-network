//! Socket verification, line framing and the reader thread against fake and real helpers.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use vigie_agent::ctparse::MAX_LINE;
use vigie_agent::ctsock::*;

fn me() -> u32 {
    fs::metadata("/proc/self").unwrap().uid()
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vigie-ctsock-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::DirBuilder::new().mode(0o755).create(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    d
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

const GOOD: &str = r#"{"v":1,"seq":1,"ts":1,"interval_s":60,"records":[{"src":"10.0.0.1","other":true,"bytes_up":1,"bytes_down":2,"flows":1}]}"#;

fn cfg(path: &Path) -> CtConfig {
    CtConfig {
        line_deadline: Duration::from_millis(400),
        backoff_base_ms: 20,
        backoff_cap_ms: 100,
        ..CtConfig::new(path.to_path_buf(), vec![0, me()])
    }
}

fn meta(socket: bool, mode: u32, uid: u32) -> PathMeta {
    PathMeta {
        symlink: false,
        socket,
        dir: !socket,
        mode,
        uid,
    }
}

#[test]
fn socket_meta_rules() {
    let t = [0u32, 1000];
    assert!(check_socket_meta(&meta(true, 0o600, 0), &t).is_ok());
    assert!(check_socket_meta(&meta(true, 0o660 & !0o020, 1000), &t).is_ok());
    assert!(
        check_socket_meta(&meta(true, 0o644, 1000), &t).is_ok(),
        "world-readable is not writable"
    );
    let sym = PathMeta {
        symlink: true,
        ..meta(true, 0o600, 0)
    };
    assert_eq!(check_socket_meta(&sym, &t), Err(Refusal::Symlink));
    assert_eq!(
        check_socket_meta(&meta(false, 0o600, 0), &t),
        Err(Refusal::NotSocket)
    );
    assert_eq!(
        check_socket_meta(&meta(true, 0o600, 1001), &t),
        Err(Refusal::WrongOwner(1001))
    );
    for bad in [0o660, 0o620, 0o602, 0o666, 0o622, 0o606] {
        assert_eq!(
            check_socket_meta(&meta(true, bad, 0), &t),
            Err(Refusal::Writable(bad)),
            "{bad:o}"
        );
    }
}

#[test]
fn dir_meta_rules() {
    let t = [0u32, 1000];
    assert!(check_dir_meta(&meta(false, 0o751, 0), &t).is_ok());
    assert!(check_dir_meta(&meta(false, 0o700, 1000), &t).is_ok());
    let sym = PathMeta {
        symlink: true,
        ..meta(false, 0o755, 0)
    };
    assert_eq!(check_dir_meta(&sym, &t), Err(Refusal::DirSymlink));
    assert_eq!(
        check_dir_meta(&meta(true, 0o755, 0), &t),
        Err(Refusal::DirNotDir)
    );
    assert_eq!(
        check_dir_meta(&meta(false, 0o755, 5), &t),
        Err(Refusal::DirWrongOwner(5))
    );
    for bad in [0o775, 0o757, 0o777, 0o1777, 0o770] {
        assert_eq!(
            check_dir_meta(&meta(false, bad, 0), &t),
            Err(Refusal::DirWritable(bad)),
            "{bad:o}"
        );
    }
}

#[test]
fn verify_socket_on_the_real_filesystem() {
    let d = tmpdir("verify");
    let sock = d.join("c.sock");
    let _l = UnixListener::bind(&sock).unwrap();
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600)).unwrap();
    let ok = [0, me()];
    assert_eq!(verify_socket(&sock, &ok), Ok(()));
    // Without root the directory (ours) is the first thing that is not trusted; the socket-owner
    // rule itself is covered on `PathMeta` in `socket_meta_rules`.
    let other = [me() + 1];
    assert!(matches!(verify_socket(&sock, &other), Err(Refusal::DirWrongOwner(u)) if u == me()));
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        verify_socket(&sock, &ok),
        Err(Refusal::Writable(_))
    ));
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600)).unwrap();

    let link = d.join("link.sock");
    symlink(&sock, &link).unwrap();
    assert_eq!(verify_socket(&link, &ok), Err(Refusal::Symlink));

    let file = d.join("plain");
    fs::write(&file, b"x").unwrap();
    assert_eq!(verify_socket(&file, &ok), Err(Refusal::NotSocket));
    assert!(matches!(
        verify_socket(&d.join("absent"), &ok),
        Err(Refusal::Io(_))
    ));

    fs::set_permissions(&d, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        verify_socket(&sock, &ok),
        Err(Refusal::DirWritable(_))
    ));
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();

    let real = d.join("real");
    fs::DirBuilder::new().mode(0o755).create(&real).unwrap();
    let _l2 = UnixListener::bind(real.join("s")).unwrap();
    let dlink = d.join("dlink");
    symlink(&real, &dlink).unwrap();
    assert_eq!(
        verify_socket(&dlink.join("s"), &ok),
        Err(Refusal::DirSymlink)
    );
}

#[test]
fn trusted_uids_are_root_and_self() {
    let t = trusted_uids().unwrap();
    assert!(t.contains(&0) && t.contains(&me()));
}

fn lines(events: Vec<LineEvent>) -> Vec<String> {
    events
        .into_iter()
        .map(|e| match e {
            LineEvent::Line(l) => String::from_utf8(l).unwrap(),
            LineEvent::Oversized => "<oversized>".into(),
        })
        .collect()
}

#[test]
fn linebuf_splits_across_chunks_and_keeps_the_tail() {
    let mut b = LineBuf::default();
    assert!(b.push(b"ab").is_empty());
    assert_eq!(b.pending(), 2);
    assert_eq!(lines(b.push(b"c\nde\nf")), ["abc", "de"]);
    assert_eq!(b.pending(), 1);
    assert_eq!(lines(b.push(b"\n\n")), ["f", ""]);
    assert_eq!(b.pending(), 0);
}

#[test]
fn linebuf_caps_an_endless_line_and_keeps_memory_bounded() {
    let mut b = LineBuf::default();
    let chunk = vec![b'x'; 64 * 1024];
    let mut oversized = false;
    for _ in 0..(MAX_LINE / chunk.len() + 2) {
        let ev = b.push(&chunk);
        assert!(
            b.pending() <= MAX_LINE,
            "pending {} over the cap",
            b.pending()
        );
        if ev == [LineEvent::Oversized] {
            oversized = true;
            break;
        }
        assert!(ev.is_empty());
    }
    assert!(oversized, "never reported");
}

#[test]
fn linebuf_boundary_at_exactly_the_cap() {
    let mut b = LineBuf::default();
    let mut at_cap = vec![b'x'; MAX_LINE];
    at_cap.push(b'\n');
    assert_eq!(b.push(&at_cap).len(), 1);
    assert!(matches!(&b.push(&at_cap)[0], LineEvent::Line(l) if l.len() == MAX_LINE));
    let mut over = vec![b'x'; MAX_LINE + 1];
    over.push(b'\n');
    assert_eq!(
        b.push(&over),
        [LineEvent::Oversized],
        "one byte over, with its newline"
    );
    // a pending tail of exactly the cap is fine, one more is not
    let mut c = LineBuf::default();
    assert!(c.push(&vec![b'y'; MAX_LINE]).is_empty());
    assert_eq!(c.push(b"y"), [LineEvent::Oversized]);
}

#[test]
fn backoff_doubles_then_stays_at_the_cap() {
    let s: Vec<u64> = (0..8).map(|a| backoff_ms(a, 1000, 60_000)).collect();
    assert_eq!(s, [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000]);
    assert_eq!(backoff_ms(31, 1000, 60_000), 60_000);
    assert_eq!(backoff_ms(32, 1000, 60_000), 60_000);
    assert_eq!(backoff_ms(u32::MAX, 1000, 60_000), 60_000);
    assert_eq!(backoff_ms(40, u64::MAX, 60_000), 60_000, "no overflow");
}

fn serve_once(l: &UnixListener, script: impl FnOnce(&mut UnixStream)) {
    let (mut s, _) = l.accept().unwrap();
    script(&mut s);
}

fn listener(tag: &str) -> (UnixListener, PathBuf) {
    let d = tmpdir(tag);
    let p = d.join("c.sock");
    let l = UnixListener::bind(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    (l, p)
}

#[test]
fn a_fake_helper_delivers_snapshots_and_reconnects_after_garbage() {
    let (l, p) = listener("garbage");
    let mut r = CtReader::spawn(cfg(&p)).unwrap();
    serve_once(&l, |s| {
        writeln!(s, "{GOOD}").unwrap();
        s.write_all(b"this is not json\n").unwrap();
        let _ = s.write_all(format!("{GOOD}\n").as_bytes());
    });
    wait_until("first snapshot", || {
        r.shared.received.load(Ordering::Relaxed) >= 1
    });
    wait_until("garbage counted", || {
        r.shared.errors.load(Ordering::Relaxed) >= 1
    });
    // the reader reconnects by itself and the next good line arrives
    serve_once(&l, |s| writeln!(s, "{GOOD}").unwrap());
    wait_until("second snapshot", || {
        r.shared.received.load(Ordering::Relaxed) >= 2
    });
    let first = r.rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first.records.len(), 1);
    r.shutdown();
}

#[test]
fn an_endless_line_without_newline_is_cut_off_and_counted() {
    let (l, p) = listener("endless");
    let r = CtReader::spawn(cfg(&p)).unwrap();
    let h = thread::spawn(move || {
        let mut hung_up = false;
        serve_once(&l, |s| {
            let junk = vec![b'z'; 64 * 1024];
            // 64 MiB offered; an unbounded reader would take all of it
            for _ in 0..1024 {
                if s.write_all(&junk).is_err() {
                    hung_up = true;
                    return;
                }
            }
        });
        hung_up
    });
    wait_until("oversize counted", || {
        r.shared.errors.load(Ordering::Relaxed) >= 1
    });
    assert!(
        h.join().unwrap(),
        "the reader must hang up on an endless line"
    );
    assert_eq!(r.shared.received.load(Ordering::Relaxed), 0);
}

#[test]
fn eof_in_the_middle_of_a_line_is_counted_and_nothing_is_delivered() {
    let (l, p) = listener("eof");
    let r = CtReader::spawn(cfg(&p)).unwrap();
    serve_once(&l, |s| {
        s.write_all(&GOOD.as_bytes()[..GOOD.len() / 2]).unwrap();
    });
    wait_until("eof counted", || {
        r.shared.errors.load(Ordering::Relaxed) >= 1
    });
    assert_eq!(r.shared.received.load(Ordering::Relaxed), 0);
    assert!(r.rx.try_recv().is_err());
}

#[test]
fn a_clean_eof_between_lines_is_not_an_error() {
    let (l, p) = listener("cleaneof");
    let r = CtReader::spawn(cfg(&p)).unwrap();
    serve_once(&l, |s| writeln!(s, "{GOOD}").unwrap());
    wait_until("delivered", || {
        r.shared.received.load(Ordering::Relaxed) == 1
    });
    thread::sleep(Duration::from_millis(200));
    assert_eq!(r.shared.errors.load(Ordering::Relaxed), 0);
}

#[test]
fn a_slow_writer_that_never_finishes_a_line_is_dropped() {
    let (l, p) = listener("slow");
    let r = CtReader::spawn(cfg(&p)).unwrap();
    let h = thread::spawn(move || {
        serve_once(&l, |s| {
            // a byte every 100 ms: always "progress", never a line
            for b in GOOD.bytes().cycle().take(100) {
                if s.write_all(&[b]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    });
    wait_until("slow peer dropped", || {
        r.shared.errors.load(Ordering::Relaxed) >= 1
    });
    assert_eq!(r.shared.received.load(Ordering::Relaxed), 0);
    drop(h);
}

#[test]
fn a_silent_connected_peer_is_not_an_error_and_never_blocks_shutdown() {
    let (l, p) = listener("silent");
    let mut r = CtReader::spawn(cfg(&p)).unwrap();
    let (s, _) = l.accept().unwrap();
    wait_until("connected", || r.shared.connected.load(Ordering::Relaxed));
    thread::sleep(Duration::from_millis(700));
    assert_eq!(
        r.shared.errors.load(Ordering::Relaxed),
        0,
        "quiet between snapshots is normal"
    );
    let t = Instant::now();
    r.shutdown();
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "shutdown took {:?}",
        t.elapsed()
    );
    drop(s);
}

#[test]
fn connect_refused_retries_with_backoff_not_a_busy_loop() {
    let (l, p) = listener("refused");
    drop(l); // the socket file stays, nobody listens
    let r = CtReader::spawn(cfg(&p)).unwrap();
    thread::sleep(Duration::from_millis(1500));
    let n = r.shared.attempts.load(Ordering::Relaxed);
    // 20,40,80 then 100 ms: at most ~17 attempts in 1.5 s; a busy loop would be thousands
    assert!((3..=20).contains(&n), "{n} attempts");
    assert!(!r.shared.connected.load(Ordering::Relaxed));
    assert_eq!(r.shared.errors.load(Ordering::Relaxed), n);
}

#[test]
fn the_backoff_cap_bounds_the_wait_after_the_helper_comes_back() {
    let (l, p) = listener("cap");
    drop(l);
    let r = CtReader::spawn(cfg(&p)).unwrap();
    wait_until("several failures", || {
        r.shared.attempts.load(Ordering::Relaxed) >= 8
    });
    fs::remove_file(&p).unwrap();
    let l = UnixListener::bind(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    let t = Instant::now();
    serve_once(&l, |s| writeln!(s, "{GOOD}").unwrap());
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "reconnect took {:?} (cap is 100 ms)",
        t.elapsed()
    );
    wait_until("delivered", || {
        r.shared.received.load(Ordering::Relaxed) == 1
    });
}

#[test]
fn a_socket_with_the_wrong_owner_is_never_connected_to() {
    let (l, p) = listener("owner");
    l.set_nonblocking(true).unwrap();
    let mut c = cfg(&p);
    c.trusted = vec![me() + 1]; // pretend root/the agent are someone else: the file's owner is wrong
    let r = CtReader::spawn(c).unwrap();
    wait_until("refusals counted", || {
        r.shared.errors.load(Ordering::Relaxed) >= 2
    });
    assert!(
        l.accept().is_err(),
        "the reader must not connect to an untrusted socket"
    );
    assert!(!r.shared.connected.load(Ordering::Relaxed));
}

#[test]
fn a_symlinked_socket_is_never_connected_to() {
    let (l, p) = listener("symlink");
    l.set_nonblocking(true).unwrap();
    let link = p.parent().unwrap().join("link.sock");
    symlink(&p, &link).unwrap();
    let r = CtReader::spawn(cfg(&link)).unwrap();
    wait_until("refusal counted", || {
        r.shared.errors.load(Ordering::Relaxed) >= 1
    });
    assert!(l.accept().is_err());
}

#[test]
fn a_full_queue_drops_and_counts_instead_of_blocking() {
    let (l, p) = listener("full");
    let r = CtReader::spawn(cfg(&p)).unwrap();
    serve_once(&l, |s| {
        for _ in 0..(QUEUE + 6) {
            writeln!(s, "{GOOD}").unwrap();
        }
        let mut b = [0u8; 1];
        let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
        let _ = s.read(&mut b);
    });
    wait_until("all received", || {
        r.shared.received.load(Ordering::Relaxed) as usize >= QUEUE + 6
    });
    assert_eq!(r.shared.dropped.load(Ordering::Relaxed), 6);
    assert_eq!(r.rx.try_iter().count(), QUEUE);
}

#[test]
fn the_real_helper_publisher_end_to_end() {
    use vigie_conntrack::agg::{Record, Snapshot};
    use vigie_conntrack::json::{snapshot_json, Meta};
    use vigie_conntrack::sock::{bind_secure_with, Publisher};

    let d = tmpdir("real");
    let p = d.join("conntrack.sock");
    let listener = bind_secure_with(&p, None, None, &[me()], &mut |_, _| {}).unwrap();
    let mut publisher = Publisher::new(listener);
    let r = CtReader::spawn(cfg(&p)).unwrap();
    let snap = Snapshot {
        records: vec![Record {
            src: "192.168.8.10".parse().unwrap(),
            dst: Some("8.8.8.8".parse().unwrap()),
            dport: Some(53),
            proto: Some(17),
            bytes_up: 70,
            bytes_down: 120,
            packets_up: 1,
            packets_down: 1,
            flows: 1,
            new_flows: 0,
            global: false,
        }],
        table_pressure: true,
        ..Snapshot::default()
    };
    let meta = Meta {
        seq: 1,
        ts: 1,
        interval_s: 60,
        skipped_lines: 0,
        acct_off: false,
    };
    wait_until("snapshot over the real publisher", || {
        publisher.poll();
        publisher.publish(snapshot_json(&meta, &snap));
        r.shared.received.load(Ordering::Relaxed) >= 1
    });
    let got = r.rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(got.table_pressure);
    assert_eq!(got.records[0].bytes_down, 120);
}

/// The agent must accept every line the helper can produce: same cap as the helper's publisher,
/// and the widest snapshot the helper's argument limits allow is below it.
#[test]
fn line_cap_matches_the_helpers_and_the_widest_accepted_snapshot_fits() {
    assert_eq!(MAX_LINE, vigie_conntrack::sock::MAX_SNAPSHOT_BYTES);
    let ip: std::net::IpAddr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
    let rec = vigie_conntrack::agg::Record {
        src: ip,
        dst: Some(ip),
        dport: Some(65535),
        proto: Some(255),
        bytes_up: u64::MAX,
        bytes_down: u64::MAX,
        packets_up: u64::MAX,
        packets_down: u64::MAX,
        flows: u64::MAX,
        new_flows: u64::MAX,
        global: false,
    };
    let n = vigie_conntrack::cli::MAX_RECORDS - 1;
    let snap = vigie_conntrack::agg::Snapshot {
        records: vec![rec; n],
        ..Default::default()
    };
    let meta = vigie_conntrack::json::Meta {
        seq: u64::MAX,
        ts: u64::MAX,
        interval_s: u64::MAX,
        skipped_lines: usize::MAX,
        acct_off: true,
    };
    let line = vigie_conntrack::json::snapshot_json(&meta, &snap);
    assert!(line.len() <= MAX_LINE, "{} bytes", line.len());
    assert!(
        vigie_agent::ctparse::parse_snapshot(line.as_bytes()).is_ok(),
        "the agent parses the widest snapshot"
    );
}
