//! Client for the conntrack helper's unix socket.
//!
//! A dedicated reader thread owns the connection, so a silent, slow or hostile peer can never
//! block the main loop: the thread hands parsed snapshots over a bounded channel (`try_send`; a
//! full channel drops the newest and counts it). Everything that goes wrong is a counted error
//! followed by a reconnect with capped exponential backoff.
//!
//! Before connecting, the socket path is verified: not a symlink, a socket, owned by root or the
//! agent, not group/other-writable, inside a real directory owned by root or the agent that
//! nobody else can write to. A path check cannot be atomic with `connect`; the directory rule is
//! what stops a swap. `UnixStream::peer_cred` (which would assert the peer's uid after
//! connecting) is not stable in std, so the remaining race (root or the agent replacing the
//! socket) is accepted.

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::ctparse::{parse_snapshot, Snapshot, MAX_LINE};

pub const DEFAULT_SOCKET: &str = "/tmp/vigie/conntrack.sock";
/// Snapshots queued between the reader thread and the main loop.
pub const QUEUE: usize = 4;
const READ_CHUNK: usize = 64 * 1024;
const TICK: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Symlink,
    NotSocket,
    WrongOwner(u32),
    Writable(u32),
    DirSymlink,
    DirNotDir,
    DirWrongOwner(u32),
    DirWritable(u32),
    Io(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symlink => f.write_str("socket path is a symlink"),
            Self::NotSocket => f.write_str("socket path is not a unix socket"),
            Self::WrongOwner(u) => write!(f, "socket is owned by uid {u}, not root or the agent"),
            Self::Writable(m) => write!(f, "socket mode {m:o} is group/other-writable"),
            Self::DirSymlink => f.write_str("socket directory is a symlink"),
            Self::DirNotDir => f.write_str("socket directory is not a directory"),
            Self::DirWrongOwner(u) => {
                write!(
                    f,
                    "socket directory is owned by uid {u}, not root or the agent"
                )
            }
            Self::DirWritable(m) => {
                write!(f, "socket directory mode {m:o} is group/other-writable")
            }
            Self::Io(e) => write!(f, "cannot inspect socket: {e}"),
        }
    }
}

/// What `symlink_metadata` says about a path, so the checks are pure and testable without root.
#[derive(Debug, Clone, Copy)]
pub struct PathMeta {
    pub symlink: bool,
    pub socket: bool,
    pub dir: bool,
    pub mode: u32,
    pub uid: u32,
}

impl PathMeta {
    pub fn of(m: &fs::Metadata) -> Self {
        let t = m.file_type();
        Self {
            symlink: t.is_symlink(),
            socket: t.is_socket(),
            dir: t.is_dir(),
            mode: m.mode() & 0o7777,
            uid: m.uid(),
        }
    }
}

pub fn check_socket_meta(m: &PathMeta, trusted: &[u32]) -> Result<(), Refusal> {
    if m.symlink {
        return Err(Refusal::Symlink);
    }
    if !m.socket {
        return Err(Refusal::NotSocket);
    }
    if !trusted.contains(&m.uid) {
        return Err(Refusal::WrongOwner(m.uid));
    }
    if m.mode & 0o022 != 0 {
        return Err(Refusal::Writable(m.mode));
    }
    Ok(())
}

pub fn check_dir_meta(m: &PathMeta, trusted: &[u32]) -> Result<(), Refusal> {
    if m.symlink {
        return Err(Refusal::DirSymlink);
    }
    if !m.dir {
        return Err(Refusal::DirNotDir);
    }
    if !trusted.contains(&m.uid) {
        return Err(Refusal::DirWrongOwner(m.uid));
    }
    if m.mode & 0o022 != 0 {
        return Err(Refusal::DirWritable(m.mode));
    }
    Ok(())
}

/// Uids allowed to own the socket and its directory: root and ourselves. `/proc/self` is owned
/// by the effective uid.
pub fn trusted_uids() -> io::Result<Vec<u32>> {
    let me = fs::metadata("/proc/self")?.uid();
    Ok(if me == 0 { vec![0] } else { vec![0, me] })
}

pub fn verify_socket(path: &Path, trusted: &[u32]) -> Result<(), Refusal> {
    let io = |e: io::Error| Refusal::Io(e.to_string());
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    check_dir_meta(
        &PathMeta::of(&fs::symlink_metadata(parent).map_err(io)?),
        trusted,
    )?;
    check_socket_meta(
        &PathMeta::of(&fs::symlink_metadata(path).map_err(io)?),
        trusted,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineEvent {
    Line(Vec<u8>),
    /// A line longer than `MAX_LINE`; the connection must be dropped.
    Oversized,
}

/// Splits a byte stream into lines with a hard cap on what is buffered.
#[derive(Debug, Default)]
pub struct LineBuf {
    buf: Vec<u8>,
}

impl LineBuf {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<LineEvent> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut start = 0;
        while let Some(off) = self.buf[start..].iter().position(|&b| b == b'\n') {
            let line = &self.buf[start..start + off];
            out.push(if line.len() > MAX_LINE {
                LineEvent::Oversized
            } else {
                LineEvent::Line(line.to_vec())
            });
            start += off + 1;
        }
        self.buf.drain(..start);
        if self.buf.len() > MAX_LINE {
            self.buf.clear();
            out.push(LineEvent::Oversized);
        }
        out
    }

    /// Bytes of an unfinished line.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// Reconnect delay: `base << attempt`, never above `cap`.
pub fn backoff_ms(attempt: u32, base_ms: u64, cap_ms: u64) -> u64 {
    if attempt >= 32 {
        return cap_ms;
    }
    base_ms.saturating_mul(1u64 << attempt).min(cap_ms)
}

#[derive(Debug, Clone)]
pub struct CtConfig {
    pub path: PathBuf,
    pub trusted: Vec<u32>,
    /// A line must be complete this long after its first byte, or the peer is dropped.
    pub line_deadline: Duration,
    pub backoff_base_ms: u64,
    pub backoff_cap_ms: u64,
}

impl CtConfig {
    pub fn new(path: PathBuf, trusted: Vec<u32>) -> Self {
        Self {
            path,
            trusted,
            line_deadline: Duration::from_secs(10),
            backoff_base_ms: 1_000,
            backoff_cap_ms: 60_000,
        }
    }
}

/// State shared with the main loop. All plain atomics: the main loop never waits on the reader.
#[derive(Debug, Default)]
pub struct CtShared {
    pub connected: AtomicBool,
    /// Counted errors: refusals, failed connects, bad lines, oversized lines, stalls, EOF mid-line.
    pub errors: AtomicU64,
    /// Snapshots dropped because the queue was full.
    pub dropped: AtomicU64,
    /// Failed connect attempts so far (tests watch it to see the backoff run).
    pub attempts: AtomicU64,
    /// Snapshots received over the connection's lifetime.
    pub received: AtomicU64,
}

pub struct CtReader {
    pub rx: Receiver<Snapshot>,
    pub shared: Arc<CtShared>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl CtReader {
    pub fn spawn(cfg: CtConfig) -> io::Result<Self> {
        let (tx, rx) = sync_channel(QUEUE);
        let shared = Arc::new(CtShared::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, st2) = (shared.clone(), stop.clone());
        let handle = thread::Builder::new()
            .name("vigie-ct".into())
            .spawn(move || run(&cfg, &tx, &s2, &st2))?;
        Ok(Self {
            rx,
            shared,
            stop,
            handle: Some(handle),
        })
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for CtReader {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn sleep_unless_stopped(total: Duration, stop: &AtomicBool) {
    let end = Instant::now() + total;
    while !stop.load(Ordering::Relaxed) {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        thread::sleep(left.min(TICK));
    }
}

fn run(cfg: &CtConfig, tx: &SyncSender<Snapshot>, sh: &CtShared, stop: &AtomicBool) {
    let mut attempt = 0u32;
    while !stop.load(Ordering::Relaxed) {
        let got = connect(cfg);
        match got {
            Ok(stream) => {
                sh.connected.store(true, Ordering::Relaxed);
                let before = sh.received.load(Ordering::Relaxed);
                serve(stream, cfg, tx, sh, stop);
                sh.connected.store(false, Ordering::Relaxed);
                if sh.received.load(Ordering::Relaxed) > before {
                    attempt = 0;
                }
            }
            Err(e) => {
                eprintln!("conntrack socket {}: {e}", cfg.path.display());
                sh.errors.fetch_add(1, Ordering::Relaxed);
                sh.attempts.fetch_add(1, Ordering::Relaxed);
            }
        }
        let wait = backoff_ms(attempt, cfg.backoff_base_ms, cfg.backoff_cap_ms);
        attempt = attempt.saturating_add(1);
        sleep_unless_stopped(Duration::from_millis(wait), stop);
    }
}

fn connect(cfg: &CtConfig) -> Result<UnixStream, String> {
    verify_socket(&cfg.path, &cfg.trusted).map_err(|r| format!("refused: {r}"))?;
    let s = UnixStream::connect(&cfg.path).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(TICK)).map_err(|e| e.to_string())?;
    Ok(s)
}

fn bump(sh: &CtShared, what: &str) {
    eprintln!("conntrack socket: {what}");
    sh.errors.fetch_add(1, Ordering::Relaxed);
}

/// Reads until the peer misbehaves or goes away. Returns on any error (already counted).
fn serve(
    mut s: UnixStream,
    cfg: &CtConfig,
    tx: &SyncSender<Snapshot>,
    sh: &CtShared,
    stop: &AtomicBool,
) {
    let mut lines = LineBuf::default();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut line_started: Option<Instant> = None;
    while !stop.load(Ordering::Relaxed) {
        match s.read(&mut buf) {
            Ok(0) => {
                if lines.pending() > 0 {
                    bump(sh, "peer closed in the middle of a line");
                }
                return;
            }
            Ok(n) => {
                for ev in lines.push(&buf[..n]) {
                    match ev {
                        LineEvent::Oversized => return bump(sh, "oversized line; dropping peer"),
                        LineEvent::Line(l) => match parse_snapshot(&l) {
                            Ok(snap) => deliver(snap, tx, sh),
                            Err(e) => return bump(sh, &format!("bad snapshot: {e}")),
                        },
                    }
                }
                line_started =
                    (lines.pending() > 0).then(|| line_started.unwrap_or_else(Instant::now));
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return bump(sh, &format!("read: {e}")),
        }
        if line_started.is_some_and(|t| t.elapsed() > cfg.line_deadline) {
            return bump(sh, "peer too slow to finish a line; dropping");
        }
    }
}

fn deliver(snap: Snapshot, tx: &SyncSender<Snapshot>, sh: &CtShared) {
    sh.received.fetch_add(1, Ordering::Relaxed);
    match tx.try_send(snap) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            sh.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}
