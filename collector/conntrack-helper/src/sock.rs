//! Unix socket creation with ownership/permission hardening, and a never-blocking publisher.

use std::fs::{self, DirBuilder};
use std::io::{self, Write};
use std::os::unix::fs::{chown, DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Largest snapshot line the publisher will buffer.
pub const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

fn denied(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg)
}

/// Effective uid/gid of this process (`/proc/self` is owned by them), without libc.
pub fn current_ids() -> io::Result<(u32, u32)> {
    let m = fs::metadata("/proc/self")?;
    Ok((m.uid(), m.gid()))
}

/// The socket directory must be a real directory (not a symlink), not world-writable, and owned
/// by one of `allowed_uids`; otherwise another local user could swap the socket under us.
pub fn check_dir_for(dir: &Path, allowed_uids: &[u32]) -> io::Result<()> {
    let m = fs::symlink_metadata(dir)?;
    if m.file_type().is_symlink() {
        return Err(denied(format!("{} is a symlink", dir.display())));
    }
    if !m.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if m.permissions().mode() & 0o002 != 0 {
        return Err(denied(format!("{} is world-writable", dir.display())));
    }
    if !allowed_uids.contains(&m.uid()) {
        return Err(denied(format!(
            "{} is owned by uid {}, not root or the helper's uid",
            dir.display(),
            m.uid()
        )));
    }
    Ok(())
}

/// Owner must be root or ourselves. Never the unprivileged agent: root later chmods/chowns
/// inside this directory and must not be steerable by a less-privileged owner.
pub fn check_dir(dir: &Path) -> io::Result<()> {
    let (euid, _) = current_ids()?;
    check_dir_for(dir, &[0, euid])
}

/// Confirms `path` is a real unix socket (not a symlink) with mode exactly 0600 and, when given,
/// the expected owner and group.
pub fn verify_socket(path: &Path, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_socket() {
        return Err(denied(format!("{} is not a unix socket", path.display())));
    }
    let mode = m.permissions().mode() & 0o7777;
    if mode != 0o600 {
        return Err(denied(format!(
            "{} has mode {mode:o}, want 600",
            path.display()
        )));
    }
    if uid.is_some_and(|u| u != m.uid()) || gid.is_some_and(|g| g != m.gid()) {
        return Err(denied(format!(
            "{} is owned by {}:{}, not the configured owner",
            path.display(),
            m.uid(),
            m.gid()
        )));
    }
    Ok(())
}

fn check_target(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.file_type().is_symlink() => {
            Err(denied(format!("{} is a symlink", path.display())))
        }
        Ok(m) if m.file_type().is_socket() => Ok(()),
        Ok(_) => Err(denied(format!(
            "{} exists and is not a socket",
            path.display()
        ))),
    }
}

fn stage_and_install(
    stage: &Path,
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> io::Result<UnixListener> {
    let staged = stage.join("s");
    let listener = UnixListener::bind(&staged)?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
    if uid.is_some() || gid.is_some() {
        chown(&staged, uid, gid)?;
    }
    verify_socket(&staged, uid, gid)?;
    fs::rename(&staged, path)?;
    verify_socket(path, uid, gid)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Binds the socket privately (0700 staging dir, so nobody can connect before mode/owner are
/// right), then atomically renames it into place. A stale socket at `path` is replaced; a
/// symlink or any other file type is refused.
pub fn bind_secure(path: &Path, uid: Option<u32>, gid: Option<u32>) -> io::Result<UnixListener> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    check_dir(parent)?;
    check_target(path)?;
    let stage: PathBuf = parent.join(format!(".vigie-stage-{}", std::process::id()));
    if fs::symlink_metadata(&stage).is_ok_and(|m| m.is_dir()) {
        fs::remove_dir_all(&stage)?;
    }
    DirBuilder::new().mode(0o700).create(&stage)?;
    let res = stage_and_install(&stage, path, uid, gid);
    let _ = fs::remove_dir_all(&stage);
    res
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Entire line written to the reader.
    Delivered,
    /// Partially written; the rest is flushed by later `poll` calls.
    Queued,
    NoReader,
    /// Previous snapshot still unsent; this one was dropped.
    DroppedBusy,
    DroppedTooLarge,
}

/// Single-reader, non-blocking snapshot publisher. Holds at most one snapshot in memory.
pub struct Publisher {
    listener: UnixListener,
    client: Option<UnixStream>,
    pending: Vec<u8>,
    pos: usize,
}

impl Publisher {
    pub fn new(listener: UnixListener) -> Self {
        Self {
            listener,
            client: None,
            pending: Vec::new(),
            pos: 0,
        }
    }

    /// Accepts a (replacement) reader and flushes any queued remainder. Never blocks.
    pub fn poll(&mut self) {
        while let Ok((s, _)) = self.listener.accept() {
            if s.set_nonblocking(true).is_ok() {
                self.client = Some(s);
                self.pending.clear();
                self.pos = 0;
            }
        }
        self.flush();
    }

    fn flush(&mut self) {
        let Some(c) = self.client.as_mut() else {
            return;
        };
        while self.pos < self.pending.len() {
            match c.write(&self.pending[self.pos..]) {
                Ok(0) => return self.drop_client(),
                Ok(n) => self.pos += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return self.drop_client(),
            }
        }
        self.pending.clear();
        self.pos = 0;
    }

    fn drop_client(&mut self) {
        self.client = None;
        self.pending.clear();
        self.pos = 0;
    }

    pub fn has_reader(&self) -> bool {
        self.client.is_some()
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending.len() - self.pos
    }

    /// Sends one snapshot line (a newline is appended). Drops it rather than ever blocking or
    /// growing the buffer past one snapshot.
    pub fn publish(&mut self, line: &str) -> Outcome {
        self.poll();
        if line.len() >= MAX_SNAPSHOT_BYTES {
            return Outcome::DroppedTooLarge;
        }
        if self.client.is_none() {
            return Outcome::NoReader;
        }
        if self.pending_bytes() > 0 {
            return Outcome::DroppedBusy;
        }
        self.pending.extend_from_slice(line.as_bytes());
        self.pending.push(b'\n');
        self.flush();
        if self.client.is_none() {
            Outcome::NoReader
        } else if self.pending_bytes() == 0 {
            Outcome::Delivered
        } else {
            Outcome::Queued
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::{symlink, DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vigie-ct-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::DirBuilder::new().mode(0o755).create(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn current_ids_match_own_files() {
        let d = tmpdir("ids");
        let m = fs::metadata(&d).unwrap();
        assert_eq!(current_ids().unwrap(), (m.uid(), m.gid()));
    }

    #[test]
    fn dir_check_rejects_world_writable() {
        let d = tmpdir("ww");
        assert!(check_dir(&d).is_ok());
        fs::set_permissions(&d, fs::Permissions::from_mode(0o757)).unwrap();
        assert_eq!(
            check_dir(&d).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&d, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(
            check_dir(&d).is_err(),
            "sticky does not excuse world-writable"
        );
    }

    #[test]
    fn dir_check_rejects_symlink_and_non_dir() {
        let d = tmpdir("dsym");
        let real = d.join("real");
        fs::create_dir(&real).unwrap();
        let link = d.join("link");
        symlink(&real, &link).unwrap();
        assert!(check_dir(&real).is_ok());
        let e = check_dir(&link).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        let file = d.join("f");
        fs::write(&file, b"x").unwrap();
        assert!(check_dir(&file).is_err());
        assert!(check_dir(&d.join("missing")).is_err());
    }

    #[test]
    fn dir_check_rejects_foreign_owner() {
        let d = tmpdir("own");
        let (uid, _) = current_ids().unwrap();
        assert!(check_dir_for(&d, &[uid]).is_ok());
        assert!(check_dir_for(&d, &[uid + 1]).is_err());
        assert!(check_dir_for(&d, &[]).is_err());
    }

    #[test]
    fn bind_creates_0600_socket_owned_by_target_and_no_stage_left() {
        let d = tmpdir("bind");
        let sock = d.join("c.sock");
        let (uid, gid) = current_ids().unwrap();
        let _l = bind_secure(&sock, Some(uid), Some(gid)).unwrap();
        let m = fs::symlink_metadata(&sock).unwrap();
        assert!(m.file_type().is_socket());
        assert_eq!(mode(&sock), 0o600);
        assert_eq!((m.uid(), m.gid()), (uid, gid));
        assert!(verify_socket(&sock, Some(uid), Some(gid)).is_ok());
        let left: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 1, "stray entries: {left:?}");
    }

    #[test]
    fn verify_rejects_wrong_mode_owner_group_type_and_symlink() {
        let d = tmpdir("ver");
        let sock = d.join("c.sock");
        let (uid, gid) = current_ids().unwrap();
        let _l = bind_secure(&sock, None, None).unwrap();
        assert!(verify_socket(&sock, Some(uid), Some(gid)).is_ok());
        assert!(verify_socket(&sock, Some(uid + 1), None).is_err());
        assert!(verify_socket(&sock, None, Some(gid + 1)).is_err());
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(verify_socket(&sock, None, None).is_err());
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o602)).unwrap();
        assert!(verify_socket(&sock, None, None).is_err());
        let file = d.join("plain");
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verify_socket(&file, None, None).is_err());
        let link = d.join("lnk");
        symlink(&sock, &link).unwrap();
        assert!(verify_socket(&link, None, None).is_err());
    }

    /// A supplementary group other than the primary one, if this user has one: chown to it works
    /// without root, so the chown step is observable.
    fn other_group(primary: u32) -> Option<u32> {
        let st = fs::read_to_string("/proc/self/status").ok()?;
        let groups = st.lines().find_map(|l| l.strip_prefix("Groups:"))?;
        groups
            .split_whitespace()
            .filter_map(|g| g.parse::<u32>().ok())
            .find(|g| *g != primary)
    }

    #[test]
    fn bind_chowns_socket_to_requested_group() {
        let (uid, gid) = current_ids().unwrap();
        let Some(other) = other_group(gid) else {
            eprintln!("SKIPPED: no supplementary group available to chown to");
            return;
        };
        let d = tmpdir("chown");
        let probe = d.join("probe");
        fs::write(&probe, b"").unwrap();
        if std::os::unix::fs::chown(&probe, None, Some(other)).is_err() {
            eprintln!("SKIPPED: gid {other} is listed but not usable for chown here");
            return;
        }
        let sock = d.join("c.sock");
        let _l = bind_secure(&sock, Some(uid), Some(other)).unwrap();
        assert_eq!(fs::symlink_metadata(&sock).unwrap().gid(), other);
    }

    #[test]
    fn bind_refuses_symlink_at_socket_path() {
        let d = tmpdir("bsym");
        let target = d.join("victim");
        fs::write(&target, b"keep").unwrap();
        let sock = d.join("c.sock");
        symlink(&target, &sock).unwrap();
        let e = bind_secure(&sock, None, None).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        assert!(fs::symlink_metadata(&sock)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn bind_refuses_regular_file_and_world_writable_dir() {
        let d = tmpdir("bfile");
        let sock = d.join("c.sock");
        fs::write(&sock, b"data").unwrap();
        assert!(bind_secure(&sock, None, None).is_err());
        assert_eq!(fs::read(&sock).unwrap(), b"data");
        fs::remove_file(&sock).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(bind_secure(&sock, None, None).is_err());
        assert!(fs::symlink_metadata(&sock).is_err());
    }

    #[test]
    fn bind_replaces_stale_socket() {
        let d = tmpdir("stale");
        let sock = d.join("c.sock");
        drop(bind_secure(&sock, None, None).unwrap());
        assert!(bind_secure(&sock, None, None).is_ok());
    }

    fn publisher(tag: &str) -> (Publisher, PathBuf) {
        let d = tmpdir(tag);
        let sock = d.join("c.sock");
        (
            Publisher::new(bind_secure(&sock, None, None).unwrap()),
            sock,
        )
    }

    #[test]
    fn publish_without_reader_returns_immediately() {
        let (mut p, _) = publisher("noreader");
        let t = Instant::now();
        for _ in 0..1000 {
            assert_eq!(p.publish("{}"), Outcome::NoReader);
        }
        assert!(t.elapsed() < Duration::from_secs(1));
        assert!(!p.has_reader());
    }

    #[test]
    fn connected_reader_gets_newline_delimited_snapshots() {
        let (mut p, sock) = publisher("reader");
        let c = UnixStream::connect(&sock).unwrap();
        p.poll();
        assert!(p.has_reader());
        assert_eq!(p.publish(r#"{"a":1}"#), Outcome::Delivered);
        assert_eq!(p.publish(r#"{"a":2}"#), Outcome::Delivered);
        let mut r = BufReader::new(c);
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        assert_eq!(l, "{\"a\":1}\n");
        l.clear();
        r.read_line(&mut l).unwrap();
        assert_eq!(l, "{\"a\":2}\n");
    }

    #[test]
    fn disconnected_reader_is_dropped() {
        let (mut p, sock) = publisher("gone");
        let c = UnixStream::connect(&sock).unwrap();
        p.poll();
        drop(c);
        // first write after close may succeed into the buffer or fail; within a few it must fail
        for _ in 0..5 {
            p.publish("{}");
        }
        assert!(!p.has_reader());
        assert_eq!(p.publish("{}"), Outcome::NoReader);
    }

    #[test]
    fn stalled_reader_never_blocks_and_buffer_stays_bounded() {
        let (mut p, sock) = publisher("stall");
        let _c = UnixStream::connect(&sock).unwrap();
        p.poll();
        let big = "x".repeat(1_500_000);
        let t = Instant::now();
        let outcomes: Vec<Outcome> = (0..10).map(|_| p.publish(&big)).collect();
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "blocked: {:?}",
            t.elapsed()
        );
        assert!(outcomes.contains(&Outcome::Queued), "{outcomes:?}");
        assert!(outcomes.contains(&Outcome::DroppedBusy), "{outcomes:?}");
        assert!(p.pending_bytes() <= MAX_SNAPSHOT_BYTES + 1);
    }

    #[test]
    fn oversize_snapshot_is_dropped() {
        let (mut p, sock) = publisher("big");
        let _c = UnixStream::connect(&sock).unwrap();
        p.poll();
        let huge = "x".repeat(MAX_SNAPSHOT_BYTES + 1);
        assert_eq!(p.publish(&huge), Outcome::DroppedTooLarge);
    }

    #[test]
    fn queued_remainder_is_flushed_when_reader_catches_up() {
        let (mut p, sock) = publisher("flush");
        let c = UnixStream::connect(&sock).unwrap();
        p.poll();
        let big = "y".repeat(1_500_000);
        assert_eq!(p.publish(&big), Outcome::Queued);
        let reader = std::thread::spawn(move || {
            let mut l = String::new();
            BufReader::new(c).read_line(&mut l).unwrap();
            l.len()
        });
        let t = Instant::now();
        while !reader.is_finished() && t.elapsed() < Duration::from_secs(5) {
            p.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(reader.is_finished(), "remainder never flushed");
        assert_eq!(reader.join().unwrap(), big.len() + 1);
    }

    #[test]
    fn new_connection_replaces_old_reader() {
        let (mut p, sock) = publisher("replace");
        let _a = UnixStream::connect(&sock).unwrap();
        p.poll();
        let b = UnixStream::connect(&sock).unwrap();
        p.poll();
        assert_eq!(p.publish("{}"), Outcome::Delivered);
        let mut l = String::new();
        BufReader::new(b).read_line(&mut l).unwrap();
        assert_eq!(l, "{}\n");
    }
}
