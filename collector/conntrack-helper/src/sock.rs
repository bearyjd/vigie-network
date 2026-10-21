//! Unix socket creation with ownership/permission hardening, and a never-blocking publisher.

use std::fs::{self, DirBuilder};
use std::io::{self, Read, Write};
use std::os::unix::fs::{lchown, DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
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

/// The socket directory must be a real directory (not a symlink), writable by nobody but its
/// owner (no group- or other-write bit, sticky or not), and owned by one of `allowed_uids`;
/// otherwise another local user could swap the socket under us.
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
    if m.permissions().mode() & 0o022 != 0 {
        return Err(denied(format!(
            "{} is group- or world-writable (mode {:o})",
            dir.display(),
            m.permissions().mode() & 0o7777
        )));
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

/// Owner must be root or ourselves (in production that is root alone). Never the unprivileged
/// agent: root later chmods/chowns inside this directory and must not be steerable by a
/// less-privileged owner.
pub fn check_dir(dir: &Path) -> io::Result<()> {
    check_dir_for(dir, &owner_uids()?)
}

fn owner_uids() -> io::Result<[u32; 2]> {
    let (euid, _) = current_ids()?;
    Ok([0, euid])
}

/// Creates the socket directory (0755) if it does not exist, then insists it is acceptable.
/// An existing directory is never repaired or reused silently: it is checked and refused.
fn ensure_dir(dir: &Path, owners: &[u32]) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            match DirBuilder::new().mode(0o755).create(dir) {
                Ok(()) => fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    check_dir_for(dir, owners)
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

/// Points at which tests may interfere with the staged socket (see `bind_secure_with`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Just bound; nothing re-checked yet.
    Bound,
    /// Identity re-checked; the next call is the chmod.
    BeforeChmod,
    /// Identity re-checked; the next call is the lchown.
    BeforeChown,
    /// Staged socket verified; the identity re-check guarding the rename comes next.
    BeforeInstall,
    /// Identity re-checked; the next call is the rename (a swap here can only be detected
    /// after the fact).
    BeforeRename,
}

/// (device, inode) of the socket we created.
type Ident = (u64, u64);

/// The staged path must still be the very socket we bound: a socket, not a symlink, same
/// device and inode.
fn recheck(staged: &Path) -> io::Result<Ident> {
    let m = fs::symlink_metadata(staged)?;
    if !m.file_type().is_socket() {
        return Err(denied(format!(
            "{} is no longer the socket we created",
            staged.display()
        )));
    }
    Ok((m.dev(), m.ino()))
}

fn recheck_same(staged: &Path, id: Ident) -> io::Result<()> {
    if recheck(staged)? != id {
        return Err(denied(format!(
            "{} was replaced after bind",
            staged.display()
        )));
    }
    Ok(())
}

fn stage_and_install(
    stage: &Path,
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    hook: &mut dyn FnMut(Step, &Path),
) -> io::Result<UnixListener> {
    let staged = stage.join("s");
    let listener = UnixListener::bind(&staged)?;
    let id = recheck(&staged)?;
    hook(Step::Bound, &staged);
    recheck_same(&staged, id)?;
    hook(Step::BeforeChmod, &staged);
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
    if uid.is_some() || gid.is_some() {
        recheck_same(&staged, id)?;
        hook(Step::BeforeChown, &staged);
        lchown(&staged, uid, gid)?;
    }
    verify_socket(&staged, uid, gid)?;
    hook(Step::BeforeInstall, &staged);
    recheck_same(&staged, id)?;
    hook(Step::BeforeRename, &staged);
    fs::rename(&staged, path)?;
    if let Err(e) = recheck_same(path, id) {
        // Whatever got renamed in is not our socket: take it back out. It came from our
        // private staging directory, so it was not planted by an unprivileged user.
        let _ = fs::remove_file(path);
        return Err(e);
    }
    verify_socket(path, uid, gid)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// 64 random bits from the kernel, hex encoded (no dependency, no predictable name).
fn random_hex() -> io::Result<String> {
    let mut b = [0u8; 8];
    fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Binds the socket privately (fresh 0700 staging dir with a random name, so nobody can
/// connect before mode/owner are right), then atomically renames it into place. The socket
/// directory is created if absent and must otherwise be acceptable (see `check_dir_for`). A
/// stale socket at `path` is replaced; a symlink or any other file type is refused.
pub fn bind_secure(path: &Path, uid: Option<u32>, gid: Option<u32>) -> io::Result<UnixListener> {
    bind_secure_with(path, uid, gid, &owner_uids()?, &mut |_, _| {})
}

/// `bind_secure` with the allowed directory owners explicit and a hook called at each `Step`.
pub fn bind_secure_with(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    owners: &[u32],
    hook: &mut dyn FnMut(Step, &Path),
) -> io::Result<UnixListener> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    ensure_dir(parent, owners)?;
    check_target(path)?;
    let stage: PathBuf = parent.join(format!(".vigie-stage-{}", random_hex()?));
    DirBuilder::new().mode(0o700).create(&stage)?;
    let res = stage_and_install(&stage, path, uid, gid, hook);
    // Non-recursive on purpose: only what we created, never a tree we did not.
    let _ = fs::remove_file(stage.join("s"));
    let _ = fs::remove_dir(&stage);
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
/// A new connection never cuts a line already in flight: it waits (one slot, newest wins) until
/// the current line is fully written, then takes over and the old reader is closed.
pub struct Publisher {
    listener: UnixListener,
    client: Option<UnixStream>,
    next: Option<UnixStream>,
    pending: Vec<u8>,
    pos: usize,
}

impl Publisher {
    pub fn new(listener: UnixListener) -> Self {
        Self {
            listener,
            client: None,
            next: None,
            pending: Vec::new(),
            pos: 0,
        }
    }

    /// Accepts new connections and flushes any queued remainder. Never blocks.
    pub fn poll(&mut self) {
        let mut newest = None;
        while let Ok((s, _)) = self.listener.accept() {
            if s.set_nonblocking(true).is_ok() {
                newest = Some(s);
            }
        }
        if let Some(s) = newest {
            self.next = Some(s);
        }
        self.promote();
        self.flush();
        self.promote();
    }

    /// A waiting connection becomes the reader once no line is in flight.
    fn promote(&mut self) {
        if self.pending_bytes() == 0 {
            if let Some(s) = self.next.take() {
                self.client = Some(s);
                self.pending.clear();
                self.pos = 0;
            }
        }
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

    /// A newer connection is waiting for the in-flight line to finish.
    pub fn has_waiting_reader(&self) -> bool {
        self.next.is_some()
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending.len() - self.pos
    }

    /// Sends one snapshot line (a newline is appended). Takes the line by value so it is moved
    /// into the send buffer, not copied. Drops it rather than ever blocking or growing the
    /// buffer past one snapshot.
    pub fn publish(&mut self, line: String) -> Outcome {
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
        self.pending = line.into_bytes();
        self.pending.push(b'\n');
        self.pos = 0;
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
    fn dir_check_rejects_group_and_world_write() {
        let d = tmpdir("ww");
        assert!(check_dir(&d).is_ok());
        for ok in [0o700, 0o750, 0o755, 0o555] {
            fs::set_permissions(&d, fs::Permissions::from_mode(ok)).unwrap();
            assert!(check_dir(&d).is_ok(), "{ok:o} should pass");
        }
        for bad in [0o757, 0o775, 0o770, 0o720, 0o702, 0o777, 0o1777, 0o2775] {
            fs::set_permissions(&d, fs::Permissions::from_mode(bad)).unwrap();
            let e = check_dir(&d).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{bad:o}");
            assert!(e.to_string().contains("writable"), "{bad:o}: {e}");
        }
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
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

    fn is_root() -> bool {
        current_ids().unwrap().0 == 0
    }

    /// A gid different from `uid` we can chown to: any gid as root, otherwise a supplementary
    /// group of this user. None (non-root only) means the caller must skip, loudly.
    fn distinct_gid(uid: u32) -> Option<u32> {
        if is_root() {
            return Some(4242);
        }
        let st = fs::read_to_string("/proc/self/status").ok()?;
        let groups = st.lines().find_map(|l| l.strip_prefix("Groups:"))?;
        let probe = tmpdir("gidprobe").join("p");
        fs::write(&probe, b"").unwrap();
        // A listed group may be unusable (unmapped in a sandbox): only accept one chown takes.
        groups
            .split_whitespace()
            .filter_map(|g| g.parse::<u32>().ok())
            .find(|g| *g != uid && lchown(&probe, None, Some(*g)).is_ok())
    }

    #[test]
    fn dir_check_rejects_foreign_owner_and_does_not_confuse_uid_with_gid() {
        let d = tmpdir("own");
        let (uid, _) = current_ids().unwrap();
        assert!(check_dir_for(&d, &[uid]).is_ok());
        assert!(check_dir_for(&d, &[uid + 1]).is_err());
        assert!(check_dir_for(&d, &[]).is_err());
        let Some(g) = distinct_gid(uid) else {
            eprintln!("SKIPPED uid!=gid owner check: no group distinct from the uid is usable");
            return;
        };
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        lchown(&d, None, Some(g)).unwrap();
        let m = fs::metadata(&d).unwrap();
        assert_ne!(m.uid(), m.gid(), "fixture must have uid != gid");
        assert!(check_dir_for(&d, &[uid]).is_ok());
        assert!(
            check_dir_for(&d, &[m.gid()]).is_err(),
            "the group id must not be accepted as an owner id"
        );
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

    #[test]
    fn bind_chowns_socket_to_requested_group() {
        let (uid, _) = current_ids().unwrap();
        let Some(other) = distinct_gid(uid) else {
            assert!(!is_root(), "root must always be able to chown");
            eprintln!("SKIPPED chown test: not root and no usable supplementary group");
            return;
        };
        let d = tmpdir("chown");
        let sock = d.join("c.sock");
        let _l = bind_secure(&sock, Some(uid), Some(other)).unwrap();
        let m = fs::symlink_metadata(&sock).unwrap();
        assert_eq!((m.uid(), m.gid()), (uid, other));
        assert_eq!(mode(&sock), 0o600);
    }

    fn swap_in_symlink(staged: &Path, victim: &Path) {
        let alt = staged.parent().unwrap().join("alt");
        symlink(victim, &alt).unwrap();
        fs::rename(&alt, staged).unwrap();
    }

    fn victim_file(d: &Path) -> PathBuf {
        let v = d.join("victim");
        fs::write(&v, b"keep").unwrap();
        fs::set_permissions(&v, fs::Permissions::from_mode(0o644)).unwrap();
        v
    }

    #[test]
    fn symlink_swapped_in_after_bind_is_refused_and_never_chmodded() {
        let d = tmpdir("swapbind");
        let victim = victim_file(&d);
        let (uid, _) = current_ids().unwrap();
        let mut hit = false;
        let e = bind_secure_with(&d.join("c.sock"), None, None, &[uid], &mut |st, staged| {
            if st == Step::Bound {
                hit = true;
                swap_in_symlink(staged, &victim);
            }
        })
        .unwrap_err();
        assert!(hit, "hook never ran");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert_eq!(mode(&victim), 0o644, "chmod went through the symlink");
        assert!(fs::symlink_metadata(d.join("c.sock")).is_err());
    }

    #[test]
    fn symlink_swapped_in_before_lchown_is_never_followed() {
        let (uid, _) = current_ids().unwrap();
        let Some(other) = distinct_gid(uid) else {
            assert!(!is_root(), "root must always be able to chown");
            eprintln!("SKIPPED lchown swap test: not root and no usable supplementary group");
            return;
        };
        let d = tmpdir("swapchown");
        let victim = victim_file(&d);
        let before = fs::metadata(&victim).unwrap().gid();
        assert_ne!(before, other);
        let mut hit = false;
        let res = bind_secure_with(
            &d.join("c.sock"),
            Some(uid),
            Some(other),
            &[uid],
            &mut |st, staged| {
                if st == Step::BeforeChown {
                    hit = true;
                    swap_in_symlink(staged, &victim);
                }
            },
        );
        assert!(hit, "hook never ran");
        assert!(res.is_err(), "a symlink must not pass verification");
        assert_eq!(
            fs::metadata(&victim).unwrap().gid(),
            before,
            "chown went through the symlink"
        );
        assert!(fs::symlink_metadata(d.join("c.sock")).is_err());
    }

    fn swap_in_socket(staged: &Path) -> UnixListener {
        let alt = staged.parent().unwrap().join("alt");
        let l = UnixListener::bind(&alt).unwrap();
        fs::set_permissions(&alt, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&alt, staged).unwrap();
        l
    }

    #[test]
    fn socket_replaced_before_install_is_refused() {
        let d = tmpdir("swapinstall");
        let (uid, _) = current_ids().unwrap();
        let mut imposter = None;
        let sock = d.join("c.sock");
        let e = bind_secure_with(&sock, None, None, &[uid], &mut |st, staged| {
            if st == Step::BeforeInstall {
                imposter = Some(swap_in_socket(staged));
            }
        })
        .unwrap_err();
        assert!(imposter.is_some(), "hook never ran");
        assert!(e.to_string().contains("replaced"), "{e}");
        assert!(
            fs::symlink_metadata(&sock).is_err(),
            "imposter was installed"
        );
    }

    #[test]
    fn socket_replaced_between_check_and_rename_is_detected_and_removed() {
        let d = tmpdir("swaprename");
        let (uid, _) = current_ids().unwrap();
        let mut imposter = None;
        let sock = d.join("c.sock");
        let e = bind_secure_with(&sock, None, None, &[uid], &mut |st, staged| {
            if st == Step::BeforeRename {
                imposter = Some(swap_in_socket(staged));
            }
        })
        .unwrap_err();
        assert!(imposter.is_some(), "hook never ran");
        assert!(e.to_string().contains("replaced"), "{e}");
        assert!(
            fs::symlink_metadata(&sock).is_err(),
            "imposter was left installed"
        );
    }

    #[test]
    fn staging_name_is_random_and_foreign_stage_dirs_are_left_alone() {
        let d = tmpdir("stage");
        let (uid, _) = current_ids().unwrap();
        let planted = d.join(format!(".vigie-stage-{}", std::process::id()));
        fs::create_dir(&planted).unwrap();
        fs::write(planted.join("precious"), b"x").unwrap();
        let mut names = Vec::new();
        for _ in 0..2 {
            let mut name = String::new();
            let l = bind_secure_with(&d.join("c.sock"), None, None, &[uid], &mut |st, staged| {
                if st == Step::Bound {
                    name = staged
                        .parent()
                        .unwrap()
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                }
            })
            .unwrap();
            drop(l);
            names.push(name);
        }
        assert_ne!(names[0], names[1], "staging name is predictable");
        assert!(names[0].starts_with(".vigie-stage-") && names[0].len() >= 13 + 16);
        assert_ne!(Path::new(&names[0]), planted.file_name().unwrap());
        assert_eq!(fs::read(planted.join("precious")).unwrap(), b"x");
        let left: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n.starts_with(".vigie-stage-") && !n.ends_with(&std::process::id().to_string())
            })
            .collect();
        assert!(left.is_empty(), "stage dirs left behind: {left:?}");
    }

    #[test]
    fn missing_socket_dir_is_created_0755() {
        let d = tmpdir("mk");
        let dir = d.join("vigie");
        let _l = bind_secure(&dir.join("c.sock"), None, None).unwrap();
        assert_eq!(mode(&dir), 0o755);
        assert_eq!(fs::metadata(&dir).unwrap().uid(), current_ids().unwrap().0);
    }

    #[test]
    fn existing_bad_socket_dir_is_refused_and_not_repaired() {
        let (uid, _) = current_ids().unwrap();
        let d = tmpdir("badmk");
        // symlink to a good directory
        let real = d.join("real");
        fs::create_dir(&real).unwrap();
        let link = d.join("vigie");
        symlink(&real, &link).unwrap();
        let e = bind_secure(&link.join("c.sock"), None, None).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert!(fs::symlink_metadata(real.join("c.sock")).is_err());
        // group-writable directory is refused and left as it was
        let gw = d.join("gw");
        fs::create_dir(&gw).unwrap();
        fs::set_permissions(&gw, fs::Permissions::from_mode(0o775)).unwrap();
        let e = bind_secure(&gw.join("c.sock"), None, None).unwrap_err();
        assert!(e.to_string().contains("writable"), "{e}");
        assert_eq!(mode(&gw), 0o775);
        // wrong owner
        let e = bind_secure_with(&real.join("c.sock"), None, None, &[uid + 1], &mut |_, _| {})
            .unwrap_err();
        assert!(e.to_string().contains("owned by"), "{e}");
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
            assert_eq!(p.publish("{}".to_string()), Outcome::NoReader);
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
        assert_eq!(p.publish(r#"{"a":1}"#.to_string()), Outcome::Delivered);
        assert_eq!(p.publish(r#"{"a":2}"#.to_string()), Outcome::Delivered);
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
            p.publish("{}".to_string());
        }
        assert!(!p.has_reader());
        assert_eq!(p.publish("{}".to_string()), Outcome::NoReader);
    }

    #[test]
    fn stalled_reader_never_blocks_and_buffer_stays_bounded() {
        let (mut p, sock) = publisher("stall");
        let _c = UnixStream::connect(&sock).unwrap();
        p.poll();
        let big = "x".repeat(1_500_000);
        let t = Instant::now();
        let outcomes: Vec<Outcome> = (0..10).map(|_| p.publish(big.clone())).collect();
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
        assert_eq!(p.publish(huge), Outcome::DroppedTooLarge);
    }

    #[test]
    fn queued_remainder_is_flushed_when_reader_catches_up() {
        let (mut p, sock) = publisher("flush");
        let c = UnixStream::connect(&sock).unwrap();
        p.poll();
        let big = "y".repeat(1_500_000);
        assert_eq!(p.publish(big.clone()), Outcome::Queued);
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
    fn new_connection_does_not_truncate_the_line_in_flight() {
        let (mut p, sock) = publisher("inflight");
        let a = UnixStream::connect(&sock).unwrap();
        p.poll();
        let big = "z".repeat(1_500_000);
        assert_eq!(p.publish(big.clone()), Outcome::Queued);
        let b = UnixStream::connect(&sock).unwrap();
        p.poll();
        assert!(p.has_waiting_reader(), "newcomer must wait for the line");
        assert!(p.pending_bytes() > 0, "in-flight line was discarded");
        let reader_a = std::thread::spawn(move || {
            let mut l = String::new();
            BufReader::new(a).read_line(&mut l).unwrap();
            l
        });
        let t = Instant::now();
        while !reader_a.is_finished() && t.elapsed() < Duration::from_secs(5) {
            p.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
        let got = reader_a.join().unwrap();
        assert_eq!(got.len(), big.len() + 1, "first reader got a cut line");
        assert!(got.ends_with('\n'));
        // now the newcomer takes over and sees only whole lines
        let t = Instant::now();
        while p.has_waiting_reader() && t.elapsed() < Duration::from_secs(5) {
            p.poll();
        }
        assert!(!p.has_waiting_reader());
        assert_eq!(p.publish("{}".to_string()), Outcome::Delivered);
        let mut l = String::new();
        BufReader::new(b).read_line(&mut l).unwrap();
        assert_eq!(l, "{}\n", "newcomer must not see a partial line");
    }

    #[test]
    fn newest_waiting_connection_wins() {
        let (mut p, sock) = publisher("newest");
        let _a = UnixStream::connect(&sock).unwrap();
        p.poll();
        assert_eq!(p.publish("y".repeat(1_500_000)), Outcome::Queued);
        let _b = UnixStream::connect(&sock).unwrap();
        let c = UnixStream::connect(&sock).unwrap();
        p.poll();
        drop(_a);
        for _ in 0..50 {
            p.poll();
        }
        assert!(p.has_reader() && !p.has_waiting_reader());
        assert_eq!(p.publish("{}".to_string()), Outcome::Delivered);
        let mut l = String::new();
        BufReader::new(c).read_line(&mut l).unwrap();
        assert_eq!(l, "{}\n");
    }

    #[test]
    fn new_connection_replaces_idle_old_reader() {
        let (mut p, sock) = publisher("replace");
        let _a = UnixStream::connect(&sock).unwrap();
        p.poll();
        let b = UnixStream::connect(&sock).unwrap();
        p.poll();
        assert_eq!(p.publish("{}".to_string()), Outcome::Delivered);
        let mut l = String::new();
        BufReader::new(b).read_line(&mut l).unwrap();
        assert_eq!(l, "{}\n");
    }
}
