//! Log tail with a cursor and rotation handling.
//!
//! - The first open of an existing file starts at its end (no replay of history after a
//!   collector restart); a file that appears later, or a new file after rotation, is read from 0.
//! - Rotation by rename: the old file is drained through the still-open handle, then the new
//!   file at the path is opened (detected by inode change).
//! - Truncation in place (emergency watchdog) or truncate-and-refill: the tail remembers the 64
//!   bytes before its cursor and compares them on every poll. A shorter file or different bytes
//!   restart at offset 0 and drop the partial line, so a cursor that now sits inside a line
//!   somebody else wrote is never trusted. Resets and lost bytes are counted (`take_counts`).
//! - `poll_with_gaps` also reports where continuity cannot be shown as `None`: a cursor reset,
//!   an overlong line, and EVERY switch to a different file (even with nothing partial pending:
//!   two rotations between polls would hide a whole intermediate file, and an inode alone cannot
//!   tell). The DHCP assembler drops its attach contexts at each `None`.
//!   Every failed poll is counted in `tail_open_failed`, also one whose drained lines are
//!   still returned.
//! - `at_eof` tells whether the last poll read everything: false when it stopped at its byte
//!   budget or on a failure (even a counted one), so the reader never takes it for a pause.
//! - Bounded: lines over `MAX_LINE` bytes are dropped, at most `MAX_POLL_BYTES` read per poll.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub const MAX_LINE: usize = 4096;
pub const MAX_POLL_BYTES: u64 = 1024 * 1024;
const FINGERPRINT: u64 = 64;

pub struct Tail {
    path: PathBuf,
    cur: Option<(File, u64)>,
    pos: u64,
    carry: Vec<u8>,
    skipping: bool,
    polled_once: bool,
    /// A gap was found in a poll that then failed with an error: report it on the next poll.
    gap_pending: bool,
    /// The (up to) 64 bytes of the file just before `pos`.
    fingerprint: Vec<u8>,
    resets: u64,
    skipped: u64,
    open_failed: u64,
    /// The last poll ended at the end of the file (not at its byte budget or on an error).
    eof: bool,
}

impl Tail {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cur: None,
            pos: 0,
            carry: Vec::new(),
            skipping: false,
            polled_once: false,
            gap_pending: false,
            fingerprint: Vec::new(),
            resets: 0,
            skipped: 0,
            open_failed: 0,
            eof: true,
        }
    }

    /// Whether the last poll read everything there was: a poll that stopped at its byte
    /// budget or failed says nothing about the writer having paused.
    pub fn at_eof(&self) -> bool {
        self.eof
    }

    /// New complete lines since the last poll. A missing file is not an error.
    pub fn poll(&mut self) -> io::Result<Vec<String>> {
        Ok(self.poll_with_gaps()?.into_iter().flatten().collect())
    }

    /// Like `poll`, with a `None` at every place where bytes were lost between two lines.
    pub fn poll_with_gaps(&mut self) -> io::Result<Vec<Option<String>>> {
        let mut out = Vec::new();
        let mut budget = MAX_POLL_BYTES;
        self.eof = false;
        if std::mem::take(&mut self.gap_pending) {
            push_gap(&mut out);
        }
        if self.cur.is_none() {
            let first = !self.polled_once;
            if let Err(e) = self.open_new(first) {
                // `out` holds no gap marker here: a pending gap is only ever set while a file
                // is open (an error inside the step loop), and this branch needs none open.
                self.open_failed += 1;
                return Err(e);
            }
            self.polled_once = true;
            // A file that reappears after a failed switch or a missing path: nothing is known
            // about what happened in between.
            if !first && self.cur.is_some() {
                push_gap(&mut out);
            }
        }
        loop {
            match self.step(&mut budget, &mut out) {
                Ok(true) => {}
                Ok(false) => break,
                // Lines already drained are returned; the failure is counted, and the next poll
                // retries (and reports the error itself when it has no line to return; gap
                // markers alone are not data, so the error still surfaces and the gap is kept
                // for the next poll).
                // `eof` stays false for such a poll: the reader must not count it as one that
                // found the writer paused.
                Err(_) if out.iter().any(Option::is_some) => {
                    self.open_failed += 1;
                    return Ok(out);
                }
                Err(e) => {
                    self.open_failed += 1;
                    self.gap_pending |= out.contains(&None);
                    return Err(e);
                }
            }
        }
        self.eof = budget > 0;
        Ok(out)
    }

    /// One drain-then-maybe-rotate step; `Ok(true)` when the loop should go on.
    fn step(&mut self, budget: &mut u64, out: &mut Vec<Option<String>>) -> io::Result<bool> {
        *budget = budget.saturating_sub(self.drain_current(*budget, out)?);
        if !self.rotated()? || *budget == 0 {
            return Ok(false);
        }
        push_gap(out);
        self.open_new(false)?;
        Ok(self.cur.is_some())
    }

    /// Drained counters, by `truncated` key: cursor resets (`tail_truncated`) and bytes known
    /// to be lost or discarded (`tail_bytes_skipped`: overlong lines, dropped partial lines) and failed opens/reads that
    /// cost a poll its follow-up (`tail_open_failed`).
    pub fn take_counts(&mut self) -> BTreeMap<String, u64> {
        [
            ("tail_truncated", std::mem::take(&mut self.resets)),
            ("tail_bytes_skipped", std::mem::take(&mut self.skipped)),
            ("tail_open_failed", std::mem::take(&mut self.open_failed)),
        ]
        .into_iter()
        .filter(|(_, v)| *v > 0)
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    /// Switches to the file at the path. A failure leaves the old file's cursor alone, and so
    /// the torn-line state: the rest of a half-read line is still not a line of its own.
    fn open_new(&mut self, at_end: bool) -> io::Result<()> {
        let partial = self.skipping || !self.carry.is_empty();
        let r = self.open_inner(at_end);
        if r.is_err() {
            self.skipping = partial;
        }
        r
    }

    fn open_inner(&mut self, at_end: bool) -> io::Result<()> {
        self.skipped += self.carry.len() as u64;
        self.carry.clear();
        self.skipping = false;
        match File::open(&self.path) {
            Ok(f) => {
                let meta = f.metadata()?;
                // Both are read before anything is assigned: a failure half-way must leave the
                // cursor of the file still in `cur` untouched.
                let pos = if at_end { meta.len() } else { 0 };
                let fingerprint = read_before(&f, pos)?;
                self.pos = pos;
                self.fingerprint = fingerprint;
                self.cur = Some((f, meta.ino()));
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.cur = None;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// True when the path now names a different file and the old one is fully drained.
    fn rotated(&self) -> io::Result<bool> {
        let Some((f, ino)) = &self.cur else {
            return Ok(false);
        };
        let now = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(now.ino() != *ino && self.pos >= f.metadata()?.len())
    }

    fn drain_current(&mut self, budget: u64, out: &mut Vec<Option<String>>) -> io::Result<u64> {
        let Some((f, _)) = &mut self.cur else {
            return Ok(0);
        };
        let len = f.metadata()?.len();
        if len < self.pos || read_before(f, self.pos)? != self.fingerprint {
            self.resets += 1;
            out.push(None);
            self.skipped += self.carry.len() as u64;
            self.pos = 0;
            self.fingerprint.clear();
            self.carry.clear();
            self.skipping = false;
        }
        if len == self.pos || budget == 0 {
            return Ok(0);
        }
        f.seek(SeekFrom::Start(self.pos))?;
        let mut buf = Vec::new();
        let n = f.take(budget).read_to_end(&mut buf)?;
        self.pos += n as u64;
        self.fingerprint.extend_from_slice(&buf);
        let keep = self.fingerprint.len().saturating_sub(FINGERPRINT as usize);
        self.fingerprint.drain(..keep);
        self.split_lines(&buf, out);
        Ok(n as u64)
    }

    fn split_lines(&mut self, buf: &[u8], out: &mut Vec<Option<String>>) {
        for &b in buf {
            if b == b'\n' {
                if !self.skipping {
                    out.push(Some(String::from_utf8_lossy(&self.carry).into_owned()));
                }
                self.carry.clear();
                self.skipping = false;
            } else if !self.skipping {
                if self.carry.len() >= MAX_LINE {
                    self.skipped += self.carry.len() as u64 + 1;
                    self.carry.clear();
                    self.skipping = true;
                    out.push(None);
                } else {
                    self.carry.push(b);
                }
            } else if b != b'\n' {
                self.skipped += 1;
            }
        }
    }
}

/// A gap marker, unless the last item already is one.
fn push_gap(out: &mut Vec<Option<String>>) {
    if out.last() != Some(&None) {
        out.push(None);
    }
}

/// The (up to) `FINGERPRINT` bytes of `f` that end at `pos`; short when the file is shorter.
fn read_before(mut f: &File, pos: u64) -> io::Result<Vec<u8>> {
    let from = pos.saturating_sub(FINGERPRINT);
    f.seek(SeekFrom::Start(from))?;
    let mut buf = Vec::new();
    f.take(pos - from).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_open_leaves_the_cursor_of_the_current_file_alone() {
        let dir = std::env::temp_dir().join(format!("vigie-tail-l2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = dir.join("old.log");
        std::fs::write(&old, "0123456789\n").unwrap();
        std::fs::write(dir.join("entry"), "x").unwrap();
        let mut tail = Tail::new(old.clone());
        tail.poll_with_gaps().unwrap();
        let before = (tail.pos, tail.fingerprint.clone());
        // A directory opens, but its bytes cannot be read: the open fails half-way.
        tail.path = dir.clone();
        assert!(tail.open_new(true).is_err());
        assert_eq!((tail.pos, tail.fingerprint.clone()), before);
        assert!(tail.cur.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    fn failing_tail(tag: &str, written: &[u8]) -> (Tail, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("vigie-tail-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("a.log");
        std::fs::write(&log, written).unwrap();
        let mut tail = Tail::new(log);
        tail.polled_once = true;
        tail.poll_with_gaps().unwrap();
        // The next open succeeds on a directory but cannot read it: a failure half-way.
        tail.path = dir.clone();
        (tail, dir)
    }

    #[test]
    fn a_failed_open_keeps_the_torn_line_state() {
        let (mut tail, dir) = failing_tail("torn", b"0123456789\nabc");
        assert!(!tail.carry.is_empty());
        assert!(tail.open_new(true).is_err());
        assert!(
            tail.skipping,
            "the rest of the torn line must still be dropped"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_failed_open_keeps_the_skipping_state_of_an_overlong_line() {
        let long = vec![b'z'; MAX_LINE + 10];
        let (mut tail, dir) = failing_tail("long", &long);
        assert!(tail.skipping);
        assert!(tail.open_new(true).is_err());
        assert!(tail.skipping);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_failed_open_of_a_clean_stream_does_not_start_skipping() {
        let (mut tail, dir) = failing_tail("clean", b"0123456789\n");
        assert!(tail.open_new(true).is_err());
        assert!(!tail.skipping);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_poll_at_its_budget_is_not_at_eof() {
        let dir = std::env::temp_dir().join(format!("vigie-tail-eof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("a.log");
        std::fs::write(&log, "").unwrap();
        let mut tail = Tail::new(log.clone());
        tail.poll_with_gaps().unwrap();
        assert!(tail.at_eof());
        let line = "x".repeat(99) + "\n";
        std::fs::write(&log, line.repeat(MAX_POLL_BYTES as usize / 100 + 10)).unwrap();
        tail.poll_with_gaps().unwrap();
        assert!(!tail.at_eof(), "stopped at the budget");
        tail.poll_with_gaps().unwrap();
        assert!(tail.at_eof());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn failed_polls_are_counted_and_never_at_eof() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("vigie-tail-cnt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("a.log");
        // First open fails (a socket cannot be opened, also for root): an error-only poll.
        let sock = UnixListener::bind(&log).unwrap();
        let mut tail = Tail::new(log.clone());
        assert!(tail.poll_with_gaps().is_err());
        assert_eq!(tail.take_counts().get("tail_open_failed"), Some(&1));
        drop(sock);
        std::fs::remove_file(&log).unwrap();
        // Lines drained, then the rotation stat fails (a self-loop link): counted, not at eof.
        std::fs::write(&log, "seed\n").unwrap();
        let mut tail = Tail::new(log.clone());
        tail.poll_with_gaps().unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"more\n"))
            .unwrap();
        std::fs::rename(&log, dir.join("a.log.1")).unwrap();
        std::os::unix::fs::symlink(&log, &log).unwrap();
        let got = tail.poll_with_gaps().unwrap();
        assert_eq!(got, vec![Some("more".to_string())]);
        assert_eq!(tail.take_counts().get("tail_open_failed"), Some(&1));
        assert!(!tail.at_eof());
        std::fs::remove_dir_all(&dir).ok();
    }
}
