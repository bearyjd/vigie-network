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
//! - `poll_with_gaps` also reports where bytes were lost (reset, rotation dropping a partial
//!   line, overlong line) as `None`, so the DHCP assembler can drop its attach contexts there.
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
    /// The (up to) 64 bytes of the file just before `pos`.
    fingerprint: Vec<u8>,
    resets: u64,
    skipped: u64,
    open_failed: u64,
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
            fingerprint: Vec::new(),
            resets: 0,
            skipped: 0,
            open_failed: 0,
        }
    }

    /// New complete lines since the last poll. A missing file is not an error.
    pub fn poll(&mut self) -> io::Result<Vec<String>> {
        Ok(self.poll_with_gaps()?.into_iter().flatten().collect())
    }

    /// Like `poll`, with a `None` at every place where bytes were lost between two lines.
    pub fn poll_with_gaps(&mut self) -> io::Result<Vec<Option<String>>> {
        let mut out = Vec::new();
        let mut budget = MAX_POLL_BYTES;
        if self.cur.is_none() {
            self.open_new(!self.polled_once)?;
            self.polled_once = true;
        }
        loop {
            match self.step(&mut budget, &mut out) {
                Ok(true) => {}
                Ok(false) => break,
                // Lines already drained are returned; the failure is counted, and the next poll
                // retries (and reports the error itself when it has nothing to return).
                Err(_) if !out.is_empty() => {
                    self.open_failed += 1;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// One drain-then-maybe-rotate step; `Ok(true)` when the loop should go on.
    fn step(&mut self, budget: &mut u64, out: &mut Vec<Option<String>>) -> io::Result<bool> {
        *budget = budget.saturating_sub(self.drain_current(*budget, out)?);
        if !self.rotated()? || *budget == 0 {
            return Ok(false);
        }
        if !self.carry.is_empty() {
            out.push(None);
        }
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

    fn open_new(&mut self, at_end: bool) -> io::Result<()> {
        self.skipped += self.carry.len() as u64;
        self.carry.clear();
        self.skipping = false;
        match File::open(&self.path) {
            Ok(f) => {
                let meta = f.metadata()?;
                self.pos = if at_end { meta.len() } else { 0 };
                self.fingerprint = read_before(&f, self.pos)?;
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

/// The (up to) `FINGERPRINT` bytes of `f` that end at `pos`; short when the file is shorter.
fn read_before(mut f: &File, pos: u64) -> io::Result<Vec<u8>> {
    let from = pos.saturating_sub(FINGERPRINT);
    f.seek(SeekFrom::Start(from))?;
    let mut buf = Vec::new();
    f.take(pos - from).read_to_end(&mut buf)?;
    Ok(buf)
}
