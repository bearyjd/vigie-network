//! Log tail with a cursor and rotation handling.
//!
//! - The first open of an existing file starts at its end (no replay of history after a
//!   collector restart); a file that appears later, or a new file after rotation, is read from 0.
//! - Rotation by rename: the old file is drained through the still-open handle, then the new
//!   file at the path is opened (detected by inode change).
//! - Truncation in place (the cron watchdog): detected by length < cursor, restart at 0.
//! - Bounded: lines over `MAX_LINE` bytes are dropped, at most `MAX_POLL_BYTES` read per poll.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub const MAX_LINE: usize = 4096;
pub const MAX_POLL_BYTES: u64 = 1024 * 1024;

pub struct Tail {
    path: PathBuf,
    cur: Option<(File, u64)>,
    pos: u64,
    carry: Vec<u8>,
    skipping: bool,
    polled_once: bool,
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
        }
    }

    /// New complete lines since the last poll. A missing file is not an error.
    pub fn poll(&mut self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut budget = MAX_POLL_BYTES;
        if self.cur.is_none() {
            self.open_new(!self.polled_once)?;
            self.polled_once = true;
        }
        loop {
            budget = budget.saturating_sub(self.drain_current(budget, &mut out)?);
            if !self.rotated()? || budget == 0 {
                break;
            }
            self.open_new(false)?;
            if self.cur.is_none() {
                break;
            }
        }
        Ok(out)
    }

    fn open_new(&mut self, at_end: bool) -> io::Result<()> {
        self.carry.clear();
        self.skipping = false;
        match File::open(&self.path) {
            Ok(f) => {
                let meta = f.metadata()?;
                self.pos = if at_end { meta.len() } else { 0 };
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

    fn drain_current(&mut self, budget: u64, out: &mut Vec<String>) -> io::Result<u64> {
        let Some((f, _)) = &mut self.cur else {
            return Ok(0);
        };
        let len = f.metadata()?.len();
        if len < self.pos {
            self.pos = 0;
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
        self.split_lines(&buf, out);
        Ok(n as u64)
    }

    fn split_lines(&mut self, buf: &[u8], out: &mut Vec<String>) {
        for &b in buf {
            if b == b'\n' {
                if !self.skipping {
                    out.push(String::from_utf8_lossy(&self.carry).into_owned());
                }
                self.carry.clear();
                self.skipping = false;
            } else if !self.skipping {
                if self.carry.len() >= MAX_LINE {
                    self.carry.clear();
                    self.skipping = true;
                } else {
                    self.carry.push(b);
                }
            }
        }
    }
}
