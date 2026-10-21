//! RAM-only spool: at most `SPOOL_CAP` bytes, drop-oldest, with a dropped-batch counter that is
//! reported to the server on the next successful send. Nothing is written to flash.

use std::collections::VecDeque;

use crate::model::EncodedBatch;

pub const SPOOL_CAP: usize = 1024 * 1024;

pub struct Spool {
    q: VecDeque<EncodedBatch>,
    cap: usize,
    dropped: u64,
}

impl Spool {
    pub fn new(cap: usize) -> Self {
        Self {
            q: VecDeque::new(),
            cap,
            dropped: 0,
        }
    }
    /// Append a batch, dropping the oldest batches until it fits. A batch larger than the whole
    /// spool is dropped itself. Every dropped batch is counted.
    pub fn push(&mut self, b: EncodedBatch) {
        if b.len() > self.cap {
            self.dropped += 1;
            return;
        }
        while self.bytes() + b.len() > self.cap {
            if self.q.pop_front().is_none() {
                break;
            }
            self.dropped += 1;
        }
        self.q.push_back(b);
    }
    pub fn front(&self) -> Option<&EncodedBatch> {
        self.q.front()
    }
    pub fn pop_front(&mut self) -> Option<EncodedBatch> {
        self.q.pop_front()
    }
    pub fn len(&self) -> usize {
        self.q.len()
    }
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
    pub fn bytes(&self) -> usize {
        self.q.iter().map(EncodedBatch::len).sum()
    }
    /// Batches dropped and not yet reported to the server.
    pub fn dropped_unreported(&self) -> u64 {
        self.dropped
    }
    /// A send carrying `n` as `dropped_batches` succeeded.
    pub fn mark_reported(&mut self, n: u64) {
        self.dropped = self.dropped.saturating_sub(n);
    }
    /// Count a batch that was discarded outside the spool (e.g. permanently rejected).
    pub fn note_dropped(&mut self, n: u64) {
        self.dropped += n;
    }
}
