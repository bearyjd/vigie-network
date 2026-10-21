//! Urgent-push policy: a DHCP lease from a MAC not seen before triggers an immediate small
//! batch, at most one per 5 s; a rate-limited request stays pending and is released later.

use std::collections::HashSet;

pub const MIN_INTERVAL_MS: u64 = 5_000;
pub const MAX_TRACKED_MACS: usize = 4096;

#[derive(Debug, Default)]
pub struct Urgent {
    seen: HashSet<String>,
    last_push_ms: Option<u64>,
    pending: bool,
}

impl Urgent {
    pub fn new() -> Self {
        Self::default()
    }
    /// Mark MACs already known at startup (no urgent push for them).
    pub fn prime<'a>(&mut self, macs: impl IntoIterator<Item = &'a str>) {
        for m in macs {
            self.seen.insert(m.to_string());
        }
    }
    /// A lease for `mac` was seen at monotonic `now_ms`. True when an urgent push should go now.
    pub fn on_lease(&mut self, mac: &str, now_ms: u64) -> bool {
        if self.seen.contains(mac) {
            return false;
        }
        if self.seen.len() >= MAX_TRACKED_MACS {
            // Table full: stop tracking rather than grow without bound or push on every lease.
            return false;
        }
        self.seen.insert(mac.to_string());
        if self.allowed(now_ms) {
            self.last_push_ms = Some(now_ms);
            self.pending = false;
            true
        } else {
            self.pending = true;
            false
        }
    }
    /// Release a push that was rate-limited earlier, once the interval has passed.
    pub fn take_pending(&mut self, now_ms: u64) -> bool {
        if self.pending && self.allowed(now_ms) {
            self.pending = false;
            self.last_push_ms = Some(now_ms);
            return true;
        }
        false
    }

    fn allowed(&self, now_ms: u64) -> bool {
        self.last_push_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= MIN_INTERVAL_MS)
    }
}
