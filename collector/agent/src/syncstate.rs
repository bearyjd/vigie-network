//! Provisional-time handling before the first server contact.
//!
//! The router has no RTC and NTP may step the wall clock by days at any moment before the first
//! HTTPS reply gives us a trustworthy `Date`. Until then:
//!   - rows are stamped with the monotonic clock (provisional), never the wall clock;
//!   - no data window is built (only an empty probe batch, whose reply, accepted or rejected,
//!     carries the server `Date`);
//!   - once the `Date` is known, provisional stamps are shifted to server time in one go.

use crate::timegate::TimeGate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushPlan {
    /// No server time yet: send an empty probe, keep accumulating, build nothing.
    Probe,
    /// Server time known but the wall clock disagrees with it: drop/hold as before.
    Hold,
    /// Clock verified against the server: build the window.
    Build,
}

#[derive(Debug, Default)]
pub struct SyncState {
    synced: bool,
}

impl SyncState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Timestamp for a row read now: monotonic seconds while provisional, wall seconds after.
    pub fn stamp(&self, wall_s: u64, mono_s: u64) -> u64 {
        if self.synced {
            wall_s
        } else {
            mono_s
        }
    }

    pub fn plan(&self, sane: bool) -> FlushPlan {
        match (self.synced, sane) {
            (false, _) => FlushPlan::Probe,
            (true, false) => FlushPlan::Hold,
            (true, true) => FlushPlan::Build,
        }
    }

    /// An urgent identity push is a data batch like any other: same gate as `FlushPlan::Build`.
    pub fn allow_identity_push(&self, sane: bool) -> bool {
        self.plan(sane) == FlushPlan::Build
    }

    /// Call after every send attempt. The first time a server `Date` has been seen, returns the
    /// offset (`server Date - mono at receipt`) that turns provisional stamps into server time;
    /// `None` otherwise. The local wall clock plays no part: it may be wrong (that is why the
    /// stamps are provisional) and is only checked against the server by the time gate.
    pub fn observe(&mut self, gate: &TimeGate) -> Option<u64> {
        if self.synced {
            return None;
        }
        let offset = gate.server_offset()?;
        self.synced = true;
        Some(offset)
    }
}
