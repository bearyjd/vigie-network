//! Time sanity gate. The router has no RTC, so nothing is sent until the wall clock is plausible:
//! not before the build date, not absurdly far ahead, and (once a server `Date` has been seen)
//! within `MAX_SKEW_S` of the server's clock extrapolated by the monotonic clock.

/// Seconds of disagreement with the server `Date` header tolerated (server limit is 300).
pub const MAX_SKEW_S: u64 = 240;
/// Wall clocks beyond this are not plausible (schema limit 2^40).
pub const MAX_PLAUSIBLE_TS: u64 = 1 << 40;

#[derive(Debug)]
pub struct TimeGate {
    build_ts: u64,
    server: Option<(u64, u64)>,
}

impl TimeGate {
    pub fn new(build_ts: u64) -> Self {
        Self {
            build_ts,
            server: None,
        }
    }
    /// Record a server `Date` (epoch seconds) seen at monotonic second `mono_s`.
    pub fn observe_server_date(&mut self, server_ts: u64, mono_s: u64) {
        self.server = Some((server_ts, mono_s));
    }
    pub fn has_server_date(&self) -> bool {
        self.server.is_some()
    }
    pub fn is_sane(&self, wall_ts: u64, mono_s: u64) -> bool {
        if wall_ts < self.build_ts || wall_ts > MAX_PLAUSIBLE_TS {
            return false;
        }
        match self.server {
            None => true,
            Some((server_ts, seen_mono)) => {
                let est = server_ts.saturating_add(mono_s.saturating_sub(seen_mono));
                est.abs_diff(wall_ts) <= MAX_SKEW_S
            }
        }
    }
}
