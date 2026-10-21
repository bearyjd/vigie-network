//! Receive-error policy: timeouts are normal; other errors are counted, throttled, and fatal
//! after a run of consecutive failures (instead of spinning at 100% CPU).

use std::io::ErrorKind;
use std::time::Duration;

pub const MAX_CONSECUTIVE_ERRORS: u32 = 100;
pub const ERROR_BACKOFF: Duration = Duration::from_millis(50);

pub fn is_timeout(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

#[derive(Debug, Default)]
pub struct ErrTracker {
    consecutive: u32,
    pub total: u64,
}

impl ErrTracker {
    pub fn on_ok(&mut self) {
        self.consecutive = 0;
    }

    /// Record a read error; returns true when it is fatal.
    pub fn on_error(&mut self) -> bool {
        self.total += 1;
        self.consecutive += 1;
        self.consecutive >= MAX_CONSECUTIVE_ERRORS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_are_not_errors() {
        for k in [
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
            ErrorKind::Interrupted,
        ] {
            assert!(is_timeout(k), "{k:?}");
        }
        for k in [
            ErrorKind::PermissionDenied,
            ErrorKind::ConnectionRefused,
            ErrorKind::Other,
        ] {
            assert!(!is_timeout(k), "{k:?}");
        }
    }

    #[test]
    fn fatal_exactly_at_the_limit() {
        let mut t = ErrTracker::default();
        for i in 1..MAX_CONSECUTIVE_ERRORS {
            assert!(!t.on_error(), "error {i}");
        }
        assert!(t.on_error());
        assert_eq!(t.total, u64::from(MAX_CONSECUTIVE_ERRORS));
    }

    #[test]
    fn success_resets_the_run_but_not_the_total() {
        let mut t = ErrTracker::default();
        for _ in 0..MAX_CONSECUTIVE_ERRORS - 1 {
            t.on_error();
        }
        t.on_ok();
        for _ in 0..MAX_CONSECUTIVE_ERRORS - 1 {
            assert!(!t.on_error());
        }
        assert_eq!(t.total, 2 * u64::from(MAX_CONSECUTIVE_ERRORS - 1));
    }
}
