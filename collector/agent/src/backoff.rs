//! Exponential backoff (5 s base, doubling) with jitter in [delay/2, delay], capped at 5 min.

pub const BASE_S: u64 = 5;
pub const CAP_S: u64 = 300;

#[derive(Debug, Default)]
pub struct Backoff {
    attempt: u32,
}

impl Backoff {
    /// Delay in seconds before the next attempt; `rand` supplies the jitter.
    pub fn next_delay_s(&mut self, rand: u64) -> u64 {
        // 5 << 6 already exceeds the cap; avoid shifting further (overflow).
        let full = if self.attempt >= 6 {
            CAP_S
        } else {
            (BASE_S << self.attempt).min(CAP_S)
        };
        self.attempt = self.attempt.saturating_add(1);
        let lo = full.div_ceil(2);
        let span = u128::from(full - lo);
        lo + u64::try_from(span * u128::from(rand) / u128::from(u64::MAX)).unwrap_or(0)
    }
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
    pub fn attempts(&self) -> u32 {
        self.attempt
    }
}
