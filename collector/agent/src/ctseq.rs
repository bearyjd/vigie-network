//! Continuity of the helper's snapshot sequence on one connection.
//!
//! The first numbered frame of a connection is its baseline (a restarted helper re-primes at 1;
//! the reconnect itself is flagged by the reader). `seq` 0 is an old helper's frame without
//! sequence metadata and is never judged. The tracker keeps a high-water mark:
//! - the successor of the mark is continuous;
//! - a jump past it is a gap (frames the helper could not hand over), revealed only by the
//!   frame after it, so the window that counts that frame is the one marked;
//! - at most `MAX_REORDER` behind it is a duplicate or a late frame: marked, mark kept;
//! - further behind is a reset or a wrap: marked, and the frame becomes the new baseline.
//!
//! Limit: an old helper advances `seq` only on successful samples, so a failed scan leaves no
//! hole to see.

/// How far behind the high-water mark a frame still counts as a duplicate or reorder.
pub const MAX_REORDER: u64 = 64;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SeqTrack {
    high: Option<u64>,
}

impl SeqTrack {
    /// Judges `seq`: the tracker after it, and whether the frame breaks continuity.
    pub fn judge(self, seq: u64) -> (Self, bool) {
        let to = |s: u64| Self { high: Some(s) };
        match self.high {
            _ if seq == 0 => (self, false),
            None => (to(seq), false),
            Some(h) if h.checked_add(1) == Some(seq) => (to(seq), false),
            Some(h) if seq > h => (to(seq), true),
            Some(h) if h - seq <= MAX_REORDER => (self, true),
            Some(_) => (to(seq), true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(seqs: &[u64]) -> Vec<bool> {
        let mut t = SeqTrack::default();
        seqs.iter()
            .map(|&s| {
                let (next, broken) = t.judge(s);
                t = next;
                broken
            })
            .collect()
    }

    #[test]
    fn judges_each_frame_against_the_high_water_mark() {
        assert_eq!(run(&[5, 6, 7]), [false, false, false]);
        assert_eq!(run(&[1, 3, 4]), [false, true, false], "gap");
        assert_eq!(run(&[1, 1, 2]), [false, true, false], "duplicate");
        assert_eq!(
            run(&[100, 99, 101]),
            [false, true, false],
            "reorder keeps the mark"
        );
        assert_eq!(
            run(&[100, 99, 100]),
            [false, true, true],
            "the mark again is a duplicate"
        );
        assert_eq!(
            run(&[100, 36, 101]),
            [false, true, false],
            "at the reorder limit"
        );
        assert_eq!(
            run(&[100, 35, 36]),
            [false, true, false],
            "past it: a reset rebaselines"
        );
        assert_eq!(run(&[u64::MAX, 1, 2]), [false, true, false], "wrap");
        assert_eq!(
            run(&[0, 0, 7, 0, 8]),
            [false; 5],
            "missing metadata is never judged"
        );
    }
}
