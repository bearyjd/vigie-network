//! Consecutive windows must tile the timeline exactly: `start_n == end_{n-1}`. Independent
//! whole-second truncation of the wall and monotonic clocks used to overlap them by 1 s.

use vigie_agent::builder::MAX_WINDOW_S;
use vigie_agent::window::WindowClock;

/// One flush at (wall, mono): returns (start, end) and records the flush like the agent does.
fn flush(c: &mut WindowClock, wall: u64, mono: u64) -> (u64, u64) {
    let s = c.window_start(wall, mono);
    c.mark_window(mono, wall);
    (s, wall)
}

#[test]
fn jittery_cadence_gives_zero_overlap_and_zero_gap() {
    for wall_phase in [0u64, 1, 2] {
        for jitter in [-1i64, 0, 1] {
            let mut c = WindowClock::new(10);
            let (mut wall, mut mono) = (1_760_000_000 + wall_phase, 10u64);
            let mut prev_end = None;
            for n in 0..200i64 {
                // 60 s +- 1.5 s (rounded to whole seconds: 59, 60, 61, 62)
                let step = (60 + (n % 3 - 1) * jitter * 3 / 2).max(1) as u64;
                wall += step;
                // wall and mono phases drift apart by up to 1 s
                mono += step - u64::from(n % 4 == 0);
                let (s, e) = flush(&mut c, wall, mono);
                assert!(s <= e && e - s <= MAX_WINDOW_S);
                if let Some(p) = prev_end {
                    assert_eq!(s, p, "window {n} must start where the previous one ended");
                }
                prev_end = Some(e);
            }
        }
    }
}

#[test]
fn first_window_uses_the_monotonic_arithmetic() {
    let c = WindowClock::new(100);
    assert_eq!(c.window_start(1_760_000_060, 160), 1_760_000_000);
}

#[test]
fn a_wall_jump_mid_window_falls_back_and_stays_bounded() {
    for jump in [86_400 * 3i64, -86_400 * 3, 86_400 * 400] {
        let mut c = WindowClock::new(0);
        let (_, e) = flush(&mut c, 1_760_000_060, 60);
        let wall = (e as i64 + 60 + jump) as u64;
        let (s, e2) = flush(&mut c, wall, 120);
        assert!(s <= e2 && e2 - s <= MAX_WINDOW_S, "jump {jump}: {s}..{e2}");
        assert_eq!(e2 - s, 60, "fallback spans the monotonic elapsed time");
        // The next window is consistent again and continues from the jumped end.
        let (s3, _) = flush(&mut c, wall + 60, 180);
        assert_eq!(s3, e2);
    }
}

#[test]
fn a_stalled_loop_never_exceeds_the_max_window() {
    let mut c = WindowClock::new(0);
    let wall = 1_760_000_000 + 3 * MAX_WINDOW_S;
    let (s, e) = flush(&mut c, wall, 3 * MAX_WINDOW_S);
    assert_eq!(e - s, MAX_WINDOW_S);
}

#[test]
fn after_a_held_flush_the_previous_end_is_not_reused() {
    let mut c = WindowClock::new(0);
    flush(&mut c, 1_760_000_060, 60);
    c.mark_flush(120); // Hold: window dropped, no end recorded
    let (s, e) = flush(&mut c, 1_760_000_180, 180);
    assert_eq!((s, e), (1_760_000_120, 1_760_000_180));
}

#[test]
fn an_end_after_now_is_not_reused() {
    let mut c = WindowClock::new(0);
    flush(&mut c, 1_760_000_060, 60);
    let (s, e) = flush(&mut c, 1_760_000_050, 120); // wall stepped back
    assert!(s <= e);
    assert_eq!(e - s, 60);
}
