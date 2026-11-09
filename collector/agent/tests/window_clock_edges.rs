//! Edges of `WindowClock::window_start`: the fallback after a wall correction never overlaps the
//! previous window, and each reuse condition of the remembered end is pinned by a test.

use vigie_agent::window::WindowClock;

const P: u64 = 1_760_000_060;

fn after_first_window() -> WindowClock {
    let mut c = WindowClock::new(0);
    c.mark_window(60, P);
    c
}

#[test]
fn a_backward_wall_correction_never_starts_before_the_previous_end() {
    // 57 s of wall time for 60 s of monotonic time: 3 s off, so the fallback runs (P - 3),
    // but it must not overlap the previous window.
    assert_eq!(after_first_window().window_start(P + 57, 120), P);
}

#[test]
fn a_forward_wall_correction_leaves_a_small_gap_not_an_overlap() {
    assert_eq!(after_first_window().window_start(P + 63, 120), P + 3);
}

#[test]
fn two_seconds_off_reuses_the_end_and_three_seconds_does_not() {
    let c = after_first_window();
    assert_eq!(c.window_start(P + 58, 120), P, "2 s short: reused");
    assert_eq!(c.window_start(P + 62, 120), P, "2 s long: reused");
    assert_eq!(c.window_start(P + 63, 120), P + 3, "3 s long: fallback");
}

#[test]
fn a_span_over_the_max_window_is_not_reused() {
    // Monotonic elapsed agrees with the wall span, but both exceed 24 h.
    assert_eq!(after_first_window().window_start(P + 86_401, 86_461), P + 1);
}

#[test]
fn a_held_flush_forgets_the_previous_end() {
    let mut c = after_first_window();
    c.mark_flush(120);
    // Reusing P would give P; the monotonic arithmetic gives P + 2.
    assert_eq!(c.window_start(P + 62, 180), P + 2);
}

#[test]
fn the_start_never_exceeds_the_end() {
    let c = after_first_window();
    for wall in [P, P + 1, P + 59, P + 61, P + 200] {
        assert!(c.window_start(wall, 120) <= wall);
    }
}
