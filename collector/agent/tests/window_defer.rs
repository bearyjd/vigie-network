//! A flush whose wall clock is behind the previous window's end is deferred, so no window ever
//! overlaps the previous one; the deferral is bounded so a permanent backward step cannot stall
//! uploads.

use vigie_agent::builder::MAX_WINDOW_S;
use vigie_agent::window::{WindowClock, MAX_DEFER_S};

const P: u64 = 1_760_000_060;

fn after_first_window() -> WindowClock {
    let mut c = WindowClock::new(0);
    c.mark_window(60, P);
    c
}

#[test]
fn a_seventy_second_backward_step_defers_instead_of_overlapping() {
    let mut c = after_first_window();
    assert!(
        c.should_defer(P - 10, 120),
        "wall is behind the previous end"
    );
}

#[test]
fn consecutive_polls_while_behind_keep_deferring() {
    let mut c = after_first_window();
    for k in 0..30 {
        assert!(c.should_defer(P - 100 + k, 120 + k), "poll {k}");
    }
}

#[test]
fn a_flush_after_the_wall_catches_up_starts_exactly_at_the_previous_end() {
    let mut c = after_first_window();
    assert!(c.should_defer(P - 10, 120));
    assert!(c.should_defer(P - 1, 131));
    assert!(!c.should_defer(P, 132), "equal is not behind");
    assert_eq!(c.window_start(P, 132), P);
    let mut c = after_first_window();
    assert!(c.should_defer(P - 10, 120));
    assert!(!c.should_defer(P + 25, 155));
    let (s, e) = (c.window_start(P + 25, 155), P + 25);
    assert_eq!(s, P, "contiguous with the previous window, no overlap");
    assert!(e - s <= MAX_WINDOW_S);
}

#[test]
fn the_deferral_expires_and_the_next_window_is_sane() {
    // A permanent backward step of ~28 h: the wall clock never catches up in time.
    let w = P - 100_000;
    let mut c = after_first_window();
    assert!(c.should_defer(w, 120));
    assert!(c.should_defer(w + MAX_DEFER_S - 1, 120 + MAX_DEFER_S - 1));
    let (wall, mono) = (w + MAX_DEFER_S, 120 + MAX_DEFER_S);
    assert!(
        !c.should_defer(wall, mono),
        "cap reached: flush with the monotonic arithmetic"
    );
    let s = c.window_start(wall, mono);
    assert!(
        s <= wall && wall - s <= MAX_WINDOW_S,
        "sane window {s}..{wall}"
    );
    assert_eq!(
        wall - s,
        mono - 60,
        "monotonic elapsed since the last flush"
    );
    c.mark_window(mono, wall);
    assert!(
        !c.should_defer(wall + 60, mono + 60),
        "no stale deferral state"
    );
    assert_eq!(c.window_start(wall + 60, mono + 60), wall);
}

#[test]
fn forward_only_operation_never_defers() {
    let mut c = after_first_window();
    for n in 1..50u64 {
        assert!(!c.should_defer(P + 60 * n, 60 + 60 * n));
        let s = c.window_start(P + 60 * n, 60 + 60 * n);
        c.mark_window(60 + 60 * n, P + 60 * n);
        assert_eq!(s, P + 60 * (n - 1));
    }
}

#[test]
fn the_first_window_and_a_held_flush_never_defer() {
    let mut c = WindowClock::new(0);
    assert!(!c.should_defer(5, 60), "no previous end");
    let mut c = after_first_window();
    c.mark_flush(120);
    assert!(!c.should_defer(P - 10, 180), "Hold forgot the end");
}

#[test]
fn the_deferral_timer_restarts_after_catching_up() {
    let mut c = after_first_window();
    assert!(c.should_defer(P - 10, 120));
    assert!(!c.should_defer(P + 5, 400), "caught up");
    c.mark_window(400, P + 5);
    // a second, later backward step gets a full deferral budget again
    assert!(c.should_defer(P - 100_000, 460));
    assert!(c.should_defer(P - 100_000 + MAX_DEFER_S - 1, 460 + MAX_DEFER_S - 1));
}

#[test]
fn after_the_cap_a_still_behind_wall_does_not_start_a_new_deferral() {
    let w = P - 100_000;
    let mut c = after_first_window();
    assert!(c.should_defer(w, 120));
    assert!(!c.should_defer(w + MAX_DEFER_S, 120 + MAX_DEFER_S));
    // flush not yet marked (e.g. the batch could not be built): the next poll still flushes
    assert!(!c.should_defer(w + MAX_DEFER_S + 1, 121 + MAX_DEFER_S));
}

#[test]
fn a_poll_with_the_wall_caught_up_restarts_the_timer_of_a_later_deferral() {
    let mut c = after_first_window();
    assert!(c.should_defer(P - 10, 120));
    assert!(!c.should_defer(P + 5, 130), "caught up");
    // behind again much later, with no window marked in between: a fresh budget
    assert!(c.should_defer(P - 100, 130 + MAX_DEFER_S + 100));
}

#[test]
fn after_deferral_is_set_only_by_a_catch_up_and_cleared_by_the_next_window() {
    let mut c = after_first_window();
    assert!(!c.deferral_min_wall().is_some(), "no deferral yet");
    assert!(c.should_defer(P - 10, 120));
    assert!(!c.deferral_min_wall().is_some(), "still deferring");
    assert!(!c.should_defer(P + 5, 135));
    assert!(
        c.deferral_min_wall().is_some(),
        "the window about to be built was deferred"
    );
    c.mark_window(135, P + 5);
    assert!(
        !c.deferral_min_wall().is_some(),
        "cleared once the window is built"
    );
}

#[test]
fn a_deferral_that_hit_the_cap_is_not_a_deferred_window() {
    let w = P - 100_000;
    let mut c = after_first_window();
    assert!(c.should_defer(w, 120));
    assert!(!c.should_defer(w + MAX_DEFER_S, 120 + MAX_DEFER_S));
    assert!(
        !c.deferral_min_wall().is_some(),
        "rows keep their own stamps after the cap"
    );
}

#[test]
fn a_hold_clears_the_deferred_state() {
    let mut c = after_first_window();
    assert!(c.should_defer(P - 10, 120));
    assert!(!c.should_defer(P + 5, 135));
    c.mark_flush(135);
    assert!(!c.deferral_min_wall().is_some());
}

#[test]
fn a_hold_in_the_middle_of_a_deferral_does_not_taint_the_next_window() {
    let mut c = after_first_window();
    assert!(c.should_defer(P - 10, 120));
    c.mark_flush(130); // Hold: the accumulated window is dropped
    assert!(!c.should_defer(P + 60, 190));
    assert!(
        c.deferral_min_wall().is_none(),
        "an unrelated window is not rewritten"
    );
    c.mark_window(190, P + 60);
    assert!(!c.should_defer(P + 120, 250));
    assert!(c.deferral_min_wall().is_none());
}

#[test]
fn a_pending_catch_up_does_not_survive_a_second_deferral() {
    let mut c = after_first_window();
    assert!(c.should_defer(P - 10, 120));
    assert!(!c.should_defer(P + 5, 135));
    assert!(
        c.deferral_min_wall().is_some(),
        "caught up, window not built yet"
    );
    // the batch could not be built (no mark_window); the wall steps back again
    assert!(c.should_defer(P - 100_000, 140));
    assert!(
        c.deferral_min_wall().is_none(),
        "a new deferral starts clean"
    );
    // ... and runs into the cap: no rewriting despite the stale catch-up
    assert!(!c.should_defer(P - 100_000 + MAX_DEFER_S, 140 + MAX_DEFER_S));
    assert!(c.deferral_min_wall().is_none());
}

#[test]
fn the_deferral_floor_is_the_lowest_wall_polled_while_deferring() {
    let mut c = after_first_window();
    assert!(c.should_defer(P - 10, 120));
    assert!(c.should_defer(P - 30, 125)); // stepped back further
    assert!(c.should_defer(P - 5, 130));
    assert!(!c.should_defer(P + 5, 140)); // the catch-up poll is not part of the deferral
    assert_eq!(c.deferral_min_wall(), Some(P - 30));
    c.mark_window(140, P + 5);
    assert_eq!(c.deferral_min_wall(), None);
}

#[test]
fn the_floor_raise_is_inclusive_of_the_lowest_polled_wall() {
    use vigie_agent::model::DnsQuery;
    use vigie_agent::window::Window;
    let mut w = Window::default();
    for (i, ts) in [99u64, 100, 101, 700].iter().enumerate() {
        w.add_dns(
            DnsQuery::new(
                *ts,
                "aa:bb:cc:dd:ee:01",
                &format!("h{i}.example.com"),
                "A",
                None,
            )
            .unwrap(),
        );
    }
    w.raise_dns_floor(100, 500);
    let (sections, _) = w.take_with_drops();
    let mut got: Vec<u64> = sections.dns.iter().map(|q| q.ts).collect();
    got.sort_unstable();
    assert_eq!(
        got,
        [99, 500, 500, 700],
        "below the lowest wall: untouched; at it: raised"
    );
}
