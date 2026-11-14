"""Round 2: clock-step tolerance (end to end from the runner), day-boundary and global caps."""

from __future__ import annotations

import pytest
from probe_helpers import NOW, pr, state_doc, target_state, write_probe_file
from test_probes import START, events, fold, inv, kinds, outage, settings, status  # noqa: F401
from test_probes_review import raw

from vigie_ingest.db import iso_utc
from vigie_pipeline import probe_file, probes
from vigie_pipeline.probe_file import ProbeFileInvalid, parse_probe_doc

MIDNIGHT = int(NOW) + 16 * 3600  # 2027-01-16T00:00:00Z


# ---------------------------------------------------------------- 1: clock step, from the runner
def test_runner_output_across_a_backward_clock_step_folds_cleanly(inv, settings):
    run_cfg = pr.parse_config(
        {"enabled": True, "state_file": str(settings.file),
         "targets": [{"id": "lan-web", "kind": "tcp_lan", "address": "10.0.0.9", "port": 8080}]}
    )  # fmt: skip
    clock = [NOW]
    ok = [False]

    def connect(host, port, timeout):
        if not ok[0]:
            raise ConnectionRefusedError

    state = pr.empty_state()

    def tick(at: float) -> None:
        nonlocal state
        clock[0] = at
        state = pr.run_pass(run_cfg, state, now=lambda: clock[0], dns=None, connect=connect)
        write_probe_file(settings.file, pr.serialize_state(state))
        fold(inv, settings, now=at + 5)

    for minute in range(3):  # F F F: the outage opens at NOW + 120
        tick(NOW + minute * 60)
    assert kinds(inv) == ["probe_outage"]
    step = NOW + 120 - 5 * 3600  # the clock is corrected back by five hours
    ok[0] = True
    for minute in range(3):
        tick(step + minute * 60)
    target = state.targets[0]
    assert target.state == "ok" and target.episode_start == int(NOW) + 120 > state.written_at
    snap = status(inv)
    assert (snap["stale"], snap["reason"]) == (False, None)
    token = f"lan-web:{int(NOW) + 120}"
    assert [(e[0], e[3]) for e in events(inv)] == [
        ("probe_outage", token),
        ("probe_recovered", token),
    ]
    tick(step + 180)  # replay: nothing new
    assert kinds(inv) == ["probe_outage", "probe_recovered"]


def test_the_skew_tolerance_is_bounded():
    limit = probe_file.MAX_CLOCK_STEP_S
    parse_probe_doc(raw(episode_start=int(NOW) + limit))
    with pytest.raises(ProbeFileInvalid):
        parse_probe_doc(raw(episode_start=int(NOW) + limit + 1))


# ---------------------------------------------------------------- 2: cap by the episode's own day
def put(settings, ident, start, written_at, day):
    t = outage(episode_start=start, episodes_day=day)
    t["id"] = ident
    write_probe_file(settings.file, state_doc(t, written_at=written_at))


def test_an_episode_folded_after_midnight_counts_toward_its_own_day(inv, settings):
    put(settings, "r", MIDNIGHT - 10, MIDNIGHT + 10, "2027-01-16")  # opened 23:59:50, folded later
    fold(inv, settings, now=MIDNIGHT + 15)
    for n in range(3):  # the new day's own three legitimate outage events
        start = MIDNIGHT + 100 + n * 100
        put(settings, "r", start, start + 20, "2027-01-16")
        fold(inv, settings, now=start + 25)
    assert kinds(inv).count("probe_outage") == 4  # 1 for the 15th, 3 for the 16th
    put(settings, "r", MIDNIGHT + 900, MIDNIGHT + 920, "2027-01-16")
    fold(inv, settings, now=MIDNIGHT + 925)
    assert kinds(inv).count("probe_outage") == 4  # a 4th on the 16th is still capped


def test_the_cap_resets_at_the_episode_day_boundary(inv, settings):
    for n in range(3):
        start = MIDNIGHT - 400 + n * 100
        put(settings, "r", start, start + 20, "2027-01-15")
        fold(inv, settings, now=start + 25)
    assert kinds(inv).count("probe_outage") == 3
    put(settings, "r", MIDNIGHT + 50, MIDNIGHT + 70, "2027-01-16")
    fold(inv, settings, now=MIDNIGHT + 75)
    assert kinds(inv).count("probe_outage") == 4


def test_a_fourth_episode_of_the_day_folded_after_midnight_is_still_capped(inv, settings):
    for n in range(3):
        start = MIDNIGHT - 400 + n * 100
        put(settings, "r", start, start + 20, "2027-01-15")
        fold(inv, settings, now=start + 25)
    put(settings, "r", MIDNIGHT - 5, MIDNIGHT + 10, "2027-01-16")  # opened 23:59:55 on the 15th
    fold(inv, settings, now=MIDNIGHT + 15)
    assert kinds(inv).count("probe_outage") == 3


# ---------------------------------------------------------------- 3: global caps, bounded scan
def rotating(settings, step, flapping=False):
    targets = []
    for n in range(10):
        t = outage(episode_start=int(NOW) - 10, flapping=flapping, suppressed=flapping)
        t["id"] = f"id{step}x{n}"
        targets.append(t)
    write_probe_file(settings.file, state_doc(*targets))


def test_rotating_ids_cannot_exceed_the_global_daily_cap(inv, settings):
    for step in range(50):
        rotating(settings, step)
        fold(inv, settings, now=NOW + 5)
    outages = kinds(inv).count("probe_outage")
    assert outages == probes.MAX_GLOBAL_OUTAGES_PER_DAY == 30
    assert kinds(inv).count("probe_recovered") <= outages


def test_rotating_flapping_ids_are_capped_globally(inv, settings):
    for step in range(20):
        rotating(settings, step, flapping=True)
        fold(inv, settings, now=NOW + 5)
    assert kinds(inv).count("probe_flapping") == probes.MAX_FLAPPING_PER_DAY == 10


def seed_open_outages(inv, count, ts):
    for n in range(count):
        inv.execute(
            "INSERT INTO events (id, device_id, ts, kind, severity, summary, dedup)"
            " VALUES (?, NULL, ?, 'probe_outage', 'warn', 's', ?)",
            (f"seed{n}", ts, f"gone{n}:{int(NOW) - 500}"),
        )


def test_the_orphan_scan_is_limited_per_pass_and_finishes(inv, settings):
    seed_open_outages(inv, 250, iso_utc(NOW - 3600))
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    assert kinds(inv).count("probe_recovered") == probes.MAX_ORPHANS_PER_PASS == 100
    for _ in range(3):
        fold(inv, settings)
    assert kinds(inv).count("probe_recovered") == 250


def test_old_outages_are_not_scanned(inv, settings):
    seed_open_outages(inv, 3, iso_utc(NOW - 40 * 86400))
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    assert kinds(inv).count("probe_recovered") == 0


# ---------------------------------------------------------------- 5: id prefix collisions
def test_ids_a_and_ab_do_not_share_cap_counts(inv, settings):
    for n in range(3):
        t = outage(episode_start=START + n)
        t["id"] = "ab"
        write_probe_file(settings.file, state_doc(t))
        fold(inv, settings)
    a = outage(episode_start=START + 10)
    a["id"] = "a"
    write_probe_file(settings.file, state_doc(a))
    fold(inv, settings)
    assert [e[3] for e in events(inv)].count(f"a:{START + 10}") == 1  # a is not capped by ab


def test_orphan_closing_does_not_mix_a_and_ab(inv, settings):
    t = outage()
    t["id"] = "ab"
    write_probe_file(settings.file, state_doc(t))
    fold(inv, settings)
    a = outage(episode_start=START + 50)
    a["id"] = "a"
    write_probe_file(settings.file, state_doc(a, t))  # a's newer episode must not close ab's
    fold(inv, settings)
    assert not [e for e in events(inv) if e[0] == "probe_recovered"]
    write_probe_file(settings.file, state_doc(a))  # ab removed: only ab closes
    fold(inv, settings)
    closed = [e[3] for e in events(inv) if e[0] == "probe_recovered"]
    assert closed == [f"ab:{START}"]
