"""Final review round: cap accounting, fail-safe status, orphan closing, per-target freshness."""

from __future__ import annotations

import dataclasses
import json
import logging

import pytest
from probe_helpers import (
    CURRENT,
    NOW,
    build_fixture,
    dump,
    pr,
    run_fixture,
    state_doc,
    target_state,
    write_probe_file,
)
from test_probes import (  # noqa: F401
    DAY,
    START,
    events,
    fold,
    inv,
    kinds,
    outage,
    recovered,
    settings,
    status,
)

from vigie_ingest.db import iso_utc
from vigie_pipeline import probe_file, probes
from vigie_pipeline.config import PipelineConfig, ProbeSettings
from vigie_pipeline.probe_file import MAX_FILE_BYTES, ProbeFileInvalid, parse_probe_doc


@pytest.fixture(autouse=True)
def _fresh_log_memory():
    probes._reset_log_memory()
    yield
    probes._reset_log_memory()


def outage_of(ident, start, **over):
    t = outage(episode_start=start, **over)
    t["id"] = ident
    return t


def seed(inv, kind, tokens, ts):
    for n, token in enumerate(tokens):
        inv.execute(
            "INSERT INTO events (id, device_id, ts, kind, severity, summary, dedup)"
            " VALUES (?, NULL, ?, ?, 'warn', 's', ?)",
            (f"{kind}{n}{token}", ts, kind, token),
        )


def count(inv, kind):
    return kinds(inv).count(kind)


# ---------------------------------------------------------------- HIGH 1: cap accounting
def test_a_fourth_outage_days_later_from_the_same_episode_day_is_capped(inv, settings):
    for n in range(3):
        write_probe_file(settings.file, state_doc(outage(episode_start=START + n)))
        fold(inv, settings)
    later = NOW + 4 * 86400
    t = outage(episode_start=START + 10, episodes_day=iso_utc(later)[:10])
    write_probe_file(settings.file, state_doc(t, written_at=later))
    fold(inv, settings, now=later + 5)
    assert count(inv, "probe_outage") == 3


def test_a_writer_choosing_its_cap_bucket_is_bounded(inv, settings):
    for step in range(200):  # one `now`, ten fresh ids per fold, every episode on a different day
        targets = [outage_of(f"i{step}x{n}", int(NOW) - step * 86400 - 100) for n in range(10)]
        write_probe_file(settings.file, state_doc(*targets))
        fold(inv, settings)
    total = count(inv, "probe_outage")
    assert 0 < total <= 7 * probes.MAX_GLOBAL_OUTAGES_PER_DAY


def test_an_episode_older_than_the_emit_window_is_not_reported_and_is_logged(inv, settings, caplog):
    old = outage(episode_start=int(NOW) - probes.EMIT_MAX_AGE_S - 1)
    write_probe_file(settings.file, state_doc(old))
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        fold(inv, settings)
    assert count(inv, "probe_outage") == 0
    assert [r.fields["kind"] for r in caplog.records if r.getMessage() == "probe_event_capped"] == [
        "probe_outage"
    ]
    young = outage(episode_start=int(NOW) + 5 - probes.EMIT_MAX_AGE_S)  # exactly the limit
    write_probe_file(settings.file, state_doc(young))
    fold(inv, settings)
    assert count(inv, "probe_outage") == 1


def test_the_global_cap_counts_events_emitted_in_the_same_pass(inv, settings):
    seed(inv, "probe_outage", [f"seed{n}:{int(NOW) - 100}" for n in range(28)], iso_utc(NOW))
    targets = [outage_of(f"t{n}", int(NOW) - 100) for n in range(10)]
    write_probe_file(settings.file, state_doc(*targets))
    fold(inv, settings)
    assert count(inv, "probe_outage") == probes.MAX_GLOBAL_OUTAGES_PER_DAY == 30


def test_the_flapping_cap_counts_events_emitted_in_the_same_pass(inv, settings):
    seed(inv, "probe_flapping", [f"seed{n}:{DAY}" for n in range(8)], iso_utc(NOW))
    targets = []
    for n in range(5):
        t = outage_of(f"f{n}", START, flapping=True, suppressed=True)
        targets.append(t)
    write_probe_file(settings.file, state_doc(*targets))
    fold(inv, settings)
    assert count(inv, "probe_flapping") == probes.MAX_FLAPPING_PER_DAY == 10


def test_a_cap_drop_is_logged_once_per_kind_and_day(inv, settings, caplog):
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        for n in range(6):
            write_probe_file(settings.file, state_doc(outage(episode_start=START + n)))
            fold(inv, settings)
    capped = [r for r in caplog.records if r.getMessage() == "probe_event_capped"]
    assert count(inv, "probe_outage") == 3 and len(capped) == 1
    assert capped[0].fields == {"kind": "probe_outage", "id": "router-dns"}


# ---------------------------------------------------------------- HIGH 2: the status fails safe
def test_status_carries_valid_until_and_unavailable_has_none(inv, settings):
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    assert status(inv)["valid_until"] == int(NOW) + settings.stale_s
    fold(inv, settings, now=NOW + 1000)
    assert status(inv)["valid_until"] is None


def test_a_failing_fold_marks_the_status_unavailable(inv, settings, monkeypatch):
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    assert status(inv)["stale"] is False

    def boom(*a, **k):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(probes, "_close_orphans", boom)
    write_probe_file(settings.file, state_doc(outage()))
    fold(inv, settings, now=NOW + 40)
    snap = status(inv)
    assert (snap["stale"], snap["reason"], snap["valid_until"]) == (True, "error", None)
    assert "probe_outage" not in kinds(inv)  # the failed fold rolled back whole


def test_a_second_failure_while_marking_is_contained(inv, settings, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("down")

    monkeypatch.setattr(probes, "_fold", boom)
    fold(inv, settings)  # neither the fold nor the fallback may raise


def test_turning_the_flag_off_marks_the_status_unavailable_once(tmp_path):
    build_fixture(tmp_path)
    t = target_state(last_attempt=CURRENT + 3600)
    path = write_probe_file(tmp_path / "p.json", state_doc(t, written_at=CURRENT + 3600))
    run_fixture(tmp_path, VIGIE_PROBE_FILE=str(path))
    assert json.loads(dict(dump(tmp_path)["pipeline_meta"])["probe_status"])["stale"] is False
    run_fixture(tmp_path)  # the flag is now off
    first = dict(dump(tmp_path)["pipeline_meta"])["probe_status"]
    assert (json.loads(first)["stale"], json.loads(first)["reason"]) == (True, "disabled")
    run_fixture(tmp_path)
    assert dict(dump(tmp_path)["pipeline_meta"])["probe_status"] == first  # written once


def test_disabled_without_a_previous_status_writes_nothing(tmp_path):
    build_fixture(tmp_path)
    run_fixture(tmp_path)
    assert "probe_status" not in dict(dump(tmp_path)["pipeline_meta"])


# ---------------------------------------------------------------- HIGH 3: open outages close
def open_one(inv, settings, start=START):
    write_probe_file(settings.file, state_doc(outage(episode_start=start)))
    fold(inv, settings)


def test_outage_closed_when_the_runner_restarts_fresh(inv, settings):
    open_one(inv, settings)
    write_probe_file(settings.file, state_doc(target_state()))  # ok, episode_start None
    fold(inv, settings, now=NOW + 40)
    closed = [e for e in events(inv) if e[0] == "probe_recovered"]
    assert [e[3] for e in closed] == [f"router-dns:{START}"] and "superseded" in closed[0][2]


def test_outage_closed_by_a_new_episode_with_a_smaller_start(inv, settings):
    open_one(inv, settings)
    write_probe_file(settings.file, state_doc(outage(episode_start=START - 3600)))
    fold(inv, settings, now=NOW + 40)
    tokens = {(e[0], e[3]) for e in events(inv)}
    assert ("probe_recovered", f"router-dns:{START}") in tokens
    assert ("probe_outage", f"router-dns:{START - 3600}") in tokens


def test_unclosable_rows_cannot_starve_a_removed_targets_outage(inv, settings):
    seed(
        inv,
        "probe_outage",
        [f"router-dns:{START + 10 + n}" for n in range(150)],
        iso_utc(NOW - 7200),
    )
    seed(inv, "probe_outage", [f"gone:{START}"], iso_utc(NOW - 60))
    write_probe_file(settings.file, state_doc(outage(episode_start=START - 5000)))
    for _ in range(3):
        fold(inv, settings)
    closed = {e[3] for e in events(inv) if e[0] == "probe_recovered"}
    assert f"gone:{START}" in closed and len(closed) == 151


def test_the_orphan_scan_closes_the_oldest_first(inv, settings):
    for n in range(250):  # the OLDEST rows have the highest numbers: rowid/token order differ
        seed(inv, "probe_outage", [f"g{n:03d}:{START}"], iso_utc(NOW - 10 * n))
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    closed = sorted(e[3] for e in events(inv) if e[0] == "probe_recovered")
    assert closed == [f"g{n:03d}:{START}" for n in range(150, 250)]  # the 100 oldest by ts


def test_an_orphan_a_few_days_old_is_closed(inv, settings):
    seed(inv, "probe_outage", [f"gone:{START}"], iso_utc(NOW - 3 * 86400))
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    assert [e[3] for e in events(inv) if e[0] == "probe_recovered"] == [f"gone:{START}"]


def test_a_present_target_with_its_current_episode_is_not_closed(inv, settings):
    for _ in range(3):
        open_one(inv, settings)
    assert kinds(inv) == ["probe_outage"]


# ---------------------------------------------------------------- MEDIUM 5: per-target freshness
@pytest.mark.parametrize("attempt", [None, NOW - 301, NOW - 36000])
def test_a_target_not_probed_recently_is_unknown_and_silent(inv, settings, attempt):
    write_probe_file(settings.file, state_doc(outage(last_attempt=attempt)))
    fold(inv, settings)
    assert status(inv)["targets"][0]["state"] == "unknown"
    assert events(inv) == []


def test_a_target_probed_within_the_window_keeps_its_state(inv, settings):
    write_probe_file(settings.file, state_doc(outage(last_attempt=NOW - 300)))
    fold(inv, settings)
    assert status(inv)["targets"][0]["state"] == "outage" and kinds(inv) == ["probe_outage"]


def test_an_unknown_target_never_recovers_an_open_outage(inv, settings):
    open_one(inv, settings)
    write_probe_file(settings.file, state_doc(recovered(last_attempt=NOW - 5000)))
    fold(inv, settings, now=NOW + 40)
    assert "probe_recovered" not in kinds(inv)


# ---------------------------------------------------------------- MEDIUM 6: a missed episode
def test_an_episode_first_seen_already_recovered_is_announced_both_ways(inv, settings):
    write_probe_file(settings.file, state_doc(recovered(episode_start=int(NOW) - 600)))
    fold(inv, settings)
    assert kinds(inv) == ["probe_outage", "probe_recovered"]
    fold(inv, settings)
    assert kinds(inv) == ["probe_outage", "probe_recovered"]


def test_a_missed_episode_older_than_the_window_or_suppressed_stays_silent(inv, settings):
    old = recovered(episode_start=int(NOW) - probes.EMIT_MAX_AGE_S - 1)
    write_probe_file(settings.file, state_doc(old))
    fold(inv, settings)
    write_probe_file(settings.file, state_doc(recovered(suppressed=True, flapping=False)))
    fold(inv, settings)
    assert events(inv) == []


def test_a_capped_missed_episode_is_not_recovered(inv, settings):
    seed(inv, "probe_outage", [f"router-dns:{START - n}" for n in range(1, 4)], iso_utc(NOW))
    write_probe_file(settings.file, state_doc(recovered()))
    fold(inv, settings)
    assert "probe_recovered" not in [e[0] for e in events(inv) if e[3] == f"router-dns:{START}"]


# ---------------------------------------------------------------- LOW 7: the runner's own output
def test_runner_repairs_an_episode_start_far_in_the_future(tmp_path):
    cfg = pr.parse_config(
        {"enabled": True, "state_file": str(tmp_path / "s.json"),
         "targets": [{"id": "lan-web", "kind": "tcp_lan", "address": "10.0.0.9", "port": 8080}]}
    )  # fmt: skip

    def ok(host, port, timeout):
        return None

    def run(state, at):
        return pr.run_pass(cfg, state, now=lambda: at, dns=None, connect=ok)

    state = run(pr.empty_state(), NOW)
    step = NOW - 2 * 86400
    for episode_state, expected in (("ok", None), ("outage", int(step))):
        future = dataclasses.replace(
            state.targets[0], state=episode_state, episode_start=int(NOW) + 3 * 86400,
            suppressed=True,
        )  # fmt: skip
        target = run(pr.State(state.written_at, (future,)), step).targets[0]
        assert target.episode_start == expected
        assert target.suppressed is (episode_state == "outage")
        after = pr.State(step, (target,))
        assert parse_probe_doc(pr.serialize_state(after)).targets[0].episode_start == expected


# ---------------------------------------------------------------- LOW 8: unavailable log
def test_unavailable_is_logged_once_per_change_of_reason(inv, settings, caplog):
    def reasons():
        return [r.fields["reason"] for r in caplog.records if r.getMessage() == "probe_unavailable"]

    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        fold(inv, settings)
        fold(inv, settings)
        assert reasons() == ["missing"]
        write_probe_file(settings.file, state_doc(target_state()))
        fold(inv, settings, now=NOW + 1000)
        fold(inv, settings, now=NOW + 1001)
        assert reasons() == ["missing", "stale"]
        fold(inv, settings)  # available again, then stale again logs again
        fold(inv, settings, now=NOW + 1000)
        assert reasons() == ["missing", "stale", "stale"]


# ---------------------------------------------------------------- survivors: bounds
def padded(size):
    body = json.dumps(state_doc(target_state())).encode()
    return body + b" " * (size - len(body))


def test_the_size_cap_is_exact_at_the_reader_and_at_the_read():
    parse_probe_doc(padded(MAX_FILE_BYTES))
    with pytest.raises(ProbeFileInvalid):
        parse_probe_doc(padded(MAX_FILE_BYTES + 1))


def test_a_file_one_byte_over_the_cap_is_invalid_when_read_from_disk(inv, settings):
    settings.file.write_bytes(padded(MAX_FILE_BYTES + 1))
    fold(inv, settings)
    assert status(inv)["reason"] == "invalid"
    settings.file.write_bytes(padded(MAX_FILE_BYTES))
    fold(inv, settings, now=NOW + 1)
    assert status(inv)["stale"] is False


def test_the_future_skew_boundary_is_exact(inv, settings):
    write_probe_file(settings.file, state_doc(target_state(), written_at=NOW + 10))
    fold(inv, settings, now=NOW)
    assert status(inv)["stale"] is False
    write_probe_file(settings.file, state_doc(target_state(), written_at=NOW + 10.5))
    fold(inv, settings, now=NOW)
    assert status(inv)["reason"] == "future"


def test_the_stage_gate_depends_only_on_the_file(tmp_path, monkeypatch):
    assert not ProbeSettings(stale_s=180).enabled
    assert not PipelineConfig.from_env({"VIGIE_PROBE_STALE_S": "180"}).probes.enabled
    from vigie_pipeline import processor

    def boom(*a, **k):
        raise AssertionError("must not run")

    monkeypatch.setattr(processor, "fold_probes", boom)
    build_fixture(tmp_path)
    run_fixture(tmp_path, VIGIE_PROBE_STALE_S="180")


def test_probe_file_has_the_per_target_freshness_field():
    assert {f.name for f in dataclasses.fields(probe_file.ProbeTarget)} >= {"last_attempt"}


# ---------------------------------------------------------------- insert-day backstop (round 3)
def test_one_id_rotating_episode_days_cannot_exceed_twice_the_daily_cap(inv, settings):
    for step in range(40):  # one real day, a different past-day episode_start on every pass
        start = int(NOW) - (step % 7) * 86400 - 100 - step
        write_probe_file(settings.file, state_doc(outage_of("router-dns", start)))
        fold(inv, settings, now=NOW + 5 + step)
    assert 0 < count(inv, "probe_outage") <= 2 * probes.MAX_OUTAGES_PER_DAY


def test_the_global_insert_day_cap_holds_across_rotating_ids(inv, settings):
    for step in range(12):  # 7 ids a pass: the in-pass overshoot (up to 39) would be visible
        targets = [outage_of(f"i{step}x{n}", int(NOW) - (step % 7) * 86400 - 100) for n in range(7)]
        write_probe_file(settings.file, state_doc(*targets))
        fold(inv, settings, now=NOW + 5 + step)
    assert count(inv, "probe_outage") == 2 * probes.MAX_GLOBAL_OUTAGES_PER_DAY


def test_flapping_insert_day_cap_holds_when_the_episode_day_rotates(inv, settings):
    for step in range(20):
        day = iso_utc(NOW + 5)[:10]
        t = outage_of(f"f{step}", START, flapping=True, suppressed=True, episodes_day=day)
        write_probe_file(settings.file, state_doc(t))
        fold(inv, settings, now=NOW + 5)
    assert count(inv, "probe_flapping") == probes.MAX_FLAPPING_PER_DAY


def test_an_open_outage_closes_across_later_episodes_with_other_starts(inv, settings):
    first = int(NOW) - 100
    write_probe_file(settings.file, state_doc(outage(episode_start=first)))
    fold(inv, settings)
    for n in (1, 2):  # two later episodes open and close while the first stays unclosed
        start = first + n * 10
        write_probe_file(settings.file, state_doc(outage(episode_start=start)))
        fold(inv, settings, now=NOW + 5 + n)
        write_probe_file(settings.file, state_doc(recovered(episode_start=start)))
        fold(inv, settings, now=NOW + 5 + n)
    recovered_tokens = {e[3] for e in events(inv) if e[0] == "probe_recovered"}
    assert f"router-dns:{first}" in recovered_tokens
    assert len(recovered_tokens) == 3


# ---------------------------------------------------------------- cap dimensions are independent
YESTERDAY_START = int(NOW) - 86400 - 100


def test_the_episode_day_global_cap_counts_events_inserted_on_other_days(inv, settings):
    seed(inv, "probe_outage", [f"s{n}:{YESTERDAY_START}" for n in range(28)], iso_utc(NOW - 86400))
    targets = [outage_of(f"t{n}", YESTERDAY_START) for n in range(7)]
    write_probe_file(settings.file, state_doc(*targets))
    fold(inv, settings)
    assert count(inv, "probe_outage") == 30  # 28 + exactly 2 (episode-day bucket, same pass)


def test_the_episode_day_global_cap_blocks_when_already_full(inv, settings):
    seed(inv, "probe_outage", [f"s{n}:{YESTERDAY_START}" for n in range(30)], iso_utc(NOW - 86400))
    write_probe_file(settings.file, state_doc(outage_of("late", YESTERDAY_START)))
    fold(inv, settings)
    assert count(inv, "probe_outage") == 30


def test_flapping_day_caps_are_independent_and_counted_in_the_pass(inv, settings):
    seed(inv, "probe_flapping", [f"s{n}:{DAY}" for n in range(8)], iso_utc(NOW - 86400))
    targets = [outage_of(f"f{n}", START, flapping=True, suppressed=True) for n in range(5)]
    write_probe_file(settings.file, state_doc(*targets))
    fold(inv, settings)
    assert count(inv, "probe_flapping") == 10  # the episode-day bucket (8 seeded) caps at 2 new


def test_flapping_insert_day_cap_alone_blocks(inv, settings):
    seed(inv, "probe_flapping", [f"s{n}:2027-01-10" for n in range(18)], iso_utc(NOW))
    targets = [outage_of(f"f{n}", START, flapping=True, suppressed=True) for n in range(5)]
    write_probe_file(settings.file, state_doc(*targets))
    fold(inv, settings)
    assert count(inv, "probe_flapping") == 20  # 18 inserted today + exactly 2, counted in the pass


def test_an_unknown_target_emits_nothing_even_when_flapping(inv, settings):
    t = outage(last_attempt=NOW - 5000, flapping=True, suppressed=True)
    write_probe_file(settings.file, state_doc(t))
    fold(inv, settings)
    assert events(inv) == []


def test_old_recovered_episodes_stay_silent_without_a_cap_log(inv, settings, caplog):
    old = recovered(episode_start=int(NOW) - probes.EMIT_MAX_AGE_S - 1)
    write_probe_file(settings.file, state_doc(old))
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        fold(inv, settings)
    assert events(inv) == []
    assert "probe_event_capped" not in [r.getMessage() for r in caplog.records]
