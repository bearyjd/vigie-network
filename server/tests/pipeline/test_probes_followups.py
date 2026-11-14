"""Follow-ups from the final review of probe slice 2: caps, stale floor, late wording, logs."""

from __future__ import annotations

import logging

import pytest
from probe_helpers import NOW, state_doc, target_state, write_probe_file
from test_probes import (  # noqa: F401
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

from vigie_pipeline import probes
from vigie_pipeline.config import ProbeSettings

MIDNIGHT = int(NOW) + 16 * 3600  # 2027-01-16T00:00:00Z


def _ten(**over):
    targets = [outage(**over) for _ in range(10)]
    for i, t in enumerate(targets):
        t["id"] = f"t{i}"
    return targets


# ---------------------------------------------------------------- 1: global insert-day slack
def test_a_midnight_spanning_outage_is_not_dropped_by_the_global_insert_day_cap(inv, settings):
    pre = outage(episode_start=MIDNIGHT - 5, episodes_day="2027-01-15")
    write_probe_file(settings.file, state_doc(pre, written_at=MIDNIGHT - 2))
    fold(inv, settings, now=MIDNIGHT + 15)  # opened on the 15th, folded on the 16th
    for n in range(3):
        start = MIDNIGHT + 100 + n * 100
        targets = _ten(episode_start=start, episodes_day="2027-01-16")
        write_probe_file(settings.file, state_doc(*targets, written_at=start + 20))
        fold(inv, settings, now=start + 25)
    assert kinds(inv).count("probe_outage") == 31


def test_a_midnight_spanning_flapping_event_is_not_dropped_by_the_insert_day_cap(inv, settings):
    pre = outage(episode_start=MIDNIGHT - 5, episodes_day="2027-01-15", flapping=True,
                 suppressed=True)  # fmt: skip
    write_probe_file(settings.file, state_doc(pre, written_at=MIDNIGHT - 2))
    fold(inv, settings, now=MIDNIGHT + 15)
    targets = _ten(episodes_day="2027-01-16", flapping=True, suppressed=True)
    write_probe_file(settings.file, state_doc(*targets, written_at=MIDNIGHT + 100))
    fold(inv, settings, now=MIDNIGHT + 105)
    assert kinds(inv).count("probe_flapping") == 11


# ---------------------------------------------------------------- 2: stale_s floor
def test_stale_s_floor_is_180():
    for bad in ("179", "86401", "abc"):
        with pytest.raises(ValueError):
            ProbeSettings.from_env({"VIGIE_PROBE_STALE_S": bad})
    assert ProbeSettings.from_env({"VIGIE_PROBE_STALE_S": "180"}).stale_s == 180
    assert ProbeSettings.from_env({"VIGIE_PROBE_STALE_S": "86400"}).stale_s == 86400


# ---------------------------------------------------------------- 3: late report wording
def test_an_old_recovered_episode_is_reported_as_late_not_as_current(inv, settings):
    old = int(NOW) - 6 * 86400
    doc = state_doc(recovered(episode_start=old, last_error_class="timeout"))
    write_probe_file(settings.file, doc)
    for _ in range(2):
        fold(inv, settings)
    token = f"router-dns:{old}"
    late = "probe router-dns was failing (timeout), reported late"
    assert events(inv) == [
        ("probe_outage", "warn", late, token, None),
        ("probe_recovered", "info", "probe router-dns recovered", token, None),
    ]


def test_a_live_outage_keeps_the_failing_wording(inv, settings):
    write_probe_file(settings.file, state_doc(outage()))
    fold(inv, settings)
    assert events(inv)[0][2] == "probe router-dns failing (timeout)"


# ---------------------------------------------------------------- 4: capped log names each id
def test_a_cap_drop_names_every_capped_id(inv, settings, caplog):
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        for n in range(4):
            ts = [outage(episode_start=START + n), outage(episode_start=START + n)]
            ts[0]["id"], ts[1]["id"] = "a", "b"
            write_probe_file(settings.file, state_doc(*ts))
            fold(inv, settings)
    named = {r.fields["id"] for r in caplog.records if r.getMessage() == "probe_event_capped"}
    assert named == {"a", "b"}


# ---------------------------------------------------------------- 5: retire emits nothing
def test_retiring_the_status_emits_no_event(inv, settings):
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    before = events(inv)
    total = inv.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    probes.retire_status(inv, lambda: NOW + 60)
    assert status(inv)["reason"] == "disabled"
    assert events(inv) == before
    assert inv.execute("SELECT COUNT(*) FROM events").fetchone()[0] == total
