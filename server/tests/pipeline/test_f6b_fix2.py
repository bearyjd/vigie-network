"""F6-b fix round 2: fail-closed flood reading, clock-free anchor, retention bound, newer
overrides schema, cheap repeat passes, and a committed unmark never notifying."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from test_f6b_essential_absence import HOUR, Env, H, env, now_after  # noqa: F401

from vigie_ingest.db import iso_utc
from vigie_ingest.essential_evidence import INFORMATIONAL_KEYS
from vigie_pipeline import essential_absence as ea

COLLECTOR_SRC = Path(__file__).resolve().parents[3] / "collector" / "agent" / "src"
# the keys the collector reports that are NOT drops (`INFORMATIONAL_KEYS`)
DROP_KEYS = [
    "dns_dropped", "dns_pending_evicted", "dns_client_throttled", "dhcp_block_evicted",
    "tail_truncated", "tail_open_failed", "tail_bytes_skipped", "dns_quota_dropped",
    "ct_lan_unmapped_flows", "ct_lan_unmapped_bytes", "ct_errors", "some_future_key",
]  # fmt: skip


def raw_batch(env, start, end, truncated, *, n=None, collector="c1", received=None) -> None:
    """A batch whose `truncated` cell is stored verbatim (None = SQL NULL, or invalid JSON)."""
    env.n += 1
    env.inv.execute(
        "INSERT INTO batches(collector_id,batch_id,received_at,truncated,dropped_batches,"
        "window_start,window_end,observation_kind) VALUES (?,?,?,?,0,?,?,'observation')",
        (collector, f"r{n or env.n}", iso_utc(received or end or H), truncated, start, end),
    )


def two_hours(env, secs=2 * 3600) -> None:
    env.device("d1")
    env.mark("d1", secs)
    env.cover(1, 2)


def flooded_hour_one(env, truncated) -> int:
    """Hour H+1 carries `truncated`; the sweep over hours 1..2 (threshold 2 h)."""
    two_hours(env)
    env.batch(H + HOUR + 60, H + HOUR + 900, truncated)
    return env.sweep(now_after(2))


# ---- R1-3: any non-informational key is a flood (fail closed) -----------------------------------
@pytest.mark.parametrize("key", DROP_KEYS)
def test_every_drop_key_makes_the_hour_blind(env, key):
    assert flooded_hour_one(env, {key: 3}) == 0
    env.cover(3, 1)
    assert env.sweep(now_after(3)) == 1


@pytest.mark.parametrize("key", INFORMATIONAL_KEYS)
def test_informational_keys_do_not_blind_the_hour(env, key):
    assert flooded_hour_one(env, {key: 40}) == 1


@pytest.mark.parametrize(
    ("truncated", "blind"),
    [({"source_flags": 8}, False), ({"source_flags": 0}, False), ({"source_flags": 1}, True),
     ({"source_flags": 9}, True), ({"leases": 0}, False), ({"leases": 1}, True)],
)  # fmt: skip
def test_source_flags_is_a_bitmask_and_odd_values_fail_closed(env, truncated, blind):
    assert flooded_hour_one(env, truncated) == (0 if blind else 1)


def collector_truncated_keys() -> set[str]:
    keys: set[str] = set()
    for path in COLLECTOR_SRC.glob("*.rs"):
        text = path.read_text()
        keys |= set(re.findall(r'note_drops\("([a-z_]+)"', text))
        keys |= set(re.findall(r'note\(&mut truncated,\s*"([a-z_]+)"', text))
        keys |= set(re.findall(r'\("([a-z_]+)",\s*std::mem::take', text))
    return keys


def test_the_key_list_is_pinned_against_the_collector():
    keys = collector_truncated_keys()
    assert {"dns_dropped", "dhcp_block_evicted", "tail_truncated", "leases"} <= keys
    assert set(INFORMATIONAL_KEYS) <= keys | {"ct_unmapped_bytes", "ct_unmapped_flows"}


@pytest.mark.parametrize("key", sorted(collector_truncated_keys()))
def test_every_key_the_collector_can_report_is_blind_unless_informational(env, key):
    expected = 1 if key in INFORMATIONAL_KEYS else 0
    assert flooded_hour_one(env, {key: 2}) == expected


# ---- R1-17: unreadable or odd truncation maps ---------------------------------------------------
@pytest.mark.parametrize("cell", ["not json", "[1]", '"x"', "7", '{"leases": '])
def test_an_unreadable_or_non_object_truncation_map_is_blind(env, cell):
    two_hours(env)
    raw_batch(env, H + HOUR + 60, H + HOUR + 900, cell)
    assert env.sweep(now_after(2)) == 0


@pytest.mark.parametrize("cell", [None, "{}"])
def test_uncertified_observations_never_authorize_an_hour(env, cell):
    two_hours(env)
    raw_batch(env, H + HOUR, H + HOUR + 300, cell)
    assert env.sweep(now_after(2)) == 0


# ---- R1-5: a clock step cannot move the anchor --------------------------------------------------
def test_a_clock_rollback_cannot_manufacture_an_episode(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 1)
    env.cover(4, 1)
    env.active("d1", 4)  # activity (and its coverage) at H+4
    assert env.sweep(H + 6 * HOUR + 30) == 0
    assert env.sweep(H + 2 * HOUR + 30) == 0  # clock stepped back: same data, same verdict
    assert env.sweep(H + 6 * HOUR + 60) == 0 and env.rows() == []


def test_accepted_activity_in_an_hour_without_coverage_can_anchor(env):
    env.device("d1")
    env.mark("d1", 2 * 3600)
    env.cover(1, 2)
    env.active("d1", 9)
    assert env.sweep(now_after(2)) == 0 and env.rows() == []


def test_the_anchor_may_be_the_newest_covered_hour(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.active("d1", 2)  # activity in the last covered hour counts
    assert env.sweep(now_after(3)) == 0
    env.cover(3, 1)
    assert env.sweep(now_after(3)) == 1 and env.rows()[0]["episode_start"] == H + 2 * HOUR


def test_equal_anchors_across_collectors_pick_the_lower_collector_id(env):
    mac = env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.inv.execute("INSERT INTO collectors(id,key_id) VALUES ('c2','k2')")
    env.inv.execute("INSERT INTO essential_activity VALUES ('c2',?,?)", (mac, H))
    env.inv.execute("INSERT INTO measurements_hourly VALUES ('c2',?,?,1,1,1,0)", (mac, H))
    env.inv.execute("INSERT INTO coverage_hourly VALUES ('c2',?,0,0,'[]')", (H + HOUR,))
    assert env.sweep(now_after(2)) == 1 and env.rows()[0]["collector_id"] == "c1"


# ---- R1-8: a newer overrides.db judges nothing --------------------------------------------------
def test_a_newer_overrides_schema_abstains_with_one_event_per_day(env):
    two_hours(env)
    env.ovw.execute("PRAGMA user_version=999")
    assert env.sweep(now_after(2)) == 0 and env.rows() == []
    env.sweep(now_after(2) + 5)
    events = env.inv.execute("SELECT kind, severity, device_id, dedup FROM events").fetchall()
    assert [tuple(e) for e in events] == [
        ("essential_unjudged", "warn", None, f"overrides_schema:{iso_utc(now_after(2))[:10]}")
    ]


def test_a_repeated_schema_abstention_takes_no_write_lock(env):
    two_hours(env)
    env.ovw.execute("PRAGMA user_version=999")
    assert writes(env, now_after(2))
    assert writes(env, now_after(2) + 5) == []


def test_a_newer_overrides_schema_closes_nothing(env):
    two_hours(env)
    env.sweep(now_after(2))
    env.ovw.execute("PRAGMA user_version=999")
    env.ovw.execute("UPDATE essential_devices SET absent_after_s=NULL, version=version+1")
    env.ovw.commit()
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["open"]


# ---- R1-9: repeat passes are cheap --------------------------------------------------------------
def test_an_announced_absence_never_rescans_the_history(env, monkeypatch):
    two_hours(env)
    env.sweep(now_after(2))
    env.decide(env.rows()[0], "acknowledged")
    env.sweep(now_after(2) + 5)  # closes it as reviewed
    calls: list[int] = []
    real = ea._eligible_hours
    monkeypatch.setattr(ea, "_eligible_hours", lambda *a: calls.append(1) or real(*a))
    env.sweep(now_after(2) + 10)
    assert calls == [] and len(env.rows()) == 1


def writes(env, now) -> list[str]:
    seen: list[str] = []
    env.inv.set_trace_callback(seen.append)
    env.sweep(now)
    env.inv.set_trace_callback(None)
    return [s for s in seen if s.lstrip().upper().startswith(("BEGIN", "INSERT", "UPDATE"))]


def test_a_repeated_unjudged_report_takes_no_write_lock(env):
    env.device("d1", measured=False)
    env.mark("d1", 3600)
    assert writes(env, now_after(1))  # the first report is written
    assert env.inv.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert writes(env, now_after(1) + 5) == []


def test_a_repeated_cap_report_takes_no_write_lock(env, monkeypatch):
    monkeypatch.setattr(ea, "MAX_PER_DAY", 1)
    for i in range(2):
        env.device(f"d{i}")
        env.mark(f"d{i}", 3600)
    env.cover(1, 2)
    assert writes(env, now_after(2))
    assert writes(env, now_after(2) + 5) == []


# ---- R1-10: a committed unmark never opens ------------------------------------------------------
def test_an_unmark_committed_between_plan_and_apply_opens_nothing(env, monkeypatch):
    two_hours(env)
    real = ea._plan

    def plan_then_unmark(inv, ov, now):
        plan = real(inv, ov, now)
        env.ovw.execute("UPDATE essential_devices SET absent_after_s=NULL, version=version+1")
        env.ovw.commit()
        return plan

    monkeypatch.setattr(ea, "_plan", plan_then_unmark)
    assert env.sweep(now_after(2)) == 0 and env.rows() == []


# ---- R2-5: the flood-window and midnight-cap boundaries are pinned -------------------------------
def three_hours(env) -> None:
    env.device("d1")
    env.mark("d1", 2 * 3600)
    env.cover(1, 3)


def test_lost_dns_could_have_been_stamped_at_the_inclusive_endpoint(env):
    three_hours(env)
    env.batch(H + HOUR + 60, H + 2 * HOUR, {"dns_dropped": 1})  # hours 1 and 2
    assert env.sweep(now_after(3)) == 0  # only hour 3 is clean


def test_a_batch_starting_exactly_at_an_hour_end_does_not_blind_that_hour(env):
    three_hours(env)
    env.batch(H + 3 * HOUR, H + 3 * HOUR + 600, {"dns_dropped": 1})  # hour 3 only
    assert env.sweep(now_after(3)) == 1  # hours 1 and 2 are clean


def test_an_incident_detected_at_midnight_counts_toward_the_daily_cap(env, monkeypatch):
    monkeypatch.setattr(ea, "MAX_PER_DAY", 1)
    two_hours(env)
    now = now_after(2)
    midnight = int(now) // 86400 * 86400
    env.inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)"
        " VALUES ('old','c1','other','old','essential_absence','resolved',?,?,?,NULL,0,0,'{}')",
        (H - HOUR, H - HOUR, iso_utc(midnight)),
    )
    assert env.sweep(now) == 0
