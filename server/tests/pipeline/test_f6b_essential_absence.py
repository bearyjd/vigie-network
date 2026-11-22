"""F6-b: the essential-device absence sweep (flag OFF by default; nothing runs when off).

Judged on hours the collector could SEE (eligible coverage hours, no identity or DNS drops) after
the device's anchor (the newest hour of ACTIVE evidence: a measurements_hourly row; a lease or a
neighbour entry is a snapshot and never counts), both stamped by the same collector clock.
Stateless: no pipeline_meta key.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import uuid

import pytest
from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401
from probe_helpers import build_fixture, digest, dump, run_fixture
from test_probe_freeze import GOLDEN_TABLES, POOLED_VERSION, TOD_VERSION, tables

from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline import essential_absence as ea
from vigie_pipeline import processor
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.processor import monitoring_policy, run_once
from vigie_pipeline.schema import open_pipeline_inventory

H = T0 // HOUR * HOUR  # the anchor hour of a device last seen at H + 600
OPAQUE = re.compile(r"[0-9a-f]{64}")


class Env:
    def __init__(self, root) -> None:
        self.root = root
        self.inv = open_pipeline_inventory(root / "inventory.db", migrate=True)
        self.ovw = open_overrides(root / "overrides.db")
        self.ov = open_overrides_ro(root / "overrides.db")
        self.inv.execute("INSERT INTO collectors(id,key_id) VALUES ('c1','k1')")
        self.n = 0
        self.macs: dict[str, str] = {}
        self.collector: dict[str, str] = {}

    def device(
        self, did, last_seen=H + 600, collector="c1", measured=True, active=0, randomized=0
    ) -> str:
        """`active` = the hour offset of its newest measured activity; `last_seen` is the snapshot
        stamp (a lease or neighbour row), which must never matter."""
        self.n += 1
        mac = f"00:00:5e:00:53:{self.n:02x}"
        self.macs[did] = mac
        self.collector[did] = collector
        self.inv.execute(
            "INSERT INTO devices(id,first_seen,last_seen) VALUES (?,?,?)",
            (did, iso_utc(H - 86400), iso_utc(last_seen)),
        )
        self.inv.execute(
            "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,"
            "last_seen) VALUES (?,?,?,'self',?,?)",
            (mac, did, randomized, iso_utc(H - 86400), iso_utc(last_seen)),
        )
        if measured:
            self.inv.execute(
                "INSERT INTO measurements_hourly VALUES (?,?,?,1,1,1,0)",
                (collector, mac, H + active * HOUR),
            )
        return mac

    def active(self, did, hours) -> None:
        """Real activity (a flow or DNS row) in the hour H + hours: moves the anchor."""
        self.inv.execute(
            "INSERT OR IGNORE INTO measurements_hourly VALUES (?,?,?,1,1,1,0)",
            (self.collector[did], self.macs[did], H + hours * HOUR),
        )

    def batch(self, start, end, truncated=None, collector="c1") -> None:
        """A recorded batch window with its `truncated` map (the collector's drop counters)."""
        self.n += 1
        self.inv.execute(
            "INSERT INTO batches(collector_id,batch_id,received_at,truncated,dropped_batches,"
            "window_start,window_end,observation_kind) VALUES (?,?,?,?,0,?,?,'observation')",
            (collector, f"b{self.n}", iso_utc(end), json.dumps(truncated or {}), start, end),
        )

    def seen(self, did, at) -> None:
        for table in ("devices", "observations"):
            col = "id" if table == "devices" else "device_id"
            self.inv.execute(
                f"UPDATE {table} SET last_seen=? WHERE {col}=?",  # noqa: S608
                (iso_utc(at), did),
            )

    def cover(self, first, count, collector="c1", qualified=3600, reasons="[]") -> None:
        for h in range(first, first + count):
            self.inv.execute(
                "INSERT OR REPLACE INTO coverage_hourly VALUES (?,?,?,?,?)",
                (collector, H + h * HOUR, qualified, qualified, reasons),
            )

    def mark(self, did, secs) -> None:
        row = self.ovw.execute(
            "SELECT version FROM essential_devices WHERE device_id=?", (did,)
        ).fetchone()
        self.ovw.execute(
            "INSERT INTO essential_devices(device_id,absent_after_s,updated_at,updated_by,version)"
            " VALUES (?,?,'2026-11-01T00:00:00Z','owner',?) ON CONFLICT(device_id) DO UPDATE SET"
            " absent_after_s=excluded.absent_after_s, version=excluded.version",
            (did, secs, 1 if row is None else row[0] + 1),
        )
        self.ovw.commit()

    def merge(self, alias, into) -> None:
        self.ovw.execute(
            "INSERT INTO identity_links(from_device,into_device,merge_id,created_at,created_by)"
            " VALUES (?,?,'m','2026-11-01T00:00:00Z','owner')",
            (alias, into),
        )
        self.ovw.commit()

    def sweep(self, now) -> int:
        return ea.sweep_essential_absence(self.inv, self.ov, now)

    def rows(self, state=None):
        sql = "SELECT * FROM monitoring_incidents WHERE detector='essential_absence'"
        if state:
            sql += f" AND state='{state}'"  # noqa: S608
        return self.inv.execute(sql + " ORDER BY seq").fetchall()

    def decide(self, row, status, until=None) -> None:
        self.ovw.execute(
            "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,detector,"
            "episode_start,status,snooze_until,version,decided_by,decided_at,id)"
            " VALUES (?,?,?,?,?,?,?,?,1,'u','2026-11-01T00:00:00Z',?)",
            (row["id"], row["collector_id"], row["device_id"], row["lineage"],
             "essential_absence", row["episode_start"], status, until, str(uuid.uuid4())),
        )  # fmt: skip
        self.ovw.commit()

    def close(self) -> None:
        for c in (self.inv, self.ov, self.ovw):
            c.close()


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def now_after(hours: int) -> int:
    """A clock where hours H+1 .. H+hours are completed."""
    return H + (hours + 1) * HOUR + 30


# ---- the rule ------------------------------------------------------------------------------------
def test_policy_versions_unchanged():
    assert monitoring_policy(PipelineConfig.from_env({})).version == POOLED_VERSION
    tod = PipelineConfig.from_env({"VIGIE_MONITORING_BASELINE": "tod"})
    assert monitoring_policy(tod).version == TOD_VERSION


@pytest.mark.parametrize(
    ("secs", "hours", "fires"),
    [(7200, 1, False), (7200, 2, True), (7200, 3, True),  # exactly N qualified hours fires
     (7201, 2, False), (7201, 3, True),  # one second over: a whole further hour is needed
     (3600, 0, False), (3600, 1, True), (604800, 167, False), (604800, 168, False),  # 168 h: unreachable (R2-2)
     (597600, 166, True)],
)  # fmt: skip
def test_threshold_boundaries(env, secs, hours, fires):
    env.device("d1")
    env.mark("d1", secs)
    env.cover(1, hours)
    assert env.sweep(now_after(hours)) == (1 if fires else 0)
    assert len(env.rows()) == (1 if fires else 0)


def test_incident_shape_is_fixed_small_and_opaque(env):
    mac = env.device("d1")
    env.mark("d1", 7200)
    env.cover(1, 5)
    env.sweep(now_after(5))
    (row,) = env.rows()
    assert OPAQUE.fullmatch(row["id"]) and row["id"] != "d1"
    assert json.loads(row["evidence"]) == {
        "reason_code": "essential_absent", "absent_for_hours": 5, "threshold_hours": 2}  # fmt: skip
    assert (row["state"], row["observed_bytes"], row["threshold_bytes"]) == ("open", 0, 0)
    assert (row["device_id"], row["collector_id"], row["episode_start"]) == ("d1", "c1", H)
    assert mac not in json.dumps(dict(row))


@pytest.mark.parametrize(
    ("qualified", "reasons", "counts"),
    [(3420, "[]", True), (3419, "[]", False), (3600, '["cross_hour"]', False), (0, "[]", False)],
)
def test_only_eligible_hours_count(env, qualified, reasons, counts):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 1, qualified=qualified, reasons=reasons)
    assert env.sweep(now_after(1)) == (1 if counts else 0)


def test_blind_collector_hours_pause_the_clock(env):
    env.device("d1")
    env.mark("d1", 4 * 3600)
    env.cover(1, 2)  # two seen hours, then the collector is blind for two days
    env.cover(51, 1, qualified=0)  # an unqualified hour counts as blind too
    assert env.sweep(now_after(80)) == 0 and env.rows() == []
    env.cover(60, 2)  # it sees again: two more qualified hours make four
    assert env.sweep(now_after(80)) == 1


def test_current_incomplete_hour_never_counts(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 1)
    assert env.sweep(H + HOUR + 10) == 0  # hour H+1 has not completed yet
    assert env.sweep(H + 2 * HOUR) == 1


def test_a_device_with_no_measurement_abstains_with_an_event(env):
    env.device("d1", measured=False)
    env.mark("d1", 3600)
    env.cover(1, 30)
    assert env.sweep(now_after(30)) == 0
    assert env.sweep(now_after(30) + 5) == 0
    kinds = [r[0] for r in env.inv.execute("SELECT kind FROM events")]
    assert kinds == ["essential_unjudged"]  # one per device per UTC day


def test_unmarked_device_nothing_happens(env):
    env.device("d1")
    env.cover(1, 200)
    assert env.sweep(now_after(200)) == 0 and env.rows() == []


# ---- once per episode, re-arm, close rules ------------------------------------------------------
def test_idempotent_and_once_per_episode_even_after_review(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 3)
    assert [env.sweep(now_after(3) + i) for i in range(3)] == [1, 0, 0]
    env.decide(env.rows()[0], "expected")
    env.sweep(now_after(3) + 9)
    assert [r["state"] for r in env.rows()] == ["resolved"]  # reviewed closes it ...
    env.cover(4, 5)
    assert env.sweep(now_after(9)) == 0 and len(env.rows()) == 1  # ... and never re-fires


def test_snoozed_review_keeps_it_open(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.decide(env.rows()[0], "snoozed", until=H + 99 * HOUR)
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["open"]


def test_return_resolves_without_a_second_row_and_rearms(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    assert [r["state"] for r in env.rows()] == ["open"]
    env.active("d1", 3)  # the device is back (anchor moves past the episode)
    env.cover(3, 1)
    env.sweep(now_after(3))
    assert [r["state"] for r in env.rows()] == ["resolved"]
    env.cover(4, 3)  # absent again: the NEW anchor is a new episode and notifies again
    assert env.sweep(now_after(6)) == 1
    states = [(r["state"], r["episode_start"]) for r in env.rows()]
    assert states == [("resolved", H), ("open", H + 3 * HOUR)]


def test_a_return_inside_the_anchor_hour_is_not_a_return(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.active("d1", 0)  # a late backlog row in the SAME hour
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["open"]


def test_unmark_resolves_and_never_fires(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.mark("d1", None)
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["resolved"]
    env.device("d2")
    env.mark("d2", 3600)
    env.mark("d2", None)  # unmarked before any sweep: never fires
    assert env.sweep(now_after(2) + 9) == 0 and len(env.rows()) == 1


def test_remark_in_the_same_absence_does_not_notify_twice(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.mark("d1", None)
    env.sweep(now_after(2) + 5)
    env.mark("d1", 7200)
    assert env.sweep(now_after(2) + 9) == 0 and len(env.rows()) == 1


# ---- canonical resolution --------------------------------------------------------------------
def test_a_mark_on_a_merged_alias_is_judged_on_the_canonical_device(env):
    env.device("canon")
    env.device("alias")
    env.mark("alias", 3600)  # marked before the merge, now stranded on an alias
    env.merge("alias", "canon")
    env.cover(1, 2)
    assert env.sweep(now_after(2)) == 1
    (row,) = env.rows()
    assert row["device_id"] == "canon"


def test_any_member_mac_seen_counts_as_seen(env):
    env.device("canon")
    env.device("alias")
    env.mark("alias", 3 * 3600)
    env.merge("alias", "canon")
    env.cover(1, 3)
    env.active("alias", 2)  # only the alias' MAC is active, in hour H+2
    assert env.sweep(now_after(3)) == 0  # one completed hour after it: below three
    env.cover(4, 3)
    assert env.sweep(now_after(6)) == 1  # H+3 .. H+6 after H+2: counted from the NEWEST member


def test_alias_and_canonical_both_marked_use_the_smallest_threshold_and_one_incident(env):
    env.device("canon")
    env.device("alias")
    env.mark("canon", 5 * 3600)
    env.mark("alias", 2 * 3600)
    env.merge("alias", "canon")
    env.cover(1, 2)
    assert env.sweep(now_after(2)) == 1
    env.cover(3, 4)
    assert env.sweep(now_after(6)) == 0 and len(env.rows()) == 1


def test_a_merge_after_the_notice_resolves_the_alias_incident_and_does_not_renotify(env):
    env.device("canon")
    env.device("alias")
    env.mark("alias", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.merge("alias", "canon")  # the incident's device is no longer canonical
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["resolved"]
    env.sweep(now_after(2) + 9)
    assert len(env.rows()) == 1  # the same absence is not announced a second time


# ---- cap --------------------------------------------------------------------------------------
def test_daily_cap_holds_the_rest_for_the_next_day(env, monkeypatch):
    monkeypatch.setattr(ea, "MAX_PER_DAY", 2)
    for i in range(5):
        env.device(f"d{i}")
        env.mark(f"d{i}", 3600)
    env.cover(1, 60)
    now = now_after(5)
    assert env.sweep(now) == 2 and env.sweep(now + 5) == 0
    caps = [r[0] for r in env.inv.execute("SELECT kind FROM events")]
    assert caps == ["essential_capped"]
    assert env.sweep(now + 86400) == 2  # the next UTC day opens the next two (nothing was lost)
    assert env.sweep(now + 2 * 86400) == 1


# ---- clock steps, gaps, skew ------------------------------------------------------------------
def test_clock_stepped_back_fires_nothing_and_does_not_raise(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 5)
    assert env.sweep(H - 10 * 86400) == 0
    assert env.sweep(H + 2 * HOUR) == 1  # the clock comes back: judged on the data


def test_clock_stepped_forward_with_no_new_data_does_not_fire(env):
    env.device("d1")
    env.mark("d1", 3 * 3600)
    env.cover(1, 1)
    assert env.sweep(now_after(1) + 40 * 86400) == 0  # a month passes with the collector blind


def test_a_pipeline_gap_changes_nothing_and_a_late_pass_opens_exactly_once(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    gap = 5 * 86400  # inside batch retention: older hours' flood status is unreadable (fix 2)
    assert env.sweep(now_after(2) + gap) == 1  # first pass after days of downtime
    assert env.sweep(now_after(2) + gap + 30) == 0


def test_far_future_activity_neither_suppresses_nor_disables_judging(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.active("d1", 24 * 365 * 30)  # one forged far-future window: ignored, not an anchor
    env.cover(1, 2)
    assert env.sweep(now_after(2)) == 1  # M4: it is still judged, on the real anchor
    assert env.rows()[0]["episode_start"] == H


@pytest.mark.parametrize("skew", [-5 * HOUR, 5 * HOUR])
def test_a_constant_collector_offset_never_fires_early(env, skew):
    env.device("d1", active=skew // HOUR)
    env.mark("d1", 3 * 3600)
    first = H + skew // HOUR * HOUR  # coverage is stamped by the same clock
    for h in range(1, 3):
        env.inv.execute(
            "INSERT INTO coverage_hourly VALUES ('c1',?,3600,3600,'[]')", (first + h * HOUR,)
        )
    assert env.sweep(H + 100 * HOUR) == 0  # two qualified hours < 3: early would be a false page
    env.inv.execute(
        "INSERT INTO coverage_hourly VALUES ('c1',?,3600,3600,'[]')", (first + 3 * HOUR,)
    )
    assert env.sweep(H + 100 * HOUR) == 1


# ---- overrides.db problems ----------
def logged(caplog) -> str:
    """Every record as the JSON line operators see: event plus its structured fields."""
    return " ".join(f"{r.getMessage()} {getattr(r, 'fields', {})}" for r in caplog.records)


class Boom:
    def __init__(self, exc):
        self.exc = exc

    def execute(self, *a, **k):
        raise self.exc


def test_ov_missing_is_a_noop(env):
    env.device("d1")
    env.cover(1, 5)
    assert ea.sweep_essential_absence(env.inv, None, now_after(5)) == 0 and env.rows() == []


@pytest.mark.parametrize("exc", [sqlite3.OperationalError("database is locked"),
                                 sqlite3.OperationalError("no such table: essential_devices"),
                                 sqlite3.DatabaseError("file is not a database"),
                                 RuntimeError("secret-path /x/y")])  # fmt: skip
def test_ov_problem_is_logged_by_class_name_and_contained(env, caplog, exc):
    env.device("d1")
    env.cover(1, 5)
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        assert ea.sweep_essential_absence(env.inv, Boom(exc), now_after(5)) == 0
    text = logged(caplog)
    assert "essential_absence_failed" in text and type(exc).__name__ in text
    assert "secret-path" not in text and "locked" not in text and "essential_devices" not in text


def test_older_overrides_schema_without_the_table_is_contained(tmp_path, caplog):
    path = tmp_path / "overrides.db"
    raw = sqlite3.connect(path)
    raw.executescript("CREATE TABLE identity_links (from_device TEXT, into_device TEXT);")
    raw.close()
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    ov = open_overrides_ro(path)
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        assert ea.sweep_essential_absence(inv, ov, T0) == 0
    assert "essential_absence_failed" in logged(caplog)
    assert "OperationalError" in logged(caplog)


def test_an_unreadable_marks_table_never_closes_open_incidents(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.ovw.execute("ALTER TABLE essential_devices RENAME TO essential_devices_x")
    env.ovw.commit()
    env.sweep(now_after(2) + 5)  # marks cannot be read: that is NOT "the owner unmarked it"
    assert [r["state"] for r in env.rows()] == ["open"]


# ---- hostile input -------------------------------------------------------------------------------
def test_marks_outside_the_bounds_or_of_the_wrong_type_are_ignored(env, caplog):
    env.ovw.execute("PRAGMA ignore_check_constraints=ON")
    for i, secs in enumerate([10, 604801, "abc", 7200.5, -1, 0, 7200]):
        env.device(f"d{i}")
        env.ovw.execute("INSERT INTO essential_devices VALUES (?,?,'t','u',1)", (f"d{i}", secs))
    env.ovw.commit()
    env.cover(1, 5)
    assert env.sweep(now_after(5)) == 1
    assert [r["device_id"] for r in env.rows()] == ["d6"]


def test_at_most_32_marks_are_read(env, caplog):
    for i in range(40):
        env.device(f"d{i:02d}")
        env.mark(f"d{i:02d}", 3600)
    env.cover(1, 3)
    env.sweep(now_after(3))
    assert [e for e in env.inv.execute("SELECT summary FROM events") if "too many" in e[0]]
    assert len(env.rows()) == ea.MAX_PER_DAY  # 32 judged, the daily cap bounds the opens
    assert {r["device_id"] for r in env.rows()} <= {f"d{i:02d}" for i in range(32)}


def test_forged_traffic_for_the_marked_mac_suppresses_the_alert_known_gap(env):
    """KNOWN GAP (docs): whoever can forge the marked device's MAC keeps it 'seen'."""
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 3)
    env.active("d1", 3)  # forged traffic
    assert env.sweep(now_after(3)) == 0


# ---- nothing marked, flag wiring ----------
def test_nothing_marked_does_zero_work_and_writes_nothing(env):
    env.device("d1")
    env.cover(1, 100)
    before = env.inv.total_changes
    assert env.sweep(now_after(100)) == 0
    assert env.inv.total_changes == before and not env.inv.in_transaction


def test_reads_are_bounded_constant_number_of_statements(env):
    for i in range(5):
        env.device(f"d{i}")
        env.mark(f"d{i}", 3600)
    env.cover(1, 1)
    seen: list[str] = []
    env.inv.set_trace_callback(seen.append)
    env.sweep(now_after(1))
    env.inv.set_trace_callback(None)
    assert len(seen) < 120


def config_for(root, **kw):
    return PipelineConfig(data_dir=root, **kw)


def test_flag_default_off_and_validated_value_free():
    assert PipelineConfig.from_env({}).essential_absence is False
    for good in ("1", "true", "YES"):
        assert PipelineConfig.from_env({"VIGIE_ESSENTIAL_ABSENCE": good}).essential_absence
    for off in ("", "0", "false", "no", "off"):
        assert PipelineConfig.from_env({"VIGIE_ESSENTIAL_ABSENCE": off}).essential_absence is False
    with pytest.raises(ValueError, match="VIGIE_ESSENTIAL_ABSENCE") as info:
        PipelineConfig.from_env({"VIGIE_ESSENTIAL_ABSENCE": "maybe-secret"})
    assert "maybe-secret" not in str(info.value)


def test_flag_off_never_calls_the_sweep(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the sweep must not run with the flag off")

    monkeypatch.setattr(processor, "sweep_essential_absence", boom)
    build_fixture(tmp_path)
    run_fixture(tmp_path)


def test_flag_off_is_digest_identical_to_main(tmp_path):
    build_fixture(tmp_path)
    run_fixture(tmp_path)
    assert digest(tables(dump(tmp_path))) == GOLDEN_TABLES


def test_flag_on_with_nothing_marked_is_digest_identical_with_no_writes(tmp_path):
    build_fixture(tmp_path)
    run_fixture(tmp_path, VIGIE_ESSENTIAL_ABSENCE="1")
    snap = dump(tmp_path)
    assert digest(tables(snap)) == GOLDEN_TABLES
    assert not [r for r in snap["pipeline_meta"] if "essential" in str(r) or "f6" in str(r)]


def test_flag_on_run_once_opens_and_a_failing_sweep_never_fails_the_pass(env, monkeypatch, caplog):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    cfg = config_for(env.root, essential_absence=True)
    run_once(cfg, now=now_after(2))
    assert len(env.rows()) == 1 and env.rows()[0]["state"] == "open"

    def boom(*a, **k):
        raise RuntimeError("secret")

    monkeypatch.setattr(ea, "_plan", boom)
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        run_once(cfg, now=now_after(2) + 60)  # does not raise
    assert "essential_absence_failed" in logged(caplog) and "RuntimeError" in logged(caplog)
    assert "secret" not in logged(caplog)


def test_sweep_skipped_when_a_shard_could_not_be_read(env, monkeypatch):
    calls = []
    monkeypatch.setattr(processor, "sweep_essential_absence", lambda *a: calls.append(a))
    monkeypatch.setattr(
        processor, "_process_batches", lambda inv, ov, cfg, failures: failures.append(
            processor.ShardReadError("x")) or {"batches": 0, "macs": 0, "new_devices": 0,
                                               "skipped_macs": 0})  # fmt: skip
    with pytest.raises(processor.ShardReadError):
        run_once(config_for(env.root, essential_absence=True), now=T0)
    assert calls == []  # a stale view must not page "absent"
