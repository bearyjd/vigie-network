"""vigie-api pilot-report: read-only gate report over the real schemas."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from incident_helpers import incident, seed_collector

from vigie_api import cli, pilot_report, pilot_report_cli
from vigie_ingest.db import iso_utc

DAY = 86400
HOUR0 = int(NOW) // 3600 * 3600
SINCE = "7d"


def run(root: Path, capsys, *extra: str) -> tuple[int, str, str]:
    argv = ["pilot-report", "--data-dir", str(root), "--since", SINCE, "--json", *extra]
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def report(env: Env, capsys, monkeypatch) -> dict:  # noqa: F811
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    code, out, _ = run(env.root, capsys)
    assert code == 0
    return json.loads(out)


def cover(env: Env, collector: str, hour: int, seconds: int = 3600, reasons: str = "[]") -> None:  # noqa: F811
    env.inv.execute(
        "INSERT OR REPLACE INTO coverage_hourly VALUES (?,?,?,?,?)",
        (collector, hour, 3600, seconds, reasons),
    )


def delivery(  # noqa: PLR0913
    env: Env,  # noqa: F811
    n: int,
    state: str,
    created: float,
    incident_id: str,
    kind="open",
    updated: float | None = None,
) -> None:
    done = created if updated is None else updated
    env.inv.execute(
        "INSERT INTO incident_deliveries(delivery_id,incident_id,kind,state,next_attempt_at,"
        "created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
        (f"{n:032d}", incident_id, kind, state, None, int(created), int(done)),
    )


def decide(env: Env, incident_id: str, status: str, n: int) -> None:  # noqa: F811
    until = int(NOW) + 3600 if status == "snoozed" else None
    env.ov.execute(
        "INSERT INTO incident_decisions(incident_id,collector_id,device_id,lineage,detector,"
        "episode_start,status,snooze_until,version,decided_by,decided_at,id) "
        "VALUES (?,?,?,?,?,?,?,?,1,'t',?,?)",
        (incident_id, "c1", "d1", "line", "large_upload", HOUR0, status, until,
         iso_utc(NOW - 3600), f"id{n}"),
    )  # fmt: skip


def set_detected(env: Env, incident_id: str, offset: float) -> None:  # noqa: F811
    """Detection time as the engine records it: last_hour is the hour just completed."""
    env.inv.execute(
        "UPDATE monitoring_incidents SET detected_at=?,last_hour=? WHERE id=?",
        (iso_utc(NOW + offset), int(NOW + offset) // 3600 * 3600 - 3600, incident_id),
    )


@pytest.fixture
def seeded(env: Env) -> Env:  # noqa: F811
    seed_collector(env)
    for i, (det, off) in enumerate(
        [("large_upload", -3600), ("large_upload", -3 * DAY), ("pooled_upload", -3 * DAY)]
    ):
        incident(
            env, f"i{i}", detector=det, episode=HOUR0 - 3600 * (i + 1),
            state="open" if i != 1 else "resolved",
        )  # fmt: skip
        set_detected(env, f"i{i}", off)
    for d in range(15):  # 15 distinct UTC dates, 2 qualified hours each, on collector c1
        for h in (0, 1):
            cover(env, "c1", HOUR0 - d * DAY - h * 3600)
    cover(env, "c2", HOUR0 - 3600, seconds=100)  # not qualified
    cover(env, "c2", HOUR0 - 7200, reasons='["gap"]')  # not qualified
    for i in range(3):
        delivery(env, i, "sent", NOW - 3600 * (i + 1), f"i{i}")
    delivery(env, 9, "failed", NOW - 3 * DAY, "i0", kind="recover")
    decide(env, "i0", "acknowledged", 0)
    decide(env, "i1", "expected", 1)
    decide(env, "i2", "expected", 2)
    return env


def test_counts_per_detector_and_day(seeded, capsys, monkeypatch):
    r = report(seeded, capsys, monkeypatch)
    assert r["incidents"]["status"] == "ok"
    assert r["incidents"]["per_detector"] == {"large_upload": 2, "pooled_upload": 1}
    assert sum(sum(d.values()) for d in r["incidents"]["per_day"].values()) == 3


def test_decision_ratios(seeded, capsys, monkeypatch):
    d = report(seeded, capsys, monkeypatch)["decisions"]
    assert d["counts"] == {"acknowledged": 1, "expected": 2, "snoozed": 0}
    assert d["ratios"]["expected"] == pytest.approx(0.6667, abs=1e-4)


def test_deliveries_per_day_sent_failed(seeded, capsys, monkeypatch):
    days = report(seeded, capsys, monkeypatch)["deliveries"]["per_day"]
    assert sum(v["sent"] for v in days.values()) == 3
    assert sum(v["failed"] for v in days.values()) == 1


def test_qualified_hours_and_distinct_dates_not_hours(seeded, capsys, monkeypatch):
    c = report(seeded, capsys, monkeypatch)["coverage"]["per_collector"]
    assert "c2" not in c  # unqualified rows never count
    assert c["c1"]["qualified_hours"] == 14  # 7 days x2 plus the edge hour, minus the open hour
    assert c["c1"]["distinct_utc_dates"] <= 8  # dates, not hours
    assert c["c1"]["dates_needed"] == 14
    assert c["c1"]["collector_dates_met_upper_bound"] is False


def test_fourteen_dates_met(seeded, capsys, monkeypatch):
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    argv = ["pilot-report", "--data-dir", str(seeded.root), "--since", "20d", "--json"]
    assert cli.main(argv) == 0
    c = json.loads(capsys.readouterr().out)["coverage"]["per_collector"]["c1"]
    assert c["distinct_utc_dates"] >= 14 and c["distinct_utc_dates"] < c["qualified_hours"]
    assert c["collector_dates_met_upper_bound"] is True


def test_unwanted_rate_derived(seeded, capsys, monkeypatch):
    u = report(seeded, capsys, monkeypatch)["unwanted_notifications"]
    assert u["status"] == "ok"
    assert u["unwanted_total"] == 2  # i1 and i2 sent and marked expected
    assert u["worst_network_day"] >= 1 and u["undecided_total"] == 0
    assert u["within_target"] is False
    assert u["target_per_network_day"] == 1


def test_empty_db_is_unknown_never_zero(env, capsys, monkeypatch):  # noqa: F811
    r = report(env, capsys, monkeypatch)
    for name in ("incidents", "decisions", "deliveries", "coverage", "profiles"):
        assert r[name]["status"] == "unknown", name
        assert "total" not in r[name] and "per_collector" not in r[name]
    assert r["unwanted_notifications"]["status"] == "unknown"


def test_missing_files_unknown(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    code, out, _ = run(tmp_path, capsys)
    r = json.loads(out)
    assert code == 0 and r["inventory"].startswith("unknown")
    assert r["incidents"]["status"] == "unknown"
    assert not list(tmp_path.iterdir())  # nothing was created


def test_missing_tables_unknown(tmp_path, capsys, monkeypatch):
    for name in ("inventory.db", "overrides.db"):
        sqlite3.connect(tmp_path / name).close()
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    r = json.loads(run(tmp_path, capsys)[1])
    assert r["coverage"]["status"] == "unknown" and r["decisions"]["status"] == "unknown"
    assert r["unwanted_notifications"]["status"] == "not_derivable"


def test_quiet_window_with_coverage_is_ok_zero(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600)
    r = report(env, capsys, monkeypatch)
    assert r["incidents"] == {
        "status": "ok", "truncated": False, "total": 0, "per_detector": {}, "per_day": {}
    }  # fmt: skip


def _fingerprint(root: Path) -> dict:
    return {
        p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
        for p in sorted(root.iterdir())
        if p.is_file()
    }


def test_report_never_modifies_the_databases(seeded, capsys, monkeypatch):
    for conn in (seeded.inv, seeded.ov):
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = _fingerprint(seeded.root)
    report(seeded, capsys, monkeypatch)
    after = _fingerprint(seeded.root)
    assert {k: after[k] for k in before if k.endswith(".db")} == {
        k: v for k, v in before.items() if k.endswith(".db")
    }


def test_since_hour_zero_incident_is_counted(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    incident(env, "edge", episode=HOUR0)
    set_detected(env, "edge", -7 * DAY + 60)  # detected in the first hour after --since
    assert report(env, capsys, monkeypatch)["incidents"]["total"] == 1


def test_connection_is_read_only(seeded):
    conn = pilot_report.open_ro(seeded.root / "inventory.db")
    assert conn is not None
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("DELETE FROM monitoring_incidents")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("CREATE TABLE x (a)")
    assert conn.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 3
    conn.close()


def test_open_ro_uses_a_ro_uri_not_query_only_alone(seeded):
    conn = pilot_report.open_ro(seeded.root / "inventory.db")
    conn.execute("PRAGMA query_only=OFF")  # even with the pragma undone, the mode refuses
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("DELETE FROM monitoring_incidents")
    conn.close()


@pytest.mark.parametrize("bad", ["", "yesterday", "0d", "-3d", "7w", "2999-01-01", "2000-01-01"])
def test_bad_since_rejected(bad, env, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    argv = ["pilot-report", "--data-dir", str(env.root), f"--since={bad}"]
    assert cli.main(argv) == 2
    assert "since" in capsys.readouterr().err


def test_since_forms_accepted():
    assert pilot_report_cli.parse_since("7d", NOW) == NOW - 7 * DAY
    assert pilot_report_cli.parse_since("36h", NOW) == NOW - 36 * 3600
    assert pilot_report_cli.parse_since("2026-10-01", NOW) < NOW


def test_text_form_and_no_private_output(seeded, capsys, monkeypatch):
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    code = cli.main(["pilot-report", "--data-dir", str(seeded.root), "--since", SINCE])
    out = capsys.readouterr().out
    assert code == 0 and "incidents: ok" in out and "distinct UTC dates" in out
    assert str(seeded.root) not in out


def test_limits_are_bounded(seeded, capsys, monkeypatch):
    monkeypatch.setattr(pilot_report, "ROW_LIMIT", 5)
    r = report(seeded, capsys, monkeypatch)
    assert r["coverage"]["truncated"] is True


# ---- review round: the report must not look healthier than its evidence ----


def _env_with_sent(env: Env, decisions: dict[str, str], capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    for i, (iid, status) in enumerate(decisions.items()):
        incident(env, iid, device="d1", detector=f"det{i}", episode=HOUR0 - 3600)
        delivery(env, i, "sent", NOW - 3600, iid)
        if status:
            decide(env, iid, status, i)
    return report(env, capsys, monkeypatch)["unwanted_notifications"]


def test_unwanted_unknown_when_notifications_have_no_decision(env, capsys, monkeypatch):  # noqa: F811
    u = _env_with_sent(env, {f"u{i}": "" for i in range(30)}, capsys, monkeypatch)
    assert u["status"] == "unknown"
    assert u["undecided_total"] == 30 and u["unwanted_total"] == 0
    assert "within_target" not in u


def test_unwanted_ok_when_all_decided_and_snoozed_not_unwanted(env, capsys, monkeypatch):  # noqa: F811
    u = _env_with_sent(env, {"a": "snoozed", "b": "acknowledged"}, capsys, monkeypatch)
    assert u["status"] == "ok" and u["unwanted_total"] == 0 and u["within_target"] is True


def test_unwanted_over_target_is_false_not_unknown(env, capsys, monkeypatch):  # noqa: F811
    u = _env_with_sent(env, {"a": "expected", "b": "expected"}, capsys, monkeypatch)
    assert u["status"] == "ok" and u["worst_network_day"] == 2 and u["within_target"] is False


def test_unwanted_network_comes_from_the_decision_row(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    delivery(env, 1, "sent", NOW - 3600, "pruned-incident")  # no monitoring_incidents row
    decide(env, "pruned-incident", "expected", 1)
    u = report(env, capsys, monkeypatch)["unwanted_notifications"]
    assert u["status"] == "ok" and u["unwanted_total"] == 1


def test_unwanted_truncation_makes_verdict_unknown(env, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(pilot_report, "ROW_LIMIT", 2)
    decisions = {"a": "expected", "b": "acknowledged", "c": "acknowledged"}
    u = _env_with_sent(env, decisions, capsys, monkeypatch)
    assert u["truncated"] is True and u["status"] == "unknown"
    assert "within_target" not in u


def test_deliveries_bucketed_by_completion_time(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    inside = NOW - 3 * DAY
    delivery(env, 1, "sent", inside - 30 * DAY, "x1", updated=inside)  # enqueued long before
    delivery(
        env, 2, "sent", NOW - 2 * DAY, "x2", updated=NOW + 3 * DAY
    )  # completes after the window
    days = report(env, capsys, monkeypatch)["deliveries"]["per_day"]
    assert sum(v["sent"] for v in days.values()) == 1
    assert set(days) == {pilot_report._day(int(inside))}


def test_deliveries_per_day_keys_are_fixed(seeded, capsys, monkeypatch):
    seeded.inv.execute(
        "UPDATE incident_deliveries SET state='suppressed' WHERE delivery_id LIKE '%1'"
    )
    days = report(seeded, capsys, monkeypatch)["deliveries"]["per_day"]
    assert all(set(v) == {"sent", "failed", "other"} for v in days.values())
    assert sum(v["other"] for v in days.values()) == 1


def test_unwanted_sent_filtered_by_completion_time(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    delivery(env, 1, "sent", NOW - 30 * DAY, "late", updated=NOW - 3600)  # sent inside window
    decide(env, "late", "expected", 1)
    u = report(env, capsys, monkeypatch)["unwanted_notifications"]
    assert u["notifications_sent"] == 1 and u["unwanted_total"] == 1


def test_refuses_to_run_as_another_user(seeded, capsys, monkeypatch):
    seeded.inv.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = sorted(p.name for p in seeded.root.iterdir())
    monkeypatch.setattr(pilot_report.os, "geteuid", lambda: seeded.root.stat().st_uid + 1)
    code, out, err = run(seeded.root, capsys)
    assert code == 2 and out == ""
    assert err.strip() == "vigie-api: pilot report must run as the database owner"
    assert sorted(p.name for p in seeded.root.iterdir()) == before


def test_database_errors_exit_3_without_paths(seeded, capsys, monkeypatch):
    def boom(*_a, **_k):
        raise sqlite3.DatabaseError(f"malformed {seeded.root}")

    monkeypatch.setattr(pilot_report_cli, "build_report", boom)
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    code, _, err = run(seeded.root, capsys)
    assert code == 3 and err.strip() == "vigie-api: pilot report failed: database unreadable"


def test_trailing_newline_since_rejected():
    with pytest.raises(ValueError, match="since"):
        pilot_report_cli.parse_since("7d\n", NOW)


def test_open_hour_is_excluded(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0)  # the currently open hour: not complete, not counted
    assert report(env, capsys, monkeypatch)["coverage"]["status"] == "unknown"


def test_qualified_seconds_boundary(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600, seconds=3419)
    cover(env, "c1", HOUR0 - 7200, seconds=3420)
    c = report(env, capsys, monkeypatch)["coverage"]["per_collector"]["c1"]
    assert c["qualified_hours"] == 1


def test_dates_are_utc_not_local(env, capsys, monkeypatch):  # noqa: F811
    midnight = HOUR0 // DAY * DAY - 2 * DAY
    cover(env, "c1", midnight - 3600)  # 23:00 UTC; 12:00 next day in Auckland
    cover(env, "c1", midnight)  # 00:00 UTC; 13:00 same local day
    monkeypatch.setenv("TZ", "Pacific/Auckland")
    time.tzset()
    try:
        c = report(env, capsys, monkeypatch)["coverage"]["per_collector"]["c1"]
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()
    assert c["distinct_utc_dates"] == 2


def _profile(env: Env, device: str, state: str, hours: int, days: int) -> None:  # noqa: F811
    env.inv.execute(
        "INSERT INTO monitoring_profiles VALUES ('c1',?,'l','v',0,?,NULL,0,?,?)",
        (device, state, hours, days),
    )


def test_profiles_gate_only_counts_learning_pooled(env, capsys, monkeypatch):  # noqa: F811
    _profile(env, "a", "learning", 25, 15)
    _profile(env, "b", "learning", 5, 3)
    _profile(env, "c", "lineage_unavailable", 25, 15)
    states = report(env, capsys, monkeypatch)["profiles"]["per_state"]
    assert states["learning"] == {"devices": 2, "gate_met": 1}
    assert states["lineage_unavailable"]["gate_met"] is None


def test_profiles_gate_not_derivable_for_tod(env, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setenv("VIGIE_MONITORING_BASELINE", "tod")
    _profile(env, "a", "learning", 25, 15)
    states = report(env, capsys, monkeypatch)["profiles"]["per_state"]
    assert states["learning"]["gate_met"] == "not_derivable"


def test_unreadable_baseline_config_is_not_derivable(env, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setenv("VIGIE_MONITORING_BASELINE", "bogus")
    _profile(env, "a", "learning", 25, 15)
    states = report(env, capsys, monkeypatch)["profiles"]["per_state"]
    assert states["learning"]["gate_met"] == "not_derivable"


def test_coverage_note_says_upper_bound(seeded, capsys, monkeypatch):
    note = report(seeded, capsys, monkeypatch)["coverage"]["note"]
    assert "upper bound" in note and "14" in note
