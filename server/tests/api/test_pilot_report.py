"""vigie-api pilot-report: read-only gate report over the real schemas."""

from __future__ import annotations

import hashlib
import json
import sqlite3
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


def delivery(env: Env, n: int, state: str, created: float, incident_id: str, kind="open") -> None:  # noqa: F811
    env.inv.execute(
        "INSERT INTO incident_deliveries(delivery_id,incident_id,kind,state,next_attempt_at,"
        "created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
        (f"{n:032d}", incident_id, kind, state, None, int(created), int(created)),
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
    env.inv.execute(
        "UPDATE monitoring_incidents SET detected_at=? WHERE id=?",
        (iso_utc(NOW + offset), incident_id),
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
    assert c["c1"]["qualified_hours"] == 15  # 7 full days x2 plus the hour at the window edge
    assert c["c1"]["distinct_utc_dates"] <= 8  # dates, not hours
    assert c["c1"]["dates_needed"] == 14
    assert c["c1"]["dates_met"] is False


def test_fourteen_dates_met(seeded, capsys, monkeypatch):
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    argv = ["pilot-report", "--data-dir", str(seeded.root), "--since", "20d", "--json"]
    assert cli.main(argv) == 0
    c = json.loads(capsys.readouterr().out)["coverage"]["per_collector"]["c1"]
    assert c["distinct_utc_dates"] >= 14 and c["distinct_utc_dates"] < c["qualified_hours"]
    assert c["dates_met"] is True


def test_unwanted_rate_derived(seeded, capsys, monkeypatch):
    u = report(seeded, capsys, monkeypatch)["unwanted_notifications"]
    assert u["status"] == "ok"
    assert u["unwanted_total"] == 2  # i1 and i2 sent and marked expected
    assert u["worst_network_day"] >= 1
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
        "status": "ok", "total": 0, "per_detector": {}, "per_day": {}
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
