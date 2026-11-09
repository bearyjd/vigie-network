"""pilot-report: evidence completeness, retention edges and partial wording."""

from __future__ import annotations

import json

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from incident_helpers import incident, seed_collector
from test_pilot_report import (  # noqa: F401
    DAY,
    HOUR0,
    _profile,
    cover,
    decide,
    delivery,
    report,
    report_since,
    seeded,
    set_detected,
)

from vigie_api import cli, pilot_report, pilot_report_cli
from vigie_ingest.db import iso_utc


def test_incident_without_open_delivery_makes_unwanted_and_deliveries_unknown(  # noqa: F811
    env, capsys, monkeypatch
):
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    incident(env, "has", detector="a", episode=HOUR0 - 3600)
    incident(env, "lost", detector="b", episode=HOUR0 - 3600)
    for iid in ("has", "lost"):
        set_detected(env, iid, -3600)
    delivery(env, 1, "sent", NOW - 3600, "has")
    decide(env, "has", "acknowledged", 1)
    r = report(env, capsys, monkeypatch)
    u = r["unwanted_notifications"]
    assert u["status"] == "unknown" and u["incidents_without_open_delivery"] == 1
    assert "within_target" not in u
    assert r["deliveries"]["status"] == "unknown"
    assert "no open delivery row" in r["deliveries"]["reason"]


def test_incident_with_a_suppressed_open_row_is_accounted_for(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    incident(env, "q", episode=HOUR0 - 3600)
    set_detected(env, "q", -3600)
    delivery(env, 1, "suppressed", NOW - 3600, "q")
    delivery(env, 2, "sent", NOW - 3000, "other")
    decide(env, "other", "acknowledged", 1)
    u = report(env, capsys, monkeypatch)["unwanted_notifications"]
    assert u["incidents_without_open_delivery"] == 0 and u["status"] == "ok"


def test_zero_sent_notifications_is_a_vacuous_verdict(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    u = report(env, capsys, monkeypatch)["unwanted_notifications"]
    assert u["status"] == "unknown" and "within_target" not in u
    assert u["reason"] == "no notifications sent: verdict vacuous"
    assert u["notifications_sent"] == 0


def test_decisions_unknown_beyond_incident_retention(seeded, capsys, monkeypatch):
    r = report_since(seeded, capsys, monkeypatch, "120d")
    assert r["decisions"]["status"] == "unknown"
    assert r["decisions"]["reason"] == "window exceeds incident retention"


def test_decisions_after_the_window_end_are_not_counted(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    decide(env, "future", "expected", 1)
    env.ov.execute("UPDATE incident_decisions SET decided_at=?", (iso_utc(NOW + 3600),))
    assert report(env, capsys, monkeypatch)["decisions"]["status"] == "unknown"


def test_ingest_without_engine_run_is_unknown(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600, engine=False)  # coverage proves ingest, not the engine
    _profile(env, "old", "mature", 1, 1, updated=HOUR0 - 30 * DAY)
    r = report(env, capsys, monkeypatch)
    for name in ("incidents", "unwanted_notifications", "deliveries"):
        assert r[name]["status"] == "unknown", name
    assert r["incidents"]["reason"] == "no incidents: monitoring engine did not run in window"


def test_quiet_window_with_engine_and_coverage_is_ok(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600)
    r = report(env, capsys, monkeypatch)
    assert r["incidents"]["status"] == "ok" and r["incidents"]["total"] == 0


def test_truncated_sections_are_partial_not_ok(seeded, capsys, monkeypatch):
    monkeypatch.setattr(pilot_report, "ROW_LIMIT", 1)
    r = report(seeded, capsys, monkeypatch)
    for name in ("incidents", "deliveries", "coverage"):
        assert r[name]["truncated"] is True and r[name]["status"] == "partial", name


def test_text_says_partial_never_ok_for_degraded_evidence(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600, engine=False)
    cover(env, "c1", HOUR0 - 7200, engine=False)
    _profile(env, "a", "learning", 25, 15, version="nondefault-hash")
    monkeypatch.setattr(pilot_report, "ROW_LIMIT", 1)
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    assert cli.main(["pilot-report", "--data-dir", str(env.root), "--since", "7d"]) == 0
    lines = capsys.readouterr().out.splitlines()
    for name in ("coverage", "profiles"):
        head = next(line for line in lines if line.startswith(f"{name}:"))
        assert "PARTIAL" in head and " ok" not in head, head


def test_coverage_beyond_its_retention_is_partial(seeded, capsys, monkeypatch):
    cover(seeded, "c1", HOUR0 - 3600)
    r = report_since(seeded, capsys, monkeypatch, "100d")
    assert r["coverage"]["status"] == "partial"
    assert "retention" in r["coverage"]["reason"]
    assert report_since(seeded, capsys, monkeypatch, "60d")["coverage"]["status"] == "ok"


def test_delivery_retention_is_stated_and_overridable(seeded, capsys, monkeypatch):
    r = report_since(seeded, capsys, monkeypatch, "15d")
    assert r["assumed_delivery_retention_s"] == 30 * DAY
    assert r["deliveries"]["status"] == "ok"
    short = report_since(seeded, capsys, monkeypatch, "15d", "--delivery-retention", str(10 * DAY))
    assert short["assumed_delivery_retention_s"] == 10 * DAY
    assert short["deliveries"]["reason"] == "window exceeds delivery retention"


@pytest.mark.parametrize("bad", ["0", "-5", "abc", "99999999999", "59"])
def test_delivery_retention_is_validated(bad, env, capsys):  # noqa: F811
    argv = ["pilot-report", "--data-dir", str(env.root), "--since", "7d"]
    with pytest.raises(SystemExit) as stop:
        cli.main([*argv, f"--delivery-retention={bad}"])
    assert stop.value.code == 2


def test_text_states_the_retention_assumption(seeded, capsys, monkeypatch):
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    assert cli.main(["pilot-report", "--data-dir", str(seeded.root), "--since", "7d"]) == 0
    assert f"assumed delivery retention: {30 * DAY}s" in capsys.readouterr().out


@pytest.mark.parametrize("reasons", ["[]", "", "null", " [ ] ", "[\n]", "{}", "0", '""'])
def test_reasons_that_the_engine_treats_as_clear_qualify(reasons, env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600, reasons=reasons)
    assert (
        report(env, capsys, monkeypatch)["coverage"]["per_collector"]["c1"]["qualified_hours"] == 1
    )


@pytest.mark.parametrize("reasons", ['["gap"]', "[1]", "{bad", '"x"', "1"])
def test_reasons_that_the_engine_does_not_treat_as_clear_do_not(reasons, env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600, reasons=reasons)
    assert report(env, capsys, monkeypatch)["coverage"]["status"] == "unknown"


def test_report_json_roundtrips(seeded, capsys, monkeypatch):
    assert json.dumps(report(seeded, capsys, monkeypatch))  # every field is plain JSON
