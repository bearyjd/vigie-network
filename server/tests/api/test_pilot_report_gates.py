"""pilot-report: evidence completeness, retention edges and partial wording."""

from __future__ import annotations

import json

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from incident_helpers import incident, seed_collector
from test_pilot_report import (  # noqa: F401
    DAY,
    HOUR0,
    TOD_V,
    _env_with_sent,
    _profile,
    cover,
    decide,
    delivery,
    profiles,
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


def test_truncated_scan_never_claims_no_qualified_hours(env, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(pilot_report, "ROW_LIMIT", 2)
    for i in range(1, 4):  # the first rows scanned all carry reasons ...
        cover(env, "c1", HOUR0 - 3600 * (10 - i), reasons='["gap"]')
    cover(env, "c1", HOUR0 - 3600)  # ... a clear qualified hour comes after the limit
    c = report(env, capsys, monkeypatch)["coverage"]
    assert c["status"] == "partial" and c["truncated"] is True
    assert "truncated" in c["reason"]


def test_complete_scan_with_no_clear_hours_is_unknown(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600, reasons='["gap"]')
    assert report(env, capsys, monkeypatch)["coverage"]["status"] == "unknown"


@pytest.mark.parametrize(("since", "status"), [("89d", "ok"), ("90d", "ok"), ("91d", "partial")])
def test_coverage_retention_edge_is_the_exact_prune_cutoff(  # noqa: F811
    since, status, env, capsys, monkeypatch
):
    cover(env, "c1", HOUR0 - 3600)
    assert report_since(env, capsys, monkeypatch, since)["coverage"]["status"] == status


# ---- liveness, watermark, boundaries ----


def _stale_engine(env: Env, age_s: int) -> None:  # noqa: F811
    """Hourly coverage up to the last complete hour; the engine's last pass `age_s` before it."""
    seed_collector(env)
    for h in range(1, 48):
        cover(env, "c1", HOUR0 - 3600 * h, engine=False)
    _profile(env, "e", "mature", 1, 1, updated=HOUR0 - 3600 - age_s)


def test_engine_that_stopped_days_ago_makes_zero_incidents_partial(env, capsys, monkeypatch):  # noqa: F811
    _stale_engine(env, 6 * DAY)
    r = report(env, capsys, monkeypatch)
    for name in ("incidents", "deliveries"):
        assert r[name]["status"] == "partial", name
        assert "no device analysed since" in r[name]["reason"]
    assert r["engine_last_hour"] == iso_utc(HOUR0 - 3600 - 6 * DAY)
    assert r["ingest_last_hour"] == iso_utc(HOUR0 - 3600)


def test_stale_engine_withholds_the_notification_verdict(env, capsys, monkeypatch):  # noqa: F811
    _stale_engine(env, 6 * DAY)
    delivery(env, 1, "sent", NOW - 3600, "n1")
    decide(env, "n1", "acknowledged", 1)
    u = report(env, capsys, monkeypatch)["unwanted_notifications"]
    assert u["status"] == "partial" and "no device analysed since" in u["reason"]
    assert "within_target" not in u


def test_fresh_engine_and_ingest_are_ok(env, capsys, monkeypatch):  # noqa: F811
    _stale_engine(env, 0)
    r = report(env, capsys, monkeypatch)
    assert r["incidents"]["status"] == "ok" and r["deliveries"]["status"] == "ok"


def test_stale_ingest_makes_sections_partial(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3 * DAY)  # coverage stopped 3 days ago, engine is fresh
    r = report(env, capsys, monkeypatch)
    assert r["incidents"]["status"] == "partial"
    assert "ingest last ran" in r["incidents"]["reason"]


@pytest.mark.parametrize(("lag", "status"), [(7200, "ok"), (10800, "partial")])
def test_liveness_boundary_is_two_hours_behind_the_current_hour(
    lag, status, env, capsys, monkeypatch
):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - lag, engine=False)
    _profile(env, "e", "mature", 1, 1, updated=HOUR0 - lag)
    assert report(env, capsys, monkeypatch)["incidents"]["status"] == status


def test_text_shows_liveness_hours(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600)
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    assert cli.main(["pilot-report", "--data-dir", str(env.root), "--since", "7d"]) == 0
    out = capsys.readouterr().out
    assert f"engine_last_hour: {iso_utc(HOUR0 - 3600)}" in out
    assert f"ingest_last_hour: {iso_utc(HOUR0 - 3600)}" in out


def _watermark(env: Env, offset: float) -> None:  # noqa: F811
    env.inv.execute(
        "INSERT OR REPLACE INTO pipeline_meta(key,value) VALUES ('delivery_eligible_since',?)",
        (str(int(NOW + offset)),),
    )


def test_pre_watermark_incident_does_not_force_unknown(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    incident(env, "old", detector="a", episode=HOUR0 - 3600)
    set_detected(env, "old", -3 * DAY)
    _watermark(env, -DAY)  # delivery was enabled after the incident: it never gets a row
    incident(env, "new", detector="b", episode=HOUR0 - 3600)
    set_detected(env, "new", -3600)
    delivery(env, 1, "sent", NOW - 1800, "new")
    decide(env, "new", "acknowledged", 1)
    u = report(env, capsys, monkeypatch)["unwanted_notifications"]
    assert u["status"] == "ok" and u["incidents_without_open_delivery"] == 0
    assert u["incidents_before_delivery_watermark"] == 1
    assert u["delivery_watermark"] == iso_utc(NOW - DAY)


def test_post_watermark_incident_without_row_is_unknown_and_named(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    _watermark(env, -5 * DAY)
    incident(env, "stuck", detector="a", episode=HOUR0 - 3600)
    set_detected(env, "stuck", -3600)
    delivery(env, 1, "sent", NOW - 1800, "other")
    decide(env, "other", "acknowledged", 1)
    r = report(env, capsys, monkeypatch)
    u = r["unwanted_notifications"]
    assert u["status"] == "unknown" and u["incidents_without_open_delivery"] == 1
    assert u["missing_open_examples"] == [
        {"incident_id": "stuck", "day": pilot_report._day(int(NOW - 3600))}
    ]
    assert "stuck" in r["deliveries"]["reason"]


def test_missing_open_examples_are_bounded(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    for i in range(8):
        incident(env, f"m{i}", detector=f"d{i}", episode=HOUR0 - 3600)
        set_detected(env, f"m{i}", -3600)
    u = report(env, capsys, monkeypatch)["unwanted_notifications"]
    assert u["incidents_without_open_delivery"] == 8
    assert len(u["missing_open_examples"]) == 5


def test_tod_profiles_are_not_derivable_status(env, capsys, monkeypatch):  # noqa: F811
    _profile(env, "a", "learning", 25, 15, version=TOD_V)
    p = report(env, capsys, monkeypatch)["profiles"]
    assert p["status"] == "not_derivable"


def test_uncheckable_missing_open_says_so(env, capsys, monkeypatch):  # noqa: F811
    cover(env, "c1", HOUR0 - 3600)
    env.inv.execute("DROP TABLE monitoring_incidents")
    r = report(env, capsys, monkeypatch)
    assert "cannot be checked" in r["deliveries"]["reason"]
    assert "None" not in r["deliveries"]["reason"]


def test_profile_stamped_exactly_at_the_window_edge_is_analysed(env, capsys, monkeypatch):  # noqa: F811
    edge = int(NOW - 7 * DAY) // 3600 * 3600 - 3600
    _profile(env, "edge", "learning", 1, 1, updated=edge)
    p = profiles(env, capsys, monkeypatch)
    assert p["profiles_not_analysed_in_window"] == 0 and "learning" in p["per_state"]


@pytest.mark.parametrize(("expected", "within"), [(1, True), (2, False)])
def test_one_per_network_day_boundary(expected, within, env, capsys, monkeypatch):  # noqa: F811
    decisions = {f"b{i}": "expected" for i in range(expected)}
    u = _env_with_sent(env, decisions, capsys, monkeypatch)
    assert u["status"] == "ok" and u["within_target"] is within


def test_coverage_outside_the_window_is_not_evidence(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 30 * DAY, engine=False)  # long before the 7d window
    _profile(env, "e", "mature", 1, 1)  # engine ran in the window
    r = report(env, capsys, monkeypatch)
    assert r["incidents"]["status"] == "unknown"
    assert "no coverage evidence" in r["incidents"]["reason"]


def test_watermark_split_happens_before_the_row_limit(env, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(pilot_report, "ROW_LIMIT", 2)
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    _watermark(env, -5 * DAY)
    for i in range(3):  # more pre-watermark incidents without rows than the limit ...
        incident(env, f"p{i}", detector=f"p{i}", episode=HOUR0 - 3600)
        set_detected(env, f"p{i}", -6 * DAY)
    incident(env, "eligible", detector="e", episode=HOUR0 - 3600)  # ... hide this one
    set_detected(env, "eligible", -3600)
    delivery(env, 1, "sent", NOW - 1800, "other")
    decide(env, "other", "acknowledged", 1)
    r = report(env, capsys, monkeypatch)
    u = r["unwanted_notifications"]
    assert (
        u["incidents_without_open_delivery"] == 1 and u["incidents_before_delivery_watermark"] == 3
    )
    assert u["status"] == "unknown" and "within_target" not in u
    assert r["deliveries"]["status"] == "unknown"
    assert [e["incident_id"] for e in u["missing_open_examples"]] == ["eligible"]


def test_examples_never_list_pre_watermark_incidents(env, capsys, monkeypatch):  # noqa: F811
    seed_collector(env)
    cover(env, "c1", HOUR0 - 3600)
    _watermark(env, -5 * DAY)
    incident(env, "ancient", detector="a", episode=HOUR0 - 3600)
    set_detected(env, "ancient", -6 * DAY)
    incident(env, "stuck", detector="b", episode=HOUR0 - 3600)
    set_detected(env, "stuck", -3600)
    u = report(env, capsys, monkeypatch)["unwanted_notifications"]
    assert [e["incident_id"] for e in u["missing_open_examples"]] == ["stuck"]


def test_stale_engine_degrades_profiles_too(env, capsys, monkeypatch):  # noqa: F811
    _stale_engine(env, 2 * DAY)
    p = report(env, capsys, monkeypatch)["profiles"]
    assert p["status"] == "partial" and "no device analysed since" in p["reason"]


def test_liveness_is_disclosed_as_a_report_time_check(seeded, capsys, monkeypatch):
    r = report(seeded, capsys, monkeypatch)
    assert "report time" in r["liveness_note"] and "idle" in r["liveness_note"]
    monkeypatch.setattr(pilot_report_cli.time, "time", lambda: NOW)
    assert cli.main(["pilot-report", "--data-dir", str(seeded.root), "--since", "7d"]) == 0
    assert "liveness_note:" in capsys.readouterr().out
