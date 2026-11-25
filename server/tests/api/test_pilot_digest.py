"""vigie-api pilot-digest: per-UTC-day pilot digest over checkpointed copies of the real schemas."""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3

import pytest
from digest_helpers import DAY, HI, HOSTNAME, IP, LO, MAC, NOW, Live, digest, items, live, run  # noqa: F401

from vigie_api import pilot_digest, pilot_report
from vigie_ingest.db import iso_utc


def test_coverage_counts_qualified_hours_and_reason_codes(live: Live, capsys) -> None:
    live.network("c1")
    live.network("c2", qualified=20)
    live.cover("c2", LO + 20 * 3600, reasons='["cross_hour"]')
    live.cover("c2", LO + 21 * 3600, reasons='["cross_hour","Private Name"]')
    live.cover("c2", LO + 22 * 3600, seconds=100)
    live.network("c3", qualified=0)  # registered but silent
    nets = digest(live, capsys)["networks"]
    assert nets["c1"]["coverage"] == {"qualified_hours": 24, "hours": 24, "complete": True,
                                      "reasons": {}}  # fmt: skip
    assert nets["c2"]["coverage"]["qualified_hours"] == 20
    assert nets["c2"]["coverage"]["reasons"] == {
        "cross_hour": 2, "other": 1, "short_observation": 1, "no_row": 1}  # fmt: skip
    assert nets["c3"]["coverage"]["qualified_hours"] == 0
    assert nets["c2"]["budget"]["verdict"] == "unknown"
    assert "observation incomplete" in nets["c2"]["budget"]["unknown_reasons"]


def test_delivery_states_and_receipt_is_never_assumed(live: Live, capsys) -> None:
    live.network("c1")
    for iid, state in [
        ("i-sent", "sent"),
        ("i-pend", "pending"),
        ("i-send", "sending"),
        ("i-supp", "suppressed"),
        ("i-fail", "failed"),
        ("i-exp", "expired"),
    ]:
        live.incident(iid)
        live.open_row(iid, state)
        live.decide(iid, "acknowledged")
    live.incident("i-none")  # after the watermark, no row
    live.decide("i-none", "acknowledged")
    live.incident("i-old", at=LO + 60)
    live.watermark(LO + 600)
    live.decide("i-old", "acknowledged")
    got = items(digest(live, capsys))
    assert {k: v["delivery"] for k, v in got.items()} == {
        "i-sent": "appended_locally", "i-pend": "pending", "i-send": "pending",
        "i-supp": "suppressed", "i-fail": "not_delivered", "i-exp": "not_delivered",
        "i-none": "no_open_row", "i-old": "not_eligible"}  # fmt: skip
    assert got["i-sent"]["receipt"] == "unverified"
    assert all(v["receipt"] == "not_sent" for k, v in got.items() if k != "i-sent")
    assert got["i-sent"]["unknown_reasons"] == ["receipt unverified"]
    assert got["i-pend"]["unknown_reasons"] == ["delivery pending"]
    assert got["i-none"]["unknown_reasons"] == ["no open delivery row"]
    assert got["i-supp"]["unknown_reasons"] == []
    assert got["i-old"]["unknown_reasons"] == []


def test_unlabeled_counts_missing_and_cleared_decisions(live: Live, capsys) -> None:
    live.network("c1")
    for iid in ("a", "b", "c", "d"):
        live.incident(iid)
        live.open_row(iid, "suppressed")
    live.decide("a", "expected")
    live.decide("b", None)  # cleared by the owner: unreviewed again
    live.decide("c", "snoozed")
    d = digest(live, capsys)
    assert d["counts"]["unlabeled"] == 2
    got = items(d)
    assert got["b"]["unknown_reasons"] == ["unreviewed"]
    assert got["d"]["decision"] is None
    assert {u["id"] for u in d["unknown"] if u["kind"] == "item"} == {"b", "d"}


def _sent(live: Live, iid: str, status: str | None, cid: str = "c1", det: str = "large_upload",
          at: int = LO + 7200) -> None:  # fmt: skip
    live.incident(iid, cid=cid, detector=det, at=at)
    live.open_row(iid, "sent", at=at + 100)
    if status is not None:
        live.decide(iid, status, cid=cid)


def test_budget_exactly_one_unwanted_is_within(live: Live, capsys) -> None:
    live.network("c1")
    _sent(live, "u1", "expected")
    _sent(live, "a1", "acknowledged")
    budget = digest(live, capsys)["networks"]["c1"]["budget"]
    assert budget["opens_sent"] == 2
    assert budget["unwanted"] == 1
    assert budget["verdict"] == "within"
    assert budget["unknown_reasons"] == []


def test_budget_two_unwanted_is_over_even_with_unknowns(live: Live, capsys) -> None:
    live.network("c1", qualified=10)
    _sent(live, "u1", "expected")
    _sent(live, "u2", "expected")
    _sent(live, "x", None)
    budget = digest(live, capsys)["networks"]["c1"]["budget"]
    assert (budget["unwanted"], budget["undecided"]) == (2, 1)
    assert budget["verdict"] == "over"


def test_budget_undecided_open_is_unknown(live: Live, capsys) -> None:
    live.network("c1")
    _sent(live, "x", None)
    budget = digest(live, capsys)["networks"]["c1"]["budget"]
    assert budget["verdict"] == "unknown"
    assert "unreviewed opens" in budget["unknown_reasons"]


def test_budget_counts_by_send_day_and_skips_non_upload(live: Live, capsys) -> None:
    live.network("c1")
    _sent(live, "prev", "expected", at=LO - 50)  # detected yesterday, sent today
    _sent(live, "nd", "expected", det="new_device")
    _sent(live, "late", "expected", at=HI - 10)  # detected today, sent tomorrow
    d = digest(live, capsys)
    budget = d["networks"]["c1"]["budget"]
    assert (budget["opens_sent"], budget["unwanted"], budget["opens_not_budgeted"]) == (1, 1, 1)
    got = items(d)
    assert got["prev"]["counts_toward_budget"] is True
    assert got["late"]["counts_toward_budget"] is False
    assert got["nd"]["budgeted_detector"] is False


def test_budget_matches_pilot_report_unwanted_total(live: Live, capsys) -> None:
    live.network("c1")
    live.network("c2")
    _sent(live, "u1", "expected")
    _sent(live, "u2", "expected", cid="c2")
    _sent(live, "a1", "acknowledged")
    _sent(live, "nd", "expected", det="new_device")
    d = digest(live, capsys)
    snap = live.snapshot("copy2")
    report = pilot_report.build_report(snap / "inventory.db", snap / "overrides.db", LO, HI)
    total = sum(n["budget"]["unwanted"] for n in d["networks"].values())
    assert total == report["unwanted_notifications"]["unwanted_total"] == 2


def test_day_not_over_makes_everything_unknown(live: Live, capsys) -> None:
    live.network("c1")
    _sent(live, "u1", "acknowledged")
    d = digest(live, capsys, now=iso_utc(HI + 600))
    assert d["day_complete"] is False
    assert d["networks"]["c1"]["budget"]["verdict"] == "unknown"
    assert any(u["kind"] == "day" for u in d["unknown"])


def test_engine_stopped_mid_day_is_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.inv.execute("UPDATE monitoring_profiles SET updated_hour=?", (LO + 6 * 3600,))
    budget = digest(live, capsys)["networks"]["c1"]["budget"]
    assert budget["verdict"] == "unknown"
    assert any(r.startswith("no device analysed since") for r in budget["unknown_reasons"])


def test_day_beyond_delivery_retention_is_unknown(live: Live, capsys) -> None:
    live.network("c1")
    _sent(live, "u1", "acknowledged")
    d = digest(live, capsys, now=iso_utc(HI + 40 * 86400))
    assert d["networks"]["c1"]["budget"]["verdict"] == "unknown"
    assert "beyond delivery retention" in d["networks"]["c1"]["budget"]["unknown_reasons"]


def test_truncated_items_make_verdict_unknown(live: Live, capsys, monkeypatch) -> None:
    monkeypatch.setattr(pilot_digest, "MAX_ITEMS", 1)
    live.network("c1")
    _sent(live, "a1", "acknowledged")
    _sent(live, "a2", "acknowledged")
    d = digest(live, capsys)
    assert d["truncated"] is True
    assert d["networks"]["c1"]["budget"]["verdict"] == "unknown"


def test_output_is_deterministic_and_private(live: Live, capsys) -> None:
    live.network("c1")
    _sent(live, "u1", "expected")
    live.incident("p1")
    live.open_row("p1", "pending")
    snap = live.snapshot()
    outs = [run(snap, capsys, *a)[1] for a in
            ([], [], ["--format", "json"], ["--labels-template", "json"],
             ["--labels-template", "csv"])]  # fmt: skip
    assert outs[0] == outs[1]
    assert "budget" in outs[0] and "receipt unverified" in outs[0]
    for out in outs:
        for secret in (MAC, HOSTNAME, IP, "err "):
            assert secret not in out


def test_labels_template_never_fills_owner_labels(live: Live, capsys) -> None:
    live.network("c1")
    _sent(live, "u1", "expected")
    _sent(live, "a1", "acknowledged")
    snap = live.snapshot()
    rows = json.loads(run(snap, capsys, "--labels-template", "json")[1])
    assert [r["incident_id"] for r in rows] == ["a1", "u1"]
    assert all(r["owner_label"] is None and r["owner_received"] is None for r in rows)
    assert {r["decision"] for r in rows} == {"expected", "acknowledged"}
    table = list(csv.DictReader(io.StringIO(run(snap, capsys, "--labels-template", "csv")[1])))
    assert [r["owner_label"] for r in table] == ["", ""]


def test_unsafe_identifiers_are_masked(live: Live, capsys) -> None:
    live.network("c1")
    _sent(live, "=HYPERLINK(1)", "acknowledged")
    assert "=HYPERLINK" not in run(live.snapshot(), capsys, "--labels-template", "csv")[1]


@pytest.mark.parametrize("suffix", ["-wal", "-journal"])
def test_refuses_non_empty_sidecar(live: Live, capsys, suffix: str) -> None:
    snap = live.snapshot()
    (snap / f"inventory.db{suffix}").write_bytes(b"x")
    code, out, err = run(snap, capsys)
    assert (code, out) == (2, "")
    assert "checkpoint" in err and str(snap) not in err


def test_refuses_live_wal_database(live: Live, capsys) -> None:
    live.inv.commit()
    code, _, err = run(live.root / "live", capsys)
    assert code == 2 and "checkpoint" in err


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_refuses_linked_database(live: Live, capsys, kind: str) -> None:
    snap = live.snapshot()
    real = live.root / "real.db"
    (snap / "overrides.db").rename(real)
    (os.symlink if kind == "symlink" else os.link)(real, snap / "overrides.db")
    code, _, err = run(snap, capsys)
    assert code == 2 and "symlink or hardlink" in err


def test_run_leaves_the_copy_untouched(live: Live, capsys) -> None:
    live.network("c1")
    snap = live.snapshot()
    os.chmod(snap, 0o500)  # a read-only directory: any sidecar creation would fail
    try:
        before = (snap.stat().st_mtime_ns, {p.name: p.stat().st_mtime_ns for p in snap.iterdir()})
        assert run(snap, capsys)[0] == 0
        assert (
            snap.stat().st_mtime_ns,
            {p.name: p.stat().st_mtime_ns for p in snap.iterdir()},
        ) == before
    finally:
        os.chmod(snap, 0o700)


@pytest.mark.parametrize(
    ("extra", "day", "now"),
    [([], "2026-13-01", NOW), ([], "20261120", NOW), ([], DAY, "yesterday"),
     ([], DAY, iso_utc(LO))],
)  # fmt: skip
def test_bad_arguments_exit_2(live: Live, capsys, extra, day, now) -> None:
    code, out, _ = run(live.snapshot(), capsys, *extra, day=day, now=now)
    assert (code, out) == (2, "")


def test_missing_or_corrupt_database_has_fixed_errors(live: Live, capsys) -> None:
    snap = live.snapshot()
    (snap / "overrides.db").unlink()
    code, _, err = run(snap, capsys)
    assert code == 2 and err == "vigie-api: pilot digest: database file missing\n"
    (snap / "overrides.db").write_bytes(b"not a database" * 100)
    code, _, err = run(snap, capsys)
    assert code == 3 and err == "vigie-api: pilot digest failed: database unreadable\n"


def test_reads_a_wal_mode_copy_in_a_read_only_directory(live: Live, capsys) -> None:
    """A plain mode=ro open of a WAL-mode file needs a -shm beside it; immutable needs nothing."""
    live.network("c1")
    snap = live.snapshot()
    for name in ("inventory.db", "overrides.db"):
        with sqlite3.connect(snap / name) as conn:
            assert conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        conn.close()
    assert sorted(p.name for p in snap.iterdir()) == ["inventory.db", "overrides.db"]
    os.chmod(snap, 0o500)
    try:
        code, _, err = run(snap, capsys)
        assert code == 0, err
        assert sorted(p.name for p in snap.iterdir()) == ["inventory.db", "overrides.db"]
    finally:
        os.chmod(snap, 0o700)
