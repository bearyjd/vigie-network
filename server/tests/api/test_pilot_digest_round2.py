"""vigie-api pilot-digest: second review round (collisions, boundaries, attribution, docs pins)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from digest_helpers import (  # noqa: F401
    HI,
    HOSTNAME,
    LO,
    NOW,
    Live,
    _sent,
    digest,
    items,
    live,
    run,
)  # fmt: skip

from vigie_api import pilot_digest, pilot_report, ro_snapshot
from vigie_ingest.db import iso_utc

DOC = Path(__file__).resolve().parents[3] / "docs" / "monitoring-pilot-acceptance.md"


def net(d: dict, name: str = "c1") -> dict:
    return d["networks"][name]["budget"]


def test_masked_label_never_collides_with_a_real_collector(live: Live, capsys) -> None:
    live.network("invalid-id-1", qualified=10)
    live.network("+a")
    d = digest(live, capsys)
    assert set(d["networks"]) == {"invalid-id-1", "invalid-id#1"}
    assert d["networks"]["invalid-id-1"]["coverage"]["qualified_hours"] == 10
    assert net(d, "invalid-id-1")["verdict"] == "unknown"
    assert d["networks"]["invalid-id#1"]["coverage"]["qualified_hours"] == 24
    assert pilot_digest.safe_id("invalid-id#1") == pilot_digest.MASKED


def test_masked_buckets_stay_distinct() -> None:
    names = pilot_digest.network_names({"+a", "@b", "-c", "ok"})
    assert names["ok"] == "ok"
    assert sorted(v for k, v in names.items() if k != "ok") == [
        "invalid-id#1", "invalid-id#2", "invalid-id#3"]  # fmt: skip


def test_docs_pin_the_live_lag() -> None:
    text = " ".join(DOC.read_text().split())
    assert f"`LIVE_LAG_S` ({pilot_digest.LIVE_LAG_S} s)" in text
    for reason in ("unrecognised delivery state", "incident row missing", "snoozed"):
        assert reason in text


def test_new_wal_during_read_is_refused(live: Live, capsys, monkeypatch) -> None:
    live.network("c1")
    snap = live.snapshot()
    real = pilot_digest.coverage

    def wal_then_read(*args):
        (snap / "inventory.db-wal").write_bytes(b"x")
        return real(*args)

    monkeypatch.setattr(pilot_digest, "coverage", wal_then_read)
    code, out, err = run(snap, capsys)
    assert (code, out) == (2, "") and "changed while being read" in err


def test_collectors_table_truncation_is_unknown(live: Live, capsys, monkeypatch) -> None:
    monkeypatch.setattr(pilot_digest, "MAX_NETWORKS", 1)
    live.network("c1")
    for n in range(5):
        live.inv.execute("INSERT INTO collectors(id,key_id,revoked) VALUES (?,?,1)", (f"r{n}", n))
    budget = net(digest(live, capsys))
    assert budget["verdict"] == "unknown" and "truncated" in budget["unknown_reasons"]


def test_watermark_one_second_after_start_is_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.watermark(LO + 1)
    budget = net(digest(live, capsys))
    assert budget["verdict"] == "unknown"
    assert "delivery not enabled for the whole day" in budget["unknown_reasons"]


def test_send_at_midnight_belongs_to_the_next_day(live: Live, capsys) -> None:
    live.network("c1")
    for h in range(24):
        live.cover("c1", HI + h * 3600)
    _sent(live, "late", "expected", at=HI - 101)  # recorded sent at 23:59:59 of the day
    _sent(live, "edge", "expected", at=HI - 100)  # recorded sent at 00:00:00 of the next day
    today = net(digest(live, capsys))
    snap = live.root / "copy"
    assert (today["opens_sent"], today["unwanted"]) == (1, 1)
    code, out, _ = run(snap, capsys, "--format", "json", day=iso_utc(HI)[:10])

    tomorrow = net(json.loads(out))
    assert code == 0 and (tomorrow["opens_sent"], tomorrow["unwanted"]) == (1, 1)


def test_missing_incident_row_makes_the_network_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.open_row("ghost", "sent")
    live.decide("ghost", "acknowledged")
    d = digest(live, capsys)
    assert items(d)["ghost"]["unknown_reasons"][0] == "incident row missing"
    assert net(d)["verdict"] == "unknown"


def test_malformed_detection_time_is_masked(live: Live, capsys) -> None:
    live.network("c1")
    live.incident("a1")
    live.inv.execute(
        "UPDATE monitoring_incidents SET detected_at=? WHERE id='a1'",
        (iso_utc(LO + 7200) + " " + HOSTNAME,),
    )
    live.open_row("a1", "suppressed")
    live.decide("a1", "acknowledged")
    assert items(digest(live, capsys))["a1"]["opened_at"] == "invalid-time"
    snap = live.root / "copy"
    assert HOSTNAME not in run(snap, capsys)[1]


@pytest.mark.timeout(15)
def test_fifo_swapped_in_before_open_does_not_block(live: Live, capsys, monkeypatch) -> None:
    snap = live.snapshot()
    real = ro_snapshot.os.open
    swapped = []

    def fifo_first(path, *args, **kwargs):
        if not swapped and str(path).endswith("inventory.db"):
            swapped.append(1)
            os.unlink(path)
            os.mkfifo(path)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(ro_snapshot.os, "open", fifo_first)
    code, _, err = run(snap, capsys)
    assert code == 2 and "changed while being read" in err


def test_open_is_attributed_to_the_decision_network_like_the_report(live: Live, capsys) -> None:
    live.network("c1")
    live.network("c2")
    for iid in ("x1", "x2"):  # incident on c1, decision recorded on c2
        live.incident(iid, cid="c1")
        live.open_row(iid, "sent")
        live.decide(iid, "expected", cid="c2")
    d = digest(live, capsys)
    report = pilot_report.build_report(
        live.snapshot("r") / "inventory.db", live.root / "r" / "overrides.db", LO, HI
    )
    assert (net(d, "c2")["unwanted"], net(d, "c2")["verdict"]) == (2, "over")
    assert net(d, "c1")["unwanted"] == 0
    assert report["unwanted_notifications"]["worst_network_day"] == 2


def test_pending_upload_row_makes_the_network_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.incident("p1")
    live.open_row("p1", "sending")
    live.decide("p1", "acknowledged")
    budget = net(digest(live, capsys))
    assert budget["verdict"] == "unknown"
    assert "incomplete delivery evidence" in budget["unknown_reasons"]
    assert "recorded as sent" in budget["counted_by"]
