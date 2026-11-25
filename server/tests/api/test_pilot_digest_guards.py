"""vigie-api pilot-digest: one killing test per evidence guard, asserting the network verdict."""

from __future__ import annotations

import json
import os

import pytest
from digest_helpers import DAY, HI, LO, NOW, Live, _sent, digest, live, run  # noqa: F401

from vigie_api import pilot_digest, pilot_digest_cli, ro_snapshot
from vigie_ingest.db import iso_utc


def c1(d: dict) -> dict:
    return d["networks"]["c1"]["budget"]


def test_quiet_day_with_complete_evidence_is_within(live: Live, capsys) -> None:
    live.network("c1")
    assert c1(digest(live, capsys))["verdict"] == "within"


def test_no_delivery_watermark_is_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.inv.execute("DELETE FROM pipeline_meta WHERE key='delivery_eligible_since'")
    budget = c1(digest(live, capsys))
    assert budget["verdict"] == "unknown"
    assert "delivery not enabled for the whole day" in budget["unknown_reasons"]


def test_watermark_after_day_start_is_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.watermark(LO + 3600)
    live.incident("e1", at=LO + 60)  # before the watermark: not_eligible, but decided expected
    live.decide("e1", "expected")
    budget = c1(digest(live, capsys))
    assert budget["verdict"] == "unknown"
    assert "delivery not enabled for the whole day" in budget["unknown_reasons"]


def test_copy_newer_than_now_is_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.cover("c1", HI + 3 * 86400)  # the copy holds an hour after --now
    budget = c1(digest(live, capsys))
    assert budget["verdict"] == "unknown"
    assert "copy holds data newer than --now" in budget["unknown_reasons"]


def test_missing_open_row_makes_the_network_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.incident("a1")
    live.decide("a1", "acknowledged")
    budget = c1(digest(live, capsys))
    assert budget["verdict"] == "unknown"
    assert budget["unknown_reasons"] == ["incomplete delivery evidence"]


def test_no_overrides_makes_the_network_unknown(live: Live, capsys) -> None:
    live.network("c1")
    snap = live.snapshot()
    argv = ["--inventory", str(snap / "inventory.db"), "--day", DAY, "--now", NOW]
    assert pilot_digest_cli.main([*argv, "--format", "json"]) == 0
    budget = json.loads(capsys.readouterr().out)["networks"]["c1"]["budget"]
    assert budget["verdict"] == "unknown"
    assert "no overrides database: decisions unavailable" in budget["unknown_reasons"]


def test_incident_and_coverage_retention_make_unknown(live: Live, capsys) -> None:
    live.network("c1")
    budget = c1(digest(live, capsys, now=iso_utc(HI + 100 * 86400)))
    assert budget["verdict"] == "unknown"
    for reason in ("beyond incident retention", "beyond coverage retention"):
        assert reason in budget["unknown_reasons"]


def test_no_engine_evidence_is_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.inv.execute("DELETE FROM monitoring_profiles")
    budget = c1(digest(live, capsys))
    assert budget["verdict"] == "unknown"
    assert "monitoring engine did not run in window" in budget["unknown_reasons"]


def test_item_without_a_network_makes_unknown(live: Live, capsys) -> None:
    live.network("c1")
    live.open_row("ghost", "sent")  # no incident row and no decision: no network
    budget = c1(digest(live, capsys))
    assert budget["verdict"] == "unknown"
    assert "item without a network" in budget["unknown_reasons"]


def test_unrecognised_delivery_state_is_never_appended() -> None:
    inc = ("c1", "dev-1", "lin-1", "large_upload", "open", iso_utc(LO + 60))
    item = pilot_digest.make_item(
        "i1", inc, ("weird", LO + 100), ("acknowledged", "c1"), (LO, HI), LO
    )
    assert (item["delivery"], item["receipt"]) == ("unrecognised", "not_sent")
    assert pilot_digest.budget("c1", [item], [])["verdict"] == "unknown"


def test_coverage_truncation_makes_unknown(live: Live, capsys, monkeypatch) -> None:
    monkeypatch.setattr(pilot_digest, "MAX_NETWORKS", 2)
    live.network("c1")
    live.network("c2")
    for h in range(24):
        live.cover("c3", LO + h * 3600)  # unregistered: only the coverage scan overflows
    d = digest(live, capsys)
    assert d["truncated"] is True
    assert c1(d)["verdict"] == "unknown"


def test_network_truncation_makes_unknown(live: Live, capsys, monkeypatch) -> None:
    monkeypatch.setattr(pilot_digest, "MAX_NETWORKS", 2)
    live.network("c1")
    for cid in ("c2", "c3"):
        live.network(cid, qualified=0)
    d = digest(live, capsys)
    assert d["truncated"] is True
    assert c1(d)["verdict"] == "unknown"


@pytest.mark.parametrize("bad", ["+x", "-x", "@x", "a\tb", "=x"])
def test_unsafe_leading_characters_are_masked(bad: str) -> None:
    assert pilot_digest.safe_id(bad) == pilot_digest.MASKED
    assert pilot_digest.safe_id("c1") == "c1"


def test_masked_networks_stay_separate(live: Live, capsys) -> None:
    for cid in ("+a", "@b"):
        live.network(cid)
        _sent(live, f"u{cid[1]}1", "expected", cid=cid)
        _sent(live, f"u{cid[1]}2", "acknowledged", cid=cid)
    d = digest(live, capsys)
    assert set(d["networks"]) == {"invalid-id#1", "invalid-id#2"}
    assert {n["budget"]["unwanted"] for n in d["networks"].values()} == {1}
    assert all(n["budget"]["verdict"] != "over" for n in d["networks"].values())


def test_revoked_collectors_are_hidden_and_counted(live: Live, capsys) -> None:
    live.network("c1")
    live.inv.execute("INSERT INTO collectors(id,key_id,revoked) VALUES ('old','k',1)")
    live.inv.execute("INSERT INTO collectors(id,key_id,revoked) VALUES ('gone','k2',1)")
    live.cover("gone", LO)  # a revoked collector with data that day stays visible
    d = digest(live, capsys)
    assert "old" not in d["networks"] and "gone" in d["networks"]
    assert d["revoked_hidden"] == 1
    assert "1 revoked collectors hidden" in run(live.snapshot("copy2"), capsys)[1]


def test_change_during_read_is_refused(live: Live, capsys, monkeypatch) -> None:
    live.network("c1")
    snap = live.snapshot()
    real = pilot_digest.coverage

    def touch_then_read(*args):
        os.utime(snap / "inventory.db", ns=(1, 1))
        return real(*args)

    monkeypatch.setattr(pilot_digest, "coverage", touch_then_read)
    code, out, err = run(snap, capsys)
    assert (code, out) == (2, "")
    assert "changed while being read" in err


@pytest.mark.timeout(10)
@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_non_regular_file_is_refused(live: Live, capsys, kind: str) -> None:
    snap = live.snapshot()
    (snap / "inventory.db").unlink()
    (os.mkfifo if kind == "fifo" else os.mkdir)(snap / "inventory.db")
    code, _, err = run(snap, capsys)
    assert code == 2
    assert err == "vigie-api: pilot digest: database is not a regular file\n"


@pytest.mark.parametrize(
    ("sql", "args"),
    [
        ("UPDATE coverage_hourly SET qualified_seconds='lots'", ()),
        ("UPDATE monitoring_incidents SET id=? WHERE id='b1'", (b"\x00blob",)),
    ],
)
def test_malformed_column_types_exit_3(live: Live, capsys, sql: str, args: tuple) -> None:
    live.network("c1")
    live.incident("a1")
    live.incident("b1")
    live.inv.execute(sql, args)
    code, out, err = run(live.snapshot(), capsys)
    assert (code, out) == (3, "")
    assert err == "vigie-api: pilot digest failed: database unreadable\n"


def test_path_swapped_after_open_is_refused(live: Live, capsys, monkeypatch) -> None:
    """The opened file and the path must stay the same inode (lstat vs fstat identity)."""
    live.network("c1")
    snap = live.snapshot()
    other = live.snapshot("other")
    real = pilot_digest.coverage

    def swap_then_read(*args):
        os.replace(other / "inventory.db", snap / "inventory.db")
        return real(*args)

    monkeypatch.setattr(pilot_digest, "coverage", swap_then_read)
    code, _, err = run(snap, capsys)
    assert code == 2 and "changed while being read" in err


@pytest.mark.parametrize("where", ["os_open", "connect"])
def test_path_swapped_while_opening_is_refused(live: Live, capsys, monkeypatch, where) -> None:
    """lstat (checked) vs the held descriptor's fstat, and vs the file SQLite then opened."""
    live.network("c1")
    snap = live.snapshot()
    other = live.snapshot("other")
    target = ro_snapshot.os if where == "os_open" else ro_snapshot.sqlite3
    name = "open" if where == "os_open" else "connect"
    real = getattr(target, name)
    swapped = []

    def swap_first(*args, **kwargs):
        if not swapped:
            swapped.append(1)
            os.replace(other / "inventory.db", snap / "inventory.db")
        return real(*args, **kwargs)

    monkeypatch.setattr(target, name, swap_first)
    code, _, err = run(snap, capsys)
    assert code == 2 and "changed while being read" in err
