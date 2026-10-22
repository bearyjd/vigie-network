"""Fix-round 3 tests for the third stitching review (H1, M1, L1, L3, surviving mutants)."""

from __future__ import annotations

import sqlite3

from pipeline_helpers import T0, Data, data  # noqa: F401
from stitch_helpers import (
    Overrides,
    appear,
    candidates,
    device_of,
    kinds,
    run,
    sig,
    suggestions,
)

from vigie_ingest.db import open_inventory
from vigie_pipeline import stitch as stitch_mod
from vigie_pipeline.activity import record_activity
from vigie_pipeline.config import ACTIVITY_MAX_REPORT_LAG_S, PipelineConfig
from vigie_pipeline.schema import apply_pipeline_migrations
from vigie_pipeline.snapshot import EMPTY
from vigie_pipeline.sources import MacActivity
from vigie_pipeline.stitch import stitch

RULE = "r1"
NOW_ABS = 1_800_000_000


def seed(data: Data, victim_end: int = 2880, step: int = 120, group: str = "iot"):
    a = appear(data, 1, 0, victim_end, step=step)
    run(data)
    dev = device_of(data, a)
    ov = Overrides(data.root)
    ov.rule(RULE, dev, sig())
    ov.override(dev, group, version=1)
    return ov, dev, a


def link(data: Data, m: str) -> str:
    return data.q("SELECT link_source FROM observations WHERE mac=?", m)[0][0]


# ---- H1: tail-lead bypass -----------------------------------------------------------------------


def test_tail_lead_attacker_is_vetoed_not_attached(data):
    ov, dev, _ = seed(data)  # victim stamps every 120 s over [0, 2880]
    b = appear(data, 2, 2280, 2890, step=10)  # 610 s dense, 10 s lead past the victim's last stamp
    run(data)
    assert device_of(data, b) != dev and link(data, b) == "self"
    assert [r["state"] for r in candidates(data)] == ["vetoed"]
    assert len(kinds(data, "identity_overlap_veto")) == 1
    ov.close()


def test_victim_is_not_locked_out_after_a_tail_lead_attempt(data):
    ov, dev, _ = seed(data)
    appear(data, 2, 2280, 2890, step=10)
    run(data)
    v = appear(data, 3, 2900, 6000, step=60)  # the victim's next MAC, after it truly left
    run(data)
    assert device_of(data, v) == dev  # nothing was attached to squat on the victim's device
    ov.close()


def _vs_victim_ending_at_1000(data: Data, attacker_start: int, attacker_end: int):
    a = appear(data, 1, 0, 1000, step=60)
    run(data)
    dev = device_of(data, a)
    ov = Overrides(data.root)
    ov.rule(RULE, dev, sig())
    ov.override(dev, "iot", version=1)
    c = appear(data, 2, attacker_start, attacker_end, step=30)
    run(data)
    ov.close()
    return dev, c


def test_small_own_time_lead_below_the_grace_overlap_is_vetoed(data):
    # covered 630 > grace, overlap 560 <= grace, but only 70 s of its own time: a tail lead
    dev, c = _vs_victim_ending_at_1000(data, 400, 1030)
    assert device_of(data, c) != dev and link(data, c) == "self"


def test_same_overlap_with_a_real_lead_still_attaches(data):
    dev, c = _vs_victim_ending_at_1000(data, 400, 1230)  # lead 270 s of its own time
    assert device_of(data, c) == dev and link(data, c) == "rule"


def test_established_peer_is_presumed_present_one_gap_past_its_last_stamp(data):
    ov, dev, _ = seed(data)  # victim present [0, 2880]: established (longer than 2 x grace)
    b = appear(data, 2, 2280, 3200, step=30)  # 320 s past the last stamp, inside last stamp + gap
    run(data)
    assert device_of(data, b) != dev and link(data, b) == "self"
    ov.close()


def test_established_peer_silent_for_a_full_gap_is_gone(data):
    ov, dev, _ = seed(data)
    c = appear(data, 2, 3300, 5000, step=30)  # entirely after last stamp + gap (3180)
    run(data)
    assert link(data, c) == "rule" and device_of(data, c) == dev
    ov.close()


# ---- H1(c): post-attach re-check never detaches -------------------------------------------------


def test_attached_mac_later_found_overlapping_is_flagged_never_detached(data):
    ov, dev, _ = seed(data, victim_end=300, step=60)
    b = appear(data, 2, 1000, 2000, step=30)
    run(data)
    assert device_of(data, b) == dev and link(data, b) == "rule"
    appear(data, 3, 1200, 4000, step=60)  # the real victim's new MAC, concurrent with b
    before = open(data.root / "overrides.db", "rb").read()
    run(data)
    suspects = kinds(data, "rule_attach_suspect")
    assert len(suspects) == 1 and suspects[0]["device_id"] == dev
    assert device_of(data, b) == dev and link(data, b) == "rule"  # trust is not rewritten
    run(data)
    assert len(kinds(data, "rule_attach_suspect")) == 1  # once per pair
    assert len(kinds(data, "mac_detached")) == 0
    assert open(data.root / "overrides.db", "rb").read() == before
    ov.close()


def test_clean_rule_attach_chain_raises_no_suspect(data):
    ov, dev, _ = seed(data, victim_end=700, step=60)
    appear(data, 2, 760, 1800, step=60)
    run(data)
    assert len(kinds(data, "mac_attached")) == 1
    assert kinds(data, "rule_attach_suspect") == []
    ov.close()


# ---- M1: peer-set evasion -----------------------------------------------------------------------


def test_victims_new_mdns_only_mac_is_a_peer_even_without_a_hostname(data):
    ov, dev, _ = seed(data, victim_end=300, step=60)
    v = appear(data, 3, 400, 4000, host=None, step=60)  # opt55/opt60 + mDNS only
    b = appear(data, 2, 1000, 2000, mdns=None, step=30)  # copies only the hostname
    run(data)
    assert device_of(data, b) != dev and link(data, b) == "self"
    assert device_of(data, v) != dev
    ov.close()


def test_unrelated_same_os_device_with_another_name_is_not_a_peer(data):
    ov, dev, _ = seed(data, victim_end=300, step=60)
    appear(data, 3, 400, 4000, host="Someone-Elses-Phone", mdns="Other", step=60)
    b = appear(data, 2, 1000, 2000, step=30)
    run(data)
    assert device_of(data, b) == dev and link(data, b) == "rule"
    ov.close()


# ---- surviving mutants --------------------------------------------------------------------------


def _bare_inventory(tmp_path, macs: list[tuple[str, str, list[tuple[int, int]]]]):
    """macs: (mac, hostname, [(start, end)]) -> an inventory.db with self devices and activity."""
    inv = open_inventory(tmp_path / "inventory.db")
    apply_pipeline_migrations(inv)
    for i, (m, host, ivs) in enumerate(macs):
        fs = f"2026-12-01T{i // 3600 % 24:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z"
        inv.execute(
            "INSERT INTO devices (id, first_seen, last_seen) VALUES (?,?,?)", (f"d-{m}", fs, fs)
        )
        inv.execute(
            "INSERT INTO observations (mac, device_id, is_randomized, dhcp_fingerprint,"
            " vendor_class, hostname, mdns_name, link_source, first_seen, last_seen)"
            " VALUES (?,?,1,'1,2,3','x',?,NULL,'self',?,?)",
            (m, f"d-{m}", host, fs, fs),
        )
        inv.executemany(
            'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
            [(m, s, e) for s, e in ivs],
        )
    inv.commit()
    return inv


def test_silent_macs_older_than_retention_do_not_count_toward_a_flood(tmp_path):
    cfg = PipelineConfig(data_dir=tmp_path)
    old = NOW_ABS - cfg.activity_retention_s - 86400
    silent = [
        (f"ae:00:00:01:00:{i:02x}", "hostX", [(old + i * 1000, old + i * 1000)]) for i in range(66)
    ]
    live = [
        (f"ae:00:00:02:00:{i:02x}", "hostX", [(NOW_ABS - 86400 + i * 2000,) * 2]) for i in range(4)
    ]
    inv = _bare_inventory(tmp_path, silent + live)
    stats = stitch(inv, EMPTY, cfg, NOW_ABS)
    assert stats.flooded == 0 and kinds_of(inv, "signature_flood") == 0
    assert stats.candidates > 0  # 70 eligible MACs share the name, only 4 are live: not a flood


def kinds_of(inv: sqlite3.Connection, kind: str) -> int:
    return inv.execute("SELECT COUNT(*) FROM events WHERE kind=?", (kind,)).fetchone()[0]


def test_candidates_own_identity_state_must_be_ok_for_a_rule_attach(data):
    a = appear(data, 1, 0, 900, step=60)
    b = appear(data, 2, 2000, 3000, step=60)
    run(data)
    dev = device_of(data, a)
    ov = Overrides(data.root)
    ov.rule(RULE, dev, sig())
    ov.override(dev, "iot", version=1)
    data.inv.execute(
        "UPDATE devices SET identity_state='conflict' WHERE id=?", (device_of(data, b),)
    )
    run(data)
    assert link(data, b) == "self"
    assert len(suggestions(data)) == 1  # the earlier fingerprint_match one is kept, for a human
    ov.close()


# ---- L1: activity lower bound is the report lag of EVERY batch ---------------------------------


def _fold(inv, mac_addr: str, stamps: set[int], received: int):
    act = MacActivity(first_ts=min(stamps), last_ts=max(stamps), stamps=set(stamps))
    record_activity(inv, {mac_addr: act}, 300, received, 7 * 86400)
    return sorted(
        r[0] for r in inv.execute("SELECT start FROM mac_activity WHERE mac=?", (mac_addr,))
    )


def test_stamps_older_than_the_report_lag_are_ignored_for_new_and_known_macs_alike(data):
    apply_pipeline_migrations(data.inv)
    rec, lag = T0, ACTIVITY_MAX_REPORT_LAG_S
    assert lag == 3600
    m = "ae:00:00:00:09:09"
    assert _fold(data.inv, m, {rec - lag - 1}, rec) == []  # first sighting: too old
    assert _fold(data.inv, m, {rec - lag}, rec) == [rec - lag]  # exactly the lag: kept
    # the MAC is known now, but a later batch cannot back-fill further than its own lag either
    assert _fold(data.inv, m, {rec - 3 * lag}, rec) == [rec - lag]
    assert _fold(data.inv, m, {rec - 3 * lag}, rec + 2 * lag) == [rec - lag]
    assert _fold(data.inv, m, {rec + lag}, rec + 2 * lag) == [rec - lag, rec + lag]


# ---- L3: flood event cap ------------------------------------------------------------------------


def test_signature_flood_events_are_capped_per_pass_with_one_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_SIGNATURE_BUCKET", 2)
    monkeypatch.setattr(stitch_mod, "MAX_FLOOD_EVENTS_PER_PASS", 2)
    cfg = PipelineConfig(data_dir=tmp_path)
    macs = [
        (f"ae:00:00:{g:02x}:00:{i:02x}", f"host{g}", [(NOW_ABS - 3600 + i * 500,) * 2])
        for g in range(4) for i in range(4)
    ]  # fmt: skip
    inv = _bare_inventory(tmp_path, macs)
    stitch(inv, EMPTY, cfg, NOW_ABS)
    assert kinds_of(inv, "signature_flood") == 2
    assert kinds_of(inv, "signature_flood_summary") == 1
    stitch(inv, EMPTY, cfg, NOW_ABS)  # the rest follow on the next pass; summary is once per day
    assert kinds_of(inv, "signature_flood") == 4
    assert kinds_of(inv, "signature_flood_summary") == 1
