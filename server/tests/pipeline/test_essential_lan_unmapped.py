"""Essential-absence evidence judges unattributed LAN bytes by the SAME rule as coverage.

ct_lan_unmapped_flows is informational; ct_lan_unmapped_bytes vetoes the hour only when
coverage's threshold (floor AND share of mapped + unmapped bytes) would disqualify it. The
parity cases run one batch through ingest (`_clean`) and coverage (`read_measurements`).
"""

from __future__ import annotations

import json

import pytest
from test_f6b_essential_absence import HOUR, H, accept_batch, env, now_after  # noqa: F401

from vigie_ingest import essential_evidence
from vigie_ingest.db import open_inventory
from vigie_ingest.lan_unmapped import LAN_UNMAPPED_MIN_BYTES, MAX_VALUE
from vigie_ingest.models import Batch
from vigie_ingest.store import apply_batch, provision_collector
from vigie_pipeline.measurements import read_measurements

FLOOR = LAN_UNMAPPED_MIN_BYTES
OTHER_MAC = "02:00:00:00:00:aa"  # traffic of some other device: the marked one stays absent
BATCH_ID = "01927f3e-8a1b-7c2d-9e4f-000000000001"
W0 = 1_700_000_000 // 3600 * 3600


def _flow(up, down, flows=1, mac=OTHER_MAC):
    return {"mac": mac, "dst_ip": "93.184.216.34", "dst_port": 443, "proto": "tcp",
            "bytes_up": up, "bytes_down": down, "flows": flows}  # fmt: skip


def _batch(truncated, conntrack) -> Batch:
    return Batch.model_validate(
        {
            "collector_id": "c1", "key_id": "k1", "boot_id": "b1", "seq": 1,
            "batch_id": BATCH_ID, "window_start": W0, "window_end": W0 + 3540,
            "sent_ts": W0 + 3540, "observation_kind": "observation", "truncated": truncated,
            "dropped_batches": 0, "dns": [], "conntrack": conntrack,
            "health": {"dns_log_quiet": False},
        }
    )  # fmt: skip


def _coverage_clean(root, batch: Batch, cell: str | None = None) -> bool:
    inv = open_inventory(root / "inventory.db")
    provision_collector(inv, "c1", "k1", False)
    inv.close()
    assert apply_batch(root / "inventory.db", root, batch, W0 + 3541, 900) == "applied"
    inv = open_inventory(root / "inventory.db")
    try:
        if cell is not None:  # a stored cell strict validation could never produce
            inv.execute("UPDATE batches SET truncated=?", (cell,))
        return read_measurements(inv, root, "c1", BATCH_ID).reasons == ()
    finally:
        inv.close()


BIG_MAPPED = 95 * FLOOR  # 5 * FLOOR unmapped is then exactly 5% of mapped + unmapped


@pytest.mark.parametrize(
    ("truncated", "conntrack", "clean"),
    [
        ({}, [_flow(600_000, 400_000)], True),  # baseline: both paths clean
        ({"ct_lan_unmapped_bytes": 0, "ct_lan_unmapped_flows": 0}, [_flow(1, 1)], True),
        ({"ct_lan_unmapped_bytes": FLOOR}, [], True),  # exactly the floor, mapped = 0
        ({"ct_lan_unmapped_bytes": FLOOR + 1}, [], False),  # over the floor, mapped = 0: 100%
        ({"ct_lan_unmapped_bytes": FLOOR + 1}, [_flow(BIG_MAPPED, 0)], True),  # ~1% share
        ({"ct_lan_unmapped_bytes": 5 * FLOOR}, [_flow(BIG_MAPPED, 0)], True),  # exactly 5%
        ({"ct_lan_unmapped_bytes": 5 * FLOOR + 1}, [_flow(BIG_MAPPED, 0)], False),  # just over
        # mapped is up + down summed over every MAC, not one direction or one row
        ({"ct_lan_unmapped_bytes": 5 * FLOOR},
         [_flow(BIG_MAPPED // 2, 0), _flow(0, BIG_MAPPED // 2, mac="02:00:00:00:00:bb")], True),
        ({"ct_lan_unmapped_bytes": 5 * FLOOR}, [_flow(0, BIG_MAPPED - 1)], False),
        ({"ct_lan_unmapped_flows": 10**12}, [], True),  # flows are informational at any size
        ({"ct_lan_unmapped_bytes": 2**63 - 1}, [_flow(BIG_MAPPED, 0)], False),  # huge
        # per-MAC totals past the cap: totals uncomputable, fail closed even under the floor
        ({"ct_lan_unmapped_bytes": 1}, [_flow(MAX_VALUE, 0), _flow(1, 0)], False),
        ({"ct_lan_unmapped_bytes": 1}, [_flow(1, 1, flows=MAX_VALUE), _flow(1, 1, flows=1)],
         False),
        ({"ct_lan_unmapped_bytes": 1}, [_flow(MAX_VALUE, MAX_VALUE)], True),  # at the cap: ok
    ],
)  # fmt: skip
def test_ingest_and_coverage_agree_on_lan_unmapped(tmp_path, truncated, conntrack, clean):
    batch = _batch(truncated, conntrack)
    assert essential_evidence._clean(batch) is clean
    assert _coverage_clean(tmp_path, batch) is clean


@pytest.mark.parametrize("bad", ["12", 1.5, -1, True, None])
def test_malformed_lan_bytes_are_dirty_on_both_paths(tmp_path, bad):
    batch = _batch({"ct_lan_unmapped_bytes": 0}, [_flow(600_000, 400_000)])
    forged = batch.model_copy(update={"truncated": {"ct_lan_unmapped_bytes": bad}})
    assert essential_evidence._clean(forged) is False
    assert _coverage_clean(tmp_path, batch, json.dumps({"ct_lan_unmapped_bytes": bad})) is False


@pytest.mark.parametrize(
    "extra",
    [{"truncated_other": 1}, {"ct_errors": 1}, {"ct_dropped_keys": 1}, {"conntrack_lost": 1},
     {"source_flags": 1}, {"dns_dropped": 1}],
)  # fmt: skip
def test_other_loss_keys_stay_dirty_next_to_lan_counters(extra):
    lan = {"ct_lan_unmapped_bytes": 4096, "ct_lan_unmapped_flows": 3}
    assert essential_evidence._clean(_batch(lan, [_flow(600_000, 400_000)])) is True
    assert essential_evidence._clean(_batch(lan | extra, [_flow(600_000, 400_000)])) is False


# ---- end to end: accepted batches -> evidence hours -> the absence sweep ------------------------
def _hour_batch(env, h, lan_bytes, lan_flows, mapped) -> None:
    """One accepted, processed full-hour batch for H + h with clean coverage for that hour."""
    batch = accept_batch(
        env, H + h * HOUR, H + (h + 1) * HOUR,
        truncated={"ct_lan_unmapped_bytes": lan_bytes, "ct_lan_unmapped_flows": lan_flows},
        conntrack=[_flow(mapped // 2, mapped - mapped // 2)],
    )  # fmt: skip
    env.processed(batch)
    env.inv.execute(
        "INSERT OR REPLACE INTO coverage_hourly VALUES (?,?,3600,3600,'[]')",
        ("c1", H + h * HOUR),
    )


def _evidence(env, h):
    return tuple(
        env.inv.execute(
            "SELECT observed IS NULL, qualified_seconds FROM essential_observation_hours"
            " WHERE collector_id='c1' AND hour=?",
            (H + h * HOUR,),
        ).fetchone()
    )


def test_realistic_lan_counters_below_threshold_let_the_absence_fire(env):
    env.device("d1")
    env.mark("d1", 2 * HOUR)
    _hour_batch(env, 1, 180_000, 42, 50_000_000)  # under the floor
    _hour_batch(env, 2, 2_000_000, 900, 100_000_000)  # over the floor, 2% share
    assert _evidence(env, 1) == (0, 3600) and _evidence(env, 2) == (0, 3600)
    assert env.sweep(now_after(2)) == 1


def test_lan_bytes_over_the_threshold_still_veto_the_hour(env):
    env.device("d1")
    env.mark("d1", 2 * HOUR)
    _hour_batch(env, 1, 180_000, 42, 50_000_000)
    _hour_batch(env, 2, 2_000_000, 900, 1_000_000)  # ~67% unattributed
    # a dirty batch also vetoes the hour holding its inclusive end (a lost DNS stamp)
    assert _evidence(env, 2) == (1, 0) and _evidence(env, 3) == (1, 0)
    assert env.sweep(now_after(3)) == 0
    _hour_batch(env, 4, 0, 0, 1_000_000)
    assert env.sweep(now_after(4)) == 1


def test_an_hour_vetoed_before_the_fix_stays_vetoed(env):
    env.device("d1")
    env.mark("d1", 2 * HOUR)
    env.inv.execute(  # what the old rule wrote for a batch carrying LAN counters
        "INSERT INTO essential_observation_hours VALUES ('c1',?,NULL,0)", (H + HOUR,)
    )
    _hour_batch(env, 1, 180_000, 42, 50_000_000)
    _hour_batch(env, 2, 180_000, 42, 50_000_000)
    assert _evidence(env, 1) == (1, 0)  # history is not rewritten
    assert env.sweep(now_after(2)) == 0
    _hour_batch(env, 3, 180_000, 42, 50_000_000)
    assert env.sweep(now_after(3)) == 1
