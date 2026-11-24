"""Adversarial characterization of the retired-MAC prune: what an incident decision does and does
not change, a pruned MAC that returns, and a monitoring-protected device beside an identical
unprotected one on a multi-MAC fixture."""

from __future__ import annotations

import json

from pipeline_helpers import data  # noqa: F401
from test_prune_exclusions import INVENTORY_SOURCES, OVERRIDES_SOURCES
from test_prune_guards import (
    LATER,
    STAMP,
    counter,
    migrated_overrides,
    prune,
    retire,
    rows,
    sql,
)

from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once


def macs_left(data) -> list[str]:
    return sorted(r["mac"] for r in data.q("SELECT mac FROM observations"))


def test_incident_decisions_protect_only_the_device_they_name(data):
    """Rows naming unrelated or unknown ids, in any status, change nothing about which other
    retired MACs go; the named device stays only while its row exists."""
    macs = retire(data, count=3)
    named, other_a, other_b = sorted(macs)
    path = migrated_overrides(data.root)
    sql(path, OVERRIDES_SOURCES["incident_decisions"], macs[named], STAMP)
    sql(
        path, OVERRIDES_SOURCES["incident_decision_cleared"].replace("'i1'", "'i2'"), "ghost", STAMP
    )
    assert prune(data) == 2
    assert macs_left(data) == [named]
    assert {other_a, other_b}.isdisjoint(macs_left(data))
    assert counter(data) == "2"
    sql(path, "DELETE FROM incident_decisions")
    assert prune(data) == 1  # its protection was the row alone: nothing latched, nothing left over
    assert rows(data) == 0
    assert counter(data) == "3"


def test_no_incident_decision_rows_prunes_the_same_as_unrelated_ones(data):
    macs = retire(data, count=2)
    path = migrated_overrides(data.root)
    sql(path, OVERRIDES_SOURCES["incident_decisions"], "ghost", STAMP)
    assert prune(data) == 2
    assert macs_left(data) == []
    assert set(macs) and counter(data) == "2"


def test_a_pruned_mac_that_returns_gets_a_new_device_and_the_old_one_stays_retired(data):
    ((mac, old_device),) = retire(data).items()
    migrated_overrides(data.root)
    assert prune(data) == 1
    assert rows(data) == 0
    data.add_batch(LATER, neigh=[mac])
    run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=LATER + 60)
    back = data.q("SELECT device_id, link_source FROM observations WHERE mac=?", mac)
    assert len(back) == 1
    new_device = back[0]["device_id"]
    assert new_device != old_device
    status = {r["id"]: r["status"] for r in data.q("SELECT id, status FROM devices")}
    assert status[old_device] == "retired"
    assert status[new_device] != "retired"
    assert data.q("SELECT 1 FROM observations WHERE device_id=?", old_device) == []
    assert counter(data) == "1"  # the return does not move the counter
    assert prune(data, LATER + 120) == 0  # the new device is live, never pruned
    assert rows(data) == 1
    assert counter(data) == "1"


def test_a_monitoring_incident_protects_a_multi_mac_device_beside_an_identical_unprotected_one(
    data,
):
    macs = retire(data, count=4)
    first, second, third, fourth = sorted(macs)
    # two devices of two MACs each (a device seen under more than one address)
    for extra, owner in ((second, first), (fourth, third)):
        data.inv.execute("UPDATE observations SET device_id=? WHERE mac=?", (macs[owner], extra))
    protected_dev, free_dev = macs[first], macs[third]
    migrated_overrides(data.root)
    evidence = json.dumps([{"hour": 0, "bytes": 1}])
    data.inv.execute(
        INVENTORY_SOURCES["monitoring_incidents"]
        .replace("{dev}", protected_dev)
        .replace("'closed'", "'open'")
        .replace("'[]'", f"'{evidence}'")
    )
    assert prune(data) == 2  # both MACs of the unprotected device, and only those
    assert macs_left(data) == sorted([first, second])
    assert {r["device_id"] for r in data.q("SELECT device_id FROM observations")} == {protected_dev}
    assert free_dev not in {r["device_id"] for r in data.q("SELECT device_id FROM observations")}
    assert counter(data) == "2"
    assert prune(data, LATER + 86400) == 0  # still held on the next pass
    assert rows(data) == 2
