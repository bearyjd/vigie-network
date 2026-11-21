"""A pruned MAC takes its last-known IP with it: a MAC that comes back (even with DNS-only
traffic, which carries no address) must not show its old IP on the new device."""

from __future__ import annotations

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, migrated_overrides, prune, retire, rows

from vigie_pipeline import prune as prune_module
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

OLD_IP = "192.0.2.77"
SHOWN_ON_A_DEVICE = (  # the join vigie_api/effective.py add_last_ips reads
    "SELECT o.device_id, p.ip FROM observations o JOIN mac_last_ip p ON p.mac=o.mac"
)
# Own retention or own meaning: a prune must leave every one of these alone.
KEPT = (
    "mac_first_received",
    "mac_activity",
    "monitoring_assignment_versions",
    "characterization_dirty",
)


def seed_last_ip(data, mac):
    data.inv.execute(
        "INSERT INTO mac_last_ip (mac, ip, observed_at, source) VALUES (?,?,?,'lease')",
        (mac, OLD_IP, 1),
    )


def test_a_dns_only_return_shows_no_old_ip_on_the_new_device(data):
    ((mac, old_device),) = retire(data).items()
    seed_last_ip(data, mac)
    migrated_overrides(data.root)
    assert prune(data) == 1
    assert data.q("SELECT 1 FROM mac_last_ip") == []
    data.add_batch(LATER, dns=[(mac, LATER)])
    run_once(PipelineConfig(data_dir=data.root), now=LATER + 60)
    returned = data.q("SELECT device_id FROM observations WHERE mac=?", mac)
    assert returned and returned[0][0] != old_device  # a new device, not the pruned one
    assert data.q(SHOWN_ON_A_DEVICE) == []


def test_only_the_pruned_macs_ip_goes(data):
    macs = retire(data, count=2)
    kept_mac, pruned_mac = sorted(macs)
    for mac in macs:
        seed_last_ip(data, mac)
    migrated_overrides(data.root)
    data.inv.execute("UPDATE observations SET link_source='human' WHERE mac=?", (kept_mac,))
    assert prune(data) == 1
    assert [r[0] for r in data.q("SELECT mac FROM mac_last_ip")] == [kept_mac]
    assert pruned_mac not in [r[0] for r in data.q("SELECT mac FROM observations")]


def dump(data):
    tables = [
        r[0]
        for r in data.q("SELECT name FROM sqlite_master WHERE type='table'")
        if r[0] not in ("observations", "mac_last_ip", "pipeline_meta")
    ]
    return {t: sorted(tuple(r) for r in data.q(f"SELECT * FROM {t}")) for t in tables}  # noqa: S608


@pytest.mark.parametrize("seeded", [True, False])
def test_every_other_table_is_untouched_by_a_prune(data, seeded):
    ((mac, device),) = retire(data).items()
    if seeded:
        seed_last_ip(data, mac)
        data.inv.execute(
            "INSERT OR REPLACE INTO mac_first_received (mac, received) VALUES (?,5)", (mac,)
        )
        data.inv.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,1,2)', (mac,))
        data.inv.execute(
            "INSERT OR REPLACE INTO monitoring_assignment_versions (mac, version) VALUES (?,3)",
            (mac,),
        )
        data.inv.execute("INSERT INTO characterization_dirty (device_id) VALUES (?)", (device,))
    migrated_overrides(data.root)
    before = dump(data)
    assert prune(data) == 1 and rows(data) == 0
    assert dump(data) == before
    assert set(KEPT) <= set(before)


def test_a_candidate_that_stopped_being_prunable_before_the_lock_keeps_row_and_ip(
    data, monkeypatch
):
    ((mac, _),) = retire(data).items()
    seed_last_ip(data, mac)
    migrated_overrides(data.root)
    select = prune_module._prune_candidates

    def select_then_change(*args):
        found = select(*args)
        assert found == [mac]
        data.inv.execute("UPDATE observations SET link_source='human'")  # after the select
        return found

    monkeypatch.setattr(prune_module, "_prune_candidates", select_then_change)
    assert prune(data) == 0
    assert rows(data) == 1
    assert [r[0] for r in data.q("SELECT mac FROM mac_last_ip")] == [mac]
