"""Every source that names a retired device (overrides.db side or inventory side) keeps its MAC
rows out of the prune, alone; the unprotected sibling still goes."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, STAMP, migrated_overrides, prune, retire, rows, sql

from vigie_pipeline.monitoring_identity import lineage
from vigie_pipeline.overrides import open_overrides_ro


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


# ---- overrides.db side: ? = the retired device id, ? = a timestamp ------------------------

_LINK = "INSERT INTO identity_links (from_device, into_device, merge_id, created_at, created_by)"
_MERGE = (
    "INSERT INTO identity_merges (id, ts, from_device, into_device, prior_overrides, decided_by,"
    " undone_at)"
)
_CAND = (
    "INSERT INTO candidate_decisions (candidate_id, device_a, device_b, action, decided_by,"
    " decided_at, id)"
)
OVERRIDES_SOURCES = {
    "incident_decisions": (
        "INSERT INTO incident_decisions (incident_id, collector_id, device_id, lineage, detector,"
        " episode_start, status, snooze_until, version, decided_by, decided_at, id)"
        " VALUES ('i1', 'rtr-1', ?, 'lin', 'det', 1, 'acknowledged', NULL, 1, 'u', ?, 'd1')"
    ),
    "incident_decision_cleared": (
        "INSERT INTO incident_decisions (incident_id, collector_id, device_id, lineage, detector,"
        " episode_start, status, snooze_until, version, decided_by, decided_at, id)"
        " VALUES ('i1', 'rtr-1', ?, 'lin', 'det', 1, NULL, NULL, 2, 'u', ?, 'd1')"
    ),
    "merge_from": f"{_MERGE} VALUES ('m1', ?2, ?1, 'other', '{{}}', 'u', NULL)",
    "merge_into": f"{_MERGE} VALUES ('m1', ?2, 'other', ?1, '{{}}', 'u', NULL)",
    "merge_from_undone": f"{_MERGE} VALUES ('m1', ?2, ?1, 'other', '{{}}', 'u', ?2)",
    "merge_into_undone": f"{_MERGE} VALUES ('m1', ?2, 'other', ?1, '{{}}', 'u', ?2)",
    "candidate_a": f"{_CAND} VALUES ('c1', ?1, 'other', 'clear_veto', 'u', ?2, 'd1')",
    "candidate_b": f"{_CAND} VALUES ('c1', 'other', ?1, 'clear_veto', 'u', ?2, 'd1')",
    "link_from_revoked": (
        "INSERT INTO identity_links (from_device, into_device, merge_id, created_at, created_by,"
        " revoked_at) VALUES (?1, 'other', 'm1', ?2, 'u', ?2)"
    ),
    "link_into_revoked": (
        "INSERT INTO identity_links (from_device, into_device, merge_id, created_at, created_by,"
        " revoked_at) VALUES ('other', ?1, 'm1', ?2, 'u', ?2)"
    ),
    "expired_rule": (
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by, expires_at,"
        " revoked_at) VALUES ('r1', ?1, 'sig', ?2, 'u', ?2, ?2)"
    ),
    "cleared_essential_mark": (
        "INSERT INTO essential_devices (device_id, updated_at, updated_by, version)"
        " VALUES (?1, ?2, 'u', 1)"
    ),
}


@pytest.mark.parametrize("source", OVERRIDES_SOURCES)
def test_each_overrides_source_alone_keeps_the_row(data, source):
    macs = retire(data, count=2)
    protected, free = sorted(macs)
    sql(migrated_overrides(data.root), OVERRIDES_SOURCES[source], macs[protected], STAMP)
    assert prune(data) == 1
    kept = [r["mac"] for r in data.q("SELECT mac FROM observations")]
    assert kept == [protected]
    assert free not in kept


# ---- inventory side: {dev} = the retired device id, {mac} = its MAC --------------------------

_PROFILE = (
    "INSERT INTO monitoring_profiles (collector_id, device_id, lineage, config_version,"
    " training_since, state, baseline_id, updated_hour, sample_hours, distinct_days)"
    " VALUES ('rtr-1', '{dev}', 'l', 'v', 0, 'learning', NULL, 0, 0, 0)"
)
_INCIDENT = (
    "INSERT INTO monitoring_incidents (id, collector_id, device_id, lineage, detector, state,"
    " episode_start, last_hour, detected_at, baseline_id, observed_bytes, threshold_bytes,"
    " evidence) VALUES ('inc1', 'rtr-1', '{dev}', 'l', 'det', 'closed', 0, 0, 'x', NULL, 0, 0,"
    " '[]')"
)
_CANDIDATE = (
    "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state, created_at)"
)
_SUGGESTION = (
    "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
    " expires_at) VALUES ('s1', 'merge_identity', '{ids}', '[]', 'rc', 'b', 'x', '1970-01-01')"
)
INVENTORY_SOURCES = {
    "candidate_a_open": f"{_CANDIDATE} VALUES ('c1', '{{dev}}', 'z', 1, 'e', 'open', 'x')",
    "candidate_b_open": f"{_CANDIDATE} VALUES ('c1', 'z', '{{dev}}', 1, 'e', 'open', 'x')",
    "candidate_a_dismissed": f"{_CANDIDATE} VALUES ('c1', '{{dev}}', 'z', 1, 'e', 'gone', 'x')",
    "candidate_b_dismissed": f"{_CANDIDATE} VALUES ('c1', 'z', '{{dev}}', 1, 'e', 'gone', 'x')",
    "suggestion_from": _SUGGESTION.format(ids='["{dev}","z"]', dev="{dev}"),
    "suggestion_into": _SUGGESTION.format(ids='["z","{dev}"]', dev="{dev}"),
    "monitoring_profiles": _PROFILE,
    "monitoring_incidents": _INCIDENT,
    "monitoring_suspicious": (
        "INSERT INTO monitoring_suspicious (collector_id, device_id, lineage, hour)"
        " VALUES ('rtr-1', '{dev}', 'l', 0)"
    ),
    "monitoring_unavailable": (
        "INSERT INTO monitoring_unavailable (collector_id, device_id, reason, retry_at)"
        " VALUES ('rtr-1', '{dev}', 'r', 0)"
    ),
    "measurements_hourly": (
        "INSERT INTO measurements_hourly (collector_id, mac, hour, bytes_up, bytes_down, flows,"
        " dns_queries) VALUES ('rtr-1', '{mac}', 0, 0, 0, 0, 0)"
    ),
    "monitoring_dirty": (
        "INSERT INTO monitoring_dirty (collector_id, mac, queued_at) VALUES ('rtr-1', '{mac}', 0)"
    ),
    "rule_attachments": (
        "INSERT INTO rule_attachments (mac, rule_id, target, views, attached_at)"
        " VALUES ('{mac}', 'r1', 't', '[]', 'x')"
    ),
}


def _seed(data, template: str, mac: str, dev: str) -> None:
    data.inv.execute(template.replace("{dev}", dev).replace("{mac}", mac))


@pytest.mark.parametrize("source", INVENTORY_SOURCES)
def test_each_inventory_source_alone_keeps_the_row(data, source):
    macs = retire(data, count=2)
    protected, free = sorted(macs)
    migrated_overrides(data.root)
    _seed(data, INVENTORY_SOURCES[source], protected, macs[protected])
    assert prune(data) == 1
    kept = [r["mac"] for r in data.q("SELECT mac FROM observations")]
    assert kept == [protected]
    assert free not in kept


def test_a_monitoring_incident_keeps_the_devices_lineage_key(data):
    macs = retire(data)
    ((mac, device),) = macs.items()
    path = migrated_overrides(data.root)
    _seed(data, INVENTORY_SOURCES["monitoring_incidents"], mac, device)

    def key() -> str:
        ov = open_overrides_ro(path)
        try:
            return lineage(data.inv, ov, device).key
        finally:
            ov.close()

    before = key()
    assert prune(data, LATER) == 0
    assert rows(data) == 1
    assert key() == before


def test_every_exclusion_is_a_seek_not_a_scan(data):
    """No exclusion table may be scanned: the prune runs inside the inventory write lock."""
    from vigie_pipeline.prune_exclusions import PRUNE_EXCLUSIONS_SQL

    retire(data)  # a pass creates the pipeline tables
    data.inv.execute("CREATE TEMP TABLE prune_protected (id TEXT PRIMARY KEY)")
    plan = data.inv.execute(
        "EXPLAIN QUERY PLAN SELECT o.mac FROM observations o JOIN devices d ON d.id=o.device_id"  # noqa: S608
        " WHERE d.status='retired' AND d.id NOT IN (SELECT id FROM prune_protected)"
        + PRUNE_EXCLUSIONS_SQL
    ).fetchall()
    scans = {row[3].split()[1] for row in plan if row[3].startswith("SCAN")}
    assert scans <= {"o", "d", "c"}  # the outer walk and the tiny collectors set only
    assert sum("<expr>=?" in row[3] for row in plan) == 2  # both suggestion directions


@pytest.mark.parametrize("table", ["incident_decisions", "identity_merges", "candidate_decisions"])
def test_a_missing_newly_protected_table_prunes_nothing(data, table):
    retire(data)
    sql(migrated_overrides(data.root), f"DROP TABLE {table}")
    assert prune(data) == 0
    assert rows(data) == 1
