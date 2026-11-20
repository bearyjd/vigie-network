"""Every source that names a retired device (overrides.db side or inventory side) keeps its MAC
rows out of the prune, alone; the unprotected sibling still goes."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import (
    LATER,
    RETENTION,
    RETIRED_AT,
    STAMP,
    migrated_overrides,
    prune,
    retire,
    rows,
    set_frontier,
    sql,
)

from vigie_ingest.db import iso_utc
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
    " expires_at) VALUES ('s1', 'merge_identity', '{ids}', '[]', 'rc', 'b', 'x', '{expires}')"
)
LIVE = "2999-01-01T00:00:00Z"
EXPIRED = "1970-01-01T00:00:00Z"


def _candidate(side: str, state: str) -> str:
    pair = "'{dev}', 'z'" if side == "a" else "'z', '{dev}'"
    stored = "gone" if state == "unknown_state" else state  # a state this build never writes
    return f"{_CANDIDATE} VALUES ('c1', {pair}, 1, 'e', '{stored}', 'x')"


INVENTORY_SOURCES = {
    **{
        f"candidate_{side}_{state}": _candidate(side, state)
        for side in "ab"
        for state in ("open", "suggested", "vetoed", "cleared", "unknown_state")
    },
    "suggestion_from": _SUGGESTION.format(ids='["{dev}","z"]', expires=LIVE),
    "suggestion_into": _SUGGESTION.format(ids='["z","{dev}"]', expires=LIVE),
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
    from vigie_pipeline.prune_exclusions import LIVE_SUGGESTION_PARAMS, PRUNE_EXCLUSIONS_SQL

    retire(data)  # a pass creates the pipeline tables
    data.inv.execute("CREATE TEMP TABLE prune_protected (id TEXT PRIMARY KEY)")
    plan = data.inv.execute(
        "EXPLAIN QUERY PLAN SELECT o.mac FROM observations o JOIN devices d ON d.id=o.device_id"  # noqa: S608
        " WHERE d.status='retired' AND d.id NOT IN (SELECT id FROM prune_protected)"
        + PRUNE_EXCLUSIONS_SQL,
        (STAMP,) * LIVE_SUGGESTION_PARAMS,
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


# ---- decided history stops pinning a retired device ---------------------------------------------


@pytest.mark.parametrize("side", ["a", "b"])
def test_a_dismissed_candidate_with_no_overrides_protection_does_not_pin_the_device(data, side):
    macs = retire(data, count=2)
    pinned, free = sorted(macs)
    migrated_overrides(data.root)
    pair = ("{dev}", "z") if side == "a" else ("z", "{dev}")
    _seed(
        data,
        f"{_CANDIDATE} VALUES ('c1', '{pair[0]}', '{pair[1]}', 1, 'e', 'dismissed', 'x')",
        pinned,
        macs[pinned],
    )
    assert prune(data) == 2
    assert rows(data) == 0
    assert {pinned, free} == set(macs)


def test_a_dismissed_candidate_whose_owner_decision_is_in_overrides_still_keeps_the_row(data):
    macs = retire(data)
    ((mac, device),) = macs.items()
    path = migrated_overrides(data.root)
    sql(path, OVERRIDES_SOURCES["candidate_a"], device, STAMP)  # the owner's clear for the pair
    _seed(
        data,
        f"{_CANDIDATE} VALUES ('c1', '{{dev}}', 'z', 1, 'e', 'dismissed', 'x')",
        mac,
        device,
    )
    assert prune(data) == 0
    assert rows(data) == 1


def test_an_expired_suggestion_does_not_pin_the_device(data):
    macs = retire(data)
    ((mac, device),) = macs.items()
    migrated_overrides(data.root)
    _seed(data, _SUGGESTION.format(ids='["{dev}","z"]', expires=EXPIRED), mac, device)
    assert prune(data) == 1


def test_an_expired_suggestion_whose_merge_was_applied_keeps_the_row_through_the_merge(data):
    macs = retire(data)
    ((mac, device),) = macs.items()
    path = migrated_overrides(data.root)
    sql(path, OVERRIDES_SOURCES["merge_from"], device, STAMP)  # the applied merge is protected
    _seed(data, _SUGGESTION.format(ids='["{dev}","z"]', expires=EXPIRED), mac, device)
    assert prune(data) == 0
    assert rows(data) == 1


@pytest.mark.parametrize("ids", ['["{dev}","z"]', '["z","{dev}"]'], ids=["from", "into"])
def test_a_suggestion_is_live_up_to_and_including_the_trusted_clock(data, ids):
    macs = retire(data)
    ((mac, device),) = macs.items()
    migrated_overrides(data.root)
    _seed(data, _SUGGESTION.format(ids=ids, expires=iso_utc(LATER)), mac, device)
    assert prune(data, LATER) == 0  # expires_at == now: still live
    data.inv.execute("UPDATE suggestions SET expires_at=?", (iso_utc(LATER - 1),))
    assert prune(data, LATER) == 1


def test_a_suggestions_liveness_is_judged_on_the_trusted_clock_not_the_servers(data):
    macs = retire(data)
    ((mac, device),) = macs.items()
    migrated_overrides(data.root)
    corroborated = RETIRED_AT + RETENTION + 100  # what the activity frontier vouches for
    set_frontier(data, corroborated)
    expires = iso_utc(corroborated + 100)  # past for the (stepped) server, future for the truth
    _seed(data, _SUGGESTION.format(ids='["{dev}","z"]', expires=expires), mac, device)
    assert prune(data, LATER) == 0
    assert rows(data) == 1
