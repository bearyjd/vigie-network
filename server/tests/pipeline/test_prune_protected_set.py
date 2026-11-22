"""The prune's protected set must not drift from the schemas. Every column that names a device or
a MAC, in BOTH databases, is either read by the prune (PROTECTED_READS / the exclusion SQL / the
prune's own predicate) or listed in a LEFT_ALONE allowlist with the reason it is safe to leave. A
new column fails these tests until somebody classifies it."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides
from vigie_pipeline import prune_exclusions
from vigie_pipeline.overrides import PROTECTED_READS, SUGGESTION_READS, SUPPORTED_USER_VERSION
from vigie_pipeline.prune_exclusions import PRUNE_EXCLUSIONS_SQL
from vigie_pipeline.schema import open_pipeline_inventory

# A column that names a device or MAC directly (device_id, from_device, device_a, device_ids, mac)
# or through another row: a suggestion, incident or candidate id, a rule target, a lineage key.
NAMES_A_DEVICE = re.compile(r"device|mac|suggestion_id|incident_id|candidate_id|target|lineage")

# overrides.db columns the prune does not read from PROTECTED_READS, and why that is safe.
LEFT_ALONE_OVERRIDES = {
    ("audit_log", "target"): "log text: what a decision touched, decides nothing by itself",
    ("candidate_decisions", "candidate_id"): "the same row names both devices, both protected",
    ("identity_merges", "suggestion_id"): (
        "the same row names both devices, both protected; the suggestion is protected through"
        " suggestion_decisions"
    ),
    ("incident_decisions", "incident_id"): "the same row names the device, protected",
    ("incident_decisions", "lineage"): "the same row names the device, protected",
    ("incident_decision_prune", "incident_id"): (
        "tombstone of an incident the API already pruned, with its decision row"
    ),
    ("monitoring_lineage_versions", "device_id"): (
        "a monotonic counter bumped by the identity_links triggers: every id in it is an end of an"
        " identity_links row, which PROTECTED_READS reads"
    ),
}

# inventory.db columns the prune does not exclude on, and why that is safe.
LEFT_ALONE_INVENTORY = {
    ("characterization_dirty", "device_id"): "derived queue, rebuilt from observations each pass",
    ("characterization_evidence", "mac"): "derived evidence with its own 7-day expiry",
    ("characterization_overflow", "mac"): "derived rate-limit marker with its own expiry",
    ("characterization_results", "device_id"): "derived cache, recomputed per device each pass",
    ("events", "device_id"): "history of the device row, which is never deleted",
    ("mac_activity", "mac"): "coverage evidence with its own 7-day retention",
    ("mac_first_received", "mac"): "maturity anchor with its own retention",
    ("monitoring_assignment_versions", "mac"): "a monotonic counter, never read back by id",
    ("monitoring_baselines", "device_id"): "reached only through monitoring_profiles, excluded",
    ("monitoring_quality_work", "after_mac"): "a paging cursor, not a reference to a device",
    ("transient_hours", "device_id"): "promotion bookkeeping, deleted once a device leaves it",
    ("transient_state", "device_id"): "the retirement stamp the prune ages devices from",
    ("incident_deliveries", "incident_id"): (
        "delivery state of an incident whose monitoring_incidents row excludes its device"
    ),
    ("monitoring_baselines", "lineage"): "same row as device_id, reached through the profile",
    ("monitoring_incidents", "lineage"): "same row as device_id, which is excluded",
    ("monitoring_profiles", "lineage"): "same row as device_id, which is excluded",
    ("monitoring_suspicious", "lineage"): "same row as device_id, which is excluded",
    ("rule_attachments", "target"): "same row as mac, which is excluded",
}

# inventory.db columns the prune itself reads or deletes with, by table.
PRUNE_OWN_INVENTORY = {
    ("observations", "mac"): "the rows the prune deletes",
    ("observations", "device_id"): "the device the prune is judged on",
    ("mac_last_ip", "mac"): "deleted together with the pruned MAC",
    ("identity_candidates", "device_a"): "excluded while open or suggested",
    ("identity_candidates", "device_b"): "excluded while open or suggested",
    ("suggestions", "device_ids"): "excluded while unexpired, and once decided (by id)",
    ("rule_attachments", "mac"): "excluded while the attachment exists",
}


def device_columns(conn: sqlite3.Connection) -> set[tuple[str, str]]:
    tables = [
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ]
    return {
        (table, row[1])
        for table in tables
        for row in conn.execute(f"PRAGMA table_info({table})")  # noqa: S608
        if NAMES_A_DEVICE.search(row[1])
    }


def protected_reads() -> set[tuple[str, str]]:
    out = set()
    for statement in (*PROTECTED_READS, *SUGGESTION_READS):
        match = re.fullmatch(r"SELECT (.+) FROM (\w+)", statement)
        assert match, f"PROTECTED_READS entry is not a plain column read: {statement}"
        out |= {(match.group(2), column.strip()) for column in match.group(1).split(",")}
    return out


def exclusion_columns() -> set[tuple[str, str]]:
    columns = {*prune_exclusions._DEVICE_BY_COLLECTOR, *prune_exclusions._MAC_BY_COLLECTOR}
    for table, column in columns:
        assert f"FROM {table} x" in PRUNE_EXCLUSIONS_SQL and f"x.{column}=" in PRUNE_EXCLUSIONS_SQL
    return columns


def test_the_supported_overrides_version_is_a_reviewed_literal():
    assert SUPPORTED_USER_VERSION == len(OVERRIDES_MIGRATIONS), (
        f"overrides.db has {len(OVERRIDES_MIGRATIONS)} migrations but the prune supports"
        f" v{SUPPORTED_USER_VERSION}. Review PROTECTED_READS and LEFT_ALONE_OVERRIDES against the"
        " new migration (does it add a table or column that names a device?), then bump"
        " SUPPORTED_USER_VERSION in overrides.py."
    )


def test_every_overrides_column_that_names_a_device_is_protected_or_left_alone(tmp_path: Path):
    conn = open_overrides(tmp_path / "overrides.db")
    found = device_columns(conn)
    conn.close()
    reads, left = protected_reads(), set(LEFT_ALONE_OVERRIDES)
    unclassified = sorted(found - reads - left)
    assert not unclassified, (
        f"overrides.db columns naming a device or MAC with no protection: {unclassified}. Add the"
        " column to PROTECTED_READS (and PROTECTED_TABLES), or to LEFT_ALONE_OVERRIDES with a"
        " reason."
    )
    assert reads <= found, f"PROTECTED_READS names a column that no longer exists: {reads - found}"
    assert left <= found, f"stale LEFT_ALONE_OVERRIDES entries: {left - found}"
    assert not reads & left, f"both protected and left alone: {reads & left}"


def test_every_inventory_column_that_names_a_device_is_excluded_or_left_alone(tmp_path: Path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", True)
    found = device_columns(conn)
    conn.close()
    covered = exclusion_columns() | set(PRUNE_OWN_INVENTORY)
    left = set(LEFT_ALONE_INVENTORY)
    unclassified = sorted(found - covered - left)
    assert not unclassified, (
        f"inventory.db columns naming a device or MAC with no protection: {unclassified}. Add an"
        " exclusion in prune_exclusions.py or an entry in LEFT_ALONE_INVENTORY with a reason."
    )
    assert covered <= found, f"covered columns that no longer exist: {covered - found}"
    assert left <= found, f"stale LEFT_ALONE_INVENTORY entries: {left - found}"
    assert not covered & left, f"both excluded and left alone: {covered & left}"


def test_the_classification_catches_a_new_device_column(tmp_path: Path):
    conn = open_overrides(tmp_path / "overrides.db")
    conn.execute("CREATE TABLE new_feature (id TEXT, pinned_device TEXT)")
    found = device_columns(conn)
    conn.close()
    assert ("new_feature", "pinned_device") in found - protected_reads() - set(LEFT_ALONE_OVERRIDES)


def test_every_id_indirect_column_name_is_matched():
    for name in ("suggestion_id", "incident_id", "candidate_id", "target", "lineage"):
        assert NAMES_A_DEVICE.search(name), name


def test_the_classification_catches_a_new_id_indirect_column(tmp_path: Path):
    for conn, left in (
        (open_overrides(tmp_path / "overrides.db"), set(LEFT_ALONE_OVERRIDES)),
        (open_pipeline_inventory(tmp_path / "inventory.db", True), set(LEFT_ALONE_INVENTORY)),
    ):
        conn.execute(
            "CREATE TABLE new_feature (suggestion_id TEXT, incident_id TEXT, candidate_id TEXT,"
            " target TEXT, lineage TEXT)"
        )
        found = device_columns(conn)
        conn.close()
        classified = protected_reads() | left | exclusion_columns() | set(PRUNE_OWN_INVENTORY)
        missing = {c for (t, c) in found - classified if t == "new_feature"}
        assert missing == {"suggestion_id", "incident_id", "candidate_id", "target", "lineage"}
