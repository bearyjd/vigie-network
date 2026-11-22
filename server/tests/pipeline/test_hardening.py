from __future__ import annotations

import sqlite3

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401

from vigie_api.schema import open_overrides
from vigie_ingest.db import INVENTORY_MIGRATIONS, connect, open_inventory
from vigie_pipeline import cli
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once
from vigie_pipeline.schema import SchemaVersionError, open_pipeline_inventory
from vigie_pipeline.sources import is_randomized, normalize_mac, opt55_string

NIC = "00:11:22:33:44:55"


# ---- F6: opt55 caps -----------------------------------------------------------------------


def test_opt55_caps_entry_count():
    out = opt55_string(str(list(range(1, 101))))
    assert out == ",".join(str(i) for i in range(1, 65))


def test_opt55_caps_total_length_on_an_entry_boundary():
    out = opt55_string(str([1_000_000_000 + i for i in range(64)]))
    assert out is not None and len(out) <= 256
    assert all(len(part) == 10 for part in out.split(","))  # no half-cut number


def test_opt55_short_list_untouched():
    assert opt55_string("[1, 3, 6]") == "1,3,6"


def test_retired_transient_mac_rows_are_pruned_after_90_days(data):
    mac = "aa:bb:cc:00:00:01"
    data.add_batch(T0, neigh=[mac])
    run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=T0 + 86400)  # retired
    open_overrides(data.root / "overrides.db").close()  # pruning needs a real, migrated file
    # 90 days after the retirement (server time), with a fresh batch proving the clock moved
    late = T0 + 86400 + 90 * 86400 + 60
    data.add_batch(late, neigh=["aa:bb:cc:00:00:02"])
    data.inv.execute("UPDATE collectors SET last_sent_ts=?", (late,))  # what ingest records
    run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=late)
    assert data.q("SELECT * FROM observations WHERE mac=?", mac) == []
    # aggregated to a count; the device row is retired, never deleted
    assert (
        data.q("SELECT value FROM pipeline_meta WHERE key='retired_mac_rows_pruned'")[0][0] == "1"
    )
    assert [r["status"] for r in data.q("SELECT status FROM devices ORDER BY first_seen")] == [
        "retired",
        "transient",
    ]


LA_MAC = "02:00:5e:00:00:01"  # locally administered: randomized, so a transient device
RETIRED = T0 + 86400  # the server time the transient below is retired at
CLOCK_MOVED_BY = "02:00:5e:00:00:02"  # a fresh batch's MAC


def retire_one(data):
    data.add_batch(T0, neigh=[LA_MAC])
    run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=RETIRED)
    assert data.q("SELECT status FROM devices")[0][0] == "retired"


def run_at(data, now):
    """A pass whose fresh batch moves the clock the prune trusts, so only the guards decide."""
    data.add_batch(now, neigh=[CLOCK_MOVED_BY])
    data.inv.execute("UPDATE collectors SET last_sent_ts=?", (now,))  # what ingest records
    run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=now)


def rows_of(data, mac):
    return len(data.q("SELECT * FROM observations WHERE mac=?", mac))


def test_retired_transient_mac_rows_are_kept_within_90_days(data):
    retire_one(data)
    open_overrides(data.root / "overrides.db").close()  # a migrated file: the prune can run
    data.inv.execute("UPDATE observations SET last_seen='2000-01-01T00:00:00Z'")  # collector clock
    run_at(data, RETIRED + 89 * 86400)
    assert rows_of(data, LA_MAC) == 1  # the server-side retirement stamp alone holds it


def test_retired_transient_merged_by_a_human_keeps_its_mac_row(data):
    data.add_batch(T0, neigh=[LA_MAC, NIC])
    run_once(PipelineConfig(data_dir=data.root), now=RETIRED)  # transient retired
    transient = data.q("SELECT device_id FROM observations WHERE mac=?", LA_MAC)[0][0]
    active = data.q("SELECT device_id FROM observations WHERE mac=?", NIC)[0][0]
    ov = open_overrides(data.root / "overrides.db")
    ov.execute(
        "INSERT INTO identity_links (from_device, into_device, merge_id, created_at, created_by)"
        " VALUES (?,?,'m','t','u')",
        (transient, active),
    )
    ov.commit()
    ov.close()
    run_at(data, RETIRED + 91 * 86400)  # past 90 days, the clock moved: the link alone protects
    assert rows_of(data, LA_MAC) == 1


def test_the_same_retired_transient_is_pruned_without_the_link(data):
    data.add_batch(T0, neigh=[LA_MAC, NIC])
    run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=RETIRED)
    open_overrides(data.root / "overrides.db").close()
    run_at(data, RETIRED + 91 * 86400)
    assert rows_of(data, LA_MAC) == 0  # the link in the test above is what kept it


def test_pruning_is_skipped_when_overrides_is_unreadable(data):
    retire_one(data)
    (data.root / "overrides.db").write_bytes(b"not a database" * 100)
    run_at(data, RETIRED + 91 * 86400)
    assert rows_of(data, LA_MAC) == 1


def test_active_device_mac_rows_are_never_pruned(data):
    data.add_batch(T0, neigh=[NIC])  # globally administered: active, not transient
    run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=RETIRED)
    open_overrides(data.root / "overrides.db").close()
    run_at(data, RETIRED + 91 * 86400)
    assert rows_of(data, NIC) == 1
    assert (
        data.q(
            "SELECT status FROM devices WHERE id=(SELECT device_id FROM observations WHERE mac=?)",
            NIC,
        )[0][0]
        == "active"
    )


# ---- F7: MAC handling ---------------------------------------------------------------------


def test_all_zero_mac_is_rejected():
    assert normalize_mac("00:00:00:00:00:00") is None


def test_all_zero_mac_is_counted_as_skipped(data):
    data.add_batch(neigh=["00:00:00:00:00:00", NIC])
    assert run_once(PipelineConfig(data_dir=data.root), now=T0 + 10).skipped_macs == 1
    assert len(data.q("SELECT * FROM observations")) == 1


def test_uppercase_mac_alone_is_stored_lowercase(data):
    data.add_batch(neigh=["AA:BB:CC:00:00:01"])
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 10)
    assert [r["mac"] for r in data.q("SELECT mac FROM observations")] == ["aa:bb:cc:00:00:01"]


def test_normalize_mac_lowercases_and_strips():
    assert normalize_mac(" AA:BB:CC:00:00:01 ") == "aa:bb:cc:00:00:01"


def test_is_randomized_normalizes_its_input():
    assert is_randomized("AA:BB:CC:00:00:01")
    assert is_randomized(" 2E:00:00:00:00:01 ")
    assert not is_randomized("00:11:22:33:44:55")


# ---- F7: CLI / config ---------------------------------------------------------------------


def test_transient_window_zero_is_an_error(data):
    with pytest.raises(SystemExit):
        cli.main(["run", "--once", "--data-dir", str(data.root), "--transient-window-s", "0"])


def test_negative_dwell_is_an_error(data):
    with pytest.raises(SystemExit):
        cli.main(["run", "--once", "--data-dir", str(data.root), "--min-dwell-s", "-1"])


def test_cli_flags_reach_config(data, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "run_once", lambda c: seen.append(c))
    cli.main(
        ["run", "--once", "--data-dir", str(data.root), "--transient-window-s", "99",
         "--min-dwell-s", "7", "--promotion-cap", "3", "--migrate"]
    )  # fmt: skip
    (c,) = seen
    assert (c.transient_window_s, c.transient_min_dwell_s, c.promotion_cap_per_hour) == (99, 7, 3)
    assert c.migrate is True


# ---- F7: URIs with special characters -----------------------------------------------------


def test_data_dir_with_uri_special_characters(tmp_path):
    root = tmp_path / "a#b c?d%e"
    root.mkdir()
    d = Data(root)
    try:
        d.add_batch(neigh=[NIC])
        d.make_overrides()
        assert run_once(PipelineConfig(data_dir=root), now=T0 + 10).batches == 1
        assert len(d.q("SELECT * FROM observations")) == 1
    finally:
        d.inv.close()


# ---- F7: ingest-owned migrations are checked, not run ---------------------------------------


def test_fresh_database_without_migrate_is_refused_and_untouched(tmp_path):
    path = tmp_path / "inventory.db"
    with pytest.raises(SchemaVersionError, match="--migrate"):
        open_pipeline_inventory(path)
    assert not path.exists()


def test_old_ingest_schema_without_migrate_is_refused_and_unchanged(tmp_path):
    path = tmp_path / "inventory.db"
    conn = connect(path)
    conn.execute("PRAGMA user_version=1")
    conn.close()
    with pytest.raises(SchemaVersionError):
        open_pipeline_inventory(path)
    check = sqlite3.connect(path)
    assert check.execute("PRAGMA user_version").fetchone()[0] == 1


def test_old_ingest_schema_with_migrate_is_upgraded(tmp_path):
    path = tmp_path / "inventory.db"
    conn = connect(path)
    conn.execute("PRAGMA user_version=0")
    conn.close()
    open_pipeline_inventory(path, migrate=True).close()
    check = sqlite3.connect(path)
    assert check.execute("PRAGMA user_version").fetchone()[0] == len(INVENTORY_MIGRATIONS)


def test_newer_schema_is_refused_even_with_migrate(tmp_path):
    path = tmp_path / "inventory.db"
    open_inventory(path).close()
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version={len(INVENTORY_MIGRATIONS) + 1}")
    conn.close()
    with pytest.raises(SchemaVersionError, match="newer"):
        open_pipeline_inventory(path)
    with pytest.raises(SchemaVersionError, match="newer"):
        open_pipeline_inventory(path, migrate=True)


def test_current_schema_needs_no_flag(tmp_path):
    path = tmp_path / "inventory.db"
    open_inventory(path).close()
    open_pipeline_inventory(path).close()


def test_run_once_refuses_fresh_database_by_default(tmp_path):
    with pytest.raises(SchemaVersionError):
        run_once(PipelineConfig(data_dir=tmp_path), now=T0)


def test_run_once_with_migrate_flag_bootstraps(tmp_path):
    stats = run_once(PipelineConfig(data_dir=tmp_path, migrate=True), now=T0)
    assert stats.batches == 0 and (tmp_path / "inventory.db").exists()
