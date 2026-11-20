from __future__ import annotations

import sqlite3

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401

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


DAY = 86400


def _retire(data, mac="aa:bb:cc:00:00:01"):
    data.add_batch(T0, neigh=[mac])
    run_once(PipelineConfig(data_dir=data.root), now=T0 + DAY)  # retired


def test_retired_transient_mac_rows_are_pruned_after_90_days(data):
    mac = "aa:bb:cc:00:00:01"
    _retire(data, mac)
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 91 * DAY)
    assert data.q("SELECT * FROM observations WHERE mac=?", mac) == []
    assert data.q("SELECT * FROM devices WHERE status='retired'") != []  # devices are kept


def test_retired_row_inside_retention_is_kept(data):
    _retire(data)
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 89 * DAY)
    assert len(data.q("SELECT * FROM observations")) == 1


def test_retired_row_with_rule_link_is_kept(data):
    _retire(data)
    data.q("UPDATE observations SET link_source='rule', link_rule_id='r1'")
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 91 * DAY)
    assert len(data.q("SELECT * FROM observations")) == 1


def test_non_retired_rows_are_never_pruned(data):
    _retire(data)
    data.q("UPDATE devices SET status='active'")
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 91 * DAY)
    assert len(data.q("SELECT * FROM observations")) == 1


def test_retired_pruning_is_idempotent(data):
    _retire(data)
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 91 * DAY)
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 92 * DAY)
    assert data.q("SELECT * FROM observations") == []
    assert len(data.q("SELECT * FROM devices")) == 1


def test_retired_retention_is_configurable_from_env():
    cfg = PipelineConfig.from_env({"VIGIE_RETIRED_RETENTION_S": "3600"})
    assert cfg.retired_retention_s == 3600


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
