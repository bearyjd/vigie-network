from __future__ import annotations

import logging
import sqlite3

import pytest
from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401

from vigie_ingest.db import iso_utc
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

PHONE = "aa:bb:cc:00:00:01"  # aa: locally administered -> randomized
NIC = "00:11:22:33:44:55"  # universal, stable MAC
PHONE2 = "ae:bb:cc:00:00:02"


def cfg(data: Data, **kw) -> PipelineConfig:
    return PipelineConfig(data_dir=data.root, **kw)


def run(data: Data, now: float = T0 + 10, **kw):
    return run_once(cfg(data, **kw), now=now)


def obs(data: Data, mac: str):
    rows = data.q("SELECT * FROM observations WHERE mac=?", mac)
    return rows[0] if rows else None


def test_lease_creates_device_and_observation(data):
    data.add_batch(
        leases=[(NIC, "laptop", "[1, 3, 6]", "MSFT 5.0")],
        sightings=[(NIC, "mdns", "Laptop._x._tcp")],
    )
    stats = run(data)
    assert stats.batches == 1 and stats.new_devices == 1
    o = obs(data, NIC)
    assert o["hostname"] == "laptop"
    assert o["dhcp_fingerprint"] == "1,3,6"
    assert o["vendor_class"] == "MSFT 5.0"
    assert o["mdns_name"] == "Laptop._x._tcp"
    assert o["link_source"] == "self" and o["link_rule_id"] is None
    assert o["first_seen"] == o["last_seen"] == iso_utc(T0)
    (dev,) = data.q("SELECT * FROM devices WHERE id=?", o["device_id"])
    assert dev["status"] == "active" and dev["identity_state"] == "ok"
    assert len(dev["id"]) == 36  # uuid


@pytest.mark.parametrize("source", ["neigh", "dns", "flows", "sightings", "leases"])
def test_every_source_creates_a_mac(data, source):
    kw = {
        "neigh": {"neigh": [NIC]},
        "dns": {"dns": [(NIC, T0)]},
        "flows": {"flows": [NIC]},
        "sightings": {"sightings": [(NIC, "mdns", "n")]},
        "leases": {"leases": [(NIC, None, None, None)]},
    }[source]
    data.add_batch(**kw)
    run(data)
    assert obs(data, NIC) is not None


@pytest.mark.parametrize("digit", "26ae")
def test_locally_administered_digit_is_randomized(data, digit):
    mac = f"0{digit}:11:22:33:44:55"
    data.add_batch(neigh=[mac])
    run(data)
    assert obs(data, mac)["is_randomized"] == 1


@pytest.mark.parametrize("digit", "048c")
def test_other_unicast_digits_not_randomized(data, digit):
    mac = f"0{digit}:11:22:33:44:55"
    data.add_batch(neigh=[mac])
    run(data)
    assert obs(data, mac)["is_randomized"] == 0


@pytest.mark.parametrize("digit", "13579bdf")
def test_multicast_source_macs_are_skipped(data, digit):
    mac = f"0{digit}:11:22:33:44:55"
    data.add_batch(neigh=[mac])
    assert run(data).skipped_macs == 1
    assert obs(data, mac) is None


def test_uppercase_mac_is_normalized(data):
    data.add_batch(neigh=["AA:BB:CC:00:00:01"], leases=[("aa:bb:cc:00:00:01", "h", None, None)])
    run(data)
    assert len(data.q("SELECT * FROM observations")) == 1


def test_invalid_mac_is_skipped(data):
    data.add_batch(neigh=["not-a-mac", NIC])
    stats = run(data)
    assert stats.skipped_macs == 1
    assert len(data.q("SELECT * FROM observations")) == 1


def test_status_transient_for_randomized_active_otherwise(data):
    data.add_batch(neigh=[PHONE, NIC])
    run(data)
    status = {
        r["mac"]: r["status"]
        for r in data.q(
            "SELECT o.mac, d.status FROM observations o JOIN devices d ON d.id=o.device_id"
        )
    }
    assert status == {PHONE: "transient", NIC: "active"}


# ---- orphan filter ----------------------------------------------------------------------


def test_orphan_shard_rows_are_ignored(data):
    data.add_batch(neigh=[PHONE], record=False)  # crashed commit
    data.add_batch(neigh=[NIC])
    stats = run(data)
    assert stats.batches == 1
    assert obs(data, PHONE) is None and obs(data, NIC) is not None
    assert data.q("SELECT COUNT(*) c FROM events")[0]["c"] == 1


def test_orphan_rows_in_same_batch_id_table_only_when_recorded(data):
    # orphan lease row appears; once the batch is recorded it is processed
    batch_id = data.add_batch(neigh=[PHONE], record=False)
    run(data)
    assert obs(data, PHONE) is None
    data.inv.execute(
        "INSERT INTO batches (collector_id, batch_id, received_at) VALUES ('rtr-1',?,?)",
        (batch_id, iso_utc(T0)),
    )
    run(data)
    assert obs(data, PHONE) is not None


# ---- cursor -----------------------------------------------------------------------------


def test_cursor_advances_and_is_durable(data):
    data.add_batch(neigh=[NIC])
    assert run(data).batches == 1
    (cur,) = data.q("SELECT * FROM pipeline_cursor")
    assert cur["collector_id"] == "rtr-1" and cur["last_batch_rowid"] >= 1
    assert run(data).batches == 0  # nothing new
    data.add_batch(T0 + 60, neigh=["00:11:22:33:44:66"])
    assert run(data).batches == 1
    assert data.q("SELECT last_batch_rowid r FROM pipeline_cursor")[0]["r"] == 2


def test_cursor_is_per_collector(data):
    data.add_batch(collector="a", neigh=[NIC])
    data.add_batch(collector="b", neigh=["00:11:22:33:44:66"])
    run(data)
    rows = {
        r["collector_id"]: r["last_batch_rowid"] for r in data.q("SELECT * FROM pipeline_cursor")
    }
    assert set(rows) == {"a", "b"}


def test_cursor_resets_when_batches_table_was_purged(data):
    data.add_batch(neigh=[NIC])
    run(data)
    data.inv.execute("DELETE FROM batches")
    data.add_batch(T0 + 60, neigh=["00:11:22:33:44:66"])  # rowid restarts below the cursor
    assert run(data).batches == 1
    assert obs(data, "00:11:22:33:44:66") is not None


# ---- idempotence / events ---------------------------------------------------------------


def snapshot(data: Data):
    return (
        [tuple(r) for r in data.q("SELECT * FROM devices ORDER BY id")],
        [tuple(r) for r in data.q("SELECT * FROM observations ORDER BY mac")],
        [tuple(r) for r in data.q("SELECT device_id, kind FROM events ORDER BY id")],
    )


def test_reprocessing_same_rows_is_idempotent(data):
    data.add_batch(leases=[(PHONE, "ph", "[1]", "x")], neigh=[PHONE, NIC], dns=[(PHONE, T0 + 5)])
    run(data)
    before = snapshot(data)
    data.inv.execute("DELETE FROM pipeline_cursor")  # force full reprocess
    stats = run(data)
    assert stats.batches == 1 and stats.new_devices == 0
    assert snapshot(data) == before


def test_new_device_event_once_across_batches(data):
    data.add_batch(neigh=[NIC])
    data.add_batch(T0 + 60, neigh=[NIC], flows=[NIC])
    run(data)
    assert len(data.q("SELECT * FROM devices")) == 1
    assert data.q("SELECT COUNT(*) c FROM events WHERE kind='new_device'")[0]["c"] == 1
    run(data)
    assert data.q("SELECT COUNT(*) c FROM events")[0]["c"] == 1


def test_two_macs_two_devices_two_events(data):
    data.add_batch(neigh=[NIC, "00:11:22:33:44:66"])
    run(data)
    assert len(data.q("SELECT * FROM devices")) == 2
    assert data.q("SELECT COUNT(*) c FROM events WHERE kind='new_device'")[0]["c"] == 2


def test_first_and_last_seen_span_batches(data):
    data.add_batch(T0, neigh=[NIC])
    data.add_batch(T0 + 600, neigh=[NIC])
    run(data, now=T0 + 700)
    o = obs(data, NIC)
    assert (o["first_seen"], o["last_seen"]) == (iso_utc(T0), iso_utc(T0 + 600))
    (dev,) = data.q("SELECT * FROM devices")
    assert (dev["first_seen"], dev["last_seen"]) == (iso_utc(T0), iso_utc(T0 + 600))


def test_late_older_batch_does_not_regress_last_seen(data):
    data.add_batch(T0 + 600, neigh=[NIC])
    run(data, now=T0 + 700)
    data.add_batch(T0, neigh=[NIC])
    run(data, now=T0 + 700)
    o = obs(data, NIC)
    assert (o["first_seen"], o["last_seen"]) == (iso_utc(T0), iso_utc(T0 + 600))


def test_older_batch_value_does_not_replace_newer_value(data):
    data.add_batch(T0 + 600, leases=[(NIC, "new-name", "[1]", "new")])
    run(data, now=T0 + 700)
    data.add_batch(T0, leases=[(NIC, "old-name", "[2]", "old")])  # arrives late
    run(data, now=T0 + 700)
    o = obs(data, NIC)
    assert (o["hostname"], o["dhcp_fingerprint"], o["vendor_class"]) == ("new-name", "1", "new")


def test_newer_batch_value_replaces_older_value(data):
    data.add_batch(T0, leases=[(NIC, "old-name", None, None)])
    data.add_batch(T0 + 600, leases=[(NIC, "new-name", None, None)])
    run(data, now=T0 + 700)
    assert obs(data, NIC)["hostname"] == "new-name"


def test_later_values_fill_but_null_does_not_erase(data):
    data.add_batch(T0, leases=[(NIC, "host", "[1]", "v")])
    data.add_batch(T0 + 60, leases=[(NIC, None, None, None)])
    run(data, now=T0 + 100)
    o = obs(data, NIC)
    assert (o["hostname"], o["dhcp_fingerprint"], o["vendor_class"]) == ("host", "1", "v")


# ---- transient promotion / GC -------------------------------------------------------------


def test_transient_promoted_with_hostname(data):
    data.add_batch(leases=[(PHONE, "pixel", None, None)])
    stats = run(data)
    assert stats.promoted == 1
    assert data.q("SELECT status FROM devices")[0]["status"] == "active"


def test_transient_promoted_after_two_distinct_hours(data):
    data.add_batch(T0, neigh=[PHONE])
    run(data)
    assert data.q("SELECT status FROM devices")[0]["status"] == "transient"
    data.add_batch(T0 + 5, dns=[(PHONE, T0 + HOUR + 5)])  # same batch ts hour, dns in next hour
    run(data)
    assert data.q("SELECT status FROM devices")[0]["status"] == "active"
    assert data.q("SELECT COUNT(*) c FROM transient_hours")[0]["c"] == 0  # pruned on exit


def test_one_hour_only_is_not_promoted(data):
    data.add_batch(T0, neigh=[PHONE], dns=[(PHONE, T0 + 1)])
    run(data)
    assert data.q("SELECT status FROM devices")[0]["status"] == "transient"


def test_unpromoted_transient_retired_after_window(data):
    data.add_batch(T0, neigh=[PHONE])
    run(data, now=T0 + 10, transient_window_s=86400)
    run(data, now=T0 + 86399, transient_window_s=86400)
    assert data.q("SELECT status FROM devices")[0]["status"] == "transient"
    stats = run(data, now=T0 + 86400, transient_window_s=86400)
    assert stats.retired == 1
    assert data.q("SELECT status FROM devices")[0]["status"] == "retired"


def test_window_is_configurable(data):
    data.add_batch(T0, neigh=[PHONE])
    run(data, now=T0 + 7200, transient_window_s=3600)
    assert data.q("SELECT status FROM devices")[0]["status"] == "retired"


def test_retired_is_never_deleted_and_trigger_blocks_delete(data):
    data.add_batch(T0, neigh=[PHONE])
    run(data, now=T0 + 90000)
    assert len(data.q("SELECT * FROM devices")) == 1
    with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
        data.inv.execute("DELETE FROM devices")


def test_active_devices_never_retired(data):
    data.add_batch(T0, neigh=[NIC])
    run(data, now=T0 + 10 * 86400)
    assert data.q("SELECT status FROM devices")[0]["status"] == "active"


# ---- overrides.db: read-only + canonical device -------------------------------------------


def test_absent_overrides_is_not_created(data):
    data.add_batch(neigh=[NIC])
    run(data)
    assert not (data.root / "overrides.db").exists()


def test_pipeline_never_modifies_overrides(data):
    path = data.make_overrides()
    data.add_batch(neigh=[NIC])
    before = path.read_bytes()
    run(data)
    assert path.read_bytes() == before


def test_overrides_connection_rejects_writes(data):
    from vigie_pipeline.overrides import open_overrides_ro

    path = data.make_overrides()
    conn = open_overrides_ro(path)
    assert conn is not None
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("INSERT INTO identity_links VALUES ('a','b','m','t','u')")
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("CREATE TABLE x (y)")


def test_open_overrides_ro_absent_returns_none(tmp_path):
    from vigie_pipeline.overrides import open_overrides_ro

    assert open_overrides_ro(tmp_path / "overrides.db") is None


def test_canonical_follows_links_and_is_loop_safe(data):
    from vigie_pipeline.overrides import canonical_device, open_overrides_ro

    path = data.make_overrides()
    w = sqlite3.connect(path)
    w.executemany(
        "INSERT INTO identity_links VALUES (?,?,'m','t','u')",
        [("a", "b"), ("b", "c"), ("x", "y"), ("y", "x")],
    )
    w.commit()
    w.close()
    conn = open_overrides_ro(path)
    assert canonical_device(conn, "a") == "c"
    assert canonical_device(conn, "c") == "c"
    assert canonical_device(conn, "zzz") == "zzz"
    assert canonical_device(conn, "x") in {"x", "y"}  # cycle terminates
    assert canonical_device(None, "a") == "a"


def test_observation_attaches_to_canonical_last_seen(data):
    path = data.make_overrides()
    data.add_batch(T0, neigh=[NIC])
    run(data, now=T0 + 10)
    (o,) = data.q("SELECT device_id FROM observations")
    dev_a = o["device_id"]
    data.inv.execute(
        "INSERT INTO devices (id, first_seen, last_seen) VALUES ('canon', ?, ?)",
        (iso_utc(T0 - 1000), iso_utc(T0 - 1000)),
    )
    w = sqlite3.connect(path)
    w.execute("INSERT INTO identity_links VALUES (?, 'canon', 'm', 't', 'u')", (dev_a,))
    w.commit()
    w.close()
    data.add_batch(T0 + 300, neigh=[NIC])
    run(data, now=T0 + 400)
    last = {r["id"]: r["last_seen"] for r in data.q("SELECT id, last_seen FROM devices")}
    assert last["canon"] == iso_utc(T0 + 300)
    assert last[dev_a] == iso_utc(T0 + 300)
    # the observation keeps its own device (history is not rewritten)
    assert data.q("SELECT device_id FROM observations")[0]["device_id"] == dev_a


# ---- logging ------------------------------------------------------------------------------


def test_logs_never_contain_qnames(data, caplog):
    data.add_batch(neigh=[NIC], dns=[(NIC, T0)])
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        run(data)
    assert caplog.records
    assert "secret-qname" not in caplog.text
