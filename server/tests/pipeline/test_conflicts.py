from __future__ import annotations

from pipeline_helpers import T0, Data, data  # noqa: F401

from vigie_ingest.db import connect, shard_name, utc_day
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

NIC = "00:11:22:33:44:55"
DAY = 86400


def run(data: Data, now: float = T0 + 10):
    return run_once(PipelineConfig(data_dir=data.root), now=now)


def obs(data: Data):
    return data.q("SELECT * FROM observations WHERE mac=?", NIC)[0]


def conflict_events(data: Data):
    return data.q("SELECT * FROM events WHERE kind='identity_conflict' ORDER BY ts, id")


def state(data: Data) -> str:
    return data.q("SELECT identity_state s FROM devices")[0]["s"]


def test_hostname_only_change_updates_hostname_without_conflict(data):
    data.add_batch(T0, leases=[(NIC, "Alices-iPhone", "[1, 121, 3]", "iPhone")])
    data.add_batch(T0 + 60, leases=[(NIC, "evil", None, None)])
    run(data)
    o = obs(data)
    assert o["hostname"] == "evil"
    assert (o["dhcp_fingerprint"], o["vendor_class"]) == ("1,121,3", "iPhone")
    assert state(data) == "ok" and conflict_events(data) == []


def test_fingerprint_change_keeps_first_value_and_flags_conflict(data):
    data.add_batch(T0, leases=[(NIC, "Alices-iPhone", "[1, 121, 3]", "iPhone")])
    data.add_batch(T0 + 60, leases=[(NIC, "Alices-iPhone", "[1, 3, 6]", "iPhone")])
    run(data)
    assert obs(data)["dhcp_fingerprint"] == "1,121,3"
    assert state(data) == "conflict"
    (ev,) = conflict_events(data)
    assert "dhcp_fingerprint" in ev["summary"]
    assert "121" not in ev["summary"] and "Alices" not in ev["summary"]


def test_vendor_class_change_flags_conflict(data):
    data.add_batch(T0, leases=[(NIC, None, None, "MSFT 5.0")])
    data.add_batch(T0 + 60, leases=[(NIC, None, None, "android-dhcp-14")])
    run(data)
    assert obs(data)["vendor_class"] == "MSFT 5.0"
    assert state(data) == "conflict"
    assert "vendor_class" in conflict_events(data)[0]["summary"]


def test_missing_value_then_value_is_not_a_conflict(data):
    data.add_batch(T0, leases=[(NIC, "h", None, None)])
    data.add_batch(T0 + 60, leases=[(NIC, "h", "[1]", "v")])
    run(data)
    assert obs(data)["dhcp_fingerprint"] == "1" and state(data) == "ok"


def test_same_value_is_not_a_conflict(data):
    data.add_batch(T0, leases=[(NIC, "h", "[1]", "v")])
    data.add_batch(T0 + 60, leases=[(NIC, "h", "[1]", "v")])
    run(data)
    assert state(data) == "ok" and conflict_events(data) == []


def test_one_event_per_device_field_per_day(data):
    data.add_batch(T0, leases=[(NIC, None, "[1]", "a")])
    data.add_batch(T0 + 60, leases=[(NIC, None, "[2]", "b")])
    data.add_batch(T0 + 120, leases=[(NIC, None, "[3]", "c")])
    run(data)
    summaries = sorted(e["summary"].split()[0] for e in conflict_events(data))
    assert summaries == ["dhcp_fingerprint", "vendor_class"]
    data.add_batch(T0 + DAY, leases=[(NIC, None, "[4]", "d")])
    run(data, T0 + DAY + 10)
    assert len(conflict_events(data)) == 4  # a new day, a new event per field


def test_reprocessing_does_not_duplicate_conflict_events(data):
    data.add_batch(T0, leases=[(NIC, None, "[1]", "a")])
    data.add_batch(T0 + 60, leases=[(NIC, None, "[2]", "a")])
    run(data)
    data.inv.execute("DELETE FROM pipeline_cursor")
    run(data)
    assert len(conflict_events(data)) == 1


def test_shard_rows_are_read_in_ts_order_not_insert_order(data):
    batch_id = data.add_batch(T0, leases=[(NIC, "late", None, None)])
    conn = connect(data.root / shard_name(utc_day(T0)))
    conn.execute(
        "INSERT INTO raw_lease (batch_id, collector_id, ts, mac, ip, hostname)"
        " VALUES (?, 'rtr-1', ?, ?, '1.2.3.4', 'early')",
        (batch_id, T0 - 100, NIC),
    )
    conn.close()
    run(data)
    assert obs(data)["hostname"] == "late"
