from __future__ import annotations

from api_helpers import Env, env, ts  # noqa: F401

from vigie_api import effective
from vigie_ingest.db import iso_utc

MAC_A = "00:11:22:33:44:55"
MAC_B = "00:11:22:33:44:66"


def ip(env, mac, value, at, source="lease"):
    env.inv.execute("INSERT INTO mac_last_ip VALUES (?,?,?,?)", (mac, value, at, source))


def test_missing_addresses_and_old_pipeline_schema(env: Env):
    env.device("a")
    for path in ("/devices", "/devices/a"):
        v = env.get(path).json()["data"]
        v = v[0] if isinstance(v, list) else v
        assert v["last_observed_ip"] is None and v["last_observed_ip_at"] is None
    env.inv.execute("DROP TABLE mac_last_ip")
    assert env.get("/devices").json()["data"][0]["last_observed_ip"] is None
    assert env.get("/devices/a").json()["data"]["last_observed_ip"] is None


def test_latest_mac_address_is_exposed_in_list_and_detail(env: Env):
    env.device("a")
    env.mac(MAC_A, "a")
    env.mac(MAC_B, "a")
    ip(env, MAC_A, "192.168.1.10", 100)
    ip(env, MAC_B, "2001:db8::1", 200, "neigh")
    for path in ("/devices", "/devices/a"):
        v = env.get(path).json()["data"]
        v = v[0] if isinstance(v, list) else v
        assert (v["last_observed_ip"], v["last_observed_ip_at"]) == ("2001:db8::1", iso_utc(200))


def test_equal_timestamp_tie_and_identity_merge_undo(env: Env):
    env.device("a")
    env.device("b", status="transient")
    env.mac(MAC_A, "a")
    env.mac(MAC_B, "b")
    ip(env, MAC_A, "192.168.1.10", 100, "neigh")
    ip(env, MAC_B, "192.168.1.20", 100)
    env.link("b", "a")
    got = env.get("/devices", include_aliases=1, include_transient=1).json()["data"]
    assert {v["last_observed_ip"] for v in got} == {"192.168.1.20"}
    assert env.get("/devices/b").json()["data"]["last_observed_ip"] == "192.168.1.20"
    env.ov.execute("DELETE FROM identity_links")
    assert env.get("/devices/a").json()["data"]["last_observed_ip"] == "192.168.1.10"
    assert env.get("/devices/b").json()["data"]["last_observed_ip"] == "192.168.1.20"
    assert len(env.get("/devices").json()["data"]) == 1


def test_page_projection_is_one_indexed_query_and_does_not_scan_unrelated_devices(env: Env):
    for n in range(40):
        device = f"d{n:02}"
        mac = f"00:11:22:33:44:{n:02x}"
        env.device(device)
        env.mac(mac, device)
        ip(env, mac, f"192.168.1.{n + 1}", n)
    statements = []
    env.inv.set_trace_callback(statements.append)
    got, _ = effective.list_devices(
        env.inv,
        env.ov,
        type_=None,
        group=None,
        identity_state=None,
        status=None,
        updated_since=None,
        include_transient=False,
        include_retired=False,
        include_aliases=False,
        cursor=None,
        limit=5,
    )
    queries = [s for s in statements if "JOIN mac_last_ip" in s]
    assert len(got) == 5 and len(queries) == 1
    plan = env.inv.execute("EXPLAIN QUERY PLAN " + queries[0]).fetchall()
    assert any("idx_obs_device" in r[3] for r in plan)
    assert all(v["last_observed_ip"] for v in got)
    # The selected member IDs are the returned page, not the whole inventory.
    assert "d39" not in queries[0]
