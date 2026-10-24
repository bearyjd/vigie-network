from api_helpers import NOW, Env, env  # noqa: F401

HOUR = int(NOW) // 3600 * 3600 - 3600
MAC = "aa:bb:cc:00:00:01"


def seed(env):
    env.inv.execute("INSERT INTO collectors(id,key_id) VALUES ('c1','k1')")
    env.device("d1")
    env.mac(MAC, "d1")
    env.inv.execute("INSERT INTO coverage_hourly VALUES ('c1',?,3600,3600,'[]')", (HOUR,))
    env.inv.execute("INSERT INTO measurements_hourly VALUES ('c1',?,?,350,4,2,0)", (MAC, HOUR))


def test_coverage_requires_token_reports_missing_instead_of_zero_and_pages(env: Env):
    seed(env)
    query = {"collector_id": "c1", "from_hour": HOUR - 3600, "to_hour": HOUR + 3600, "limit": 1}
    assert env.client.get("/coverage", params=query).status_code == 401
    first = env.get("/coverage", **query)
    assert first.status_code == 200, first.text
    data = first.json()["data"]
    assert data["hours"][0]["state"] == "missing"
    assert data["hours"][0]["qualified_seconds"] is None
    token = first.json()["page"]["next_cursor"]
    assert token
    second = env.get("/coverage", **query, cursor=token)
    assert second.json()["data"]["hours"][0]["qualified_seconds"] == 3600
    assert second.json()["data"]["hours"][0]["state"] == "eligible"
    assert second.json()["page"]["next_cursor"] is None
    assert env.get("/coverage", **query, cursor="not-valid").status_code == 400


def test_activity_reads_350_scoped_bytes_missing_hour_is_null(env: Env):
    seed(env)
    result = env.get(
        "/devices/d1/activity", collector_id="c1", from_hour=HOUR - 3600, to_hour=HOUR + 3600
    )
    assert result.status_code == 200, result.text
    hours = result.json()["data"]["hours"]
    assert hours[0]["bytes_up"] is None
    assert hours[1]["bytes_up"] == 350
    assert result.json()["data"]["collector_id"] == "c1"
    assert env.get("/devices/absent/activity", collector_id="c1").status_code == 404
    assert (
        env.get(
            "/coverage", collector_id="c1", from_hour=HOUR - 3600 * 24 * 91, to_hour=HOUR
        ).status_code
        == 400
    )


def test_positive_dns_freshness_requires_real_dns_rows_and_never_a_probe(env: Env):
    seed(env)
    env.inv.execute(
        "INSERT INTO batches(collector_id,batch_id,received_at,window_start,window_end,"
        "observation_kind,dns_queries,health) VALUES ('c1','dns','2026-01-01T00:00:00Z',?,?,"
        "'observation',3,'{}')",
        (HOUR, HOUR + 60),
    )
    env.inv.execute(
        "INSERT INTO batches(collector_id,batch_id,received_at,window_start,window_end,"
        "observation_kind,dns_queries,health) VALUES ('c1','probe','2026-01-01T00:01:00Z',?,?,"
        "'probe',0,'{\"dns_log_quiet\":false}')",
        (HOUR + 60, HOUR + 120),
    )
    result = env.get("/coverage", collector_id="c1", from_hour=HOUR, to_hour=HOUR + 3600)
    assert result.status_code == 200, result.text
    summary = result.json()["data"]["collector"]
    assert summary["latest_dns_observation_window_end"] == HOUR + 60
    assert summary["last_received_at"] == "2026-01-01T00:01:00Z"


def test_lineage_does_not_reuse_old_reference_after_merge_undo_or_assignment_roundtrip(env: Env):
    from vigie_api.monitoring import device_macs

    env.device("a")
    env.device("b")
    env.mac(MAC, "a")
    original = device_macs(env.inv, env.ov, "a")[2]
    env.link("b", "a")
    env.ov.execute(
        "UPDATE identity_links SET revoked_at='2026-01-01T00:00:00Z' WHERE from_device='b'"
    )
    undone = device_macs(env.inv, env.ov, "a")[2]
    assert undone != original
    env.inv.execute("UPDATE observations SET device_id='b' WHERE mac=?", (MAC,))
    env.inv.execute("UPDATE observations SET device_id='a' WHERE mac=?", (MAC,))
    reassigned = device_macs(env.inv, env.ov, "a")[2]
    assert reassigned != undone
    env.patch("/devices/a", {"name": "only a human name"}, '"0"')
    assert device_macs(env.inv, env.ov, "a")[2] == reassigned


def test_incidents_are_readonly_authenticated_scoped_and_keyset_paged(env: Env):
    import json

    seed(env)
    evidence = {
        "reason_code": "large_upload_threshold",
        "hour": HOUR,
        "previous_hour": None,
        "observed_bytes": 1073741824,
        "threshold_bytes": 1073741824,
        "baseline_id": None,
        "algorithm": "pooled-median-v1",
        "config_version": "cfg",
        "coverage_required_seconds": 3420,
        "lineage": "line",
        "unusual_is_not_malicious": True,
    }
    for number in [1, 2]:
        env.inv.execute(
            "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
            "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_"
            "bytes,evidence) "
            "VALUES (?,'c1','d1','line','large_upload',?, ?,?,'now',NULL,1073741824,1073741824,?)",
            (
                f"inc{number}",
                "resolved" if number == 1 else "open",
                HOUR,
                HOUR,
                json.dumps(evidence),
            ),
        )
    assert env.client.get("/incidents", params={"collector_id": "c1"}).status_code == 401
    result = env.get("/incidents", collector_id="c1", limit=1)
    assert result.status_code == 200, result.text
    assert len(result.json()["data"]) == 1
    cursor = result.json()["page"]["next_cursor"]
    assert cursor
    more = env.get("/incidents", collector_id="c1", limit=1, cursor=cursor)
    assert more.json()["data"][0]["id"] == "inc2"
    assert (
        env.get("/incidents/inc1", collector_id="c1").json()["data"]["evidence"][
            "unusual_is_not_malicious"
        ]
        is True
    )
    assert env.get("/incidents", collector_id="c1", cursor="bad").status_code == 400
    assert env.get("/incidents/inc1", collector_id="other").status_code == 404


def test_maximum64_mac_activity_sum_cannot_overflow_sqlite(env: Env):
    seed(env)
    cap = (2**63 - 1) // 64
    env.inv.execute("UPDATE measurements_hourly SET bytes_up=?", (cap,))
    for i in range(2, 65):
        mac = f"aa:bb:cc:00:00:{i:02x}"
        env.mac(mac, "d1")
        env.inv.execute(
            "INSERT INTO measurements_hourly VALUES ('c1',?,?,?,0,1,0)", (mac, HOUR, cap)
        )
    result = env.get("/devices/d1/activity", collector_id="c1", from_hour=HOUR, to_hour=HOUR + 3600)
    assert result.status_code == 200, result.text
    assert result.json()["data"]["hours"][0]["bytes_up"] == cap * 64


def test_characterization_evidence_and_expiry_are_hints_and_type_filter_is_consistent(
    env: Env, monkeypatch
):
    import vigie_api.effective as effective
    from vigie_pipeline.characterization_store import refresh_characterization, save_services

    seed(env)
    monkeypatch.setattr(effective.time, "time", lambda: NOW)
    save_services(
        env.inv,
        [
            (MAC, "mdns", "_googlecast._tcp", int(NOW)),
            (MAC, "mdns", "_androidtvremote2._tcp", int(NOW)),
        ],
        NOW,
    )
    refresh_characterization(env.inv, env.ov, NOW)
    detail = env.get("/devices/d1").json()["data"]
    assert detail["type"] == "tv"
    hint = detail["explanation"]["characterization"]
    assert hint["confidence"] is None and hint["strength"] == "corroborated"
    assert {e["service"] for e in hint["evidence"]} == {
        "_googlecast._tcp",
        "_androidtvremote2._tcp",
    }
    monkeypatch.setattr(effective.time, "time", lambda: NOW + 86401)
    assert env.get("/devices/d1").json()["data"]["type"] == "unknown"
    assert env.get("/devices", type="tv").json()["data"] == []
    assert len(env.get("/devices", type="unknown").json()["data"]) == 1


def test_type_hint_filter_scan_work_is_bounded_and_cursor_crosses_unknown_prefix(env: Env):
    from vigie_api.effective import list_devices

    def page(cursor=None):
        return list_devices(
            env.inv,
            env.ov,
            type_="tv",
            group=None,
            identity_state=None,
            status=None,
            updated_since=None,
            include_transient=True,
            include_retired=True,
            include_aliases=False,
            cursor=cursor,
            limit=1,
        )

    for i in range(100):
        env.device(f"a{i:04}", inferred_type="unknown", source="deterministic-services")
    statements = []
    env.inv.set_trace_callback(statements.append)
    first, cursor = page()
    small = len(statements)
    env.inv.set_trace_callback(None)
    for i in range(100, 1000):
        env.device(f"a{i:04}", inferred_type="unknown", source="deterministic-services")
    env.device("z-match", inferred_type="tv", source="other-model")
    statements = []
    env.inv.set_trace_callback(statements.append)
    first, cursor = page()
    env.inv.set_trace_callback(None)
    assert len(statements) <= 150 and len(statements) <= small + 5
    assert first == [] and cursor is not None
    found = []
    for _ in range(40):
        items, cursor = page(cursor)
        found += [item["id"] for item in items]
        if cursor is None:
            break
    assert found == ["z-match"] and cursor is None


def test_api_withholds_model_after_training_hour_quality_changes_and_reports_backoff(env: Env):
    from vigie_pipeline.baselines import BaselineConfig
    from vigie_pipeline.monitoring_engine import analyze_monitoring

    seed(env)
    env.inv.execute("INSERT INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, HOUR))
    analyze_monitoring(env.inv, env.ov, BaselineConfig(minimum_hours=1, minimum_days=1), NOW)
    path = "/devices/d1/activity"
    assert env.get(path, collector_id="c1").json()["data"]["baseline"]["state"] == "mature"
    env.inv.execute(
        "UPDATE coverage_hourly SET qualified_seconds=0,reasons=?", ('["raw_missing"]',)
    )
    env.inv.execute(
        "INSERT INTO monitoring_unavailable VALUES ('c1','bad','lineage_unavailable',?)",
        (int(NOW) + 60,),
    )
    response = env.get(path, collector_id="c1", from_hour=HOUR, to_hour=HOUR + 3600).json()["data"]
    assert response["baseline"]["state"] == "rebuilding_quality"
    assert response["baseline"]["baseline_id"] is None
    assert response["hours"][0]["dns_queries"] is None
    summary = env.get("/coverage", collector_id="c1").json()["data"]["collector"]
    assert summary["monitoring_unavailable"] == [
        {"device_id": "bad", "reason": "lineage_unavailable", "retry_at": int(NOW) + 60}
    ]
