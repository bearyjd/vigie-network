from pathlib import Path

from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.monitoring_engine import analyze_monitoring
from vigie_pipeline.schema import open_pipeline_inventory

HOUR = 1_791_997_200
MIB = 1024 * 1024
MAC = "aa:bb:cc:00:00:01"


def seeded(root: Path):
    inv = open_pipeline_inventory(root / "inventory.db", migrate=True)
    ov = open_overrides(root / "overrides.db")
    inv.execute("INSERT INTO collectors(id,key_id) VALUES ('c1','k1')")
    for device in ["d1", "d2"]:
        inv.execute(
            "INSERT INTO devices(id,first_seen,last_seen) VALUES (?,?,?)",
            (device, iso_utc(HOUR), iso_utc(HOUR)),
        )
    inv.execute(
        "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,last_seen) "
        "VALUES (?, 'd1', 0, 'self', ?, ?)",
        (MAC, iso_utc(HOUR), iso_utc(HOUR)),
    )
    return inv, ov


def hour(inv, stamp, value, coverage=3600):
    inv.execute(
        "INSERT INTO measurements_hourly VALUES ('c1',?,?,?,0,1,0) "
        "ON CONFLICT(collector_id,mac,hour) DO UPDATE SET bytes_up=excluded.bytes_up",
        (MAC, stamp, value),
    )
    inv.execute(
        "INSERT OR REPLACE INTO coverage_hourly VALUES ('c1',?,?,?,'[]')",
        (stamp, coverage, coverage),
    )
    inv.execute("INSERT OR IGNORE INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, stamp))


def history(inv):
    for i in range(20):
        hour(inv, HOUR + (i % 14) * 86400 + (i // 14) * 3600, 10 * MIB)


def test_real_state_fits_frozen_reference_and_incident_retry_is_idempotent(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        history(inv)
        current = HOUR + 20 * 86400
        hour(inv, current - 3600, 51 * MIB)
        hour(inv, current, 51 * MIB)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3610)
        row = inv.execute(
            "SELECT median_twice,sample_hours,distinct_days FROM monitoring_baselines"
        ).fetchone()
        assert tuple(row) == (20 * MIB, 20, 14)
        incident = inv.execute(
            "SELECT detector,observed_bytes,threshold_bytes,state FROM monitoring_incidents"
        ).fetchone()
        assert tuple(incident) == ("upload_deviation", 51 * MIB, 50 * MIB, "open")
        hour(inv, current, 51 * MIB)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3620)
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 1
        assert inv.execute("SELECT COUNT(*) FROM monitoring_baselines").fetchone()[0] == 1
        hour(inv, HOUR - 3600, 1024 * MIB)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3630)
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 1
    finally:
        inv.close()
        ov.close()


def test_assignment_roundtrip_resets_learning_name_changes_do_not(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        history(inv)
        current = HOUR + 20 * 86400
        hour(inv, current, 10 * MIB)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3610)
        before = inv.execute("SELECT baseline_id FROM monitoring_profiles").fetchone()[0]
        assert before is not None
        ov.execute(
            "INSERT INTO device_overrides(device_id,name,updated_at,updated_by) VALUES"
            " ('d1','new name','now','test')"
        )
        hour(inv, current, 10 * MIB)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3620)
        assert inv.execute("SELECT baseline_id FROM monitoring_profiles").fetchone()[0] == before
        inv.execute("UPDATE observations SET device_id='d2' WHERE mac=?", (MAC,))
        inv.execute("UPDATE observations SET device_id='d1' WHERE mac=?", (MAC,))
        hour(inv, current, 10 * MIB)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3630)
        row = inv.execute(
            "SELECT baseline_id,training_since,state FROM monitoring_profiles"
        ).fetchone()
        assert tuple(row) == (None, current + 7200, "learning")
    finally:
        inv.close()
        ov.close()


def test_missing_previous_hour_breaks_deviation_and_95_percent_is_inclusive(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        history(inv)
        current = HOUR + 20 * 86400
        hour(inv, current, 51 * MIB, 3420)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3610)
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 0
        hour(inv, current + 3600, 51 * MIB, 3419)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 7210)
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 0
        hour(inv, current + 7200, 51 * MIB, 3420)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 10810)
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 0
        hour(inv, current + 10800, 51 * MIB, 3420)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 14410)
        assert inv.execute("SELECT COUNT(*) FROM monitoring_incidents").fetchone()[0] == 1
    finally:
        inv.close()
        ov.close()


def test_retention_is_bounded_and_keeps_live_dedupe_receipts(tmp_path):
    from vigie_pipeline.monitoring_engine import prune_monitoring

    inv, ov = seeded(tmp_path)
    try:
        now = HOUR + 100 * 86400
        hour(inv, HOUR, 10)
        hour(inv, now - 3600, 20)
        for i in range(1003):
            inv.execute(
                "INSERT INTO measurement_batches VALUES ('c1',?,?,?, ?,?, '[]')",
                (str(i), HOUR, HOUR + 60, iso_utc(HOUR), HOUR),
            )
        inv.execute(
            "INSERT INTO batches(collector_id,batch_id,received_at) VALUES ('c1','live',?)",
            (iso_utc(HOUR),),
        )
        inv.execute(
            "INSERT INTO measurement_batches VALUES ('c1','live',?,?,?,?,'[]')",
            (HOUR, HOUR + 60, iso_utc(HOUR), HOUR),
        )
        prune_monitoring(inv, now)
        assert inv.execute("SELECT COUNT(*) FROM measurement_batches").fetchone()[0] == 4
        assert [r[0] for r in inv.execute("SELECT bytes_up FROM measurements_hourly")] == [20]
        prune_monitoring(inv, now)
        assert [r[0] for r in inv.execute("SELECT batch_id FROM measurement_batches")] == ["live"]
    finally:
        inv.close()
        ov.close()


def test_late_training_quality_loss_rebuilds_reference_and_supersedes_incident(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        history(inv)
        current = HOUR + 20 * 86400
        hour(inv, current - 3600, 51 * MIB)
        hour(inv, current, 51 * MIB)
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3610)
        assert inv.execute("SELECT state FROM monitoring_profiles").fetchone()[0] == "mature"
        inv.execute(
            "UPDATE coverage_hourly SET qualified_seconds=0,reasons=? WHERE hour=?",
            ('["overlapping_window"]', HOUR),
        )
        inv.execute("INSERT OR IGNORE INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, current))
        analyze_monitoring(inv, ov, BaselineConfig(), current + 3620)
        row = inv.execute(
            "SELECT state,baseline_id,training_since FROM monitoring_profiles"
        ).fetchone()
        assert tuple(row) == ("rebuilding_quality", None, current + 7200)
        assert inv.execute("SELECT state FROM monitoring_incidents").fetchone()[0] == "superseded"
    finally:
        inv.close()
        ov.close()


def test_oversized_identity_cannot_starve_later_independent_upload_scope(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        for i in range(65):
            mac = f"aa:bb:dd:00:00:{i:02x}"
            inv.execute(
                "INSERT INTO "
                "observations(mac,device_id,is_randomized,link_source,"
                "first_seen,last_seen) VALUES (?,'d2',0,'self','t','t')",
                (mac,),
            )
            inv.execute("INSERT INTO monitoring_dirty VALUES ('c1',?,?)", (mac, HOUR))
        current = HOUR + 3600
        hour(inv, current, 1024 * MIB)
        for _ in range(5):
            analyze_monitoring(inv, ov, BaselineConfig(), current + 3610)
        assert (
            inv.execute(
                "SELECT COUNT(*) FROM monitoring_incidents WHERE device_id='d1'"
            ).fetchone()[0]
            == 1
        )
    finally:
        inv.close()
        ov.close()
