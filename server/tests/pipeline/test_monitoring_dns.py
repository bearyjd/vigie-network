"""DNS uses the same dirty queue and qualified coverage as upload monitoring."""

import json

import pytest
from probe_helpers import build_fixture, dump, run_fixture
from test_monitoring_engine import HOUR, MAC, MIB, history, hour, seeded
from test_probe_freeze import POOLED_VERSION, TOD_VERSION

from vigie_pipeline import schema
from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.baselines_dns import DnsBaselineConfig
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.delivery_types import DEFAULT_DETECTORS
from vigie_pipeline.measurements import MAX_VALUE
from vigie_pipeline.monitoring_engine import analyze_monitoring, prune_monitoring
from vigie_pipeline.monitoring_identity import lineage
from vigie_pipeline.processor import monitoring_policy

CURRENT = HOUR + 20 * 86400
DNS = "dns_deviation"
TABLES = (
    "monitoring_dns_profiles",
    "monitoring_dns_baselines",
    "monitoring_dns_suspicious",
    "monitoring_dns_retries",
)


def dns_hour(inv, stamp, queries, upload=0, coverage=3600):
    hour(inv, stamp, upload, coverage)
    inv.execute(
        "UPDATE measurements_hourly SET dns_queries=? WHERE collector_id='c1' AND mac=? AND hour=?",
        (queries, MAC, stamp),
    )


def incidents(inv):
    return {
        row["detector"]: row
        for row in inv.execute("SELECT * FROM monitoring_incidents ORDER BY seq")
    }


def analyze(inv, ov, stamp=CURRENT, floor=200):
    analyze_monitoring(
        inv,
        ov,
        BaselineConfig(),
        stamp + 3610,
        dns_policy=DnsBaselineConfig(minimum_queries=floor),
    )


@pytest.fixture
def inventory(tmp_path):
    inv, ov = seeded(tmp_path)
    try:
        history(inv)
        inv.execute("UPDATE measurements_hourly SET dns_queries=200")
        yield inv, ov
    finally:
        inv.close()
        ov.close()


def test_flag_config_and_frozen_upload_versions():
    off = PipelineConfig.from_env({})
    assert off.monitoring_dns is False
    assert off.monitoring_dns_min_queries == 200
    assert DNS not in DEFAULT_DETECTORS
    env = {"VIGIE_MONITORING_DNS": "true", "VIGIE_MONITORING_DNS_MIN_QUERIES": "300"}
    on = PipelineConfig.from_env(env)
    assert on.monitoring_dns is True
    assert on.monitoring_dns_min_queries == 300
    assert monitoring_policy(on).version == POOLED_VERSION
    assert (
        monitoring_policy(
            PipelineConfig.from_env({**env, "VIGIE_MONITORING_BASELINE": "tod"})
        ).version
        == TOD_VERSION
    )
    for invalid in ("0", "1000001", "invalid"):
        with pytest.raises(ValueError, match="VIGIE_MONITORING_DNS_MIN_QUERIES"):
            PipelineConfig.from_env({"VIGIE_MONITORING_DNS_MIN_QUERIES": invalid})


def test_additive_migration_preserves_preexisting_rows(tmp_path, monkeypatch):
    migrations = schema.PIPELINE_MIGRATIONS
    path = tmp_path / "inventory.db"
    with monkeypatch.context() as patch:
        patch.setattr(schema, "PIPELINE_MIGRATIONS", migrations[:12])
        old = schema.open_pipeline_inventory(path, migrate=True)
        old.execute("INSERT INTO collectors(id,key_id) VALUES ('c1','k1')")
        old_definition = dict(
            old.execute("SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")
        )
        old.close()
    inv = schema.open_pipeline_inventory(path)
    try:
        assert inv.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 13
        present = dict(inv.execute("SELECT name,sql FROM sqlite_schema"))
        assert {name: present[name] for name in old_definition} == old_definition
        assert inv.execute("SELECT key_id FROM collectors WHERE id='c1'").fetchone()[0] == "k1"
        assert set(TABLES) <= present.keys()
        inv.execute("INSERT INTO pipeline_schema VALUES (14)")
    finally:
        inv.close()
    with pytest.raises(RuntimeError, match="newer"):
        schema.open_pipeline_inventory(path)


def test_normal_entry_point_preserves_upload_and_coverage_with_dns_flag(tmp_path):
    off, on = (tmp_path / name for name in ("off", "on"))
    for root in (off, on):
        root.mkdir()
        build_fixture(root)
        inv = schema.open_pipeline_inventory(root / "inventory.db")
        try:
            inv.execute("UPDATE measurements_hourly SET dns_queries=200")
            inv.execute("UPDATE measurements_hourly SET dns_queries=801 WHERE hour=?", (CURRENT,))
        finally:
            inv.close()
    run_fixture(off)
    run_fixture(on, VIGIE_MONITORING_DNS="true")
    on_dump = dump(on)
    dns_rows = [row for row in on_dump["monitoring_incidents"] if row[5] == DNS]
    assert len(dns_rows) == 1
    on_dump["monitoring_incidents"] = [
        row for row in on_dump["monitoring_incidents"] if row[5] != DNS
    ]
    assert on_dump == dump(off)
    inv = schema.open_pipeline_inventory(off / "inventory.db")
    try:
        for table in TABLES:
            assert inv.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0  # noqa: S608
    finally:
        inv.close()


def test_frozen_dns_episode_and_upload_resolve_independently(inventory):
    inv, ov = inventory
    dns_hour(inv, CURRENT - 3600, 200, 51 * MIB)
    dns_hour(inv, CURRENT, 801, 51 * MIB)
    analyze(inv, ov)
    rows = incidents(inv)
    assert rows.keys() == {DNS, "upload_deviation"}
    initial = rows[DNS]
    assert (initial["observed_bytes"], initial["threshold_bytes"]) == (801, 800)
    evidence = json.loads(initial["evidence"])
    assert evidence["unit"] == "queries"
    assert evidence["reason_code"] == "dns_deviation_threshold"
    assert evidence["baseline_median_queries"] == 200

    dns_hour(inv, CURRENT + 3600, 900)
    analyze(inv, ov, CURRENT + 3600)
    rows = incidents(inv)
    assert rows[DNS]["id"] == initial["id"]
    assert rows[DNS]["last_hour"] == CURRENT + 3600
    assert rows["upload_deviation"]["state"] == "resolved"
    assert rows[DNS]["state"] == "open"

    dns_hour(inv, CURRENT + 7200, 200)
    analyze(inv, ov, CURRENT + 7200)
    rows = incidents(inv)
    assert rows[DNS]["state"] == "resolved"
    assert rows[DNS]["baseline_id"] == initial["baseline_id"]
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dns_baselines").fetchone()[0] == 1


def test_quality_and_policy_rebuilds_only_supersede_dns(inventory):
    from vigie_pipeline.monitoring_dns import dns_baseline_view

    inv, ov = inventory
    key = lineage(inv, ov, "d1").key
    assert dns_baseline_view(inv, "c1", "d1", key) is None
    dns_hour(inv, CURRENT - 3600, 200, 51 * MIB)
    dns_hour(inv, CURRENT, 801, 51 * MIB)
    analyze(inv, ov)
    view = dns_baseline_view(inv, "c1", "d1", key)
    assert view["state"] == "mature"
    assert view["median_queries"] == 200
    assert dns_baseline_view(inv, "c1", "d1", "stale")["state"] == "rebuilding"
    dns_hour(inv, CURRENT, 801, 51 * MIB)
    analyze(inv, ov, floor=201)
    assert incidents(inv)[DNS]["state"] == "superseded"
    assert incidents(inv)["upload_deviation"]["state"] == "open"


def test_saturated_constituent_excluded_even_when_coverage_is_good(inventory):
    inv, ov = inventory
    dns_hour(inv, HOUR, MAX_VALUE)
    dns_hour(inv, CURRENT, MAX_VALUE)
    analyze(inv, ov)
    assert DNS not in incidents(inv)
    assert inv.execute("SELECT baseline_id FROM monitoring_dns_profiles").fetchone()[0] is None
    assert (
        inv.execute("SELECT hour FROM monitoring_dns_suspicious ORDER BY hour").fetchall()[-1][0]
        == CURRENT
    )


def test_quality_invalidation_of_training_supersedes_dns(inventory):
    inv, ov = inventory
    dns_hour(inv, CURRENT, 801)
    analyze(inv, ov)
    dns_hour(inv, HOUR, 200, coverage=3419)
    analyze(inv, ov)
    assert incidents(inv)[DNS]["state"] == "superseded"
    assert (
        inv.execute("SELECT state FROM monitoring_dns_profiles").fetchone()[0]
        == "rebuilding_quality"
    )


def test_dns_retention_is_bounded(inventory):
    inv, ov = inventory
    inv.executemany(
        "INSERT INTO monitoring_dns_suspicious VALUES ('c1','d1','k',?)",
        [(HOUR + i * 3600,) for i in range(1002)],
    )
    prune_monitoring(inv, HOUR + 200 * 86400, dns_enabled=True)
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dns_suspicious").fetchone()[0] == 2


def test_failed_dns_publish_rolls_back_dns_and_retries_after_upload_commits(inventory):
    inv, ov = inventory
    dns_hour(inv, CURRENT - 3600, 200, 51 * MIB)
    dns_hour(inv, CURRENT, 801, 51 * MIB)
    inv.execute(
        """CREATE TEMP TRIGGER fail_dns BEFORE INSERT ON monitoring_dns_profiles BEGIN
             SELECT RAISE(ABORT, 'simulated DNS storage failure');
           END"""
    )
    analyze(inv, ov)
    assert set(incidents(inv)) == {"upload_deviation"}
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dns_baselines").fetchone()[0] == 0
    assert inv.execute("SELECT COUNT(*) FROM monitoring_unavailable").fetchone()[0] == 0
    queued = CURRENT + 3610 + 60
    assert inv.execute("SELECT queued_at FROM monitoring_dirty").fetchone()[0] == queued

    inv.execute("DROP TRIGGER fail_dns")
    analyze_monitoring(inv, ov, BaselineConfig(), queued, dns_policy=DnsBaselineConfig())
    assert set(incidents(inv)) == {"upload_deviation", DNS}
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dirty").fetchone()[0] == 0


def test_invalid_per_mac_dns_counter_does_not_block_upload(inventory):
    inv, ov = inventory
    dns_hour(inv, CURRENT - 3600, 200, 51 * MIB)
    dns_hour(inv, CURRENT, -1, 51 * MIB)
    analyze(inv, ov)
    assert set(incidents(inv)) == {"upload_deviation"}
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dns_profiles").fetchone()[0] == 0
    assert inv.execute("SELECT queued_at FROM monitoring_dirty").fetchone()[0] == CURRENT + 3670


def test_double_median_round_trips_beyond_sqlite_integer_range(tmp_path):
    from vigie_ingest.db import iso_utc
    from vigie_pipeline.monitoring_dns import dns_baseline_view

    inv, ov = seeded(tmp_path)
    try:
        dns_hour(inv, CURRENT, MAX_VALUE - 1)
        for i in range(2, 34):
            mac = f"aa:bb:cc:00:00:{i:02x}"
            inv.execute(
                "INSERT INTO observations "
                "(mac,device_id,is_randomized,link_source,first_seen,last_seen) "
                "VALUES (?, 'd1', 0, 'self', ?, ?)",
                (mac, iso_utc(HOUR), iso_utc(HOUR)),
            )
            inv.execute(
                "INSERT INTO measurements_hourly VALUES ('c1',?,?,0,0,1,?)",
                (mac, CURRENT, MAX_VALUE - 1),
            )
        policy = DnsBaselineConfig(minimum_hours=1, minimum_days=1)
        analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 3610, dns_policy=policy)
        total = 33 * (MAX_VALUE - 1)
        assert total * 2 > 2**63 - 1
        row = inv.execute(
            "SELECT median_twice,typeof(median_twice) FROM monitoring_dns_baselines"
        ).fetchone()
        assert tuple(row) == (str(total * 2), "text")
        key = lineage(inv, ov, "d1").key
        assert dns_baseline_view(inv, "c1", "d1", key)["median_queries"] == total

        inv.execute("UPDATE monitoring_dns_baselines SET median_twice='123'")
        assert dns_baseline_view(inv, "c1", "d1", key)["state"] == "rebuilding"
        dns_hour(inv, CURRENT + 3600, 900)
        analyze_monitoring(inv, ov, BaselineConfig(), CURRENT + 7210, dns_policy=policy)
        assert dns_baseline_view(inv, "c1", "d1", key)["state"] == "rebuilding_quality"
    finally:
        inv.close()
        ov.close()


def test_default_delivery_only_publishes_upload_incident(inventory):
    from vigie_pipeline.delivery_publish import FakePublisher
    from vigie_pipeline.delivery_runner import run_delivery
    from vigie_pipeline.delivery_types import DeliveryConfig

    inv, ov = inventory
    dns_hour(inv, CURRENT - 3600, 200, 51 * MIB)
    dns_hour(inv, CURRENT, 801, 51 * MIB)
    analyze(inv, ov)
    publisher = FakePublisher()
    run_delivery(inv, ov, publisher, DeliveryConfig(), lambda: CURRENT + 3620)
    assert (
        inv.execute(
            "SELECT i.detector FROM incident_deliveries d "
            "JOIN monitoring_incidents i ON i.id=d.incident_id"
        ).fetchone()[0]
        == "upload_deviation"
    )
    assert inv.execute("SELECT COUNT(*) FROM incident_deliveries").fetchone()[0] == 1
    assert len(publisher.sent) == 1


def test_dns_retry_across_hour_boundary_scores_original_hour_then_catches_up(inventory):
    inv, ov = inventory
    dns_hour(inv, CURRENT, 801)
    dns_hour(inv, CURRENT + 3600, 200)
    inv.execute(
        """CREATE TEMP TRIGGER fail_dns BEFORE INSERT ON monitoring_dns_profiles BEGIN
             SELECT RAISE(ABORT, 'simulated DNS storage failure');
           END"""
    )
    policy = DnsBaselineConfig()
    first_attempt = CURRENT + 7190
    analyze_monitoring(inv, ov, BaselineConfig(), first_attempt, dns_policy=policy)
    inv.execute("DROP TRIGGER fail_dns")
    retry_at = first_attempt + 60
    analyze_monitoring(inv, ov, BaselineConfig(), retry_at, dns_policy=policy)
    assert incidents(inv)[DNS]["last_hour"] == CURRENT
    assert incidents(inv)[DNS]["state"] == "open"

    analyze_monitoring(inv, ov, BaselineConfig(), retry_at + 1, dns_policy=policy)
    assert incidents(inv)[DNS]["last_hour"] == CURRENT
    assert incidents(inv)[DNS]["state"] == "resolved"
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dirty").fetchone()[0] == 0


def test_stale_dns_retry_cannot_publish_an_older_hour_after_success(inventory):
    from vigie_pipeline.monitoring_dns import record_dns_retry

    inv, ov = inventory
    dns_hour(inv, CURRENT, 801)
    dns_hour(inv, CURRENT + 3600, 200)
    analyze(inv, ov, CURRENT + 3600)
    identity = lineage(inv, ov, "d1")
    record_dns_retry(inv, "c1", identity, CURRENT)
    dns_hour(inv, CURRENT + 7200, 200)
    analyze(inv, ov, CURRENT + 7200)
    assert DNS not in incidents(inv)
    assert inv.execute("SELECT updated_hour FROM monitoring_dns_profiles").fetchone()[0] == (
        CURRENT + 7200
    )
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dns_retries").fetchone()[0] == 0


@pytest.mark.parametrize("delivered_state", ["open", "resolved", "superseded"])
def test_dns_prune_keeps_incident_until_delivery_row_is_removed(inventory, delivered_state):
    from test_f5_s2a_plumbing import ids, put

    inv, _ = inventory
    put(inv, "dns-with-delivery", DNS, delivered_state)
    inv.execute("UPDATE monitoring_incidents SET lineage='other' WHERE id='dns-with-delivery'")
    put(inv, "old-open-dns", DNS, "open")
    inv.execute(
        "INSERT INTO incident_deliveries(delivery_id,incident_id,kind,state,created_at,updated_at)"
        " VALUES (?,'dns-with-delivery','open','sent',1,1)",
        ("1" * 32,),
    )

    now = HOUR + 200 * 86400
    prune_monitoring(inv, now, dns_enabled=True)
    assert ids(inv) == {"dns-with-delivery"}
    assert inv.execute("SELECT COUNT(*) FROM incident_deliveries").fetchone()[0] == 1
    inv.execute("DELETE FROM incident_deliveries")
    prune_monitoring(inv, now, dns_enabled=True)
    assert ids(inv) == set()


def test_dns_burst_after_unqualified_gap_supersedes_without_claiming_recovery(inventory):
    inv, ov = inventory
    dns_hour(inv, CURRENT, 801)
    analyze(inv, ov)
    first = incidents(inv)[DNS]["id"]

    dns_hour(inv, CURRENT + 3600, 200, coverage=3419)
    analyze(inv, ov, CURRENT + 3600)
    assert incidents(inv)[DNS]["state"] == "open"

    dns_hour(inv, CURRENT + 7200, 801)
    analyze(inv, ov, CURRENT + 7200)
    rows = inv.execute(
        "SELECT id,state,episode_start FROM monitoring_incidents WHERE detector=? ORDER BY seq",
        (DNS,),
    ).fetchall()
    assert tuple(rows[0]) == (first, "superseded", CURRENT)
    assert rows[1]["id"] != first
    assert (rows[1]["state"], rows[1]["episode_start"]) == ("open", CURRENT + 7200)


def test_dns_alias_merge_retires_source_and_requires_new_training(inventory):
    inv, ov = inventory
    dns_hour(inv, CURRENT, 801)
    analyze(inv, ov)
    assert incidents(inv)[DNS]["device_id"] == "d1"
    ov.execute("INSERT INTO identity_links VALUES ('d1','d2','m','t','u',NULL)")

    dns_hour(inv, CURRENT + 3600, 901)
    analyze(inv, ov, CURRENT + 3600)
    assert incidents(inv)[DNS]["device_id"] == "d1"
    assert incidents(inv)[DNS]["state"] == "superseded"
    profile = inv.execute(
        "SELECT state,baseline_id,training_since FROM monitoring_dns_profiles WHERE device_id='d2'"
    ).fetchone()
    assert tuple(profile) == ("learning", None, CURRENT + 10800)


@pytest.mark.parametrize("continuity_break", [None, "alias", "policy", "retry"])
def test_explicit_dns_delivery_validates_open(inventory, tmp_path, continuity_break):
    from vigie_pipeline.config import DeliverySettings
    from vigie_pipeline.monitoring_dns import record_dns_retry
    from vigie_pipeline.processor import run_once

    inv, ov = inventory
    dns_hour(inv, CURRENT, 801)
    analyze(inv, ov)
    clock = CURRENT + 3610
    floor = 200
    if continuity_break == "alias":
        ov.execute("INSERT INTO identity_links VALUES ('d1','d2','m','t','u',NULL)")
    elif continuity_break == "policy":
        floor = 201
    elif continuity_break == "retry":
        # A failed analysis must hold this delivery even before its dirty-row retry comes due.
        record_dns_retry(inv, "c1", lineage(inv, ov, "d1"), CURRENT)
        inv.execute("INSERT INTO monitoring_dirty VALUES ('c1',?,?)", (MAC, clock + 60))

    path = tmp_path / "delivery.jsonl"
    config = PipelineConfig(
        tmp_path,
        monitoring_dns=True,
        monitoring_dns_min_queries=floor,
        delivery=DeliverySettings(enabled=True, file=path, detectors=(DNS,)),
    )
    run_once(config, now=clock)
    assert incidents(inv)[DNS]["state"] == "open"
    deliveries = inv.execute("SELECT state,attempts FROM incident_deliveries").fetchall()
    if continuity_break is None:
        assert [row["state"] for row in deliveries] == ["sent"]
        assert "Unusual DNS activity" in path.read_text()
    else:
        # The normal planner may enqueue it, but an unverified dispatch never takes an attempt.
        assert [tuple(row) for row in deliveries] == [("pending", 0)]
        assert not path.exists()


def _dns_delivery_config(root, **kwargs):
    from vigie_pipeline.config import DeliverySettings

    return PipelineConfig(
        root,
        monitoring_dns=True,
        delivery=DeliverySettings(
            enabled=True, file=root / "delivery.jsonl", detectors=(DNS,), **kwargs
        ),
    )


@pytest.mark.parametrize("above_watermark", [False, True])
def test_dns_delivery_reaches_valid_candidate_past_older_backlog(
    inventory, tmp_path, above_watermark
):
    from test_f5_s2a_plumbing import put

    from vigie_ingest.db import iso_utc
    from vigie_pipeline.processor import run_once

    inv, ov = inventory
    clock = CURRENT + 3610
    for index in range(140):
        identifier = f"000-obsolete-{index:03}"
        put(inv, identifier, DNS, "resolved")
        inv.execute(
            "UPDATE monitoring_incidents SET lineage=?,detected_at=?,state='open' WHERE id=?",
            (identifier, iso_utc(clock if above_watermark else clock - 1), identifier),
        )
    dns_hour(inv, CURRENT, 801)
    analyze(inv, ov)
    active = inv.execute(
        "SELECT id FROM monitoring_incidents WHERE baseline_id IS NOT NULL"
    ).fetchone()[0]

    config = _dns_delivery_config(tmp_path, max_per_run=1)
    run_once(config, now=clock)
    if above_watermark:
        run_once(config, now=clock + 1)
    assert [
        (row["incident_id"], row["state"])
        for row in inv.execute("SELECT incident_id,state FROM incident_deliveries WHERE attempts>0")
    ] == [(active, "sent")]
    if not above_watermark:
        assert inv.execute("SELECT COUNT(*) FROM incident_deliveries").fetchone()[0] == 1


def _overlap(inv, stamp):
    from vigie_ingest.db import iso_utc
    from vigie_pipeline.measurements import Measurements, apply_measurements

    inv.execute(
        "INSERT INTO measurement_batches VALUES ('c1',?,?,?,?,?,'[]')",
        (f"first-{stamp}", stamp, stamp + 3500, iso_utc(stamp + 3500), stamp),
    )
    apply_measurements(
        inv,
        Measurements(
            "c1",
            f"overlap-{stamp}",
            stamp + 3400,
            stamp + 3600,
            iso_utc(stamp + 3600),
            (),
            {MAC: (0, 0, 1, 1)},
        ),
    )
    assert (
        inv.execute(
            "SELECT qualified_seconds FROM coverage_hourly WHERE collector_id='c1' AND hour=?",
            (stamp,),
        ).fetchone()[0]
        == 0
    )


def test_dns_late_overlap_blocks_open_after_dirty_marker_has_drained(inventory, tmp_path):
    from vigie_pipeline.delivery_wiring import WATERMARK_KEY
    from vigie_pipeline.processor import run_once

    inv, ov = inventory
    dns_hour(inv, CURRENT, 801)
    analyze(inv, ov)
    _overlap(inv, CURRENT)
    inv.execute("INSERT INTO pipeline_meta VALUES (?,?)", (WATERMARK_KEY, str(CURRENT + 3610)))
    clock = CURRENT + 7210
    run_once(_dns_delivery_config(tmp_path), now=clock)
    assert incidents(inv)[DNS]["state"] == "superseded"
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dirty").fetchone()[0] == 0
    assert not (tmp_path / "delivery.jsonl").exists()


def test_dns_late_training_overlap_blocks_open_before_quality_fanout(inventory, tmp_path):
    from vigie_pipeline.delivery_wiring import WATERMARK_KEY
    from vigie_pipeline.processor import run_once

    inv, ov = inventory
    dns_hour(inv, CURRENT, 801)
    analyze(inv, ov)
    _overlap(inv, HOUR)
    inv.execute(
        "INSERT INTO monitoring_quality_work VALUES ('another-collector',?,'')", (HOUR - 3600,)
    )
    clock = CURRENT + 3610
    inv.execute("INSERT INTO pipeline_meta VALUES (?,?)", (WATERMARK_KEY, str(clock)))
    run_once(_dns_delivery_config(tmp_path), now=clock)
    assert (
        inv.execute("SELECT hour FROM monitoring_quality_work WHERE collector_id='c1'").fetchone()[
            0
        ]
        == HOUR
    )
    assert inv.execute("SELECT COUNT(*) FROM monitoring_dirty").fetchone()[0] == 0
    assert not (tmp_path / "delivery.jsonl").exists()


@pytest.mark.parametrize("invalidate_recovery", [False, True])
def test_dns_recovery_send_requires_a_still_qualified_hour(
    inventory, tmp_path, invalidate_recovery
):
    from vigie_pipeline.processor import run_once

    inv, ov = inventory
    config = _dns_delivery_config(tmp_path)
    path = tmp_path / "delivery.jsonl"
    dns_hour(inv, CURRENT, 801)
    run_once(config, now=CURRENT + 3610)
    assert len(path.read_text().splitlines()) == 1

    recovery = CURRENT + 3600
    dns_hour(inv, recovery, 200)
    analyze(inv, ov, recovery)
    assert incidents(inv)[DNS]["state"] == "resolved"
    if invalidate_recovery:
        _overlap(inv, recovery)
    run_once(config, now=recovery + 7210)
    notices = [json.loads(line)["kind"] for line in path.read_text().splitlines()]
    assert notices == (["open"] if invalidate_recovery else ["open", "recover"])


def test_late_middle_overlap_blocks_delivery_and_retires_disqualified_episode(inventory, tmp_path):
    from vigie_pipeline.delivery_wiring import WATERMARK_KEY
    from vigie_pipeline.processor import run_once

    inv, ov = inventory
    middle = CURRENT + 3600
    last = CURRENT + 7200
    for stamp in (CURRENT, middle, last):
        dns_hour(inv, stamp, 801)
        analyze(inv, ov, stamp)
    opened = incidents(inv)[DNS]
    assert (opened["episode_start"], opened["last_hour"]) == (CURRENT, last)

    _overlap(inv, middle)
    inv.execute(
        "INSERT INTO monitoring_quality_work VALUES ('another-collector',?,'')", (middle - 3600,)
    )
    inv.execute("INSERT INTO pipeline_meta VALUES (?,?)", (WATERMARK_KEY, str(CURRENT + 3610)))
    config = _dns_delivery_config(tmp_path)
    path = tmp_path / "delivery.jsonl"

    # The invalidation has reached coverage, but the oldest fanout belongs to another collector.
    run_once(config, now=last + 7210)
    assert (
        inv.execute("SELECT hour FROM monitoring_quality_work WHERE collector_id='c1'").fetchone()[
            0
        ]
        == middle
    )
    assert not path.exists()

    # A qualified normal hour cannot make a disqualified episode eligible for a recovery notice.
    normal = last + 7200
    dns_hour(inv, normal, 200)
    run_once(config, now=normal + 3610)
    assert incidents(inv)[DNS]["state"] == "superseded"
    assert not path.exists()

    fresh = normal + 3600
    dns_hour(inv, fresh, 801)
    run_once(config, now=fresh + 3610)
    new = incidents(inv)[DNS]
    assert new["id"] != opened["id"]
    assert (new["state"], new["episode_start"]) == ("open", fresh)
    assert [json.loads(line)["kind"] for line in path.read_text().splitlines()] == ["open"]


@pytest.mark.parametrize("page_size", [18, 128])
@pytest.mark.parametrize("interruption", ["budget", "stop"])
def test_bounded_dns_delivery_resumes_after_last_examined_row(inventory, page_size, interruption):
    from itertools import count

    from test_f5_s2a_plumbing import put

    from vigie_ingest.db import iso_utc
    from vigie_pipeline.delivery_publish import FakePublisher
    from vigie_pipeline.delivery_runner import run_delivery
    from vigie_pipeline.delivery_types import DeliveryConfig

    inv, ov = inventory
    now = CURRENT + 3610
    for index in range(page_size - 1):
        identifier = f"000-obsolete-{index:03}"
        put(inv, identifier, DNS, "resolved")
        inv.execute(
            "UPDATE monitoring_incidents SET lineage=?,detected_at=?,state='open' WHERE id=?",
            (identifier, iso_utc(now), identifier),
        )
    dns_hour(inv, CURRENT, 801)
    analyze(inv, ov)
    budget = 60 if page_size == 128 else 7
    actual = FakePublisher()
    for _ in range(3):
        ticks = count()
        signals = count()
        run_delivery(
            inv,
            ov,
            actual,
            DeliveryConfig(eligible_since=now, transmit_deadline_seconds=1),
            lambda: now,
            detectors=(DNS,),
            dns_policy=DnsBaselineConfig(),
            drain_budget_seconds=budget,
            monotonic=(lambda ticks=ticks: next(ticks))
            if interruption == "budget"
            else (lambda: 0),
            should_stop=lambda signals=signals: (
                interruption == "stop" and next(signals) >= budget - 1
            ),
        )
    assert len(actual.sent) == 1
    assert inv.execute("SELECT SUM(attempts) FROM incident_deliveries").fetchone()[0] == 1


@pytest.mark.parametrize("change", ["rule_attach_then_undo", "merge_then_undo"])
def test_dns_first_enable_does_not_bootstrap_across_historic_lineage_change(
    inventory, tmp_path, change
):
    from vigie_pipeline.processor import run_once

    inv, ov = inventory
    if change == "rule_attach_then_undo":
        inv.execute(
            "UPDATE observations SET device_id='d2',link_source='rule',link_rule_id='rule' "
            "WHERE mac=?",
            (MAC,),
        )
    else:
        ov.execute("INSERT INTO identity_links VALUES ('d1','d2','m','t','u',NULL)")
    off = PipelineConfig(tmp_path)
    run_once(off, now=CURRENT + 3610)
    if change == "rule_attach_then_undo":
        inv.execute(
            "UPDATE observations SET device_id='d1',link_source='self',link_rule_id=NULL "
            "WHERE mac=?",
            (MAC,),
        )
    else:
        ov.execute("UPDATE identity_links SET revoked_at='u' WHERE from_device='d1'")

    assert inv.execute("SELECT COUNT(*) FROM monitoring_dns_profiles").fetchone()[0] == 0
    identity = lineage(inv, ov, "d1")
    assert not identity.rule_attached and not identity.aliases
    burst = CURRENT + 3600
    dns_hour(inv, burst, 801)
    run_once(PipelineConfig(tmp_path, monitoring_dns=True), now=burst + 3610)
    profile = inv.execute(
        "SELECT state,baseline_id,training_since,sample_hours FROM monitoring_dns_profiles"
    ).fetchone()
    assert tuple(profile) == ("learning", None, burst + 7200, 0)
    assert DNS not in incidents(inv)
