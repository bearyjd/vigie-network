from vigie_ingest.db import open_inventory
from vigie_ingest.models import Batch
from vigie_ingest.store import apply_batch, provision_collector
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

NOW = 1791997260
MAC = "aa:bb:cc:00:00:01"


def test_services_accumulate_only_same_mac_expire_and_never_write_human_intent(tmp_path):
    inv = open_inventory(tmp_path / "inventory.db")
    provision_collector(inv, "c1", "k1", False)
    inv.close()
    for seq, service in enumerate(["_googlecast._tcp", "_androidtvremote2._tcp"], 1):
        batch = Batch.model_validate(
            dict(
                collector_id="c1",
                key_id="k1",
                boot_id="boot1",
                seq=seq,
                batch_id=f"01927f3e-8a1b-7c2d-9e4f-{seq:012x}",
                window_start=NOW - 60,
                window_end=NOW,
                sent_ts=NOW,
                sightings=[dict(mac=MAC, kind="mdns", service=service)],
            )
        )
        apply_batch(tmp_path / "inventory.db", tmp_path, batch, NOW + seq, 900)
        run_once(PipelineConfig(data_dir=tmp_path), now=NOW + seq)
    inv = open_inventory(tmp_path / "inventory.db")
    row = inv.execute(
        "SELECT inferred_type,inferred_confidence,inferred_source FROM devices"
    ).fetchone()
    assert tuple(row) == ("tv", None, "deterministic-services")
    run_once(PipelineConfig(data_dir=tmp_path), now=NOW + 86401)
    assert inv.execute("SELECT inferred_type FROM devices").fetchone()[0] == "unknown"
    inv.close()


def test_different_macs_never_supply_the_two_halves_of_a_type_rule(tmp_path):
    from vigie_api.schema import open_overrides
    from vigie_pipeline.characterization_store import refresh_characterization, save_services
    from vigie_pipeline.schema import open_pipeline_inventory

    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    ov = open_overrides(tmp_path / "overrides.db")
    inv.execute("INSERT INTO devices(id,first_seen,last_seen) VALUES ('d','t','t')")
    for suffix in ["01", "02"]:
        inv.execute(
            "INSERT INTO observations(mac,device_id,is_randomized,link_source,"
            "first_seen,last_seen) "
            "VALUES (?,'d',0,'self','t','t')",
            (f"aa:bb:cc:00:00:{suffix}",),
        )
    save_services(
        inv,
        [
            (MAC, "mdns", "_googlecast._tcp", NOW),
            ("aa:bb:cc:00:00:02", "mdns", "_androidtvremote2._tcp", NOW),
        ],
        NOW,
    )
    refresh_characterization(inv, ov, NOW)
    assert inv.execute("SELECT inferred_type FROM devices").fetchone()[0] == "unknown"
    inv.close()
    ov.close()


def test_service_overflow_cannot_classify_a_favorable_prefix(tmp_path):
    from vigie_api.schema import open_overrides
    from vigie_pipeline.characterization_store import refresh_characterization, save_services
    from vigie_pipeline.schema import open_pipeline_inventory

    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    ov = open_overrides(tmp_path / "overrides.db")
    inv.execute("INSERT INTO devices(id,first_seen,last_seen) VALUES ('d','t','t')")
    inv.execute(
        "INSERT INTO observations(mac,device_id,is_randomized,link_source,"
        "first_seen,last_seen) "
        "VALUES (?,'d',0,'self','t','t')",
        (MAC,),
    )
    rows = [
        (MAC, "mdns", service, NOW)
        for service in [
            "_googlecast._tcp",
            "_androidtvremote2._tcp",
            *[f"_noise{i}._tcp" for i in range(255)],
        ]
    ]
    save_services(inv, rows, NOW)
    refresh_characterization(inv, ov, NOW)
    assert inv.execute("SELECT COUNT(*) FROM characterization_evidence").fetchone()[0] == 256
    assert inv.execute("SELECT inferred_type FROM devices").fetchone()[0] == "unknown"
    inv.close()
    ov.close()
