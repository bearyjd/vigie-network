"""ct_lan_unmapped_bytes: floor AND share threshold; the flows counter never degrades."""

import json

import pytest
from test_flow_degraded_informational import INFO, _hour
from test_monitoring import HOUR, MAC

from vigie_ingest.db import open_inventory
from vigie_ingest.models import Batch
from vigie_ingest.store import apply_batch, provision_collector
from vigie_pipeline import measurements
from vigie_pipeline.measurements import read_measurements

FLOOR = 262144
BATCH_ID = "01927f3e-8a1b-7c2d-9e4f-000000000001"


def _record(root, truncated, up, down):
    inv = open_inventory(root / "inventory.db")
    provision_collector(inv, "c1", "k1", False)
    inv.close()
    batch = Batch.model_validate(
        {
            "collector_id": "c1",
            "key_id": "k1",
            "boot_id": "boot1",
            "seq": 1,
            "batch_id": BATCH_ID,
            "window_start": HOUR,
            "window_end": HOUR + 3540,
            "sent_ts": HOUR + 3540,
            "observation_kind": "observation",
            "conntrack": [
                {
                    "mac": MAC,
                    "dst_ip": "93.184.216.34",
                    "dst_port": 443,
                    "proto": "tcp",
                    "bytes_up": up,
                    "bytes_down": down,
                    "flows": 1,
                }
            ],
            "health": {"dns_log_quiet": True},
            "truncated": truncated,
        }
    )
    assert apply_batch(root / "inventory.db", root, batch, HOUR + 3541, 900) == "applied"


def _lan(tmp_path, truncated, up=600_000, down=400_000):
    _record(tmp_path, truncated, up, down)
    return _hour(tmp_path)


def test_constants_are_the_documented_policy():
    assert measurements.LAN_UNMAPPED_MIN_BYTES == 262144
    assert measurements.LAN_UNMAPPED_MAX_SHARE_PCT == 5


def test_below_floor_qualifies_even_when_share_is_huge(tmp_path):
    qualified, reasons = _lan(tmp_path, {"ct_lan_unmapped_bytes": 10_000}, up=5, down=5)
    assert reasons == []
    assert qualified == 3540


def test_exactly_at_floor_qualifies_even_when_share_is_huge(tmp_path):
    assert _lan(tmp_path, {"ct_lan_unmapped_bytes": FLOOR}, up=5, down=5)[1] == []


def test_one_byte_above_floor_with_huge_share_degrades(tmp_path):
    qualified, reasons = _lan(tmp_path, {"ct_lan_unmapped_bytes": FLOOR + 1}, up=5, down=5)
    assert reasons == ["lan_unmapped_share"]
    assert qualified == 0


def test_above_floor_but_below_share_qualifies(tmp_path):
    result = _lan(tmp_path, {"ct_lan_unmapped_bytes": FLOOR + 1}, up=9_500_000, down=9_500_000)
    assert result == (3540, [])


def test_exactly_five_percent_of_total_qualifies(tmp_path):
    # mapped 19_000_000 + lan 1_000_000 = 20_000_000; 5% of that is exactly lan
    result = _lan(tmp_path, {"ct_lan_unmapped_bytes": 1_000_000}, up=9_500_000, down=9_500_000)
    assert result == (3540, [])


def test_one_byte_over_five_percent_degrades(tmp_path):
    truncated = {"ct_lan_unmapped_bytes": 1_000_001}
    qualified, reasons = _lan(tmp_path, truncated, up=9_500_000, down=9_500_000)
    assert reasons == ["lan_unmapped_share"]
    assert qualified == 0


def test_above_both_thresholds_degrades(tmp_path):
    qualified, reasons = _lan(tmp_path, {"ct_lan_unmapped_bytes": 500_000})
    assert reasons == ["lan_unmapped_share"]
    assert qualified == 0


def test_threshold_trip_beside_a_collector_fault_lists_both_reasons_sorted(tmp_path):
    truncated = {"ct_lan_unmapped_bytes": 500_000, "ct_errors": 1}
    qualified, reasons = _lan(tmp_path, truncated)
    assert reasons == ["flow_degraded", "lan_unmapped_share"]
    assert qualified == 0


def test_a_fault_alone_is_still_flow_degraded_only(tmp_path):
    assert _lan(tmp_path, {"ct_lan_unmapped_bytes": 1_000, "ct_errors": 1}) == (
        0,
        ["flow_degraded"],
    )


def test_mapped_bytes_is_up_plus_down(tmp_path):
    # up alone (1_000) would make lan 99.9%; up + down (19_000_000) makes it exactly 5%
    result = _lan(tmp_path, {"ct_lan_unmapped_bytes": 1_000_000}, up=1_000, down=18_999_000)
    assert result == (3540, [])


def test_flows_alone_never_degrade(tmp_path):
    assert _lan(tmp_path, {"ct_lan_unmapped_flows": 10**9}) == (3540, [])


def test_flows_never_degrade_beside_bytes_that_qualify(tmp_path):
    truncated = {"ct_lan_unmapped_bytes": 1_000, "ct_lan_unmapped_flows": 10**9}
    assert _lan(tmp_path, truncated) == (3540, [])


def test_legacy_informational_pair_is_still_informational(tmp_path):
    assert _lan(tmp_path, {**INFO, "ct_lan_unmapped_bytes": 1_000}) == (3540, [])


def test_old_collector_without_lan_keys_is_unchanged(tmp_path):
    assert _lan(tmp_path, INFO) == (3540, [])


@pytest.mark.parametrize(
    "extra",
    [{"ct_errors": 1}, {"ct_dropped_keys": 2}, {"conntrack_lost": 1}, {"truncated_other": 1}],
)
def test_a_loss_key_beside_lan_unmapped_still_degrades(tmp_path, extra):
    qualified, reasons = _lan(tmp_path, {"ct_lan_unmapped_bytes": 1_000, **extra})
    assert "flow_degraded" in reasons
    assert qualified == 0


def test_similar_unlisted_key_is_not_informational(tmp_path):
    assert "flow_degraded" in _lan(tmp_path, {"ct_lan_unmapped_errors": 1})[1]


def _reasons(tmp_path, truncated):
    """Reasons from a stored (possibly hostile) truncated blob; ingest would reject these."""
    _record(tmp_path, {}, 600_000, 400_000)
    inv = open_inventory(tmp_path / "inventory.db")
    try:
        inv.execute("UPDATE batches SET truncated=?", (json.dumps(truncated),))
        return read_measurements(inv, tmp_path, "c1", BATCH_ID).reasons
    finally:
        inv.close()


@pytest.mark.parametrize("bad", ["12", 1.5, -1, True, None, [1], {"a": 1}])
def test_garbage_or_negative_lan_bytes_degrade(tmp_path, bad):
    assert _reasons(tmp_path, {"ct_lan_unmapped_bytes": bad}) == ("flow_degraded",)


def test_zero_lan_bytes_qualifies(tmp_path):
    assert _reasons(tmp_path, {"ct_lan_unmapped_bytes": 0}) == ()


def test_lan_bytes_with_uncomputable_totals_degrade(tmp_path, monkeypatch):
    monkeypatch.setattr(measurements, "MAX_VALUE", 100)  # per-MAC totals saturate
    reasons = _reasons(tmp_path, {"ct_lan_unmapped_bytes": 1})
    assert reasons == ("counter_overflow", "flow_degraded")


@pytest.mark.parametrize(
    "key",
    ["CT_ERRORS", "Ct_errors", "CONNTRACK_LOST", "Conntrack_lost", "CT_UNMAPPED_BYTES"],
)
def test_loss_key_prefix_match_is_case_insensitive(tmp_path, key):
    assert _reasons(tmp_path, {key: 1}) == ("flow_degraded",)


@pytest.mark.parametrize(
    "key", ["CT_LAN_UNMAPPED_FLOWS", "Ct_Unmapped_Flows", "CT_LAN_UNMAPPED_BYTES"]
)
def test_informational_set_stays_exact_match_for_upper_case(tmp_path, key):
    assert _reasons(tmp_path, {key: 1}) == ("flow_degraded",)


def test_lower_case_informational_keys_still_do_not_degrade(tmp_path):
    assert _reasons(tmp_path, {**INFO, "ct_lan_unmapped_flows": 5}) == ()


def test_engine_treats_an_hour_with_the_new_reason_as_ineligible(tmp_path):
    from types import SimpleNamespace

    from test_monitoring_engine import MAC as ENGINE_MAC
    from test_monitoring_engine import hour, seeded

    from vigie_pipeline.monitoring_engine import samples_for

    inv, ov = seeded(tmp_path)
    try:
        hour(inv, HOUR, 1000)
        identity = SimpleNamespace(macs=[ENGINE_MAC], device_id="d1", key="k")
        now = HOUR + 7200
        assert samples_for(inv, "c1", identity, now)[0].eligible is True
        inv.execute("UPDATE coverage_hourly SET reasons=?", ('["lan_unmapped_share"]',))
        assert samples_for(inv, "c1", identity, now)[0].eligible is False
    finally:
        inv.close()
        ov.close()
