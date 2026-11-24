"""M2b-I inventory input: strict, bounded, fail-closed parsing of synthetic inventories."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigie_pipeline import product_signal_input as psi
from vigie_pipeline.product_signal_input import InventoryError, load_inventory, parse_inventory

FIXTURE = Path(__file__).parent / "fixtures" / "product_signal" / "inventory.json"


def raw() -> dict:
    return json.loads(FIXTURE.read_text())


def device(i: int, status: str = "active", mac: str | None = None) -> dict:
    return {"id": f"x{i}", "status": status,
            "macs": [{"mac": mac or f"00:00:5e:00:54:{i:02x}", "oui_vendor": None}]}  # fmt: skip


def minimal(**extra) -> dict:
    return {"format": "vigie-product-signal-inventory", "version": 1, "now": 1800000000,
            "devices": [device(1)], "links": [], "observations": [], **extra}  # fmt: skip


def rejects(doc: dict) -> None:
    with pytest.raises(InventoryError):
        parse_inventory(doc)


def test_fixture_and_minimal_documents_parse():
    assert len(parse_inventory(raw()).devices) == 20
    inv = parse_inventory(minimal())
    assert inv.ttl_seconds == 86400.0
    assert inv.devices[0].macs[0].mac == "00:00:5e:00:54:01"


def test_mac_case_and_separators_normalize_like_the_pipeline():
    doc = minimal()
    doc["devices"][0]["macs"][0]["mac"] = "00:00:5E:00:54:01"
    assert parse_inventory(doc).devices[0].macs[0].mac == "00:00:5e:00:54:01"


@pytest.mark.parametrize("mac", ["01:00:5e:00:00:01", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00",
                                 "00-00-5e-00-54-01", "zz:00:5e:00:54:01", ""])  # fmt: skip
def test_invalid_macs_are_rejected(mac):
    doc = minimal()
    doc["devices"][0]["macs"][0]["mac"] = mac
    rejects(doc)


def test_a_mac_on_two_device_rows_is_rejected():
    rejects(minimal(devices=[device(1), device(2, mac="00:00:5e:00:54:01")]))


def test_duplicate_device_ids_are_rejected():
    rejects(minimal(devices=[device(1), device(1, mac="00:00:5e:00:54:02")]))


@pytest.mark.parametrize(
    "links",
    [
        [{"from": "x1", "into": "x9", "revoked": False}],  # unknown device
        [{"from": "x1", "into": "x1", "revoked": False}],  # self link
        [
            {"from": "x1", "into": "x2", "revoked": False},
            {"from": "x2", "into": "x1", "revoked": False},
        ],  # cycle  # fmt: skip
        [
            {"from": "x1", "into": "x2", "revoked": False},
            {"from": "x1", "into": "x3", "revoked": False},
        ],  # duplicate active from  # fmt: skip
    ],
)
def test_inconsistent_links_are_rejected(links):
    rejects(minimal(devices=[device(1), device(2), device(3)], links=links))


def test_revoked_links_may_repeat_and_are_ignored():
    links = [{"from": "x1", "into": "x2", "revoked": True},
             {"from": "x1", "into": "x3", "revoked": False}]  # fmt: skip
    inv = parse_inventory(minimal(devices=[device(1), device(2), device(3)], links=links))
    assert inv.active_links == {"x1": "x3"}


def test_link_depth_is_bounded():
    n = psi.MAX_LINK_DEPTH + 2
    devices = [device(i) for i in range(n)]
    links = [{"from": f"x{i}", "into": f"x{i + 1}", "revoked": False} for i in range(n - 1)]
    rejects(minimal(devices=devices, links=links))


@pytest.mark.parametrize(
    "obs",
    [
        {"mac": "00:00:5e:00:54:01", "kind": "mdns", "observed_at": 1800000001},  # future
        {"mac": "00:00:5e:00:54:01", "kind": "mdns", "observed_at": True},
        {"mac": "00:00:5e:00:54:01", "kind": "arp", "observed_at": 1},
        {"mac": "00:00:5e:00:54:01", "kind": "dhcp", "observed_at": 1, "model": "m"},
        {"mac": "00:00:5e:00:54:01", "kind": "mdns", "observed_at": 1, "extra": "x"},
        {"mac": "00:00:5e:00:54:01", "kind": "mdns", "observed_at": 1, "service": "a\nb"},
        {"mac": "00:00:5e:00:54:01", "kind": "mdns", "observed_at": 1, "service": "é" * 129},
        {"mac": "00:00:5e:00:54:01", "kind": "mdns", "observed_at": 1, "service": 5},
        {"mac": "01:00:5e:00:54:01", "kind": "mdns", "observed_at": 1},
    ],
)
def test_invalid_observations_are_rejected(obs):
    rejects(minimal(observations=[obs]))


@pytest.mark.parametrize(
    "patch",
    [
        {"format": "other"},
        {"version": 2},
        {"now": True},
        {"now": -1},
        {"ttl_seconds": 0},
        {"ttl_seconds": 10 * 366 * 86400},
        {"unexpected": 1},
        {"devices": {}},
    ],
)
def test_invalid_envelopes_are_rejected(patch):
    rejects({**minimal(), **patch})


def test_invalid_device_fields_are_rejected():
    for bad in ({"status": "gone"}, {"id": "has space"}, {"id": "x" * 65}, {"macs": []},
                {"macs": [{"mac": "00:00:5e:00:54:01"}]}):  # fmt: skip
        rejects(minimal(devices=[{**device(1), **bad}]))


def test_count_caps_are_enforced(monkeypatch):
    monkeypatch.setattr(psi, "MAX_DEVICES", 2)
    rejects(minimal(devices=[device(1), device(2), device(3)]))
    monkeypatch.setattr(psi, "MAX_OBSERVATIONS", 1)
    obs = {"mac": "00:00:5e:00:54:01", "kind": "mdns", "observed_at": 1}
    rejects(minimal(observations=[obs, obs]))


@pytest.mark.parametrize(
    "text",
    [
        b'{"now": NaN}',
        b'{"now": Infinity}',
        b'{"format": "a", "format": "b"}',
        b"[1, 2]",
        b"\xff\xfe",
        b"{",
    ],
)
def test_strict_json_loading(text):
    with pytest.raises(InventoryError):
        load_inventory(text)


@pytest.mark.parametrize("text", [b'{"now": NaN}', b'{"now": -Infinity}'])
def test_non_finite_constants_are_rejected_while_decoding(text):
    with pytest.raises(InventoryError, match="non-finite"):
        load_inventory(text)


def test_oversize_input_is_rejected_before_parsing(monkeypatch):
    monkeypatch.setattr(psi, "MAX_INPUT_BYTES", 10)
    with pytest.raises(InventoryError, match="too large"):
        load_inventory(b" " * 11)


def test_error_messages_do_not_echo_input_values():
    doc = minimal()
    doc["devices"][0]["status"] = "secret-household-value"
    with pytest.raises(InventoryError) as info:
        parse_inventory(doc)
    assert "secret" not in str(info.value)
