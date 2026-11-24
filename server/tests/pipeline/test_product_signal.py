"""M2b-I product-signal coverage: classification, scope and coverage over synthetic data."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path

import pytest

from vigie_pipeline.product_signal import CLASSES, REASONS, RULES_VERSION, build_report, render
from vigie_pipeline.product_signal_input import parse_inventory

FIXTURE = Path(__file__).parent / "fixtures" / "product_signal" / "inventory.json"
FRESH = 1799996400
NOW = 1800000000


def raw() -> dict:
    return json.loads(FIXTURE.read_text())


def report(doc: dict | None = None, threshold: str | None = None) -> dict:
    return build_report(parse_inventory(doc if doc is not None else raw()), threshold)


def classes(rep: dict) -> dict[str, tuple[str, str]]:
    return {d["device_id"]: (d["class"], d["reason"]) for d in rep["devices"]}


def test_per_device_classification_covers_every_stress_case():
    assert classes(report()) == {
        "d01": ("product_level", "fresh_product_claim"),  # OUI vendor differs: not a conflict
        "d02": ("product_level", "fresh_product_claim"),  # merged group, agreeing claims
        "d04": ("conflicting", "product_claims_disagree"),  # merged group, disagreeing claims
        "d06": ("unknown", "random_mac_oui_ignored"),
        "d07": ("product_level", "fresh_product_claim"),  # random MAC, own product claim
        "d08": ("oui_only", "oui_vendor_only"),
        "d09": ("generic", "generic_hint"),
        "d10": ("generic", "type_level_service_match"),  # services-v1 pair is type-level only
        "d11": ("expired", "product_claim_expired"),
        "d14": ("generic", "vendor_without_model"),
        "d15": ("unknown", "no_signal"),  # hostname is never evidence
        "d16": ("unknown", "expired_generic_only"),
        "d17": ("product_level", "fresh_product_claim"),  # undone merge: separate devices
        "d18": ("product_level", "fresh_product_claim"),
        "d19": ("oui_only", "oui_vendors_differ"),
    }


def test_coverage_has_explicit_numerator_and_denominator():
    rep = report()
    assert rep["coverage"] == {"numerator": 5, "denominator": 15, "ratio": 0.333333, "reason": None}
    assert rep["scope"] == {
        "input_devices": 20,
        "in_scope": 15,
        "aliases_folded": 3,
        "excluded_retired": 1,
        "excluded_transient": 1,
        "unattributed_observations": 1,
    }
    assert rep["rules_version"] == RULES_VERSION


def test_class_and_reason_counts_are_exhaustive_and_sum_to_denominator():
    rep = report()
    assert list(rep["counts_by_class"]) == sorted(CLASSES)
    assert list(rep["counts_by_reason"]) == sorted(REASONS)
    assert sum(rep["counts_by_class"].values()) == rep["coverage"]["denominator"]
    assert sum(rep["counts_by_reason"].values()) == rep["coverage"]["denominator"]
    assert rep["counts_by_class"]["product_level"] == rep["coverage"]["numerator"]
    assert rep["counts_by_class"] == {
        "conflicting": 1,
        "expired": 1,
        "generic": 3,
        "oui_only": 2,
        "product_level": 5,
        "unknown": 3,
    }


def test_merge_members_are_listed_on_the_canonical_device():
    by_id = {d["device_id"]: d for d in report()["devices"]}
    assert by_id["d02"]["members"] == ["d02", "d03"]
    assert by_id["d17"]["members"] == ["d17"]
    assert by_id["d07"]["random_mac_count"] == 1
    assert by_id["d02"]["sources"] == ["mdns_model", "mdns_service", "ssdp_model"]


def test_undo_restores_the_merge_conflict_and_reactivating_a_link_folds_devices():
    doc = raw()
    for link in doc["links"]:
        if link["from"] == "d18":
            link["revoked"] = False
        if link["from"] == "d05":
            link["revoked"] = True  # undo the conflicting merge
    rep = report(doc)
    got = classes(rep)
    assert got["d17"] == ("conflicting", "product_claims_disagree")
    assert "d18" not in got
    assert got["d04"] == ("product_level", "fresh_product_claim")
    assert got["d05"] == ("product_level", "fresh_product_claim")
    assert rep["coverage"]["denominator"] == 15


def test_a_single_product_claim_is_not_overridden_by_differing_ouis_in_its_group():
    doc = raw()
    doc["observations"].append(
        {
            "mac": "00:00:5e:00:53:20",
            "kind": "ssdp",
            "observed_at": FRESH,
            "manufacturer": "Fictional Widgets",
            "model": "Widget Three",
        }  # fmt: skip
    )
    assert classes(report(doc))["d19"] == ("product_level", "fresh_product_claim")


def test_fresh_claim_wins_over_an_expired_disagreeing_claim():
    doc = raw()
    doc["observations"].append(
        {
            "mac": "00:00:5e:00:53:01",
            "kind": "ssdp",
            "observed_at": NOW - 90000,
            "manufacturer": "Other Fake Corp",
            "model": "Gizmo",
        }  # fmt: skip
    )
    assert classes(report(doc))["d01"] == ("product_level", "fresh_product_claim")


def test_freshness_boundary_matches_characterization():
    doc = raw()
    for obs in doc["observations"]:
        if obs["mac"] == "00:00:5e:00:53:01":
            obs["observed_at"] = NOW - 86400  # observed_at + ttl == now: expired
    assert classes(report(doc))["d01"] == ("expired", "product_claim_expired")


def test_alias_of_a_retired_canonical_is_out_of_scope():
    doc = raw()
    doc["links"].append({"from": "d01", "into": "d12", "revoked": False})
    rep = report(doc)
    assert "d01" not in classes(rep)
    assert rep["scope"]["excluded_retired"] == 1
    assert rep["scope"]["aliases_folded"] == 4
    assert rep["coverage"]["denominator"] == 14


def test_output_never_echoes_raw_strings():
    text = render(report()).decode()
    for secret in ("Fictional", "Widget", "Gizmo", "Example Radio", "Sample Silicon",
                   "synthetic-host", "FakeOS", "_fake-", "_googlecast", "_http"):  # fmt: skip
        assert secret.lower() not in text.lower()


def test_empty_scope_reports_null_ratio_with_reason():
    doc = raw()
    doc["devices"] = [d for d in doc["devices"] if d["status"] != "active"]
    doc["links"] = []
    rep = report(doc, threshold="0.5")
    assert rep["coverage"] == {"numerator": 0, "denominator": 0, "ratio": None,
                               "reason": "empty_scope"}  # fmt: skip
    assert rep["threshold"] == {"value": "0.5", "met": None}


@pytest.mark.parametrize(
    ("text", "met"), [("0.333333", True), ("0.3334", False), ("1", False), ("0.01", True)]
)
def test_threshold_is_compared_exactly(text, met):
    assert report(threshold=text)["threshold"] == {"value": text, "met": met}


def test_threshold_is_not_evaluated_without_an_owner_value():
    assert report()["threshold"] == {"value": None, "met": None}


@pytest.mark.parametrize("text", ["0", "1.1", "-0.5", "nan", "inf", "0.5e0", "1/2", "", " 0.5",
                                  "0.1234567", "00.5", "0.0", "0.000000"])  # fmt: skip
def test_invalid_thresholds_are_rejected(text):
    with pytest.raises(ValueError, match="invalid threshold"):
        report(threshold=text)


@pytest.mark.parametrize("threshold", [None, "0.01", "1"])
def test_report_never_authorizes_known_issue_notes(threshold):
    rep = report(threshold=threshold)
    assert rep["authorizes_known_issue_notes"] is False
    assert "evidence only" in rep["notice"]


def test_output_is_byte_identical_under_input_reordering():
    expected = render(report())
    rng = random.Random(7)  # noqa: S311 - deterministic shuffle, not security
    for _ in range(5):
        doc = copy.deepcopy(raw())
        for key in ("devices", "links", "observations"):
            rng.shuffle(doc[key])
        assert render(report(doc)) == expected
    assert expected.endswith(b"\n")
    assert expected.isascii()
