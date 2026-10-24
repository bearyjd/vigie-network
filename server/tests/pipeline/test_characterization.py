from __future__ import annotations

import math

import pytest

from vigie_pipeline.characterization import Observation, classify

NOW = 2_000_000.0
MAC = "02:11:22:33:44:55"
OTHER = "02:11:22:33:44:56"


def obs(service=None, age=0, **kwargs):
    return Observation(
        mac=kwargs.pop("mac", MAC),
        observed_at=NOW - age,
        kind=kwargs.pop("kind", "mdns"),
        service=service,
        **kwargs,
    )


def tv(age=0):
    return [obs("_googlecast._tcp.local", age), obs("_androidtvremote2._tcp.local", age)]


def printing(age=0):
    return [obs("_printer._tcp.local", age), obs("_ipps._tcp.local", age)]


def test_tv_exact_pair_has_qualitative_strength_and_versioned_provenance():
    result = classify(tv(10), NOW)
    assert (result.inferred_type, result.role, result.strength, result.confidence) == (
        "tv",
        "television",
        "corroborated",
        None,
    )
    assert result.rule_ids == ("android-tv-services-v1",)
    assert result.model_version == "services-v1"
    assert result.source == "deterministic-services"
    assert result.valid_until == NOW - 10 + 86400
    assert {e.service for e in result.evidence} == {"_googlecast._tcp", "_androidtvremote2._tcp"}


@pytest.mark.parametrize("service", ["_ipp._tcp", "_ipps._tcp.local."])
def test_printing_pair_uses_existing_iot_enum_with_printing_role(service):
    result = classify([obs("_printer._tcp"), obs(service)], NOW)
    assert (result.inferred_type, result.role) == ("iot", "printing")


@pytest.mark.parametrize(
    "signals",
    [
        [],
        [obs("_googlecast._tcp")],
        [obs("_ipp._tcp")],
        [obs(kind="dhcp", hostname="Living room TV", opt55="1,3,6", opt60="Android TV")],
        [obs(kind="ssdp", service="urn:schemas-upnp-org:device:MediaRenderer:1", ua="TV vendor")],
    ],
)
def test_single_claims_and_fingerprints_do_not_establish_type(signals):
    result = classify(signals, NOW)
    assert result.inferred_type == "unknown"
    assert result.strength == "none" and result.confidence is None


def test_conflicting_roles_abstain_with_both_rule_explanations():
    result = classify(tv() + printing(), NOW)
    assert result.inferred_type == "unknown" and result.reason == "conflicting_roles"
    assert len(result.rule_ids) == 2


def test_different_macs_cannot_complete_a_pair():
    result = classify([obs("_googlecast._tcp"), obs("_androidtvremote2._tcp", mac=OTHER)], NOW)
    assert result.inferred_type == "unknown" and result.reason == "mixed_macs"


def test_expiry_uses_oldest_required_support_not_unrelated_newer_claim():
    signals = [
        obs("_googlecast._tcp", 500),
        obs("_androidtvremote2._tcp", 10),
        obs("_irrelevant._tcp"),
    ]
    assert classify(signals, NOW).valid_until == NOW - 500 + 86400
    assert classify(signals, NOW - 500 + 86400).inferred_type == "unknown"
    assert (
        classify([obs("_googlecast._tcp", 86400), obs("_androidtvremote2._tcp")], NOW).inferred_type
        == "unknown"
    )


def test_latest_duplicate_and_best_alternative_support_control_expiry():
    signals = printing(500) + [obs("_ipp._tcp", 10), obs("_printer._tcp", 20)]
    assert classify(signals, NOW).valid_until == NOW - 20 + 86400


@pytest.mark.parametrize("token", ["_GOOGLECAST._TCP.LOCAL.", "_googlecast._tcp"])
def test_only_precise_case_and_local_suffix_normalization(token):
    assert classify([obs(token), obs("_androidtvremote2._tcp")], NOW).inferred_type == "tv"


@pytest.mark.parametrize(
    "token",
    [
        "x_googlecast._tcp",
        "_googlecast._tcp.local.evil",
        "_googlecast._tcp.evil",
        "instance._googlecast._tcp.local",
        " _googlecast._tcp",
        "_googlecast._tcp..",
    ],
)
def test_suffix_substring_and_instance_spoofs_do_not_match(token):
    assert classify([obs(token), obs("_androidtvremote2._tcp")], NOW).inferred_type == "unknown"


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_invalid_clock_abstains(value):
    assert classify(tv(), value).reason == "invalid_input"


@pytest.mark.parametrize("value", [0, -1, math.nan, math.inf])
def test_invalid_ttl_abstains(value):
    assert classify(tv(), NOW, ttl_seconds=value).reason == "invalid_input"


def test_future_timestamp_fails_closed_even_with_other_complete_support():
    assert classify(tv() + [obs("_anything._tcp", -1)], NOW).reason == "invalid_input"


@pytest.mark.parametrize(
    "extra",
    [
        obs("bad\nservice"),
        obs("é" * 129),
        obs(kind="dhcp", hostname="evil\x00name"),
        obs(mac="bad"),
    ],
)
def test_malformed_or_oversized_input_fails_closed(extra):
    assert classify(tv() + [extra], NOW).reason == "invalid_input"


def test_bound_reads_only_one_overflow_item_and_never_classifies_partial_input():
    reads = []

    def signals():
        for i in range(1000):
            reads.append(i)
            yield obs("_googlecast._tcp" if i % 2 else "_androidtvremote2._tcp")

    assert classify(signals(), NOW).reason == "input_limit"
    assert len(reads) == 257


def test_private_mac_has_no_vendor_consequence_and_evidence_excludes_claimed_names():
    result = classify(
        tv() + [obs(kind="dhcp", hostname="secret household", opt60="vendor assertion")], NOW
    )
    assert result.inferred_type == "tv"
    assert "secret" not in repr(result) and "vendor assertion" not in repr(result)


@pytest.mark.parametrize("value", [True, "clock", pytest.param(10**10000, id="huge_integer")])
def test_nonnumeric_or_unrepresentable_clocks_fail_closed(value):
    assert classify(tv(), value).reason == "invalid_input"


def test_expired_support_reports_abstention_reason():
    result = classify(tv(86400), NOW)
    assert result.inferred_type == "unknown" and result.reason == "expired_evidence"
    assert result.valid_until is None and result.evidence == ()


def test_exact_input_bound_is_allowed_and_mac_case_normalizes():
    signals = tv() + [obs("_unused._tcp", mac=MAC.upper())] * 254
    assert classify(signals, NOW).inferred_type == "tv"


def test_malformed_kind_and_non_observation_fail_closed():
    assert classify(tv() + [obs(kind=None)], NOW).reason == "invalid_input"
    assert classify(tv() + [{}], NOW).reason == "invalid_input"


def test_custom_ttl_and_exact_expiry_boundary():
    assert classify(tv(9), NOW, ttl_seconds=10).valid_until == NOW + 1
    assert classify(tv(10), NOW, ttl_seconds=10).inferred_type == "unknown"
