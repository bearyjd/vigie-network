"""E0 feasibility tool: other share, key match, warm-up, gate. Synthetic data only."""

from __future__ import annotations

import json

import pytest
from e0_synth import DAY, MAC, MAC_B, T0, batch, e0, event, flow, lines, scope, scope_dict

inputs = e0.inputs
report = e0.report
model = e0.model

LATE = T0 + DAY + 3600  # past the 24 h warm-up of an export starting at T0


def run(batches, flows, events, sc=None, **router_over):
    sc = sc or scope(export_start=T0)
    router = model.RouterData(
        batches={(b.collector_id, b.batch_id): b for b in batches},
        flows=tuple(flows),
        **router_over,
    )
    return report.build_report(sc, router, inputs.parse_events(lines(*events), sc))


def win(bid: str, start: int, **over):
    return batch(bid, start, start + 60, **over)


def test_other_share_counts_both_directions_and_keeps_other_rows_in_denominator() -> None:
    b = win("b1", LATE)
    rows = [flow("b1", LATE + 60, up=50, down=50), flow("b1", LATE + 60, None, None, up=5, down=6)]
    share = run([b], rows, [])["other_share"]
    assert share["other_bytes"] == 11
    assert share["mapped_bytes"] == 111
    assert share["other_flows"] == 1 and share["mapped_flows"] == 2


def test_gate_other_share_exactly_ten_percent_fails_and_just_below_passes() -> None:
    b = win("b1", LATE)
    ev = [event(LATE + 10)]
    at10 = [flow("b1", LATE + 60, up=90, down=0), flow("b1", LATE + 60, None, None, up=5, down=5)]
    out = run([b], at10, ev)
    assert out["gate"]["verdict"] == "no_go"
    assert "other_share_at_or_above_10pct" in out["gate"]["reasons"]
    below = [flow("b1", LATE + 60, up=91, down=0), flow("b1", LATE + 60, None, None, up=4, down=5)]
    assert run([b], below, ev)["gate"]["verdict"] == "go"


def test_match_ratio_exactly_ninety_percent_passes() -> None:
    batches = [win(f"b{i}", LATE + i * 60) for i in range(10)]
    rows = [flow(f"b{i}", LATE + i * 60 + 60, dst=f"192.0.2.{i + 10}") for i in range(10)]
    events = [event(LATE + i * 60 + 5, dst=f"192.0.2.{i + 10}") for i in range(9)]
    out = run(batches, rows, events)
    combined = out["match"]["gated"]["combined"]
    assert combined == {"matched": 9, "denominator": 10}
    assert out["gate"]["verdict"] == "go"
    events8 = events[:8]
    assert run(batches, rows, events8)["gate"]["verdict"] == "no_go"


def test_direct_tolerance_is_120s_both_sides() -> None:
    b = win("b1", LATE)
    rows = [flow("b1", LATE + 60)]
    edge = run([b], rows, [event(LATE + 60 + 120)])["match"]["gated"]
    assert edge["direct"]["matched"] == 1
    past = run([b], rows, [event(LATE + 60 + 121)])["match"]["gated"]
    assert past["direct"]["matched"] == 0 and past["combined"]["matched"] == 0
    before = run([b], rows, [event(LATE - 120)])["match"]["gated"]
    assert before["direct"]["matched"] == 1


def test_carryover_counts_long_lived_flow_reported_within_24h_separately() -> None:
    b = win("b1", LATE)
    out = run([b], [flow("b1", LATE + 60)], [event(LATE - 3600)])["match"]["gated"]
    assert out["direct"] == {"matched": 0, "denominator": 1}
    assert out["carryover_only"] == {"matched": 1, "denominator": 1}
    assert out["combined"] == {"matched": 1, "denominator": 1}
    stale = run([b], [flow("b1", LATE + 60)], [event(LATE - DAY - 1)])["match"]["gated"]
    assert stale["combined"]["matched"] == 0


def test_uncorrected_skew_loses_direct_but_carryover_still_matches_and_skew_input_fixes_it():
    b = win("b1", LATE)
    rows = [flow("b1", LATE + 60)]
    skewed = [event(LATE - 200 - 120)]  # endpoint clock 200 s slow relative to the router
    out = run([b], rows, skewed)
    assert out["match"]["gated"]["direct"]["matched"] == 0
    assert out["match"]["gated"]["combined"]["matched"] == 1
    assert "skew_assumed_zero" in codes(out)
    fixed = run([b], rows, skewed, sc=scope(export_start=T0, skew_s=-200))
    assert fixed["match"]["gated"]["direct"]["matched"] == 1
    assert "skew_supplied" in codes(fixed)


def test_warm_up_keys_are_reported_apart_from_the_gated_denominator() -> None:
    early, late = win("e", T0 + 600), win("l", LATE)
    rows = [flow("e", T0 + 660), flow("l", LATE + 60, dst="192.0.2.11")]
    out = run([early, late], rows, [event(T0 + 610)])
    assert out["match"]["warm_up"]["combined"] == {"matched": 1, "denominator": 1}
    assert out["match"]["gated"]["combined"] == {"matched": 0, "denominator": 1}
    assert "warm_up" in codes(out)


def test_distinct_keys_collapse_duplicate_rows_and_count_exclusions_by_reason() -> None:
    b = win("b1", LATE)
    ts = LATE + 60
    rows = [
        flow("b1", ts),
        flow("b1", ts),  # exact duplicate row
        flow("b1", ts, port=53, proto="udp"),
        flow("b1", ts, proto="icmp", port=None),
        flow("b1", ts, dst="192.168.8.30"),
        flow("b1", ts, dst="192.168.8.1"),
        flow("b1", ts, dst="ff02::fb", proto="udp", port=5353),
        flow("b1", ts, None, None),
        flow("b1", ts, mac="02:00:00:00:00:99"),
    ]
    out = run([b], rows, [event(LATE)])
    m = out["match"]
    assert m["eligible_keys"] == 1
    assert m["excluded_keys"] == {
        "port_excluded": 2,
        "proto_excluded": 1,
        "lan_dst": 1,
        "router_dst": 1,
        "other_row": 1,
    }
    assert out["flows"]["duplicate_rows"] == 1
    assert out["flows"]["unattributed_rows"] == 1
    assert out["other_share"]["mapped_bytes"] == 7 * 1000  # duplicate dropped, stranger excluded


def test_degraded_and_legacy_windows_excluded_from_keys_but_bytes_reported() -> None:
    good, bad = win("g", LATE), win("d", LATE + 60, reasons=("flow_degraded",))
    legacy = batch("old", None, None, reasons=("legacy_window",))
    rows = [
        flow("g", LATE + 60),
        flow("d", LATE + 120, dst="192.0.2.11"),
        flow("old", LATE + 180, dst="192.0.2.12"),
    ]
    out = run([good, bad, legacy], rows, [event(LATE)])
    assert out["match"]["eligible_keys"] == 1
    assert out["match"]["excluded_keys"] == {"flow_degraded": 1, "legacy_window": 1}
    assert out["other_share"]["degraded_bytes"] == 2000
    assert out["batches"]["by_reason"] == {"flow_degraded": 1, "legacy_window": 1}
    assert {"degraded_coverage", "legacy_windows"} <= set(codes(out))


def test_flows_join_to_batches_by_collector_and_batch_id_only() -> None:
    b = win("b1", LATE)
    rows = [flow("b1", LATE + 60), flow("b1", LATE + 60, collector_id="rtr-2", dst="192.0.2.11")]
    out = run([b], rows, [event(LATE)])
    assert out["flows"]["orphan_rows"] == 1
    assert out["match"]["eligible_keys"] == 1
    assert "orphan_flow_rows" in codes(out)


def test_attribution_change_honours_mac_validity_spans() -> None:
    sc = scope(
        export_start=T0,
        macs=[{"mac": MAC, "until": LATE + 100}, {"mac": MAC_B, "from": LATE + 100}],
    )
    b1, b2 = win("b1", LATE), win("b2", LATE + 120)
    rows = [
        flow("b1", LATE + 60),
        flow("b2", LATE + 180, mac=MAC_B, dst="192.0.2.11"),
        flow("b2", LATE + 180, mac=MAC, dst="192.0.2.12"),  # old MAC after the change
    ]
    out = run([b1, b2], rows, [event(LATE), event(LATE + 130, dst="192.0.2.11")], sc=sc)
    assert out["match"]["gated"]["combined"] == {"matched": 2, "denominator": 2}
    assert out["flows"]["unattributed_rows"] == 1
    assert "attribution_changed" in codes(out)


def test_zero_denominators_fail_closed_with_reasons() -> None:
    out = run([], [], [])
    assert out["gate"]["verdict"] == "no_result"
    assert set(out["gate"]["reasons"]) == {"zero_mapped_bytes", "zero_gated_keys"}
    assert out["match"]["gated"]["combined"] == {"matched": 0, "denominator": 0}


def test_ipv6_shared_cdn_and_tls_identity_classes_are_explained() -> None:
    b = win("b1", LATE)
    rows = [flow("b1", LATE + 60, dst="2001:db8::10"), flow("b1", LATE + 60, dst="192.0.2.11")]
    events = [
        event(LATE, dst="2001:DB8:0::10", dst_host="cdn-a.example"),
        event(LATE + 1, dst="2001:db8::10", dst_host="cdn-b.example"),
        event(LATE + 2, dst="198.51.100.4", dst_host=""),
    ]
    out = run([b], rows, events)
    assert out["match"]["gated"]["combined"] == {"matched": 1, "denominator": 2}
    assert out["match"]["unmatched_by_class"] == {"ipv4_tcp": 1}
    assert out["events"]["shared_destinations"] == 1
    assert out["events"]["no_app_identity"] == 1
    assert {"ipv6_keys", "shared_destinations", "tls_without_app_identity"} <= set(codes(out))


def test_report_never_carries_process_paths_or_hostnames() -> None:
    b = win("b1", LATE)
    out = run([b], [flow("b1", LATE + 60)], [event(LATE, dst_host="secret.example")])
    text = report.render(out)
    assert "secret.example" not in text and "/usr/bin/synthetic" not in text


def codes(out: dict) -> list[str]:
    return [item["code"] for item in out["explanations"]]


def hourly(n: int, first_event_hour: int, sc=None):
    """n hourly keys with distinct destinations; events only from `first_event_hour` on."""
    batches = [win(f"h{i}", T0 + i * 3600) for i in range(n)]
    rows = [flow(f"h{i}", T0 + i * 3600 + 60, dst=f"192.0.2.{i + 1}") for i in range(n)]
    events = [event(T0 + i * 3600 + 5, dst=f"192.0.2.{i + 1}") for i in range(first_event_hour, n)]
    return run(batches, rows, events, sc=sc)


def test_guard_silent_at_export_start_fails_the_gate_through_the_warm_up_bucket() -> None:
    out = hourly(48, 12)
    assert out["match"]["gated"]["combined"] == {"matched": 24, "denominator": 24}
    assert out["match"]["warm_up"]["combined"] == {"matched": 12, "denominator": 24}
    assert out["gate"]["verdict"] == "no_go"
    assert out["gate"]["reasons"] == ["warm_up_match_ratio_below_90pct"]


def test_warm_up_ratio_threshold_is_ninety_percent() -> None:
    sc = scope(export_start=T0, period_end=T0 + 3 * DAY)
    out = hourly(30, 2, sc=sc)  # hours 0..23 warm-up, 22 of 24 matched
    assert out["match"]["warm_up"]["combined"] == {"matched": 22, "denominator": 24}
    assert out["gate"]["verdict"] == "go"
    assert hourly(30, 3, sc=sc)["gate"]["reasons"] == ["warm_up_match_ratio_below_90pct"]


def test_scope_without_export_start_is_rejected_not_inferred_from_events() -> None:
    raw = scope_dict()
    del raw["export_start"]
    with pytest.raises(inputs.InputError):
        inputs.parse_scope(json.dumps(raw))


def test_match_key_needs_the_same_port_and_protocol() -> None:
    b = win("b1", LATE)
    rows = [flow("b1", LATE + 60)]
    port = run([b], rows, [event(LATE + 5, port=8443)])["match"]["gated"]["combined"]
    assert port == {"matched": 0, "denominator": 1}
    proto = run([b], rows, [event(LATE + 5, proto="udp")])["match"]["gated"]["combined"]
    assert proto == {"matched": 0, "denominator": 1}


def test_unsorted_event_input_still_matches() -> None:
    b = win("b1", LATE)
    events = [event(LATE + 10, src_port=40001), event(LATE - 2 * DAY + 4000, src_port=40002)]
    out = run([b], [flow("b1", LATE + 60)], events)
    assert out["match"]["gated"]["direct"] == {"matched": 1, "denominator": 1}


def test_gate_ratio_eight_of_nine_fails() -> None:
    batches = [win(f"b{i}", LATE + i * 60) for i in range(9)]
    rows = [flow(f"b{i}", LATE + i * 60 + 60, dst=f"192.0.2.{i + 10}") for i in range(9)]
    events = [event(LATE + i * 60 + 5, dst=f"192.0.2.{i + 10}") for i in range(8)]
    out = run(batches, rows, events)
    assert out["match"]["gated"]["combined"] == {"matched": 8, "denominator": 9}
    assert out["gate"]["reasons"] == ["match_ratio_below_90pct"]


@pytest.mark.parametrize(
    ("offset", "want"),
    [(-DAY, (0, 1)), (-DAY - 1, (0, 0)), (-121, (0, 1)), (-120, (1, 0))],
)
def test_carryover_and_direct_window_seams(offset: int, want: tuple[int, int]) -> None:
    b = win("b1", LATE)
    gated = run([b], [flow("b1", LATE + 60)], [event(LATE + offset)])["match"]["gated"]
    assert (gated["direct"]["matched"], gated["carryover_only"]["matched"]) == want


@pytest.mark.parametrize(("start", "bucket"), [(T0 + DAY, "gated"), (T0 + DAY - 1, "warm_up")])
def test_warm_up_cut_is_a_full_24h_lookback_from_export_start(start: int, bucket: str) -> None:
    out = run([batch("b1", start, start + 60)], [flow("b1", start + 60)], [event(start + 5)])
    assert out["match"][bucket]["combined"] == {"matched": 1, "denominator": 1}


@pytest.mark.parametrize(
    ("ts", "attributed"), [(LATE - 1, False), (LATE, True), (LATE + 99, True), (LATE + 100, False)]
)
def test_mac_span_since_is_inclusive_and_until_exclusive(ts: int, attributed: bool) -> None:
    span = model.MacSpan(MAC, LATE, LATE + 100)
    assert span.covers(MAC, ts) is attributed
    assert span.covers(MAC_B, LATE + 10) is False


def test_attributed_orphan_rows_count_in_the_other_share() -> None:
    b = win("b1", LATE)
    rows = [
        flow("b1", LATE + 60, up=5000, down=5000),
        flow("ghost", LATE + 60, None, None, up=600, down=600),
        flow("ghost", LATE + 60, None, None, mac="02:00:00:00:00:99", up=9, down=9),
    ]
    out = run([b], rows, [event(LATE + 5)])
    share = out["other_share"]
    assert share["other_bytes"] == 1200 and share["mapped_bytes"] == 11200
    assert share["orphan_bytes"] == 1200
    assert out["flows"]["orphan_rows"] == 1 and out["flows"]["unattributed_rows"] == 1
    assert out["gate"]["reasons"] == ["other_share_at_or_above_10pct"]


def test_explanations_cover_rejects_duplicates_nat_flows_shards_and_defaults() -> None:
    b = win("b1", LATE)
    rows = [flow("b1", LATE + 60), flow("b1", LATE + 60)]
    events = [event(LATE), event(LATE), event(LATE, src_ip="10.88.0.5"), event("bad")]
    out = run([b], rows, events, missing_shards=("raw-20231115.db",))
    assert {
        "key_level_match",
        "skew_assumed_zero",
        "events_rejected",
        "duplicate_events",
        "nat_or_off_lan_sources",
        "duplicate_flow_rows",
        "raw_shard_missing",
    } <= set(codes(out))
    clean = run([b], [flow("b1", LATE + 60)], [event(LATE)])
    assert codes(clean) == [
        "clean_window_scope",
        "export_ends_before_period_end",
        "key_level_match",
        "skew_assumed_zero",
    ]
    assert "zero_denominator" in codes(run([], [], []))


def test_out_of_span_row_alone_flags_attribution_change() -> None:
    sc = scope(export_start=T0, macs=[{"mac": MAC, "until": LATE + 100}])
    b1, b2 = win("b1", LATE), win("b2", LATE + 120)
    rows = [flow("b1", LATE + 60), flow("b2", LATE + 180, dst="192.0.2.11")]
    out = run([b1, b2], rows, [event(LATE)], sc=sc)
    assert out["flows"]["out_of_span_rows"] == 1
    assert "attribution_changed" in codes(out)


def test_export_end_explanation_only_when_last_event_precedes_period_end() -> None:
    sc = scope(export_start=T0)
    b = win("b1", LATE)
    rows = [flow("b1", LATE + 60)]
    end = sc.period_end
    covered = run([b], rows, [event(LATE), event(end, dst="192.0.2.99")], sc=sc)
    assert "export_ends_before_period_end" not in codes(covered)
    short = run([b], rows, [event(LATE), event(end - 1, dst="192.0.2.99")], sc=sc)
    assert "export_ends_before_period_end" in codes(short)
    assert short["events"]["last_accepted_t"] == end - 1
    assert short["gate"]["verdict"] == "go"  # an explanation, not a gate


def test_clean_window_scope_explains_what_clean_does_not_check() -> None:
    text = report.explain.TEXTS["clean_window_scope"]
    assert "raw_missing" in text and "ct_lan_unmapped_bytes" in text and "overlap" in text
    assert "clean_window_scope" in codes(run([], [], []))


def _repro(missing: tuple[str, ...], sc=None):
    """The review repro: 48 h, 100 directly matched windows on day 2 only."""
    batches = [win(f"b{i}", LATE + i * 60) for i in range(100)]
    rows = [flow(f"b{i}", LATE + i * 60 + 60, dst=f"192.0.2.{i + 1}") for i in range(100)]
    events = [event(LATE + i * 60 + 5, dst=f"192.0.2.{i + 1}") for i in range(100)]
    return run(batches, rows, events, sc=sc, missing_shards=missing)


def test_missing_in_period_shard_never_passes_the_gate() -> None:
    out = _repro(("raw-20231115.db", "raw-20231117.db"))
    assert out["match"]["gated"]["direct"] == {"matched": 100, "denominator": 100}
    assert out["gate"]["verdict"] == "no_result"
    assert out["gate"]["reasons"] == ["raw_shard_missing_in_period"]
    assert "zero_denominator" not in codes(out)


def test_only_the_midnight_boundary_shard_is_exempt() -> None:
    assert _repro(("raw-20231117.db",))["gate"]["verdict"] == "go"
    late_end = scope(export_start=T0, period_end=T0 + 2 * DAY + 30)
    out = _repro(("raw-20231117.db",), sc=late_end)
    assert out["gate"]["verdict"] == "no_result"
