"""E0 feasibility tool: input validation, normalization and caps. Synthetic data only."""

from __future__ import annotations

import json

import pytest
from e0_synth import HOST, MAC, T0, e0, event, lines, scope, scope_dict

report = e0.report
router = e0.router
DT_MAX = 253_402_300_799  # 9999-12-31T23:59:59Z

inputs = e0.inputs
net = e0.netutil


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("2001:DB8:0:0::1", "2001:db8::1"),
        ("::ffff:192.0.2.7", "192.0.2.7"),
        ("192.0.2.7", "192.0.2.7"),
        ("not-an-ip", None),
        ("", None),
    ],
)
def test_ip_normalization_folds_ipv6_spelling_and_mapped_v4(raw: str, want: str | None) -> None:
    assert net.norm_ip(raw) == want


@pytest.mark.parametrize(("raw", "want"), [("TCP", "tcp"), ("tcp6", "tcp"), ("udp6", "udp")])
def test_protocol_spellings_fold(raw: str, want: str) -> None:
    assert net.norm_proto(raw) == want


@pytest.mark.parametrize(
    ("dst", "reason"),
    [
        ("192.168.8.20", "lan_dst"),
        ("fd00:8::5", "lan_dst"),
        ("192.168.8.1", "router_dst"),
        ("224.0.0.251", "multicast_dst"),
        ("ff02::fb", "multicast_dst"),
        ("169.254.1.1", "link_local_dst"),
        ("fe80::1", "link_local_dst"),
        ("127.0.0.1", "loopback_dst"),
        ("255.255.255.255", "broadcast_dst"),
        ("0.0.0.0", "unspecified_dst"),  # noqa: S104
        # Documentation ranges are `is_private` in Python 3.12 but are WAN for this tool.
        ("192.0.2.10", None),
        ("2001:db8::10", None),
        # A private address outside the declared LAN (e.g. a VPN peer) stays eligible.
        ("10.200.0.1", None),
    ],
)
def test_destination_exclusions_use_declared_lan_not_is_private(dst: str, reason) -> None:
    sc = scope()
    assert net.dst_exclusion(dst, sc.lan_prefixes, sc.router_ips) == reason


def test_scope_parses_and_is_immutable() -> None:
    sc = scope()
    assert sc.host_id == HOST
    assert sc.skew_s == 0
    with pytest.raises(AttributeError):
        sc.skew_s = 5  # type: ignore[misc]


@pytest.mark.parametrize(
    "over",
    [
        {"period_end": T0},  # empty period
        {"period_end": T0 + 8 * 86400},  # beyond the 7-day cap
        {"macs": []},
        {"macs": [{"mac": "zz:00:00:00:00:01"}]},
        {"lan_prefixes": ["not-a-prefix"]},
        {"skew_s": 10**9},
        {"extra": 1},
        {"macs": [{"mac": "02:00:00:00:00:01"}] * 65},
        {"router_ips": 5},
        {"router_ips": None},
        {"router_ips": "192.168.8.1"},
        {"router_ips": ["192.168.8.1"] * 65},
        {"lan_prefixes": [5]},  # ip_network(5) would be 0.0.0.5/32
        {"lan_prefixes": [True]},
        {"lan_prefixes": ["192.168.8.0/24", 5]},
        {"macs": [{"mac": "02:00:00:00:00:01", "from": T0 + 10, "until": T0}]},
    ],
)
def test_scope_rejects_invalid_values(over: dict) -> None:
    with pytest.raises(inputs.InputError):
        inputs.parse_scope(json.dumps(scope_dict(**over)))


@pytest.mark.parametrize(
    "text",
    ['{"a": 1, "a": 2}', '{"a": NaN}', '{"a": 12345678901}', "[1,", '{"a": Infinity}'],
)
def test_strict_json_rejects_duplicates_nonfinite_and_huge_ints(text: str) -> None:
    with pytest.raises(inputs.InputError):
        inputs.strict_loads(text)


def test_events_parse_with_epoch_and_iso_times_and_skew_correction() -> None:
    sc = scope(skew_s=30)
    log = inputs.parse_events(
        lines(event(T0 + 100), event("2023-11-15T00:03:20+00:00", dst="2001:DB8::10")), sc
    )
    assert [ev.t for ev in log.events] == [T0 + 70, T0 + 170]
    assert log.events[1].dst_ip == "2001:db8::10"
    assert log.accepted == 2 and log.read == 2


def test_event_rejections_are_counted_by_reason_not_fatal() -> None:
    sc = scope()
    bad_extra = event(T0, process_args="leak")
    missing = event(T0)
    del missing["user_id"]
    raw = lines(
        bad_extra,
        missing,
        event(T0, Type=1),
        event(T0, host_id="other-host"),
        event(T0, dst_port=70000),
        event(T0, dst_ip="nope"),
        event(T0, process_path="/bin/‮sneaky"),
        event("yesterday"),
        event(T0, src_ip="10.88.0.5"),  # container NAT source off the LAN
    ) + [b'{"time": 1, "time": 2}', b"not json", b"x" * 9000]
    log = inputs.parse_events(raw, sc)
    assert log.accepted == 0
    assert dict(log.rejected) == {
        "unexpected_field": 1,
        "missing_field": 1,
        "type_skip": 1,
        "host_id_mismatch": 1,
        "bad_value": 4,
        "src_off_lan": 1,
        "dup_key": 1,
        "json_bad": 1,
        "frame_bad": 1,
    }


def test_duplicate_events_collapse_on_prp_dedup_key() -> None:
    sc = scope()
    log = inputs.parse_events(lines(event(T0), event(T0), event(T0, src_port=40001)), sc)
    assert log.accepted == 2 and log.duplicates == 1


def test_nil_action_and_empty_dst_host_still_count_as_reported() -> None:
    log = inputs.parse_events(lines(event(T0, Action="<nil>", Rule="<nil>", dst_host="")), scope())
    assert log.accepted == 1
    assert log.no_app_identity == 1


def test_event_count_cap_is_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inputs, "MAX_EVENTS", 2)
    with pytest.raises(inputs.InputError, match="event"):
        inputs.parse_events(lines(event(T0), event(T0 + 1), event(T0 + 2)), scope())


def test_events_file_size_cap_is_fatal(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"\n".join(lines(event(T0), event(T0 + 1))))
    monkeypatch.setattr(inputs, "MAX_EVENTS_FILE_BYTES", 10)
    with pytest.raises(inputs.InputError, match="size"):
        inputs.read_events(path, scope())


def test_missing_events_file_is_an_input_error(tmp_path) -> None:
    with pytest.raises(inputs.InputError):
        inputs.read_events(tmp_path / "absent.jsonl", scope())


@pytest.mark.parametrize(
    ("time", "skew"),
    [
        ("0001-01-01T00:00:00+14:00", 0),
        ("9999-12-31T23:59:59-14:00", 0),
        ("9999-12-31T23:59:59+00:00", -1),  # in range until the skew shift
        (0, 1),
    ],
)
def test_out_of_range_event_times_are_rejected_not_fatal(time: object, skew: int) -> None:
    sc = scope(skew_s=skew)
    log = inputs.parse_events(lines(event(time), event(T0)), sc)
    assert log.accepted == 1 and log.rejected == {"bad_value": 1}
    empty = e0.model.RouterData(batches={}, flows=())
    report.build_report(sc, empty, log)


def test_event_times_at_the_representable_edges_are_accepted() -> None:
    top = "9999-12-31T23:59:59+00:00"
    log = inputs.parse_events(lines(event(0), event(top), event(9_999_999_999)), scope())
    assert [ev.t for ev in log.events] == [0, 9_999_999_999, DT_MAX]


def test_input_caps_are_pinned() -> None:
    assert inputs.MAX_LINE_BYTES == 8192
    assert inputs.MAX_EVENTS == 500_000
    assert inputs.MAX_SCOPE_BYTES == 1 << 20
    assert inputs.MAX_EVENTS_FILE_BYTES == 256 << 20
    assert router.MAX_BATCHES == 20_000
    assert router.MAX_FLOW_ROWS == 1_000_000
    assert router.MAX_COUNTER == 1 << 62


def padded(size: int, **over) -> bytes:
    """A valid event line of exactly `size` bytes (inner JSON whitespace)."""
    body = json.dumps(event(T0, **over)).encode()
    return b"{" + b" " * (size - len(body)) + body[1:]


def test_bounded_reader_frames_oversize_lines_and_keeps_the_next_line(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    exact = padded(inputs.MAX_LINE_BYTES)
    over = padded(inputs.MAX_LINE_BYTES + 1, src_port=40001)
    huge = b"x" * (3 * inputs.MAX_LINE_BYTES + 7)
    last = json.dumps(event(T0, src_port=40002)).encode()  # no trailing newline
    path.write_bytes(b"\n".join([exact, over, huge, b"", last]))
    log = inputs.read_events(path, scope())
    assert log.accepted == 2 and log.read == 4
    assert log.rejected == {"frame_bad": 2}


@pytest.mark.parametrize("pad", [b" " * 20 + b"trailing", b" " * 20])
def test_valid_json_padded_past_the_cap_is_frame_bad(tmp_path, pad: bytes) -> None:
    path = tmp_path / "events.jsonl"
    exact = padded(inputs.MAX_LINE_BYTES)
    path.write_bytes(exact + pad + b"\n" + json.dumps(event(T0, src_port=40002)).encode())
    log = inputs.read_events(path, scope())
    assert log.accepted == 1 and log.read == 2
    assert log.rejected == {"frame_bad": 1}


def test_whitespace_padded_oversize_line_is_counted_not_skipped() -> None:
    log = inputs.parse_events([b" " * (inputs.MAX_LINE_BYTES + 1)], scope())
    assert log.read == 1 and log.rejected == {"frame_bad": 1}


def test_scope_mac_span_with_equal_bounds_is_allowed() -> None:
    sc = inputs.parse_scope(json.dumps(scope_dict(macs=[{"mac": MAC, "from": T0, "until": T0}])))
    assert sc.macs[0].since == sc.macs[0].until == T0


def test_event_count_cap_allows_exactly_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inputs, "MAX_EVENTS", 2)
    assert inputs.parse_events(lines(event(T0), event(T0 + 1)), scope()).accepted == 2


def test_scope_size_cap_is_fatal(tmp_path) -> None:
    text = json.dumps(scope_dict())
    big = text[:-1] + " " * (inputs.MAX_SCOPE_BYTES + 1 - len(text)) + "}"
    with pytest.raises(inputs.InputError, match="size"):
        inputs.parse_scope(big)
    path = tmp_path / "scope.json"
    path.write_text(big)
    with pytest.raises(inputs.InputError, match="size"):
        inputs.read_scope(path)
