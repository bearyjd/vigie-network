"""Contracts for the bounded probe runner (pure; the clock, resolver and connect are injected)."""

from __future__ import annotations

import ast
import dataclasses
import errno
import importlib.util
import json
import logging
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

PERSISTENT = Path(__file__).parents[1] / "persistent"
MODULE = PERSISTENT / "probe_runner.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(PERSISTENT))
pr = _load("probe_runner_under_test", MODULE)
rs = _load("run_soak_for_parity", PERSISTENT / "run_soak.py")

DNS_ADDR, TCP_ADDR, QNAME, PORT = "10.0.0.7", "10.0.0.9", "svc.home.lan", 8443
TCP_ID = "router-web"


def raw_config(**over):
    base = {
        "enabled": True,
        "state_file": "/srv/probe-test/probe-state.json",
        "targets": [
            {"id": "router-dns", "kind": "dns_local", "resolver": DNS_ADDR, "qname": QNAME},
            {"id": TCP_ID, "kind": "tcp_lan", "address": TCP_ADDR, "port": PORT},
        ],
    }
    return {**base, **over}


def target(**over):
    base = {"id": "t1", "kind": "tcp_lan", "address": TCP_ADDR, "port": PORT}
    return {**base, **over}


def with_targets(*targets):
    return raw_config(targets=list(targets))


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


# ---------------------------------------------------------------- DNS vector helpers
QID = b"\x12\x34"
EXAMPLE = ("example", "com")


def qwire(labels):
    return b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\0"


def rr(owner, kind=1, cls=1, rdata=b"\x0a\0\0\x01"):
    return owner + struct.pack("!HHIH", kind, cls, 60, len(rdata)) + rdata


def reply(qid=QID, flags=0x8180, qd=1, an=1, ns=0, ar=0, labels=EXAMPLE, qtype=1, body=None):
    question = qwire(labels) + struct.pack("!HH", qtype, 1)
    answers = rr(b"\xc0\x0c") if body is None else body
    return qid + struct.pack("!HHHHH", flags, qd, an, ns, ar) + question + answers


def vectors():
    good = reply()
    return {
        "ok": good,
        "ok_inline_owner": reply(body=rr(qwire(EXAMPLE))),
        "ok_uppercase_echo": reply(labels=("EXAMPLE", "com")),
        "bad_id": reply(qid=b"\xff\xff"),
        "rcode_nxdomain": reply(flags=0x8183, an=0, body=b""),
        "no_answer": reply(an=0, body=b""),
        "not_response": reply(flags=0x0100),
        "type_28_len4": reply(body=rr(b"\xc0\x0c", kind=28)),
        "class_ch": reply(body=rr(b"\xc0\x0c", cls=3)),
        "a_only_in_authority": reply(
            an=1, ns=1, body=rr(qwire(("other", "com"))) + rr(b"\xc0\x0c")
        ),
        "not_response_noanswer": reply(flags=0x0100, an=0, body=b""),
        "not_response_rcode": reply(flags=0x0103, an=0, body=b""),
        "answers_over_cap": reply(an=65, body=rr(b"\xc0\x0c") * 65),
        "records_over_cap": reply(an=1, ar=128, body=rr(b"\xc0\x0c") * 129),
        "answers_at_cap": reply(an=64, body=rr(b"\xc0\x0c") * 64),
        "rdlength_past_end": reply(
            body=b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 200) + b"\x0a\0\0\x01"
        ),
        "truncated_flag": reply(flags=0x8380),
        "truncated_packet": good[:-3],
        "too_short": good[:11],
        "oversize": good + b"\0" * 4100,
        "trailing_data": good + b"\0",
        "compression_self_loop": reply(body=b"\xc0\x1a" + struct.pack("!HHIH", 1, 1, 60, 4)),
        "compression_forward": reply(body=b"\xc0\xff" + struct.pack("!HHIH", 1, 1, 60, 4)),
        "wrong_question": reply(labels=("evil", "com")),
        "wrong_qtype": reply(qtype=28),
        "wrong_owner": reply(body=rr(qwire(("other", "com")))),
        "cname_only": reply(body=rr(b"\xc0\x0c", kind=5, rdata=b"\xc0\x0c")),
        "aaaa_only": reply(body=rr(b"\xc0\x0c", kind=28, rdata=b"\0" * 16)),
        "bad_rdlength": reply(body=rr(b"\xc0\x0c", rdata=b"\x0a\0\0")),
        "two_questions": reply(qd=2),
        "too_many_answers": reply(an=65),
        "zero_ans_with_authority": reply(
            an=0, ns=1, body=rr(b"\xc0\x0c", kind=2, rdata=b"\xc0\x0c")
        ),
    }


# ---------------------------------------------------------------- fakes
class FakeNet:
    """Scripted dns/connect fakes recording every call; outcomes pop from a list (last repeats)."""

    def __init__(self, clock, outcomes=("ok",), cost=0.01):
        self.clock, self.outcomes, self.cost = clock, list(outcomes), cost
        self.dns_calls, self.connect_calls = [], []

    def _next(self):
        return self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]

    def dns(self, resolver, packet, timeout_s):
        self.dns_calls.append((resolver, packet, timeout_s))
        self.clock.t += self.cost
        outcome = self._next()
        if outcome == "ok":
            return (
                packet[:2]
                + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                + packet[12:]
                + rr(b"\xc0\x0c")
            )
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def connect(self, address, port, timeout_s):
        self.connect_calls.append((address, port, timeout_s))
        self.clock.t += self.cost
        outcome = self._next()
        if isinstance(outcome, BaseException):
            raise outcome

    @property
    def calls(self):
        return len(self.dns_calls) + len(self.connect_calls)


def run(cfg, state, clock, net):
    return pr.run_pass(cfg, state, now=clock, dns=net.dns, connect=net.connect)


def tcp_cfg(n=1):
    return pr.parse_config(
        with_targets(
            *[
                {"id": f"t{i}", "kind": "tcp_lan", "address": f"10.0.1.{i + 1}", "port": 80 + i}
                for i in range(n)
            ]
        )
    )


FAIL = TimeoutError()


def drive(outcomes, cfg=None, clock=None, step=60.0, gaps=None):
    """Run one pass per outcome, `step` seconds apart (gaps[i] overrides the gap after pass i)."""
    cfg = cfg or tcp_cfg(1)
    clock = clock or Clock()
    net = FakeNet(clock, outcomes)
    state, seen = pr.empty_state(), []
    for i, _ in enumerate(outcomes):
        state = run(cfg, state, clock, net)
        seen.append(state.targets[0])
        clock.t += (gaps or {}).get(i, step)
    return seen


# ================================================================ config validation
def test_parse_config_valid_and_defaults():
    cfg = pr.parse_config(raw_config())
    assert cfg.enabled is True and cfg.state_file == "/srv/probe-test/probe-state.json"
    assert [t.id for t in cfg.targets] == ["router-dns", TCP_ID]
    assert all(t.timeout_s == 2.0 for t in cfg.targets)
    dns, tcp = cfg.targets
    assert (dns.kind, dns.host, dns.qname) == ("dns_local", DNS_ADDR, QNAME)
    assert (tcp.kind, tcp.host, tcp.port) == ("tcp_lan", TCP_ADDR, PORT)


def test_default_is_disabled_and_needs_nothing():
    cfg = pr.parse_config({})
    assert cfg.enabled is False and cfg.targets == ()


def test_enabled_requires_state_file_and_targets():
    for raw in ({"enabled": True}, {"enabled": True, "state_file": "/srv/x"}):
        with pytest.raises(pr.ProbeError):
            pr.parse_config(raw)


def test_exactly_ten_targets_ok_eleven_rejected():
    ten = [target(id=f"t{i}", address=f"10.0.1.{i + 1}") for i in range(10)]
    assert len(pr.parse_config(raw_config(targets=ten)).targets) == 10
    with pytest.raises(pr.ProbeError):
        pr.parse_config(raw_config(targets=[*ten, target(id="t10", address="10.0.2.1")]))


BAD_ADDRESSES = [
    "8.8.8.8",  # public
    "2001:4860:4860::8888",
    "127.0.0.1",
    "::1",
    "0.0.0.0",  # noqa: S104
    "::",
    "224.0.0.1",
    "ff02::1",
    "169.254.169.254",  # metadata / link-local
    "169.254.1.1",
    "fe80::1",
    "::ffff:10.0.0.1",  # v4-mapped
    "100.64.0.1",  # CGNAT, not private
    "255.255.255.255",
    "fd00::1%eth0",  # scoped
    "router.lan",  # hostname: no rebinding
    "10.0.0.1.example.com",
    "10.0.0.1/24",
    " 10.0.0.1",
    "010.0.0.1",
    "",
    None,
    1,
]


@pytest.mark.parametrize("address", BAD_ADDRESSES)
def test_rejects_bad_tcp_address(address):
    with pytest.raises(pr.ProbeError) as info:
        pr.parse_config(with_targets(target(address=address)))
    assert str(address) not in str(info.value) or address in ("", None)


@pytest.mark.parametrize("address", BAD_ADDRESSES)
def test_rejects_bad_dns_resolver(address):
    raw = with_targets({"id": "d", "kind": "dns_local", "resolver": address, "qname": QNAME})
    with pytest.raises(pr.ProbeError):
        pr.parse_config(raw)


@pytest.mark.parametrize("address", ["10.1.2.3", "172.16.0.1", "192.168.1.1", "fd00::1", "fc00::5"])
def test_accepts_private_addresses(address):
    assert pr.parse_config(with_targets(target(address=address))).targets[0].host == address


def test_two_dns_upstream_rejected_one_accepted():
    up = lambda i: {  # noqa: E731
        "id": f"u{i}",
        "kind": "dns_upstream",
        "resolver": DNS_ADDR,
        "qname": "canary.example.org",
    }
    assert pr.parse_config(with_targets(up(1)))
    with pytest.raises(pr.ProbeError):
        pr.parse_config(with_targets(up(1), up(2)))


def test_multiple_dns_local_allowed():
    loc = lambda i: {"id": f"l{i}", "kind": "dns_local", "resolver": DNS_ADDR, "qname": QNAME}  # noqa: E731
    assert len(pr.parse_config(with_targets(loc(1), loc(2))).targets) == 2


@pytest.mark.parametrize(
    "qname",
    [
        "a" * 64 + ".lan",  # label too long
        ".".join(["a" * 63] * 3 + ["b" * 62]),  # 254 bytes
        "under_score.lan",
        "sp ace.lan",
        "exaémple.lan",
        "a..lan",
        "",
        ".",
        "svc.lan.",  # trailing dot
        "-lead.lan",
        "trail-.lan",
        "svc.lan\n",
        "svc.lan\0",
        None,
        5,
    ],
)
def test_rejects_bad_qname(qname):
    with pytest.raises(pr.ProbeError):
        pr.parse_config(
            with_targets({"id": "d", "kind": "dns_local", "resolver": DNS_ADDR, "qname": qname})
        )


def test_accepts_max_length_qname_and_lowercases():
    name = ".".join(["a" * 63] * 3 + ["b" * 61])  # 253 bytes
    assert len(name) == 253
    t = pr.parse_config(
        with_targets({"id": "d", "kind": "dns_local", "resolver": DNS_ADDR, "qname": name.upper()})
    ).targets[0]
    assert t.qname == name


def test_unknown_keys_rejected_everywhere():
    for raw in (
        raw_config(extra=1),
        with_targets(target(extra=1)),
        with_targets(target(qname=QNAME)),  # tcp with dns key
        with_targets(
            {"id": "d", "kind": "dns_local", "resolver": DNS_ADDR, "qname": QNAME, "port": 53}
        ),
        with_targets({"id": "d", "kind": "dns_local", "address": DNS_ADDR, "qname": QNAME}),
    ):
        with pytest.raises(pr.ProbeError):
            pr.parse_config(raw)


def test_missing_required_keys_rejected():
    for t in (
        {"id": "t", "kind": "tcp_lan", "address": TCP_ADDR},
        {"id": "t", "kind": "tcp_lan", "port": 80},
        {"kind": "tcp_lan", "address": TCP_ADDR, "port": 80},
        {"id": "t", "address": TCP_ADDR, "port": 80},
    ):
        with pytest.raises(pr.ProbeError):
            pr.parse_config(with_targets(t))


@pytest.mark.parametrize(
    "timeout", [0, 0.0, -1, 2.0001, 3, 1e9, True, "1", None, float("nan"), float("inf")]
)
def test_rejects_bad_timeout(timeout):
    with pytest.raises(pr.ProbeError):
        pr.parse_config(with_targets(target(timeout_s=timeout)))


@pytest.mark.parametrize("timeout", [0.1, 1, 2, 2.0])
def test_accepts_good_timeout(timeout):
    assert pr.parse_config(with_targets(target(timeout_s=timeout))).targets[0].timeout_s == timeout


@pytest.mark.parametrize("port", [0, -1, 65536, True, "80", 80.0, None])
def test_rejects_bad_port(port):
    with pytest.raises(pr.ProbeError):
        pr.parse_config(with_targets(target(port=port)))


@pytest.mark.parametrize("port", [1, 80, 65535])
def test_accepts_good_port(port):
    assert pr.parse_config(with_targets(target(port=port))).targets[0].port == port


@pytest.mark.parametrize("ident", ["UPPER", "a" * 33, "a b", "", "a\n", "x.y", "é", 5, None])
def test_rejects_bad_id(ident):
    with pytest.raises(pr.ProbeError):
        pr.parse_config(with_targets(target(id=ident)))


def test_id_boundaries_and_duplicates():
    assert pr.parse_config(with_targets(target(id="a" * 32))).targets[0].id == "a" * 32
    assert pr.parse_config(with_targets(target(id="a_b-9")))
    with pytest.raises(pr.ProbeError):
        pr.parse_config(with_targets(target(id="d"), target(id="d", address="10.0.0.2")))


@pytest.mark.parametrize("kind", ["http", "dns", "TCP_LAN", "tcp_wan", "", None])
def test_rejects_bad_kind(kind):
    with pytest.raises(pr.ProbeError):
        pr.parse_config(with_targets(target(kind=kind)))


@pytest.mark.parametrize("path", ["relative.json", "./x", "", None, "/x/a\0b", "/" + "a" * 5000])
def test_rejects_bad_state_file(path):
    with pytest.raises(pr.ProbeError):
        pr.parse_config(raw_config(state_file=path))


@pytest.mark.parametrize(
    "raw", [[], "x", None, 5, {"enabled": "yes"}, {"targets": {}}, {"targets": [1]}]
)
def test_rejects_wrong_shapes(raw):
    with pytest.raises(pr.ProbeError):
        pr.parse_config(raw)


def test_config_errors_are_fixed_and_never_echo_values():
    with pytest.raises(pr.ProbeError) as info:
        pr.parse_config(with_targets(target(address="8.8.4.4")))
    assert "8.8.4.4" not in str(info.value)
    with pytest.raises(pr.ProbeError) as info:
        pr.parse_config(
            with_targets(
                {"id": "d", "kind": "dns_local", "resolver": DNS_ADDR, "qname": "bad_name.lan"}
            )
        )
    assert "bad_name" not in str(info.value)


def test_load_config_size_cap_and_roundtrip(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(raw_config()))
    assert pr.load_config(str(path)).enabled
    path.write_text(" " * 20000 + json.dumps(raw_config()))
    with pytest.raises(pr.ProbeError):
        pr.load_config(str(path))
    path.write_text("{not json")
    with pytest.raises(pr.ProbeError):
        pr.load_config(str(path))


# ================================================================ rate cap, allowlist, deadline
def test_two_passes_30s_apart_second_makes_no_calls():
    clock, cfg = Clock(), pr.parse_config(raw_config())
    net = FakeNet(clock)
    state = run(cfg, pr.empty_state(), clock, net)
    assert net.calls == 2
    clock.t += 30
    run(cfg, state, clock, net)
    assert net.calls == 2


def test_rate_cap_boundary_and_60s():
    cfg = tcp_cfg(1)
    for gap, expect in ((54.0, 1), (54.9, 1), (55.0, 2), (60.0, 2)):
        clock = Clock()
        net = FakeNet(clock, cost=0.0)
        state = run(cfg, pr.empty_state(), clock, net)
        clock.t += gap
        run(cfg, state, clock, net)
        assert net.calls == expect, gap


def test_each_target_probed_once_per_pass_and_dispatched_by_kind():
    clock, cfg = Clock(), pr.parse_config(raw_config())
    net = FakeNet(clock)
    run(cfg, pr.empty_state(), clock, net)
    assert [c[0] for c in net.dns_calls] == [DNS_ADDR]
    assert [(c[0], c[1]) for c in net.connect_calls] == [(TCP_ADDR, PORT)]


def test_rate_cap_survives_fresh_process_state_reload():
    clock, cfg = Clock(), pr.parse_config(raw_config())
    net = FakeNet(clock)
    state = run(cfg, pr.empty_state(), clock, net)
    reloaded = pr.state_from_bytes(pr.serialize_state(state), cfg)
    clock.t += 10
    run(cfg, reloaded, clock, net)
    assert net.calls == 2


def test_clock_step_back_beyond_60s_probes_once_and_notes():
    clock, cfg = Clock(), tcp_cfg(1)
    net = FakeNet(clock, cost=0.0)
    state = run(cfg, pr.empty_state(), clock, net)
    clock.t -= 3600
    state = run(cfg, state, clock, net)
    assert net.calls == 2 and state.targets[0].note == "clock_step"
    clock.t += 10
    run(cfg, state, clock, net)
    assert net.calls == 2  # the cap holds again after the step


def test_small_step_back_does_not_probe():
    clock, cfg = Clock(), tcp_cfg(1)
    net = FakeNet(clock, cost=0.0)
    state = run(cfg, pr.empty_state(), clock, net)
    clock.t -= 30
    run(cfg, state, clock, net)
    assert net.calls == 1


def test_step_back_boundary_exactly_60s_is_not_a_step():
    clock, cfg = Clock(), tcp_cfg(1)
    net = FakeNet(clock, cost=0.0)
    state = run(cfg, pr.empty_state(), clock, net)
    clock.t -= 60
    run(cfg, state, clock, net)
    assert net.calls == 1
    clock.t -= 0.5
    run(cfg, state, clock, net)
    assert net.calls == 2


def test_state_ids_outside_the_allowlist_are_never_probed_or_kept():
    clock, cfg = Clock(), tcp_cfg(1)
    evil = dataclasses.replace(pr.new_target_state("evil"), last_attempt=None)
    state = dataclasses.replace(pr.empty_state(), targets=(evil,))
    net = FakeNet(clock)
    out = run(cfg, state, clock, net)
    assert [t.id for t in out.targets] == ["t0"]
    assert net.connect_calls == [("10.0.1.1", 80, 2.0)]


def test_state_from_bytes_drops_unknown_ids():
    cfg, clock = tcp_cfg(1), Clock()
    good = run(cfg, pr.empty_state(), clock, FakeNet(clock))
    doc = json.loads(pr.serialize_state(good))
    doc["targets"].append({**doc["targets"][0], "id": "evil"})
    out = pr.state_from_bytes(json.dumps(doc).encode(), cfg)
    assert out is not None and [t.id for t in out.targets] == ["t0"]


def test_deadline_stops_probing_and_marks_remainder():
    clock, cfg = Clock(), tcp_cfg(10)
    net = FakeNet(clock, [FAIL], cost=3.0)  # hangs past its own 2 s timeout
    start = clock.t
    state = run(cfg, pr.empty_state(), clock, net)
    assert clock.t - start <= 25.0
    assert net.calls == 8
    assert [t.note for t in state.targets] == [None] * 8 + ["skipped_deadline"] * 2
    assert all(t.last_attempt is None for t in state.targets[8:])


def test_deadline_not_hit_when_all_probes_are_fast():
    clock, cfg = Clock(), tcp_cfg(10)
    net = FakeNet(clock, [FAIL], cost=2.0)
    state = run(cfg, pr.empty_state(), clock, net)
    assert net.calls == 10 and all(t.note is None for t in state.targets)


def test_skipped_deadline_target_is_not_a_failure():
    clock, cfg = Clock(), tcp_cfg(10)
    net = FakeNet(clock, [FAIL], cost=3.0)
    state = run(cfg, pr.empty_state(), clock, net)
    assert all(t.consecutive_fail == 0 and t.ring == () for t in state.targets[8:])


def test_per_probe_timeout_is_passed_to_the_io_functions():
    clock = Clock()
    cfg = pr.parse_config(
        raw_config(
            targets=[
                {
                    "id": "d",
                    "kind": "dns_local",
                    "resolver": DNS_ADDR,
                    "qname": QNAME,
                    "timeout_s": 0.5,
                },
                target(id="t", timeout_s=1.5),
            ]
        )
    )
    net = FakeNet(clock)
    run(cfg, pr.empty_state(), clock, net)
    assert net.dns_calls[0][2] == 0.5 and net.connect_calls[0][2] == 1.5


def test_dns_packet_is_a_wellformed_query_for_the_configured_name():
    clock, cfg = Clock(), pr.parse_config(raw_config())
    net = FakeNet(clock)
    run(cfg, pr.empty_state(), clock, net)
    packet = net.dns_calls[0][1]
    assert packet[2:12] == struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
    assert packet[12:] == qwire(QNAME.split(".")) + b"\0\1\0\1"
    ids = set()
    for _ in range(20):
        net2 = FakeNet(Clock())
        run(cfg, pr.empty_state(), net2.clock, net2)
        ids.add(net2.dns_calls[0][1][:2])
    assert len(ids) > 1  # random per query


def test_disabled_config_probes_nothing_and_touches_no_files(tmp_path):
    clock = Clock()
    cfg = pr.parse_config(
        {"enabled": False, "state_file": str(tmp_path / "s.json"), "targets": [target()]}
    )
    net = FakeNet(clock)
    assert pr.run_once(cfg, now=clock, dns=net.dns, connect=net.connect) is None
    out = run(cfg, pr.empty_state(), clock, net)
    assert net.calls == 0 and out == pr.empty_state()
    assert list(tmp_path.iterdir()) == []


# ================================================================ results and error classes
@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (TimeoutError(), "timeout"),
        (ConnectionRefusedError(), "refused"),
        (OSError(errno.ENETUNREACH, "x"), "unreachable"),
        (OSError(errno.EHOSTUNREACH, "x"), "unreachable"),
        (OSError(errno.EIO, "x"), "other"),
    ],
)
def test_tcp_error_classes(exc, expected):
    state = drive([exc])[0]
    assert state.ring[-1][1:] == (False, None, expected) and state.last_error_class == expected


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [(TimeoutError(), "timeout"), (OSError(errno.EIO, "x"), "oserror"), (b"\0" * 5, "malformed")],
)
def test_dns_error_classes(outcome, expected):
    clock = Clock()
    cfg = pr.parse_config(
        with_targets({"id": "d", "kind": "dns_local", "resolver": DNS_ADDR, "qname": QNAME})
    )
    state = run(cfg, pr.empty_state(), clock, FakeNet(clock, [outcome]))
    assert state.targets[0].ring[-1][3] == expected


def test_ok_result_records_latency_ms_only():
    clock = Clock()
    net = FakeNet(clock, cost=0.123)
    state = run(tcp_cfg(1), pr.empty_state(), clock, net)
    t = state.targets[0]
    assert t.ring[-1] == (int(1_800_000_000 // 60), True, 123, None)
    assert t.last_latency_ms == 123 and t.state == "ok" and t.last_ok_at == pytest.approx(clock.t)


def test_latency_is_clamped_and_nonnegative():
    clock = Clock()
    net = FakeNet(clock, cost=500.0)
    assert run(tcp_cfg(1), pr.empty_state(), clock, net).targets[0].ring[-1][2] == pr.MAX_LATENCY_MS
    net = FakeNet(clock, cost=-5.0)
    assert run(tcp_cfg(1), pr.empty_state(), clock, net).targets[0].ring[-1][2] == 0


def test_bad_dns_replies_are_failures_with_error_class():
    clock = Clock()
    cfg = pr.parse_config(
        with_targets({"id": "d", "kind": "dns_local", "resolver": DNS_ADDR, "qname": QNAME})
    )
    net = FakeNet(clock, [b"x" * 5000])
    assert run(cfg, pr.empty_state(), clock, net).targets[0].ring[-1][3] == "malformed"


def test_run_pass_does_not_mutate_its_input_and_state_is_frozen():
    clock, cfg = Clock(), tcp_cfg(2)
    before = run(cfg, pr.empty_state(), clock, FakeNet(clock))
    snapshot = pr.serialize_state(before)
    clock.t += 120
    after = run(cfg, before, clock, FakeNet(clock, [FAIL]))
    assert pr.serialize_state(before) == snapshot and after is not before
    with pytest.raises(dataclasses.FrozenInstanceError):
        before.targets[0].state = "outage"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        before.written_at = 0.0  # type: ignore[misc]


# ================================================================ hysteresis
def test_f_f_ok_does_not_open():
    states = drive([FAIL, FAIL, None])
    assert all(s.state != "outage" for s in states)


def test_three_failures_open_an_episode():
    states = drive([FAIL, FAIL, FAIL])
    assert [s.state for s in states] == ["unknown", "unknown", "outage"]
    assert states[2].episode_start == 1_800_000_000 + 120
    assert states[1].episode_start is None


def test_ok_in_between_resets_failure_count():
    states = drive([FAIL, FAIL, None, FAIL, FAIL])
    assert all(s.state != "outage" for s in states)


def test_two_oks_do_not_recover_three_do():
    states = drive([FAIL] * 3 + [None, None, None])
    assert [s.state for s in states[3:]] == ["outage", "outage", "ok"]
    assert states[5].episode_start == states[2].episode_start  # kept for the recover token


def test_failure_resets_recovery_streak():
    states = drive([FAIL] * 3 + [None, None, FAIL, None, None])
    assert states[-1].state == "outage"
    states = drive([FAIL] * 3 + [None, None, FAIL, None, None, None])
    assert states[-1].state == "ok"


def test_first_success_from_unknown_is_ok():
    assert drive([None])[0].state == "ok"


def test_ok_state_needs_three_fresh_failures_to_open():
    states = drive([None, FAIL, FAIL, None, FAIL, FAIL])
    assert states[-1].state == "ok"


def episodes(count, outcomes_gap=60.0):
    seq = []
    for _ in range(count):
        seq += [FAIL] * 3 + [None] * 3
    return seq


MIDNIGHT = 1_800_000_000.0 - (1_800_000_000 % 86400)


def test_fourth_episode_in_one_utc_day_is_flapping():
    states = drive(episodes(4), clock=Clock(MIDNIGHT))
    assert [s.flapping for s in states[:20]] == [False] * 20  # episodes 1-3 are normal
    assert states[20].state == "outage" and states[20].flapping is True
    assert states[20].episodes_today == 3


def test_third_episode_is_not_flapping():
    states = drive(episodes(3), clock=Clock(MIDNIGHT))
    assert not any(s.flapping for s in states)
    assert states[-1].episodes_today == 3


def test_flapping_keeps_updating_status_then_clears_next_utc_day():
    states = drive(episodes(4) + [FAIL], clock=Clock(MIDNIGHT), gaps={23: 86400})
    assert states[23].state == "ok" and states[23].flapping is True  # status kept updating
    assert states[24].flapping is False and states[24].episodes_today == 0


# ================================================================ ring and state bounds
def test_ring_is_capped_at_60_and_keeps_newest():
    states = drive([None] * 75)
    ring = states[-1].ring
    assert len(ring) == pr.RING == 60
    assert [e[0] for e in ring] == sorted(e[0] for e in ring)
    assert ring[-1][0] == int((1_800_000_000 + 74 * 60) // 60)


def full_state():
    clock, cfg = Clock(), tcp_cfg(10)
    state = pr.empty_state()
    for _ in range(61):
        clock.t += 60
        state = run(cfg, state, clock, FakeNet(clock, [OSError(errno.ENETUNREACH, "x")], cost=0.01))
    return state


def test_worst_case_serialized_state_fits_32kib():
    state = full_state()
    assert len(state.targets) == 10 and all(len(t.ring) == 60 for t in state.targets)
    assert len(pr.serialize_state(state)) <= pr.MAX_STATE_BYTES == 32768


def test_oversize_state_is_refused_before_writing():
    huge = dataclasses.replace(
        pr.new_target_state("t0"), ring=tuple((1, False, None, "no_answer") for _ in range(5000))
    )
    with pytest.raises(pr.ProbeError):
        pr.serialize_state(dataclasses.replace(pr.empty_state(), targets=(huge,)))


def test_state_roundtrip_and_hostile_bytes_are_rejected():
    cfg, clock = tcp_cfg(2), Clock()
    state = run(cfg, pr.empty_state(), clock, FakeNet(clock, [FAIL]))
    again = pr.state_from_bytes(pr.serialize_state(state), cfg)
    assert again == state
    doc = json.loads(pr.serialize_state(state))

    def mutated(fn):
        d = json.loads(json.dumps(doc))
        fn(d)
        return json.dumps(d).encode()

    hostile = [
        b"",
        b"not json",
        b"[]",
        b"x" * 70000,
        mutated(lambda d: d.update(v=2)),
        mutated(lambda d: d.update(extra=1)),
        mutated(lambda d: d["targets"][0].update(state="weird")),
        mutated(lambda d: d["targets"][0].update(consecutive_fail=-1)),
        mutated(lambda d: d["targets"][0].update(consecutive_fail=True)),
        mutated(lambda d: d["targets"][0].update(last_error_class="<script>")),
        mutated(lambda d: d["targets"][0].update(last_latency_ms=10**9)),
        mutated(lambda d: d["targets"][0].update(ring=[[1, True, 5, None]] * 61)),
        mutated(lambda d: d["targets"][0].update(ring=[[1, "yes", 5, None]])),
        mutated(lambda d: d["targets"][0].update(ring=[[1, False, None, "nope"]])),
        mutated(lambda d: d["targets"][0].update(note="x")),
        mutated(lambda d: d["targets"][0].update(unknown=1)),
        mutated(lambda d: d.update(written_at="now")),
        mutated(lambda d: d.update(targets=doc["targets"] * 20)),
        mutated(
            lambda d: d.update(
                targets=[{**doc["targets"][0], "id": f"t{i}"} for i in range(pr.MAX_TARGETS + 1)]
            )
        ),
        pr.serialize_state(state) + b" " * 70000,
    ]
    for data in hostile:
        assert pr.state_from_bytes(data, cfg) is None, data[:60]


# ================================================================ file I/O, lock, run_once
def file_cfg(tmp_path, **over):
    return pr.parse_config(raw_config(state_file=str(tmp_path / "probe-state.json"), **over))


def test_write_state_is_private_atomic_and_leaves_no_temp(tmp_path):
    cfg, clock = file_cfg(tmp_path), Clock()
    state = run(cfg, pr.empty_state(), clock, FakeNet(clock))
    pr.write_state(cfg.state_file, state)
    assert (os.stat(cfg.state_file).st_mode & 0o777) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["probe-state.json"]
    assert pr.read_state(cfg.state_file, cfg) == state


def test_read_state_missing_or_corrupt_gives_fresh_state(tmp_path):
    cfg = file_cfg(tmp_path)
    assert pr.read_state(cfg.state_file, cfg) == pr.empty_state()
    Path(cfg.state_file).write_text("{broken")
    assert pr.read_state(cfg.state_file, cfg) == pr.empty_state()


def test_read_state_refuses_symlink(tmp_path):
    cfg = file_cfg(tmp_path)
    real = tmp_path / "real.json"
    real.write_text("{}")
    os.symlink(real, cfg.state_file)
    with pytest.raises(pr.ProbeError):
        pr.read_state(cfg.state_file, cfg)


def test_run_once_end_to_end_with_fresh_process_rate_cap(tmp_path):
    cfg, clock = file_cfg(tmp_path), Clock()
    net = FakeNet(clock)
    out = pr.run_once(cfg, now=clock, dns=net.dns, connect=net.connect)
    assert out is not None and net.calls == 2
    assert out.written_at == pytest.approx(clock.t)
    on_disk = json.loads(Path(cfg.state_file).read_bytes())
    assert on_disk["v"] == 1 and len(on_disk["targets"]) == 2
    clock.t += 20
    pr.run_once(cfg, now=clock, dns=net.dns, connect=net.connect)
    assert net.calls == 2
    clock.t += 60
    pr.run_once(cfg, now=clock, dns=net.dns, connect=net.connect)
    assert net.calls == 4


def test_run_once_skips_when_another_run_holds_the_lock(tmp_path):
    import fcntl

    cfg, clock = file_cfg(tmp_path), Clock()
    fd = os.open(cfg.state_file + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        net = FakeNet(clock)
        assert pr.run_once(cfg, now=clock, dns=net.dns, connect=net.connect) is None
        assert net.calls == 0 and not Path(cfg.state_file).exists()
    finally:
        os.close(fd)


def test_run_once_releases_the_lock(tmp_path):
    cfg, clock = file_cfg(tmp_path), Clock()
    net = FakeNet(clock)
    for _ in range(2):
        clock.t += 100
        assert pr.run_once(cfg, now=clock, dns=net.dns, connect=net.connect) is not None


# ================================================================ log hygiene
def test_logs_never_carry_address_qname_or_port(caplog):
    clock = Clock()
    cfg = pr.parse_config(raw_config())
    net = FakeNet(clock, [FAIL], cost=0.01)
    state = pr.empty_state()
    with caplog.at_level(logging.DEBUG):
        for _ in range(8):
            state = run(cfg, state, clock, net)
            clock.t += 60
    text = "\n".join(r.getMessage() + repr(r.args) for r in caplog.records)
    assert caplog.records, "the runner must log failures (otherwise this test is vacuous)"
    assert "timeout" in text and "router-dns" in text
    for secret in (DNS_ADDR, TCP_ADDR, QNAME, "svc", str(PORT), "8443", "home.lan"):
        assert secret not in text


def test_error_messages_never_carry_address_qname_or_port():
    for raw in (with_targets(target(address="8.8.4.4", port=PORT)),):
        with pytest.raises(pr.ProbeError) as info:
            pr.parse_config(raw)
        assert "8.8.4.4" not in str(info.value) and str(PORT) not in str(info.value)


# ================================================================ parser vectors and parity
@pytest.mark.parametrize("name", sorted(vectors()))
def test_classify_reply_matches_soak_parser(name, monkeypatch):
    vector = vectors()[name]
    labels = tuple(x.encode() for x in EXAMPLE)
    mine = pr.classify_reply(vector, QID, labels)

    class FakeSocket:
        def __init__(self, *_a, **_k):
            self.sent = b""

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def settimeout(self, _t):
            pass

        def connect(self, _addr):
            pass

        def send(self, data):
            self.sent = data

        def recv(self, _n):
            # the soak picks a random id: substitute it into any vector that carried QID
            return self.sent[:2] + vector[2:] if vector[:2] == QID else vector

    monkeypatch.setattr(rs.socket, "socket", FakeSocket)
    diag = {}
    theirs = rs.dns_probe("10.0.0.1", diag)
    assert (mine is None) == theirs, name
    if mine is not None and name != "bad_id":
        assert mine == diag["error"], name
    if name == "bad_id":
        assert mine == "bad_id" and diag["error"] == "bad_id"


def test_vector_expectations_are_the_documented_classes():
    labels = tuple(x.encode() for x in EXAMPLE)
    expect = {
        "ok": None,
        "ok_inline_owner": None,
        "ok_uppercase_echo": None,
        "bad_id": "bad_id",
        "rcode_nxdomain": "rcode",
        "no_answer": "no_answer",
        "not_response": "malformed",
        "type_28_len4": "no_answer",
        "class_ch": "no_answer",
        "a_only_in_authority": "no_answer",
        "not_response_noanswer": "malformed",
        "not_response_rcode": "malformed",
        "answers_over_cap": "malformed",
        "records_over_cap": "malformed",
        "answers_at_cap": None,
        "rdlength_past_end": "malformed",
        "truncated_packet": "malformed",
        "too_short": "malformed",
        "oversize": "malformed",
        "trailing_data": "malformed",
        "compression_self_loop": "malformed",
        "compression_forward": "malformed",
        "wrong_question": "malformed",
        "wrong_qtype": "malformed",
        "wrong_owner": "no_answer",
        "cname_only": "no_answer",
        "aaaa_only": "no_answer",
        "bad_rdlength": "no_answer",
        "two_questions": "malformed",
        "too_many_answers": "malformed",
    }
    got = vectors()
    for name, want in expect.items():
        assert pr.classify_reply(got[name], QID, labels) == want, name


def test_parameterized_question_is_enforced():
    labels = tuple(x.encode() for x in QNAME.split("."))
    good = reply(labels=QNAME.split("."))
    assert pr.classify_reply(good, QID, labels) is None
    assert (
        pr.classify_reply(reply(), QID, labels) == "malformed"
    )  # example.com echo for another name
    assert pr.classify_reply(good, QID, tuple(x.encode() for x in EXAMPLE)) == "malformed"


def test_encode_qname_and_build_query():
    assert pr.encode_qname("svc.home.lan") == b"\x03svc\x04home\x03lan\0"
    assert (
        pr.build_query(QID, "svc.home.lan")
        == QID + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + b"\x03svc\x04home\x03lan\0\0\1\0\1"
    )


# ================================================================ module hygiene
def test_module_is_stdlib_only_and_small():
    tree = ast.parse(MODULE.read_text())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            mods.add((node.module or "").split(".")[0])
    assert mods <= set(sys.stdlib_module_names), mods - set(sys.stdlib_module_names)
    assert len(MODULE.read_text().splitlines()) < 800
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assert node.end_lineno - node.lineno + 1 < 50, node.name


def test_import_opens_no_network_and_creates_no_files(tmp_path):
    code = (
        "import socket,sys,importlib.util\n"
        "def boom(*a,**k): raise SystemExit('network touched')\n"
        "socket.socket=boom; socket.getaddrinfo=boom; socket.create_connection=boom\n"
        "spec=importlib.util.spec_from_file_location('probe_runner_imp', sys.argv[1])\n"
        "m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m\n"
        "spec.loader.exec_module(m)\n"
    )
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code, str(MODULE)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    assert list(tmp_path.iterdir()) == []
