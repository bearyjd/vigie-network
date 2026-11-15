"""Contracts for the real probe adapters and the one-shot CLI (loopback sockets only)."""

from __future__ import annotations

import errno
import importlib.util
import json
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

PERSISTENT = Path(__file__).parents[1] / "persistent"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pr = _load("probe_runner_adapters_under_test", PERSISTENT / "probe_runner.py")
LOOP = "127.0.0.1"  # loopback only: tests never touch a real network


class UdpServer:
    """Loopback UDP server on its own thread. `reply(query)` returns bytes to send, or None."""

    def __init__(self, reply, *, from_other_socket=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LOOP, 0))
        self.sock.settimeout(5)
        self.other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if from_other_socket else None
        self.port = self.sock.getsockname()[1]
        self.reply = reply
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            data, peer = self.sock.recvfrom(65535)
        except OSError:
            return
        out = self.reply(data)
        if out is not None:
            (self.other or self.sock).sendto(out, peer)

    def close(self):
        self.sock.close()
        if self.other:
            self.other.close()


@pytest.fixture
def udp():
    made = []

    def make(reply, **kw):
        server = UdpServer(reply, **kw)
        made.append(server)
        return server

    yield make
    for server in made:
        server.close()


def echo(query):
    return query


# ---------------------------------------------------------------- real_dns
def test_real_dns_returns_the_reply_of_the_configured_resolver(udp):
    server = udp(lambda q: q + b"tail")
    got = pr.real_dns(LOOP, b"\x12\x34query", 1.0, port=server.port)
    assert got == b"\x12\x34query" + b"tail"


def test_real_dns_ignores_a_reply_from_any_other_source(udp):
    # connected socket: the kernel drops datagrams not from the resolver's address and port
    server = udp(echo, from_other_socket=True)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        pr.real_dns(LOOP, b"\x12\x34query", 0.3, port=server.port)
    assert time.monotonic() - start < 1.5


def test_real_dns_reads_one_byte_past_the_parser_cap(udp):
    server = udp(lambda q: b"\xab" * 6000)
    got = pr.real_dns(LOOP, b"\x12\x34q", 1.0, port=server.port)
    assert len(got) == pr.MAX_REPLY + 1  # an oversize reply is detectable, never truncated to ok
    assert pr.classify_reply(got, b"\xab\xab", (b"x",)) == "malformed"


def test_real_dns_times_out_when_nothing_answers(udp):
    server = udp(lambda q: None)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        pr.real_dns(LOOP, b"\x12\x34q", 0.3, port=server.port)
    assert time.monotonic() - start < 1.5


class FakeSocket:
    instances: list[FakeSocket] = []

    def __init__(self, family, kind):
        self.family, self.kind, self.calls, self.closed = family, kind, [], False
        FakeSocket.instances.append(self)

    def settimeout(self, value):
        self.calls.append(("settimeout", value))

    def connect(self, addr):
        self.calls.append(("connect", addr))

    def send(self, data):
        self.calls.append(("send", data))

    def sendto(self, *a):  # an unconnected send would defeat the source filter
        raise AssertionError("sendto must not be used")

    def recv(self, size):
        self.calls.append(("recv", size))
        return b"reply"

    def recvfrom(self, *a):
        raise AssertionError("recvfrom must not be used")

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


@pytest.fixture
def fake_socket(monkeypatch):
    FakeSocket.instances = []
    monkeypatch.setattr(pr.socket, "socket", FakeSocket)
    monkeypatch.setattr(
        pr.socket, "getaddrinfo", lambda *a, **k: pytest.fail("name resolution is forbidden")
    )
    return FakeSocket


def test_real_dns_call_shape(fake_socket):
    assert pr.real_dns("10.0.0.7", b"q", 1.5) == b"reply"
    (sock,) = fake_socket.instances
    assert sock.kind == socket.SOCK_DGRAM and sock.family == socket.AF_INET
    assert sock.calls == [
        ("settimeout", 1.5),
        ("connect", ("10.0.0.7", 53)),
        ("send", b"q"),
        ("recv", pr.MAX_REPLY + 1),
    ]
    assert sock.closed


def test_real_dns_ipv6_family_and_close_on_error(fake_socket):
    pr.real_dns("fd12::7", b"q", 1.0)
    assert fake_socket.instances[0].family == socket.AF_INET6

    def boom(self, size):
        raise TimeoutError

    fake_socket.recv = boom
    with pytest.raises(TimeoutError):
        pr.real_dns("10.0.0.7", b"q", 1.0)
    assert fake_socket.instances[-1].closed


@pytest.mark.parametrize("call", ["dns", "tcp"])
def test_adapters_refuse_hostnames_without_resolving(fake_socket, call):
    with pytest.raises(OSError) as info:
        if call == "dns":
            pr.real_dns("resolver.example", b"q", 1.0)
        else:
            pr.real_connect("router.example", 80, 1.0)
    assert info.value.errno == errno.EINVAL
    assert not fake_socket.instances


# ---------------------------------------------------------------- real_connect
def test_real_connect_succeeds_against_a_listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((LOOP, 0))
    listener.listen(1)
    try:
        assert pr.real_connect(LOOP, listener.getsockname()[1], 1.0) is None
    finally:
        listener.close()


def test_real_connect_refused_maps_through_the_classifier():
    probe = socket.socket()
    probe.bind((LOOP, 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listens here now
    with pytest.raises(ConnectionRefusedError):
        pr.real_connect(LOOP, port, 1.0)


def test_real_connect_call_shape_sends_nothing(fake_socket):
    pr.real_connect("192.168.1.1", 8080, 1.25)
    (sock,) = fake_socket.instances
    assert sock.kind == socket.SOCK_STREAM
    assert sock.calls == [("settimeout", 1.25), ("connect", ("192.168.1.1", 8080))]
    assert sock.closed


# ---------------------------------------------------------------- main
def _cfg_file(tmp_path, **over):
    raw = {
        "enabled": True,
        "state_file": str(tmp_path / "probe-state.json"),
        "targets": [{"id": "lan-web", "kind": "tcp_lan", "address": "10.0.0.9", "port": 8080}],
    }
    path = tmp_path / "probe.json"
    path.write_text(json.dumps({**raw, **over}))
    return path


def _fake_connect(host, port, timeout):
    return None


def test_main_disabled_does_nothing_and_writes_no_file(tmp_path, capsys):
    path = _cfg_file(tmp_path, enabled=False)
    assert pr.main([str(path)], connect=_fake_connect) == pr.EXIT_OK
    assert sorted(p.name for p in tmp_path.iterdir()) == ["probe.json"]


def test_main_one_pass_writes_state_and_prints_no_address(tmp_path, capsys):
    path = _cfg_file(tmp_path)
    assert pr.main([str(path), "--once"], connect=_fake_connect) == pr.EXIT_OK
    out = capsys.readouterr().out
    assert "10.0.0.9" not in out and "8080" not in out
    cfg = pr.load_config(str(path))
    state = pr.read_state(cfg.state_file, cfg)
    assert [t.state for t in state.targets] == ["ok"] and state.targets[0].ring[0][1] is True
    assert (tmp_path / "probe-state.json.lock").exists()


def test_main_config_errors_exit_2_with_fixed_text(tmp_path, caplog):
    path = _cfg_file(
        tmp_path, targets=[{"id": "x", "kind": "tcp_lan", "address": "8.8.8.8", "port": 1}]
    )
    with caplog.at_level(logging.INFO):
        assert pr.main([str(path)]) == pr.EXIT_CONFIG
    assert "8.8.8.8" not in caplog.text
    assert pr.main([str(tmp_path / "missing.json")]) == pr.EXIT_CONFIG


def test_main_unexpected_error_logs_class_name_only(tmp_path, caplog):
    def explode(host, port, timeout):
        raise RuntimeError("secret 10.0.0.9")

    path = _cfg_file(tmp_path)
    with caplog.at_level(logging.INFO):
        assert pr.main([str(path)], connect=explode) == pr.EXIT_INTERNAL
    assert "10.0.0.9" not in caplog.text and "RuntimeError" in caplog.text


def test_main_unwritable_state_exits_io(tmp_path, caplog):
    path = _cfg_file(tmp_path, state_file=str(tmp_path / "nodir" / "probe-state.json"))
    assert pr.main([str(path)], connect=_fake_connect) == pr.EXIT_IO


def test_main_lock_held_skips_cleanly(tmp_path):
    path = _cfg_file(tmp_path)
    cfg = pr.load_config(str(path))
    held = pr.acquire_lock(cfg.state_file + ".lock")
    try:
        calls = []
        assert pr.main([str(path)], connect=lambda *a: calls.append(a)) == pr.EXIT_OK
        assert calls == []
    finally:
        os.close(held)


def test_main_defaults_to_the_real_adapters():
    import inspect

    params = inspect.signature(pr.main).parameters
    assert params["dns"].default is None and params["connect"].default is None


def test_state_world_readable_opt_in(tmp_path):
    path = _cfg_file(tmp_path, state_world_readable=True)
    old = os.umask(0o077)  # the unit sets UMask=0077: it must not narrow the opted-in mode
    try:
        assert pr.main([str(path)], connect=_fake_connect) == pr.EXIT_OK
    finally:
        os.umask(old)
    assert os.stat(tmp_path / "probe-state.json").st_mode & 0o777 == 0o644
    path2 = tmp_path / "b"
    path2.mkdir()
    assert pr.main([str(_cfg_file(path2))], connect=_fake_connect) == pr.EXIT_OK
    assert os.stat(path2 / "probe-state.json").st_mode & 0o777 == 0o600
    bad = _cfg_file(tmp_path, state_world_readable="yes")
    assert pr.main([str(bad)], connect=_fake_connect) == pr.EXIT_CONFIG
