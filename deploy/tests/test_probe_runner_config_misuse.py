"""The probe runner's config file as a hostile source, through main() (files, not parse_config).

Nothing may be probed or written when the config is rejected."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

PERSISTENT = Path(__file__).parents[1] / "persistent"
_spec = importlib.util.spec_from_file_location(
    "probe_runner_source_misuse", PERSISTENT / "probe_runner.py"
)
pr = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pr
_spec.loader.exec_module(pr)

DNS = {"id": "router-dns", "kind": "dns_local", "resolver": "10.0.0.7", "qname": "svc.home.lan"}


def config(tmp_path, *targets):
    return {
        "enabled": True,
        "state_file": str(tmp_path / "state" / "probe-state.json"),
        "targets": list(targets) or [DNS],
    }


def lan(n):
    return {"id": f"t{n}", "kind": "tcp_lan", "address": f"10.0.1.{n + 1}", "port": 80}


def run_main(tmp_path, raw, mode=0o600):
    path = tmp_path / "probe.json"
    path.write_text(json.dumps(raw))
    path.chmod(mode)
    calls = []

    def dns(*args):
        calls.append(args)
        raise TimeoutError

    def connect(*args):
        calls.append(args)
        raise TimeoutError

    code = pr.main([str(path)], dns=dns, connect=connect)
    return code, calls


def assert_untouched(tmp_path, calls):
    assert calls == []
    assert not (tmp_path / "state").exists()


REJECTED = {
    "public_resolver": lambda p: config(p, {**DNS, "resolver": "8.8.8.8"}),
    "loopback_resolver": lambda p: config(p, {**DNS, "resolver": "127.0.0.1"}),
    "link_local_resolver": lambda p: config(p, {**DNS, "resolver": "169.254.1.1"}),
    "hostname_resolver": lambda p: config(p, {**DNS, "resolver": "router.home.lan"}),
    "hostname_tcp": lambda p: config(p, {**lan(1), "address": "router.home.lan"}),
    "scoped_resolver": lambda p: config(p, {**DNS, "resolver": "fd12::7%eth0"}),
    "second_dns_upstream": lambda p: config(
        p,
        {**DNS, "id": "up1", "kind": "dns_upstream"},
        {**DNS, "id": "up2", "kind": "dns_upstream"},
    ),
    "eleven_targets": lambda p: config(p, *[lan(i) for i in range(11)]),
    "relative_state_file": lambda p: {**config(p), "state_file": "probe-state.json"},
    "unknown_key": lambda p: {**config(p), "extra": 1},
}


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_a_misused_config_file_exits_with_the_config_error_and_does_nothing(tmp_path, name):
    code, calls = run_main(tmp_path, REJECTED[name](tmp_path))
    assert code == pr.EXIT_CONFIG
    assert_untouched(tmp_path, calls)


def test_ten_targets_and_one_dns_upstream_are_the_accepted_edge(tmp_path):
    raw = config(tmp_path, {**DNS, "id": "up", "kind": "dns_upstream"}, *[lan(i) for i in range(9)])
    (tmp_path / "state").mkdir()
    code, calls = run_main(tmp_path, raw)
    assert code == pr.EXIT_OK and len(calls) == 10


def test_a_symlinked_config_exits_with_the_config_error_and_does_nothing(tmp_path):
    real = tmp_path / "real.json"
    real.write_text(json.dumps(config(tmp_path)))
    link = tmp_path / "link.json"
    os.symlink(real, link)
    calls = []
    code = pr.main([str(link)], dns=lambda *a: calls.append(a), connect=lambda *a: calls.append(a))
    assert code == pr.EXIT_CONFIG
    assert_untouched(tmp_path, calls)


SINGLE_BITS = [0o600 | bit for bit in (0o040, 0o020, 0o010, 0o004, 0o002, 0o001)]
EXTRA_BITS = [0o4600, 0o2600, 0o1600, 0o700, 0o500, 0o4400]


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666, 0o660, *SINGLE_BITS, *EXTRA_BITS])
def test_a_config_with_any_bit_beyond_owner_read_write_is_refused_and_does_nothing(tmp_path, mode):
    code, calls = run_main(tmp_path, config(tmp_path), mode=mode)
    assert code == pr.EXIT_CONFIG
    assert_untouched(tmp_path, calls)


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_a_private_config_is_accepted(tmp_path, mode):
    (tmp_path / "state").mkdir()
    code, calls = run_main(tmp_path, config(tmp_path), mode=mode)
    assert code == pr.EXIT_OK and len(calls) == 1


def test_a_config_owned_by_another_uid_is_refused_and_does_nothing(tmp_path, monkeypatch):
    # chown to another user needs root, so shift the effective uid instead: same comparison.
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(tmp_path).st_uid + 1)
    code, calls = run_main(tmp_path, config(tmp_path))
    assert code == pr.EXIT_CONFIG
    assert_untouched(tmp_path, calls)


def test_the_refusal_message_echoes_no_path_or_content(tmp_path, caplog):
    run_main(tmp_path, config(tmp_path), mode=0o644)
    text = caplog.text
    assert "private" in text and str(tmp_path) not in text and "probe-state" not in text


def test_a_directory_config_exits_with_the_config_error_and_does_nothing(tmp_path, caplog):
    path = tmp_path / "dir.json"
    path.mkdir()
    calls = []
    code = pr.main([str(path)], dns=lambda *a: calls.append(a), connect=lambda *a: calls.append(a))
    assert code == pr.EXIT_CONFIG
    assert_untouched(tmp_path, calls)
    assert "Traceback" not in caplog.text and str(tmp_path) not in caplog.text


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_the_check_reads_the_opened_fd_not_the_path(tmp_path, monkeypatch, mode):
    """A path-based stat can be raced between open and check; fstat cannot."""
    real_stat, real_lstat = os.stat, os.lstat
    config_path = str(tmp_path / "probe.json")

    def guard(real):
        def inner(path, *a, **kw):
            if os.fspath(path) == config_path:
                raise AssertionError("config checked by path")
            return real(path, *a, **kw)

        return inner

    monkeypatch.setattr(os, "stat", guard(real_stat))
    monkeypatch.setattr(os, "lstat", guard(real_lstat))
    (tmp_path / "state").mkdir()
    code, calls = run_main(tmp_path, config(tmp_path), mode=mode)
    assert code == (pr.EXIT_OK if mode == 0o600 else pr.EXIT_CONFIG)
