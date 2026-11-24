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


# Delete or invert when the mode check lands (docs/monitoring.md:1129 says the config is private).
@pytest.mark.parametrize("mode", [0o644, 0o666, 0o640])
def test_known_gap_config_mode_not_enforced(tmp_path, mode):
    """FINDING: the runner never checks the config's mode or owner (only render's skeleton and
    the docs say private). A group/world-readable or writable config is loaded and probed.
    Pinned so that adding the check is a visible, deliberate change."""
    (tmp_path / "state").mkdir()
    code, calls = run_main(tmp_path, config(tmp_path), mode=mode)
    assert code == pr.EXIT_OK and len(calls) == 1
