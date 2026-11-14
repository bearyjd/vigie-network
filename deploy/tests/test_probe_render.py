"""render.py probe wiring: disabled output is byte-identical to main; enabled adds exactly the probe
volume, a read-only pipeline mount, the env var and the probe service/timer units."""

# ruff: noqa: E501, S104
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

PERSISTENT = Path(__file__).parents[1] / "persistent"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


render = _load("persistent_render_probe_tests", PERSISTENT / "render.py")
runner = _load("probe_runner_render_parity", PERSISTENT / "probe_runner.py")

BASE = {
    "namespace": "vigie_test",
    "image": "sha256:" + "a" * 64,
    "ingest_address": "192.0.2.20",
    "ingest_port": 18443,
    "api_port": 18444,
    "collector_key_id": "k1",
}
# sha256 of each rendered file, captured from origin/main (73bd7f6) before any probe code existed.
GOLDEN_FILES = {
    "vigie_test-api.container": "38fbe297b076d0e1bf7187cc19f67e22d6871a5e99e905e9be1892b6d07624e4",
    "vigie_test-ingest.container": "4481942e2cfd96c7c1bcf87251c50ff33ec34b7500c4aa58d6f7669d21afa621",
    "vigie_test-inv.volume": "4477fed973818287a2b46fc5625f36b8e505150c6578f513674269eb5f0369c6",
    "vigie_test-overrides.volume": "890fbb0b09ccc1f9f1b82cff9d1555d7de91352b6be950a63fbf6ef123a39869",
    "vigie_test-pipeline.container": "34e2a09daaf5873e7a6a24b1e67e48decedd95f3c78e7ce9f3f150854c7b6714",
    "vigie_test-raw.volume": "de1a5531cf37fc4eba4febbccfdee127ccd99d19ba0107c92f40a0098a54dd16",
}
GOLDEN_PLAN = "f606c217ff4cb60f7c708fde5884d6751fa6939e0cc46d1555500fcb145a320b"
GOLDEN_TOD_PIPELINE = "08e380149bba4f704f50a0b892f8e011c7338b6b23bba94fae68ea571f3bb564"
PROBE = {"probes_enabled": True, "probe_allow": ["10.0.0.7", "10.0.0.9", "fd12::7"]}


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def digests(files):
    return {name: sha(text) for name, text in sorted(files.items())}


# ---------------------------------------------------------------- disabled == main, byte for byte
def test_disabled_output_is_byte_identical_to_main():
    assert digests(render.render(BASE)) == GOLDEN_FILES


def test_explicitly_disabled_is_byte_identical_to_main():
    assert digests(render.render({**BASE, "probes_enabled": False})) == GOLDEN_FILES


def test_disabled_bundle_plan_is_byte_identical_to_main():
    with tempfile.TemporaryDirectory() as tmp:
        render.write_bundle(BASE, Path(tmp) / "out")
        assert sha((Path(tmp) / "out" / "plan.json").read_text()) == GOLDEN_PLAN


def test_disabled_tod_pipeline_is_byte_identical_to_main():
    tod = {**BASE, "monitoring_baseline": "tod", "monitoring_large_upload_bytes": 2**30}
    assert sha(render.render(tod)["vigie_test-pipeline.container"]) == GOLDEN_TOD_PIPELINE


def test_disabled_output_has_no_probe_trace():
    for name, text in render.render(BASE).items():
        assert "probe" not in name.lower() and "probe" not in text.lower(), name


# ---------------------------------------------------------------- enabled
def test_enabled_adds_only_the_probe_artifacts():
    files = render.render({**BASE, **PROBE})
    assert set(files) - set(GOLDEN_FILES) == {
        "vigie_test-probe.volume",
        "vigie_test-probe.service",
        "vigie_test-probe.timer",
    }
    assert files["vigie_test-probe.volume"] == "[Volume]\nVolumeName=vigie_test_probe\n"
    for name in ("api", "ingest"):
        assert (
            sha(files[f"vigie_test-{name}.container"])
            == GOLDEN_FILES[f"vigie_test-{name}.container"]
        )
    for volume in ("raw", "inv", "overrides"):
        assert (
            sha(files[f"vigie_test-{volume}.volume"]) == GOLDEN_FILES[f"vigie_test-{volume}.volume"]
        )


def test_enabled_pipeline_is_main_plus_exactly_two_lines():
    files = render.render({**BASE, **PROBE})
    main = render.render(BASE)["vigie_test-pipeline.container"].splitlines()
    new = files["vigie_test-pipeline.container"].splitlines()
    added = [line for line in new if line not in main]
    assert added == [
        "Volume=vigie_test-probe.volume:/probe:ro",
        "Environment=VIGIE_PROBE_FILE=/probe/probe-state.json",
    ]
    assert [line for line in main if line not in new] == []
    assert "Network=none" in new
    assert [x for x in new if x.startswith("Volume=")][
        -1
    ] == "Volume=vigie_test-probe.volume:/probe:ro"


def test_probe_volume_is_mounted_read_only_into_the_pipeline_only():
    files = render.render({**BASE, **PROBE})
    mounts = {
        name: [line for line in text.splitlines() if "probe" in line.lower()]
        for name, text in files.items()
        if name.endswith(".container")
    }
    assert mounts["vigie_test-api.container"] == []
    assert mounts["vigie_test-ingest.container"] == []
    assert all(
        ":ro" in m for m in mounts["vigie_test-pipeline.container"] if m.startswith("Volume=")
    )


def test_service_unit_is_filled_from_the_template_with_the_allowed_targets():
    service = render.render({**BASE, **PROBE})["vigie_test-probe.service"]
    assert "IPAddressDeny=any\n" in service
    assert "IPAddressAllow=10.0.0.7 10.0.0.9 fd12::7\n" in service
    assert "@PROBE_TARGET_IPS@" not in service
    assert "TimeoutStartSec=45" in service and "Type=oneshot" in service
    template = (PERSISTENT / "probe.service").read_text()
    assert service == template.replace("@PROBE_TARGET_IPS@", "10.0.0.7 10.0.0.9 fd12::7")


def test_timer_unit_targets_the_namespaced_service():
    timer = render.render({**BASE, **PROBE})["vigie_test-probe.timer"]
    assert "Unit=vigie_test-probe.service\n" in timer
    assert "OnUnitActiveSec=60s" in timer
    assert timer == (PERSISTENT / "probe.timer").read_text().replace(
        "Unit=probe.service", "Unit=vigie_test-probe.service"
    )


def test_unit_templates_follow_the_podman_unshare_hardening_rules():
    text = (PERSISTENT / "probe.service").read_text()
    directives = [x.split("=")[0] for x in text.splitlines() if "=" in x and not x.startswith("#")]
    for banned in (
        "PrivateTmp",
        "ProtectSystem",
        "ProtectHome",
        "ReadWritePaths",
        "NoNewPrivileges",
        "RestrictNamespaces",
        "CapabilityBoundingSet",
        "SystemCallFilter",
    ):
        assert banned not in directives
    assert not [d for d in directives if d.startswith("Protect")]
    assert "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" in text
    assert "podman unshare /usr/bin/python3 -I " in text and "probe_runner.py" in text


def test_enabled_bundle_hashes_every_file(tmp_path):
    render.write_bundle({**BASE, **PROBE}, tmp_path / "out")
    plan = json.loads((tmp_path / "out" / "plan.json").read_text())
    assert {"vigie_test-probe.service", "vigie_test-probe.timer", "vigie_test-probe.volume"} <= set(
        plan["files"]
    )


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize(
    "extra",
    [
        {"probes_enabled": "yes", "probe_allow": ["10.0.0.7"]},
        {"probes_enabled": 1, "probe_allow": ["10.0.0.7"]},
        {"probes_enabled": True},  # enabled needs targets
        {"probes_enabled": True, "probe_allow": []},
        {"probes_enabled": True, "probe_allow": "10.0.0.7"},
        {"probes_enabled": True, "probe_allow": [f"10.0.0.{i}" for i in range(1, 12)]},
        {"probes_enabled": True, "probe_allow": ["10.0.0.7", "10.0.0.7"]},
        {"probes_enabled": True, "probe_allow": ["8.8.8.8"]},
        {"probes_enabled": True, "probe_allow": ["router.lan"]},
        {"probes_enabled": True, "probe_allow": ["10.0.0.0/8"]},
        {"probes_enabled": True, "probe_allow": ["127.0.0.1"]},
        {"probes_enabled": True, "probe_allow": ["169.254.169.254"]},
        {"probes_enabled": True, "probe_allow": ["fe80::1%eth0"]},
        {"probes_enabled": True, "probe_allow": ["fd12::7%eth0"]},
        {"probes_enabled": True, "probe_allow": ["fd00:ec2::254"]},
        {"probes_enabled": True, "probe_allow": ["10.0.0.7 8.8.8.8"]},
        {"probes_enabled": True, "probe_allow": ["10.0.0.7\nExecStart=/bin/sh"]},
        {"probes_enabled": True, "probe_allow": [7]},
        {"probes_enabled": False, "probe_allow": ["10.0.0.7"]},  # no half-configured probes
        {"probe_allow": ["10.0.0.7"]},
        {"probes_enabled": True, "probe_allow": ["10.0.0.7"], "unknown": 1},
    ],
)
def test_invalid_probe_configuration_is_rejected(extra):
    with pytest.raises(ValueError):
        render.render({**BASE, **extra})


def test_render_address_policy_matches_the_runner_policy():
    vectors = [
        "10.0.0.7", "172.16.0.1", "172.32.0.1", "192.168.1.1", "192.0.2.1", "100.64.0.1",
        "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "8.8.8.8", "fc00::1", "fd12::7",
        "fd00:ec2::1", "fd12::7%eth0", "fe80::1", "::1", "::ffff:10.0.0.1", "2001:db8::1", "10.0.0.7/8", "10.0.0.7 ",
        "router.lan", "", "1e1.0.0.1",
    ]  # fmt: skip
    for value in vectors:
        accepted = render.private_probe_address(value) is not None
        assert accepted == (runner._private_ip(value) is not None), value
