"""Behavioral contracts for an inert persistent deployment renderer."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "persistent_render", Path(__file__).parents[1] / "persistent" / "render.py"
)
render = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = render
SPEC.loader.exec_module(render)


def config(**updates):
    value = {
        "namespace": "vigie_test",
        "image": "sha256:" + "a" * 64,
        "ingest_address": "192.0.2.20",
        "ingest_port": 18443,
        "api_port": 18444,
        "collector_key_id": "k1",
    }
    value.update(updates)
    return value


class RendererTests(unittest.TestCase):
    def test_mount_and_secret_boundaries_and_local_api(self):
        files = render.render(config())
        ingest = files["vigie_test-ingest.container"]
        api = files["vigie_test-api.container"]
        pipeline = files["vigie_test-pipeline.container"]
        self.assertIn("PublishPort=192.0.2.20:18443:8443", ingest)
        self.assertIn("PublishPort=127.0.0.1:18444:8444", api)
        self.assertNotIn("/overrides", ingest)
        self.assertNotIn("/raw", api)
        expected = {
            "ingest": ["raw.volume:/raw:rw", "inv.volume:/inv:rw"],
            "pipeline": [
                "raw.volume:/raw:ro",
                "inv.volume:/inv:rw",
                "overrides.volume:/overrides:ro",
            ],
            "api": ["inv.volume:/inv:ro", "overrides.volume:/overrides:rw"],
        }
        for role, mounts in expected.items():
            text = files[f"vigie_test-{role}.container"]
            self.assertEqual(
                [line for line in text.splitlines() if line.startswith("Volume=")],
                ["Volume=vigie_test-" + mount for mount in mounts],
            )
            for setting in [
                "User=10001",
                "Group=10001",
                "DropCapability=all",
                "ReadOnly=true",
                "NoNewPrivileges=true",
                "Pull=never",
                "PidsLimit=256",
                "Restart=on-failure",
            ]:
                self.assertIn(setting, text)
        self.assertIn("target=collector_key_k1,uid=10001,gid=10001,mode=0400", ingest)
        self.assertNotIn("Secret=", pipeline)
        self.assertNotIn("vigie_test_ingest_key", api)
        self.assertIn("StartLimitBurst=5", api)

    def test_recovery_dependencies_order_without_cancelling_own_restart(self):
        files = render.render(config())
        for role in ("api", "pipeline"):
            text = files[f"vigie_test-{role}.container"]
            self.assertIn("After=vigie_test-ingest.service", text)
            self.assertIn("Wants=vigie_test-ingest.service", text)
            self.assertNotIn("Requires=", text)
            self.assertIn("Restart=on-failure", text)
            self.assertIn("StartLimitBurst=5", text)

    def test_monitoring_threshold_default_override_and_bounds(self):
        key = "monitoring_large_upload_bytes"
        default = render.render(config())["vigie_test-pipeline.container"]
        self.assertIn(
            "Environment=VIGIE_MONITORING_LARGE_UPLOAD_BYTES=1073741824", default
        )
        custom = render.render(config(**{key: 2**50}))["vigie_test-pipeline.container"]
        self.assertIn(
            f"Environment=VIGIE_MONITORING_LARGE_UPLOAD_BYTES={2**50}", custom
        )
        for invalid in (0, -1, True, "1073741824", 2**50 + 1):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                render.render(config(**{key: invalid}))

    def test_monitoring_baseline_selector_default_override_and_strict_values(self):
        key = "monitoring_baseline"
        default = render.render(config())["vigie_test-pipeline.container"]
        self.assertIn("Environment=VIGIE_MONITORING_BASELINE=pooled", default)
        custom = render.render(config(**{key: "tod"}))
        self.assertIn(
            "Environment=VIGIE_MONITORING_BASELINE=tod",
            custom["vigie_test-pipeline.container"],
        )
        for role in ("ingest", "api"):
            self.assertNotIn(
                "VIGIE_MONITORING_BASELINE", custom[f"vigie_test-{role}.container"]
            )
        for invalid in ("", "TOD", " tod", "pooled-median-v1", None, True, ["tod"]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                render.render(config(**{key: invalid}))

    def test_invalid_or_injected_config_rejected(self):
        for updates in [
            {"namespace": "dev"},
            {"namespace": "vigie_x\n[Service]"},
            {"image": "latest"},
            {"image": "sha256:" + "a" * 64 + "\nExec=x"},
            {"ingest_address": "0.0.0.0"},
            {"ingest_address": "127.0.0.1"},
            {"ingest_address": "host.example"},
            {"ingest_address": 3221226004},
            {"ingest_port": True},
            {"api_port": 18443},
            {"collector_key_id": "x,target=/etc/passwd"},
            {"extra": "unexpected"},
        ]:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                render.render(config(**updates))

    def test_write_never_overwrites_existing_or_symlink_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "rendered"
            render.write_bundle(config(), output)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                render.write_bundle(config(), output)
            alias = Path(tmp) / "alias"
            alias.symlink_to(output)
            with self.assertRaises(FileExistsError):
                render.write_bundle(config(), alias)
            self.assertTrue((output / "plan.json").is_file())


# Keys accepted by the Podman 4.9 quadlet generator in each section. Derived from
# podman-systemd.unit(5) for 4.9 (from memory of the 4.9 docs; confirmed empirically
# only for the keys this renderer emits, on 4.9.3). Memory= is NOT here: it needs a newer Podman.
ALLOWED_QUADLET_KEYS_4_9 = {
    "Unit": {
        "Description",
        "After",
        "Wants",
        "StartLimitIntervalSec",
        "StartLimitBurst",
    },
    "Container": {
        "Image",
        "Pull",
        "ContainerName",
        "User",
        "Group",
        "ReadOnly",
        "DropCapability",
        "NoNewPrivileges",
        "PidsLimit",
        "PodmanArgs",
        "Tmpfs",
        "LogDriver",
        "Volume",
        "Environment",
        "Network",
        "Exec",
        "Secret",
        "PublishPort",
        "HealthCmd",
        "HealthStartPeriod",
        "HealthInterval",
        "HealthTimeout",
        "HealthRetries",
        "HealthOnFailure",
    },
    "Service": {"Restart", "RestartSec", "TimeoutStartSec", "TimeoutStopSec"},
    "Install": {"WantedBy"},
    "Volume": {"VolumeName"},
}


def emitted_keys(files):
    found = {}
    for name, text in files.items():
        section = None
        for line in text.splitlines():
            if line.startswith("["):
                section = line.strip("[]")
            elif line:
                found.setdefault(section, set()).add(line.split("=", 1)[0])
    return found


class QuadletCompatTests(unittest.TestCase):
    def test_no_memory_key_and_memory_limit_via_podmanargs(self):
        for name, text in render.render(config()).items():
            if not name.endswith(".container"):
                continue
            lines = text.splitlines()
            self.assertFalse([x for x in lines if x.startswith("Memory=")], name)
            args = [x for x in lines if x.startswith("PodmanArgs=")]
            self.assertEqual(args, ["PodmanArgs=--memory=512m --cpus=1"], name)

    def test_emitted_keys_subset_of_podman_4_9_allowlist(self):
        for updates in ({}, {"monitoring_baseline": "tod"}):
            found = emitted_keys(render.render(config(**updates)))
            for section, keys in found.items():
                self.assertLessEqual(keys, ALLOWED_QUADLET_KEYS_4_9[section], section)


if __name__ == "__main__":
    unittest.main()
