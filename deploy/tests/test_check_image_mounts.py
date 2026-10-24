"""Adversarial inspect evidence: protected data cannot acquire extra or replacement mounts."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).with_name("check_image_mounts.py")


def inventory():
    return {
        "Config": {"User": "10001:10001"},
        "HostConfig": {"ReadonlyRootfs": True},
        "Mounts": [
            {"Destination": "/raw", "Type": "volume", "Name": "pilot_vigie-raw", "RW": True},
            {"Destination": "/inv", "Type": "volume", "Name": "pilot_vigie-inv", "RW": True},
        ],
    }


class ImageMountEvidenceTests(unittest.TestCase):
    def check_evidence(self, evidence):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inspect.json"
            path.write_text(json.dumps([evidence]))
            return subprocess.run(  # noqa: S603 - fixed interpreter/checker, private fixture file
                [sys.executable, str(CHECKER), "ingest", str(path), "--project-prefix", "pilot"],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_legitimate_runtime_tmp_and_secret_mounts_are_allowed(self):
        evidence = inventory()
        evidence["Mounts"].extend(
            [
                {"Destination": "/tmp", "Type": "tmpfs", "RW": True},  # noqa: S108 - inspect fixture
                {"Destination": "/run/secrets/key", "Type": "bind", "RW": False},
            ]
        )
        result = self.check_evidence(evidence)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unexpected_data_roots_children_and_ancestors_are_rejected(self):
        for destination, kind in [
            ("/overrides", "bind"),
            ("/raw", "bind"),
            ("/overrides", "volume"),
            ("/inv/overrides.db", "bind"),
            ("/raw/cache", "tmpfs"),
            ("/", "bind"),
        ]:
            with self.subTest(destination=destination, kind=kind):
                evidence = inventory()
                evidence["Mounts"].append(
                    {"Destination": destination, "Type": kind, "Name": "unexpected", "RW": True}
                )
                self.assertNotEqual(self.check_evidence(evidence).returncode, 0)

    def test_expected_named_volume_cannot_be_replaced_by_bind(self):
        evidence = inventory()
        evidence["Mounts"][1]["Type"] = "bind"
        self.assertNotEqual(self.check_evidence(evidence).returncode, 0)


if __name__ == "__main__":
    unittest.main()
