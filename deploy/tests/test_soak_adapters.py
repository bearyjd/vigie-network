import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "soak_runner", Path(__file__).parents[1] / "persistent" / "run_soak.py"
)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class AdapterTests(unittest.TestCase):
    def test_fixed_dns_query_and_matching_response_only(self):
        question = b"\x07example\x03com\x00\x00\x01\x00\x01"

        class Socket:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def settimeout(self, value):
                pass

            def connect(self, target):
                self.target = target

            def send(self, packet):
                self.packet = packet
                assert packet[12:] == question
                assert self.target == ("192.0.2.1", 53)

            def recv(self, size):
                return (
                    self.packet[:2]
                    + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                    + question
                    + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x14"
                )

        with patch.object(runner.socket, "socket", return_value=Socket()):
            self.assertTrue(runner.dns_probe("192.0.2.1"))

        class HeaderOnly(Socket):
            def recv(self, size):
                return super().recv(size)[: 12 + len(question)]

        with patch.object(runner.socket, "socket", return_value=HeaderOnly()):
            self.assertFalse(
                runner.dns_probe("192.0.2.1"),
                "answer count alone is not a complete DNS response",
            )

        class Wrong(Socket):
            def recv(self, size):
                return b"invalid"

        with patch.object(runner.socket, "socket", return_value=Wrong()):
            self.assertFalse(runner.dns_probe("192.0.2.1"))

    def test_metrics_adapter_has_no_shell_no_agent_and_checks_digest(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            meter = Path(tmp) / "meter"
            meter.write_text(
                '#!/bin/sh\n[ -z "${SSH_AUTH_SOCK:-}" ] || exit 8\nprintf \'{"helper_rss_kib":1000}\\n\'\n'
            )
            meter.chmod(0o700)
            digest = hashlib.sha256(meter.read_bytes()).hexdigest()
            self.assertEqual(runner.read_meter(meter, digest), {"helper_rss_kib": 1000})
            with self.assertRaises(ValueError):
                runner.read_meter(meter, "0" * 64)
            link = Path(tmp) / "alias"
            link.symlink_to(meter)
            with self.assertRaises((ValueError, OSError)):
                runner.read_meter(link, digest)

    def test_oversized_meter_output_is_rejected(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            meter = Path(tmp) / "meter"
            meter.write_text("#!/bin/sh\nhead -c 100000 /dev/zero\n")
            meter.chmod(0o700)
            with self.assertRaises(ValueError):
                runner.read_meter(meter, hashlib.sha256(meter.read_bytes()).hexdigest())

    def test_coverage_does_not_invent_dns_capture_from_health_default(self):
        result = runner.coverage_metrics(
            {"dns_log_quiet": False, "agent_rss_kb": 1700}, 1000
        )
        self.assertIsNone(result["dns_parsed_age_s"])
        self.assertIsNone(result["freshness_s"])
        result = runner.coverage_metrics(
            {"latest_window_end": 970, "latest_dns_observation_window_end": 990}, 1000
        )
        self.assertEqual(result["freshness_s"], 30)
        self.assertEqual(result["dns_parsed_age_s"], 10)


if __name__ == "__main__":
    unittest.main()
