import importlib.util
import struct
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


class DnsProbeTests(unittest.TestCase):
    QUESTION = b"\x07example\x03com\0\0\1\0\1"

    def reply(
        self,
        owner,
        *,
        question=None,
        flags=0x8180,
        kind=1,
        dns_class=1,
        data=b"\xc0\x00\x02\x14",
    ):
        question = self.QUESTION if question is None else question
        return (
            struct.pack("!5H", flags, 1, 1, 0, 0)
            + question
            + owner
            + struct.pack("!HHIH", kind, dns_class, 60, len(data))
            + data
        )

    def probe(self, response, wrong_id=False):
        class Socket:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def settimeout(self, value):
                self.timeout = value

            def connect(self, target):
                self.target = target

            def send(self, packet):
                self.request = packet

            def recv(self, size):
                ident = self.request[:2]
                if wrong_id:
                    ident = bytes([ident[0] ^ 255, ident[1]])
                return ident + response

        socket = Socket()
        with patch.object(runner.socket, "socket", return_value=socket):
            result = runner.dns_probe("192.0.2.1")
        self.assertEqual(socket.target, ("192.0.2.1", 53))
        self.assertEqual(socket.request[12:], self.QUESTION)
        return result

    def test_unrelated_owner_and_self_pointer_are_not_dns_success(self):
        answer_offset = 12 + len(self.QUESTION)
        for owner in (b"\x04evil\x03com\0", bytes([0xC0, answer_offset])):
            with self.subTest(owner=owner):
                self.assertFalse(self.probe(self.reply(owner)))

    def test_direct_plain_compressed_and_casefolded_names_succeed(self):
        for owner in (b"\x07example\x03com\0", b"\xc0\x0c", b"\x07EXAMPLE\x03COM\0"):
            with self.subTest(owner=owner):
                self.assertTrue(self.probe(self.reply(owner)))
        self.assertTrue(
            self.probe(
                self.reply(b"\xc0\x0c", question=b"\x07EXAMPLE\x03COM\0\0\1\0\1")
            )
        )

    def test_dotted_single_labels_cannot_impersonate_question_or_owner(self):
        dotted = b"\x0bexample.com\0"
        self.assertFalse(self.probe(self.reply(dotted)))
        self.assertFalse(
            self.probe(self.reply(b"\xc0\x0c", question=dotted + b"\0\1\0\1"))
        )

    def test_malformed_pointer_targets_are_not_followed_or_skipped(self):
        for owner in (
            b"\xc0\x1d",  # self
            b"\xc0\x1f\xc0\x1d",  # two-pointer cycle, first jump forward
            b"\xc0\x29",  # forward into RDATA
            b"\xc0\x00",  # header
            b"\xc0\x0d",  # middle of question label
            b"\xff\xff",  # out of packet
            b"\x40" + b"x" * 64 + b"\0",  # invalid label prefix/length
        ):
            with self.subTest(owner=owner):
                self.assertFalse(self.probe(self.reply(owner)))
        header_question = struct.pack("!5H", 0x8180, 1, 1, 0, 0) + self.QUESTION
        self.assertFalse(self.probe(header_question + b"\xc0"))

    def test_positive_first_answer_cannot_hide_overlong_or_truncated_tail(self):
        good = self.reply(b"\xc0\x0c")
        overlong = (b"\x3f" + b"x" * 63) * 4 + b"\0"
        second = overlong + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x14"
        two = struct.pack("!5H", 0x8180, 1, 2, 0, 0) + good[10:] + second
        self.assertFalse(self.probe(two))
        self.assertFalse(self.probe(good[:-1]))
        self.assertFalse(self.probe(good + b"\0"))
        self.assertFalse(self.probe(good + b"x" * 4096))

    def test_flags_question_fields_record_types_and_transaction_are_checked(self):
        for flags in (0x0180, 0x8380, 0x8183, 0x8980):
            with self.subTest(flags=flags):
                self.assertFalse(self.probe(self.reply(b"\xc0\x0c", flags=flags)))
        for tail in (b"\0\x1c\0\1", b"\0\1\0\3"):
            self.assertFalse(
                self.probe(self.reply(b"\xc0\x0c", question=self.QUESTION[:-4] + tail))
            )
        self.assertFalse(self.probe(self.reply(b"\xc0\x0c", kind=28, data=b"x" * 16)))
        self.assertFalse(self.probe(self.reply(b"\xc0\x0c", dns_class=3)))
        self.assertFalse(self.probe(self.reply(b"\xc0\x0c"), wrong_id=True))
        too_many = (
            struct.pack("!5H", 0x8180, 1, 1, 0, 128) + self.reply(b"\xc0\x0c")[10:]
        )
        self.assertFalse(self.probe(too_many))

    def test_authority_or_additional_address_is_not_a_direct_answer(self):
        packet = self.reply(b"\xc0\x0c", kind=5, data=b"\x04evil\x03com\0")
        address = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x14"
        for ns, ar in ((1, 0), (0, 1)):
            response = struct.pack("!5H", 0x8180, 1, 1, ns, ar) + packet[10:] + address
            self.assertFalse(self.probe(response))


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


class FinalCoverageContract(unittest.TestCase):
    def test_actual_api_capped_fields_cannot_produce_favorable_partial_counts(self):
        collector = {
            "backlog_batches": 0,
            "dropped_batches_in_retained_detail": 0,
            "ct_unmapped_flows_in_retained_detail": 0,
            "ct_unmapped_bytes_in_retained_detail": 0,
            "backlog_capped": True,
            "summary_capped": False,
        }
        self.assertIsNone(runner.coverage_metrics(collector, 1000)["backlog_batches"])
        collector.update(backlog_capped=False, summary_capped=True)
        self.assertIsNone(runner.coverage_metrics(collector, 1000)["dropped_batches"])
        self.assertIsNone(runner.coverage_metrics(collector, 1000)["ct_unmapped_flows"])
        collector["summary_capped"] = False
        self.assertEqual(runner.coverage_metrics(collector, 1000)["backlog_batches"], 0)
        self.assertEqual(runner.coverage_metrics(collector, 1000)["dropped_batches"], 0)
        collector.pop("summary_capped")
        self.assertIsNone(runner.coverage_metrics(collector, 1000)["dropped_batches"])


class ReviewRegressions(unittest.TestCase):
    def test_live_rss_cannot_be_replaced_by_older_api_report(self):
        with (
            patch.object(runner, "clock_sample", return_value={"wall": 1000}),
            patch.object(
                runner, "read_meter", return_value={"collector_rss_kib": 20000}
            ),
            patch.object(
                runner, "read_coverage", return_value={"collector_rss_kib": 1700}
            ),
            patch.object(runner, "dns_probe", return_value=True),
        ):
            result = runner.collect(
                {
                    "meter_executable": "/unused",
                    "meter_sha256": "a" * 64,
                    "router_address": "192.0.2.1",
                }
            )
        self.assertEqual(result["collector_rss_kib"], 20000)
        self.assertEqual(result["api_collector_rss_kib"], 1700)

    def test_resume_persists_failing_and_missing_first_observation(self):
        import hashlib
        import io
        import json
        from contextlib import redirect_stdout

        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                config = {
                    "api_port": 18444,
                    "api_token_file": "/unused",
                    "api_ca_file": "/unused",
                    "collector_id": "test",
                    "meter_executable": "/unused",
                    "meter_sha256": "a" * 64,
                    "router_address": "192.0.2.1",
                }
                raw = json.dumps(config).encode()
                config_path = base / "config"
                config_path.write_bytes(raw)
                config_path.chmod(0o600)
                initial = {
                    "wall": 1800000000,
                    "monotonic": 1000,
                    "boottime": 2000,
                    "host_boot_id": "host",
                    "router_boot_id": "router",
                    "collector_start": 10,
                    "helper_start": 20,
                    "collector_rss_kib": 1700,
                    "helper_rss_kib": 1000,
                    "mem_available_kib": 200000,
                    "log_used_kib": 100,
                    "log_capacity_kib": 20480,
                    "collector_cpu_ticks": 0,
                    "total_cpu_ticks": 100,
                    "logical_cpus": 2,
                    "freshness_s": 30,
                    "backlog_batches": 0,
                    "dropped_batches": 0,
                    "source_flags": 0,
                    "dns_log_quiet": False,
                    "ct_unmapped_flows": 0,
                    "ct_unmapped_bytes": 0,
                    "dns_probe_ok": True,
                    "dns_parsed_age_s": 30,
                }
                next_sample = dict(
                    initial,
                    wall=1800000060,
                    monotonic=1060,
                    boottime=2060,
                    collector_rss_kib=20000,
                    collector_cpu_ticks=60,
                    total_cpu_ticks=12100,
                )
                if missing:
                    next_sample.pop("collector_rss_kib")
                journal_path = base / "journal"
                metadata = {"config_sha256": hashlib.sha256(raw).hexdigest()}
                with runner.Journal(
                    journal_path, mode="real", metadata=metadata
                ) as journal:
                    journal.append(initial)
                before = journal_path.read_bytes()
                with (
                    patch.object(
                        sys, "argv", ["run_soak", str(config_path), str(journal_path)]
                    ),
                    patch.object(runner, "collect", return_value=next_sample),
                    redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(runner.main(), 2 if missing else 1)
                self.assertNotEqual(journal_path.read_bytes(), before)
                with runner.Journal(
                    journal_path, mode="real", metadata=metadata
                ) as journal:
                    self.assertEqual(len(journal.samples), 2)

    def test_meter_executes_reviewed_snapshot_despite_swap_or_inplace_mutation(self):
        import hashlib

        for mutation in ("replace", "inplace"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                meter = Path(tmp) / "meter"
                marker = Path(tmp) / "unreviewed-executed"
                meter.write_text("#!/bin/sh\nprintf '{\"reviewed\":true}\\n'\n")
                meter.chmod(0o700)
                digest = hashlib.sha256(meter.read_bytes()).hexdigest()
                evil = (
                    f"#!/bin/sh\ntouch '{marker}'\nprintf '{{\"reviewed\":false}}\\n'\n"
                )
                actual_popen = runner.subprocess.Popen

                def swap(
                    *args,
                    mutation=mutation,
                    meter=meter,
                    tmp=tmp,
                    evil=evil,
                    actual_popen=actual_popen,
                    **kwargs,
                ):
                    if mutation == "replace":
                        other = Path(tmp) / "other"
                        other.write_text(evil)
                        other.chmod(0o700)
                        other.replace(meter)
                    else:
                        meter.write_text(evil)
                    return actual_popen(*args, **kwargs)

                with patch.object(runner.subprocess, "Popen", side_effect=swap):
                    self.assertEqual(
                        runner.read_meter(meter, digest), {"reviewed": True}
                    )
                self.assertFalse(
                    marker.exists(), "unreviewed replacement must never execute"
                )

    def test_meter_refuses_untrusted_writable_parent(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "writable"
            parent.mkdir(mode=0o777)
            parent.chmod(0o777)
            meter = parent / "meter"
            meter.write_text("#!/bin/sh\nprintf '{}\\n'\n")
            meter.chmod(0o700)
            with self.assertRaises(ValueError):
                runner.read_meter(meter, hashlib.sha256(meter.read_bytes()).hexdigest())

    def test_meter_reaps_leader_only_after_background_group_cleanup(self):
        import subprocess

        # This isolated harness adopts and reaps its own grandchild; it cannot leave a sleep
        # or zombie behind on assertion failure. prctl is confined to this test subprocess.
        harness = r"""import ctypes,hashlib,importlib.util,os,signal,sys,tempfile,time
from pathlib import Path
ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)
spec=importlib.util.spec_from_file_location("meter_runner",sys.argv[1]);runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
with tempfile.TemporaryDirectory() as tmp:
    meter=Path(tmp)/"meter";pidfile=Path(tmp)/"background.pid"
    meter.write_text("#!/bin/sh\nsleep 30 >/dev/null 2>&1 &\necho $! > '"+str(pidfile)+"'\nprintf '{}\\n'\n")
    meter.chmod(0o700);pid=None
    try:
        runner.read_meter(meter,hashlib.sha256(meter.read_bytes()).hexdigest())
        pid=int(pidfile.read_text())
        for _ in range(100):
            stat=Path('/proc')/str(pid)/'stat'
            if not stat.exists() or stat.read_text().split(') ')[-1].startswith('Z'):break
            time.sleep(.01)
        else:raise AssertionError('background child remained alive after meter returned')
    finally:
        if pid is None and pidfile.exists():pid=int(pidfile.read_text())
        if pid is not None:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:os.waitpid(pid,0)
            except ChildProcessError:pass
"""
        result = subprocess.run(
            [sys.executable, "-c", harness, str(Path(runner.__file__))],
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
