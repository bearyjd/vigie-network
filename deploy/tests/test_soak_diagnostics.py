"""Soak runner diagnostics are informational: verdicts must not depend on them."""

import hashlib
import importlib.util
import json
import re
import struct
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

PERSISTENT = Path(__file__).parents[1] / "persistent"
sys.path.insert(0, str(PERSISTENT))
import soak  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "soak_runner_diag", PERSISTENT / "run_soak.py"
)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

QUESTION = b"\x07example\x03com\0\0\1\0\1"
CONFIG = {
    "meter_executable": "m",
    "meter_sha256": "0" * 64,
    "router_address": "192.0.2.1",
}
NEW_FIELDS = {
    "dns_probe_error": "timeout",
    "dns_probe_retry_ok": True,
    "meter_error_class": "timeout",
    "meter_exit_code": 3,
    "meter_signal": 9,
    "coverage_error_class": "timeout",
    "host_load1": 0.5,
    "host_psi_cpu_avg10": 1.25,
}


def sample(second, **overrides):
    value = {
        "wall": 1_800_000_000 + second,
        "monotonic": 1000 + second,
        "boottime": 2000 + second,
        "host_boot_id": "host-one",
        "router_boot_id": "router-one",
        "collector_start": 10,
        "helper_start": 20,
        "collector_rss_kib": 1700,
        "helper_rss_kib": 1100,
        "mem_available_kib": 200000,
        "log_used_kib": 1000,
        "log_capacity_kib": 20480,
        "collector_cpu_ticks": second,
        "total_cpu_ticks": second * 200,
        "logical_cpus": 2,
        "freshness_s": 30,
        "backlog_batches": 0,
        "backlog_capped": False,
        "oldest_pending_received_at": None,
        "processing_backlog_age_s": 0,
        "processing_backlog_reference_wall": 1_800_000_000 + second,
        "dropped_batches": 0,
        "source_flags": 0,
        "dns_log_quiet": False,
        "ct_unmapped_flows": 0,
        "ct_unmapped_bytes": 0,
        "dns_probe_ok": True,
        "dns_parsed_age_s": 30,
    }
    value.update(overrides)
    return value


class FakeSocket:
    def __init__(self, reply=None, error=None, wrong_id=False):
        self.reply, self.error, self.wrong_id = reply, error, wrong_id

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, value):
        pass

    def connect(self, target):
        pass

    def send(self, packet):
        self.request = packet

    def recv(self, size):
        if self.error:
            raise self.error
        if self.wrong_id:
            return bytes([self.request[0] ^ 255, self.request[1]]) + self.reply
        return self.request[:2] + self.reply


def classify(reply=None, error=None, wrong_id=False):
    diag = {}
    with patch.object(
        runner.socket, "socket", return_value=FakeSocket(reply, error, wrong_id)
    ):
        ok = runner.dns_probe("192.0.2.1", diag)
    return ok, diag.get("error")


class DnsClassTests(unittest.TestCase):
    def test_each_failure_class(self):
        good_tail = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x14"
        header = lambda flags, answers: struct.pack("!5H", flags, 1, answers, 0, 0)  # noqa: E731
        self.assertEqual(classify(error=TimeoutError()), (False, "timeout"))
        self.assertEqual(classify(error=ConnectionRefusedError()), (False, "oserror"))
        self.assertEqual(classify(b"\x81"), (False, "malformed"))
        self.assertEqual(classify(header(0x8183, 0)[0:] + QUESTION), (False, "rcode"))
        self.assertEqual(classify(header(0x8180, 0) + QUESTION), (False, "no_answer"))
        self.assertEqual(
            classify(header(0x8180, 1) + QUESTION + b"\xc0"), (False, "malformed")
        )
        self.assertEqual(
            classify(header(0x8180, 1) + QUESTION + good_tail), (True, None)
        )

    def test_boolean_result_matches_origin_main_for_every_path(self):
        # Expected booleans were verified by running origin/main's dns_probe on each reply.
        a_rec = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x14"
        cname = a_rec[:3] + b"\x05" + a_rec[4:]
        head = lambda flags, n: struct.pack("!5H", flags, 1, n, 0, 0)  # noqa: E731
        table = [
            (head(0x8180, 1) + QUESTION + a_rec, None, True),
            (None, TimeoutError(), False),
            (None, ConnectionRefusedError(), False),
            (b"\x81", None, False),
            (head(0x8183, 0) + QUESTION, None, False),
            (head(0x8180, 0) + QUESTION, None, False),
            (head(0x8180, 1) + QUESTION + cname, None, False),
            # Otherwise-valid answer with a wrong transaction ID must still fail.
            (head(0x8180, 1) + QUESTION + a_rec, None, False, True),
        ]
        for reply, error, expected, *wrong_id in table:
            ok, _ = classify(reply, error, bool(wrong_id))
            self.assertIs(ok, expected, (reply, error, wrong_id))

    def test_wrong_id_is_bad_id(self):
        class Wrong(FakeSocket):
            def recv(self, size):
                return bytes([self.request[0] ^ 255, self.request[1]]) + b"\0" * 20

        with patch.object(runner.socket, "socket", return_value=Wrong()):
            diag = {}
            self.assertFalse(runner.dns_probe("192.0.2.1", diag))
        self.assertEqual(diag["error"], "bad_id")

    def test_diag_argument_is_optional(self):
        with patch.object(
            runner.socket, "socket", return_value=FakeSocket(error=OSError())
        ):
            self.assertFalse(runner.dns_probe("192.0.2.1"))


class CollectDiagnosticsTests(unittest.TestCase):
    def collect(self, probes, meter=None, coverage=None):
        calls = []

        def fake_probe(address, diag=None):
            calls.append(address)
            ok = probes[len(calls) - 1]
            if not ok and diag is not None:
                diag["error"] = "timeout"
            return ok

        with (
            patch.object(runner, "read_meter", **meter or {"return_value": {}}),
            patch.object(runner, "dns_probe", fake_probe),
            patch.object(runner, "read_coverage", **coverage or {"return_value": {}}),
            patch.object(runner, "clock_sample", return_value={"wall": 1.0}),
        ):
            return runner.collect(CONFIG, None), calls

    def test_failed_probe_records_class_and_one_retry(self):
        result, calls = self.collect([False, True])
        self.assertIs(result["dns_probe_ok"], False)
        self.assertEqual(result["dns_probe_error"], "timeout")
        self.assertIs(result["dns_probe_retry_ok"], True)
        self.assertEqual(len(calls), 2)

    def test_retry_failure_still_one_retry_and_primary_decides(self):
        result, calls = self.collect([False, False, True])
        self.assertIs(result["dns_probe_ok"], False)
        self.assertIs(result["dns_probe_retry_ok"], False)
        self.assertEqual(len(calls), 2)

    def test_diagnosed_probe_does_not_take_or_mutate_a_result_dict(self):
        with patch.object(runner, "dns_probe", return_value=False):
            ok, extra = runner.dns_probe_diagnosed("192.0.2.1")
        self.assertIs(ok, False)
        self.assertEqual(extra, {"dns_probe_retry_ok": False})

    def test_success_has_no_dns_diagnostics_and_no_retry(self):
        result, calls = self.collect([True])
        self.assertIs(result["dns_probe_ok"], True)
        self.assertNotIn("dns_probe_error", result)
        self.assertNotIn("dns_probe_retry_ok", result)
        self.assertEqual(len(calls), 1)

    def test_meter_error_classes(self):
        err = runner.MeterError("nonzero_exit", exit_code=7)
        result, _ = self.collect([True], meter={"side_effect": err})
        self.assertIs(result["meter_error"], True)
        self.assertEqual(result["meter_error_class"], "nonzero_exit")
        self.assertEqual(result["meter_exit_code"], 7)
        err = runner.MeterError("nonzero_exit", signal_number=9)
        result, _ = self.collect([True], meter={"side_effect": err})
        self.assertEqual(result["meter_signal"], 9)
        self.assertNotIn("meter_exit_code", result)
        result, _ = self.collect(
            [True], meter={"side_effect": ValueError("secret /path")}
        )
        self.assertEqual(result["meter_error_class"], "setup_error")

    def test_coverage_error_classes(self):
        cases = {
            TimeoutError("http://127.0.0.1/?token=x"): "timeout",
            urllib.error.URLError(TimeoutError()): "timeout",
            urllib.error.HTTPError("u", 500, "m", {}, None): "http_error",
            ConnectionRefusedError(): "network_error",
            KeyError("data"): "bad_response",
            ValueError("coverage response limit"): "bad_response",
        }
        for error, expected in cases.items():
            result, _ = self.collect([True], coverage={"side_effect": error})
            self.assertIs(result["coverage_error"], True)
            self.assertEqual(result["coverage_error_class"], expected, error)

    def test_no_secret_or_address_in_new_fields(self):
        err = ValueError("token abc 192.0.2.1")
        result, _ = self.collect(
            [False, False], meter={"side_effect": err}, coverage={"side_effect": err}
        )
        new = {k: v for k, v in result.items() if k in NEW_FIELDS | {"meter_signal": 0}}
        text = json.dumps(new)
        self.assertNotIn("192.0.2.1", text)
        self.assertNotIn("abc", text)
        self.assertLess(len(text), 400)


class MeterProcessTests(unittest.TestCase):
    def run_meter(self, script):
        with tempfile.TemporaryDirectory() as tmp:
            meter = Path(tmp) / "meter"
            meter.write_text(script)
            meter.chmod(0o700)
            digest = hashlib.sha256(meter.read_bytes()).hexdigest()
            with self.assertRaises(runner.MeterError) as caught:
                runner.read_meter(meter, digest)
            return caught.exception

    def test_nonzero_exit_records_code_only(self):
        error = self.run_meter("#!/bin/sh\necho SECRET-KEY >&2\nexit 5\n")
        self.assertEqual((error.error_class, error.exit_code), ("nonzero_exit", 5))
        self.assertNotIn("SECRET", str(error))

    def test_signal_records_signal(self):
        error = self.run_meter("#!/bin/sh\nkill -TERM $$\n")
        self.assertEqual(error.error_class, "nonzero_exit")
        self.assertEqual(error.signal_number, 15)
        self.assertIsNone(error.exit_code)

    def test_oversized_and_not_json(self):
        error = self.run_meter("#!/bin/sh\nhead -c 100000 /dev/zero\n")
        self.assertEqual(error.error_class, "oversized")
        error = self.run_meter("#!/bin/sh\necho nope\n")
        self.assertEqual(error.error_class, "not_json")
        error = self.run_meter("#!/bin/sh\necho '[1]'\n")
        self.assertEqual(error.error_class, "not_json")
        error = self.run_meter("#!/bin/sh\nhead -c 12000 /dev/zero | tr '\\0' '['\n")
        self.assertEqual(error.error_class, "not_json")


class HostLoadTests(unittest.TestCase):
    def test_reads_load_and_psi(self):
        with tempfile.TemporaryDirectory() as tmp:
            load, psi = Path(tmp) / "loadavg", Path(tmp) / "cpu"
            load.write_text("0.42 0.30 0.20 1/100 999\n")
            psi.write_text("some avg10=1.50 avg60=0.5 avg300=0.1 total=5\n")
            self.assertEqual(
                runner.host_load(load, psi),
                {"host_load1": 0.42, "host_psi_cpu_avg10": 1.5},
            )

    def test_unreadable_or_malformed_is_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            load = Path(tmp) / "loadavg"
            load.write_text("garbage")
            self.assertEqual(runner.host_load(load, Path(tmp) / "missing"), {})
            load.write_text("nan 1 1")
            self.assertEqual(runner.host_load(load, Path(tmp) / "missing"), {})
            load.write_text("")
            self.assertEqual(runner.host_load(load, Path(tmp) / "missing"), {})

    def test_collect_survives_missing_proc_files(self):
        with (
            patch.object(
                runner.host_load, "__defaults__", ("/nonexistent", "/nonexistent")
            ),
            patch.object(runner, "read_meter", return_value={}),
            patch.object(runner, "dns_probe", return_value=True),
            patch.object(runner, "read_coverage", return_value={}),
            patch.object(runner, "clock_sample", return_value={"wall": 1.0}),
        ):
            result = runner.collect(CONFIG, None)
        self.assertNotIn("host_load1", result)


class VerdictIdentityTests(unittest.TestCase):
    def series(self, extra):
        rows = [sample(t) for t in range(0, 172801, 60)]
        rows[100] = sample(6000, dns_probe_ok=False, **extra)
        return rows

    def test_same_status_and_reasons_with_and_without_diagnostics(self):
        for rows in (
            lambda extra: self.series(extra),
            lambda extra: [sample(t, **extra) for t in range(0, 172801, 60)],
            lambda extra: [sample(0, **extra), sample(60, **extra)],
            lambda extra: [sample(0), sample(60, collector_rss_kib=99999, **extra)],
        ):
            old = soak.assess(rows({}))
            new = soak.assess(rows(dict(NEW_FIELDS, dns_probe_retry_ok=False)))
            self.assertEqual(
                json.dumps(old, sort_keys=True), json.dumps(new, sort_keys=True)
            )

    def test_failed_probe_without_recovery_evidence_is_unchanged(self):
        plain = [sample(t, dns_probe_ok=False) for t in range(0, 172801, 60)]
        bad_retry = [
            sample(t, dns_probe_ok=False, dns_probe_retry_ok=False)
            for t in range(0, 172801, 60)
        ]
        self.assertEqual(soak.assess(plain), soak.assess(bad_retry))
        self.assertIn("dns_probe_failed", soak.assess(plain)["reasons"])
        self.assertNotEqual(soak.assess(plain)["status"], "pass")


def rescued_series():
    rows = [sample(t) for t in range(0, 172801, 60)]
    for index in (100, 400, 800, 1200, 1800, 2200, 2600):
        rows[index] = dict(rows[index], dns_probe_ok=False, dns_probe_retry_ok=True)
    return rows


class DnsRetryRuleTests(unittest.TestCase):
    def test_rescued_failure_is_noted_and_sample_stays_valid(self):
        rows = [sample(0), sample(60, dns_probe_ok=False, dns_probe_retry_ok=True)]
        result = soak.assess(rows)
        self.assertNotIn("dns_probe_failed", result["reasons"])
        self.assertEqual(result["quality_notes"], ["dns_probe_retry_recovered"])
        self.assertEqual(result["coverage"], 1.0)

    def test_failed_with_failed_or_missing_retry_still_blocks(self):
        for extra in ({"dns_probe_retry_ok": False}, {}):
            result = soak.assess([sample(0), sample(60, dns_probe_ok=False, **extra)])
            self.assertEqual(result["status"], "pending", extra)
            self.assertIn("dns_probe_failed", result["reasons"], extra)
            self.assertNotIn("dns_probe_retry_recovered", result["quality_notes"])

    def test_retry_true_without_a_failed_probe_adds_no_note(self):
        absent = sample(60, dns_probe_retry_ok=True)
        del absent["dns_probe_ok"]
        for row in (sample(60, dns_probe_retry_ok=True), absent):
            notes = soak.assess([sample(0), row])["quality_notes"]
            self.assertNotIn("dns_probe_retry_recovered", notes)

    def test_only_strict_true_counts(self):
        for value in (1, "true", None):
            row = sample(60, dns_probe_ok=False, dns_probe_retry_ok=value)
            result = soak.assess([sample(0), row])
            self.assertIn("dns_probe_failed", result["reasons"], value)
            self.assertNotIn("dns_probe_retry_recovered", result["quality_notes"])

    def test_48h_with_seven_rescued_failures_is_pass_eligible(self):
        clean = soak.assess([sample(t) for t in range(0, 172801, 60)])
        result = soak.assess(rescued_series())
        self.assertEqual(result["status"], clean["status"])
        self.assertEqual(result["coverage"], clean["coverage"])
        self.assertEqual(result["reasons"], clean["reasons"])
        self.assertIn("dns_probe_retry_recovered", result["quality_notes"])

    def test_unrescued_failure_in_the_same_run_still_blocks(self):
        rows = rescued_series()
        rows[1000] = dict(rows[1000], dns_probe_ok=False, dns_probe_retry_ok=False)
        result = soak.assess(rows)
        self.assertEqual(result["status"], "pending")
        self.assertIn("dns_probe_failed", result["reasons"])

    def test_rescued_failures_never_mask_other_problems(self):
        stale = rescued_series()
        stale[500] = dict(stale[500], dns_parsed_age_s=500)
        self.assertIn("parsed_dns_stale", soak.assess(stale)["reasons"])
        hard = rescued_series()
        hard[500] = dict(hard[500], dropped_batches=3)
        self.assertEqual(soak.assess(hard)["status"], "fail")
        both = rescued_series()
        both[100] = dict(both[100], collector_rss_kib=99999)
        self.assertEqual(soak.assess(both)["status"], "fail")


class JournalCompatTests(unittest.TestCase):
    def test_old_journal_loads_and_new_fields_persist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            with soak.Journal(path, mode="simulated") as journal:
                journal.append(sample(0))
            with soak.Journal(path, mode="simulated") as journal:
                journal.append(sample(60, **NEW_FIELDS))
            with soak.Journal(path, mode="simulated") as journal:
                self.assertEqual(len(journal.samples), 2)
                self.assertEqual(journal.samples[1]["dns_probe_error"], "timeout")
            header = json.loads(path.read_text().splitlines()[0])
            self.assertEqual(header["schema"], 2)

    def test_invalid_diagnostics_are_dropped_not_failed(self):
        bad = {
            "dns_probe_error": "x" * 10000,
            "dns_probe_retry_ok": "yes",
            "meter_error_class": "<script>",
            "meter_exit_code": 10**9,
            "coverage_error_class": {"a": 1},
            "host_load1": float("nan"),
            "host_psi_cpu_avg10": -1,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            with soak.Journal(path, mode="simulated") as journal:
                journal.append(sample(0, **bad))
                stored = journal.samples[0]
            self.assertFalse(set(bad) & set(stored))
            self.assertNotIn("invalid_record", stored)
            self.assertLess(len(path.read_text()), 2000)

    def test_bad_exit_code_and_signal_values_are_dropped(self):
        bad = [
            ("meter_exit_code", True),
            ("meter_exit_code", 256),
            ("meter_signal", False),
            ("meter_signal", 0),
            ("meter_signal", 65),
        ]
        for key, value in bad:
            self.assertFalse(soak.diagnostics_valid(key, value), (key, value))
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "journal.jsonl"
                with soak.Journal(path, mode="simulated") as journal:
                    journal.append(sample(0, **{key: value}))
                    self.assertNotIn(key, journal.samples[0])

    def test_valid_values_survive_and_fit_record_bound(self):
        for key, value in NEW_FIELDS.items():
            self.assertTrue(soak.diagnostics_valid(key, value), key)
        self.assertTrue(
            all(len(v) <= 16 for v in sum(map(list, soak._DIAG_ENUMS.values()), []))
        )
        self.assertFalse(re.search(r"\d+\.\d+\.\d+\.\d+", json.dumps(soak._DIAG_ENUMS)))


if __name__ == "__main__":
    unittest.main()
