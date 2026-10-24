"""A fake clock verifies logic; it never supplies real acceptance evidence."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "vigie_soak", Path(__file__).parents[1] / "persistent" / "soak.py"
)
soak = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = soak
SPEC.loader.exec_module(soak)


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


def full():
    return [sample(t) for t in range(0, 172801, 60)]


class SoakTests(unittest.TestCase):
    def test_short_run_never_passes_and_simulation_is_explicit(self):
        result = soak.assess([sample(0), sample(600)])
        self.assertNotEqual(result["status"], "pass")
        self.assertEqual(result["evidence_mode"], "simulated")
        self.assertEqual(soak.assess([sample(0), sample(60)])["status"], "pending")

    def test_actual_full_duration_and_coverage_are_required(self):
        self.assertEqual(soak.assess(full())["status"], "pass")
        self.assertNotEqual(soak.assess(full()[:-1])["status"], "pass")
        self.assertEqual(soak.assess(full())["elapsed_seconds"], 172800)
        self.assertEqual(soak.assess(full())["coverage"], 1)

    def test_gap_over_180_and_under_99_percent_fail(self):
        values = full()
        del values[1:4]
        self.assertEqual(soak.assess(values)["status"], "fail")
        values = [sample(t) for t in range(0, 172801, 120)]
        self.assertEqual(soak.assess(values)["status"], "fail")

    def test_exact_180_gap_can_meet_99_percent(self):
        values = full()
        del values[1:3]
        self.assertEqual(soak.assess(values)["status"], "pass")

    def test_missing_required_resource_never_becomes_healthy(self):
        values = full()
        for value in values:
            value.pop("helper_rss_kib")
        result = soak.assess(values)
        self.assertNotEqual(result["status"], "pass")
        self.assertIn("missing_metrics", result["reasons"])

    def test_resource_thresholds_are_not_relaxed(self):
        for changes in [
            {"collector_rss_kib": 9765},
            {"helper_rss_kib": 65536},
            {"mem_available_kib": 65535},
            {"log_used_kib": 20481},
            {"log_capacity_kib": 20481},
            {"backlog_batches": 1},
            {"dropped_batches": 1},
            {"source_flags": 1},
            {"freshness_s": 181},
        ]:
            values = full()
            values[1].update(changes)
            with self.subTest(changes=changes):
                self.assertEqual(soak.assess(values)["status"], "fail")

    def test_cpu_uses_counter_ratio_per_logical_cpu(self):
        values = full()
        for value in values:
            value["collector_cpu_ticks"] *= 3
        self.assertEqual(soak.assess(values)["status"], "fail")
        self.assertAlmostEqual(soak.assess(values)["collector_cpu_percent"], 3)

    def test_reboot_restart_skew_suspend_and_counter_reset_fail(self):
        for changes in [
            {"host_boot_id": "new"},
            {"router_boot_id": "new"},
            {"collector_start": 11},
            {"helper_start": 21},
            {"monotonic": 0},
            {"wall": 1_800_000_900},
            {"boottime": 2900},
            {"collector_cpu_ticks": -1},
            {"total_cpu_ticks": 0},
        ]:
            values = [sample(0), sample(60, **changes)]
            with self.subTest(changes=changes):
                self.assertEqual(soak.assess(values)["status"], "fail")

    def test_no_oversampling_to_fake_coverage(self):
        self.assertEqual(soak.assess([sample(0), sample(1)])["status"], "fail")

    def test_dns_gap_blocks_pass_and_unmapped_remains_visible(self):
        values = full()
        values[-1]["dns_log_quiet"] = True
        self.assertNotEqual(soak.assess(values)["status"], "pass")
        values = full()
        values[-1]["ct_unmapped_flows"] = 5
        self.assertIn("unmapped_conntrack", soak.assess(values)["quality_notes"])

    def test_invalid_numbers_fail_closed(self):
        for value in [float("nan"), float("inf"), True, -1]:
            self.assertEqual(
                soak.assess([sample(0, collector_rss_kib=value)])["status"], "fail"
            )

    def test_journal_is_private_resumeable_and_rejects_truncation_or_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            with soak.Journal(path, mode="simulated") as journal:
                journal.append(sample(0))
                journal.append(sample(60))
                self.assertEqual(len(journal.samples), 2)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with soak.Journal(path, mode="simulated") as journal:
                self.assertEqual(len(journal.samples), 2)
            with self.assertRaises(ValueError), soak.Journal(path, mode="real"):
                pass
            with path.open("ab") as f:
                f.write(b'{"partial":')
            with self.assertRaises(ValueError), soak.Journal(path, mode="simulated"):
                pass
            link = Path(tmp) / "alias"
            link.symlink_to(path)
            with (
                self.assertRaises((OSError, ValueError)),
                soak.Journal(link, mode="simulated"),
            ):
                pass

    def test_journal_excludes_concurrent_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            with (
                soak.Journal(path, mode="simulated"),
                self.assertRaises(BlockingIOError),
                soak.Journal(path, mode="simulated"),
            ):
                pass


class AdditionalBoundaries(unittest.TestCase):
    def test_cpu_hotplug_cannot_hide_between_matching_endpoints(self):
        values = full()
        values[1]["logical_cpus"] = 4
        self.assertEqual(soak.assess(values)["status"], "fail")

    def test_nonfinite_record_failure_survives_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            with soak.Journal(path, mode="simulated") as journal:
                journal.append(sample(0))
                journal.append(sample(60, collector_rss_kib=float("nan")))
            with soak.Journal(path, mode="simulated") as journal:
                self.assertEqual(soak.assess(journal.samples)["status"], "fail")


if __name__ == "__main__":
    unittest.main()
