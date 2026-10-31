"""A fake clock verifies logic; it never supplies real acceptance evidence."""

import importlib.util
import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime
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
        "backlog_capped": False,
        "oldest_pending_received_at": None,
        "processing_backlog_age_s": 0,
        "processing_backlog_reference_wall": 1_800_000_000 + second,
        "dropped_batches": 0,
        "retained_batches_since": "2026-01-01T00:00:00+00:00",
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
            {
                "backlog_batches": 1,
                "processing_backlog_age_s": 181,
                "oldest_pending_received_at": datetime.fromtimestamp(
                    1_800_000_060 - 181, UTC
                ).isoformat(),
            },
            {"dropped_batches": 1},
            {"source_flags": 1},
            {"freshness_s": 181},
        ]:
            values = full()
            values[1].update(changes)
            with self.subTest(changes=changes):
                self.assertEqual(soak.assess(values)["status"], "fail")

    def drop_run(self, base, per_index=None, since="2026-01-01T00:00:00+00:00"):
        per_index = per_index or {}
        values = full()
        for i, value in enumerate(values):
            value.update(
                dropped_batches=base,
                dropped_baseline=base,
                retained_batches_since=since,
            )
            value.update(per_index.get(i, {}))
        return values

    def test_preexisting_drops_at_baseline_do_not_fail_the_run(self):
        for base in (0, 7):
            with self.subTest(base=base):
                result = soak.assess(self.drop_run(base))
                self.assertEqual(result["status"], "pass")

    def test_drop_after_baseline_fails(self):
        for base in (0, 7):
            with self.subTest(base=base):
                values = self.drop_run(base, {5: {"dropped_batches": base + 1}})
                result = soak.assess(values)
                self.assertEqual(result["status"], "fail")
                self.assertIn("dropped_batches_limit", result["reasons"])

    def test_baseline_is_the_first_sample_even_without_stamped_copies(self):
        values = full()
        values[0]["dropped_batches"] = 4
        for value in values[1:]:
            value["dropped_batches"] = 4
            value["retained_batches_since"] = "2026-01-01T00:00:00+00:00"
        self.assertEqual(soak.assess(values)["status"], "pass")
        values[3]["dropped_batches"] = 5
        self.assertIn("dropped_batches_limit", soak.assess(values)["reasons"])

    def test_missing_or_unknown_first_baseline_fails(self):
        for first in (None, "bad"):
            values = self.drop_run(0)
            values[0]["dropped_batches"] = first
            result = soak.assess(values)
            self.assertEqual(result["status"], "fail")
            self.assertIn("dropped_baseline_missing", result["reasons"])

    def test_tampered_or_missing_baseline_copy_fails(self):
        for index, change in (
            (0, {"dropped_baseline": 1}),
            (3, {"dropped_baseline": 1}),
            (3, {"dropped_baseline": None}),
        ):
            values = self.drop_run(0)
            values[index].update(change)
            with self.subTest(index=index, change=change):
                result = soak.assess(values)
                self.assertEqual(result["status"], "fail")
                self.assertIn("dropped_baseline_mismatch", result["reasons"])
        values = self.drop_run(0)
        del values[3]["dropped_baseline"]
        self.assertIn("dropped_baseline_mismatch", soak.assess(values)["reasons"])
        values = self.drop_run(0)
        del values[0]["dropped_baseline"]
        self.assertIn("dropped_baseline_mismatch", soak.assess(values)["reasons"])

    def test_lowered_total_with_nonzero_baseline_is_unverifiable(self):
        # Old drops rolling out of the window could mask new ones: never a pass.
        values = self.drop_run(7, {5: {"dropped_batches": 6}})
        result = soak.assess(values)
        self.assertEqual(result["status"], "fail")
        self.assertIn("dropped_window_unverifiable", result["reasons"])

    def test_window_advance_with_nonzero_baseline_is_unverifiable(self):
        for since in ("2026-01-02T00:00:00+00:00", None):
            values = self.drop_run(7, {5: {"retained_batches_since": since}})
            with self.subTest(since=since):
                result = soak.assess(values)
                self.assertEqual(result["status"], "fail")
                self.assertIn("dropped_window_unverifiable", result["reasons"])

    def test_rows_must_still_be_retained_from_before_the_run_for_any_baseline(self):
        for base in (0, 7):
            for since in (None, "garbage", "2027-06-01T00:00:00+00:00", 5):
                values = self.drop_run(base)
                for value in values:
                    value["retained_batches_since"] = since
                with self.subTest(base=base, since=since):
                    result = soak.assess(values)
                    self.assertEqual(result["status"], "fail")
                    self.assertIn("dropped_window_unverifiable", result["reasons"])

    def test_zero_baseline_tolerates_a_moving_window_start_before_the_run(self):
        values = self.drop_run(
            0, {5: {"retained_batches_since": "2026-02-01T00:00:00+00:00"}}
        )
        self.assertEqual(soak.assess(values)["status"], "pass")

    def test_boolean_baseline_stamp_is_not_a_number(self):
        values = self.drop_run(1)
        for value in values:
            value["dropped_baseline"] = True
        result = soak.assess(values)
        self.assertEqual(result["status"], "fail")
        self.assertIn("dropped_baseline_mismatch", result["reasons"])

    def test_real_mode_requires_a_stamp_but_simulated_legacy_does_not(self):
        values = self.drop_run(0)
        for value in values:
            del value["dropped_baseline"]
        self.assertEqual(soak.assess(values)["status"], "pass")
        result = soak.assess(values, mode="real")
        self.assertEqual(result["status"], "fail")
        self.assertIn("dropped_baseline_mismatch", result["reasons"])
        self.assertEqual(soak.assess(self.drop_run(0), mode="real")["status"], "pass")

    def test_invalid_first_record_keeps_the_drop_baseline_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o700)
            path = Path(tmp) / "journal"
            first = dict(
                sample(0),
                dropped_batches=7,
                dropped_baseline=7,
                retained_batches_since="2026-01-01T00:00:00+00:00",
                helper_rss_kib=float("nan"),
            )
            with soak.Journal(path, mode="real") as journal:
                journal.append(first)
            with soak.Journal(path, mode="real") as journal:
                kept = journal.samples[0]
        self.assertTrue(kept["invalid_record"])
        self.assertEqual(kept["dropped_batches"], 7)
        self.assertEqual(kept["dropped_baseline"], 7)
        self.assertEqual(kept["retained_batches_since"], "2026-01-01T00:00:00+00:00")

    def test_nonzero_baseline_requires_a_window_start(self):
        values = self.drop_run(7, since=None)
        self.assertIn("dropped_window_unverifiable", soak.assess(values)["reasons"])

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

    def test_missing_meter_sample_is_pending_not_a_fictitious_restart(self):
        values = [sample(0), sample(60)]
        for key in [
            "router_boot_id",
            "collector_start",
            "helper_start",
            "logical_cpus",
        ]:
            values[-1].pop(key)
        result = soak.assess(values)
        self.assertEqual(result["status"], "pending")
        self.assertIn("missing_metrics", result["reasons"])

    def test_nonfinite_record_failure_survives_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            with soak.Journal(path, mode="simulated") as journal:
                journal.append(sample(0))
                journal.append(sample(60, collector_rss_kib=float("nan")))
            with soak.Journal(path, mode="simulated") as journal:
                self.assertEqual(soak.assess(journal.samples)["status"], "fail")


class ProcessingAgeTests(unittest.TestCase):
    def queued(self, value, age):
        return dict(
            value,
            backlog_batches=1,
            backlog_capped=False,
            oldest_pending_received_at=datetime.fromtimestamp(
                value["wall"] - age, UTC
            ).isoformat(),
            processing_backlog_age_s=age,
            processing_backlog_reference_wall=value["wall"],
        )

    def test_normal_29_second_handoff_and_exact_180_seconds_are_allowed(self):
        for age in (29, 180):
            values = full()
            values[-1] = self.queued(values[-1], age)
            self.assertEqual(soak.assess(values)["status"], "pass")

    def test_stalled_processing_fails_despite_fresh_new_ingest(self):
        values = full()
        values[-1] = self.queued(values[-1], 181)
        values[-1]["freshness_s"] = 1
        result = soak.assess(values)
        self.assertEqual(result["status"], "fail")
        self.assertIn("processing_backlog_age_s_limit", result["reasons"])

    def test_unknown_capped_and_inconsistent_pending_state_cannot_pass(self):
        for changes in [
            {"oldest_pending_received_at": None, "processing_backlog_age_s": None},
            {"oldest_pending_received_at": "bad", "processing_backlog_age_s": None},
            {"backlog_capped": True, "processing_backlog_age_s": None},
            {"oldest_pending_received_at": None, "processing_backlog_age_s": 0},
        ]:
            values = full()
            values[-1] = self.queued(values[-1], 29)
            values[-1].update(changes)
            self.assertNotEqual(soak.assess(values)["status"], "pass")

    def test_future_pending_time_and_reference_clock_regression_fail(self):
        values = full()
        values[-1] = self.queued(values[-1], -1)
        self.assertEqual(soak.assess(values)["status"], "fail")
        values = full()
        values[-1] = self.queued(values[-1], 29)
        values[-1].update(
            processing_backlog_reference_wall=values[-1]["wall"] - 1,
            processing_backlog_age_s=28,
        )
        self.assertEqual(soak.assess(values)["status"], "fail")

    def test_future_timestamp_cannot_hide_as_missing_computed_age(self):
        values = full()
        values[-1] = self.queued(values[-1], -1)
        values[-1]["processing_backlog_age_s"] = None
        self.assertEqual(soak.assess(values)["status"], "fail")

    def test_prior_journal_contract_is_retained_and_refused(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            before = (
                json.dumps(
                    {
                        "schema": 1,
                        "mode": "simulated",
                        "duration_seconds": 172800,
                        "metadata": {},
                    }
                )
                + "\n"
            ).encode()
            path.write_bytes(before)
            path.chmod(0o600)
            with self.assertRaises(ValueError), soak.Journal(path, mode="simulated"):
                pass
            self.assertEqual(path.read_bytes(), before)

    def test_raw_processing_evidence_survives_failed_journal_and_resume(self):
        value = self.queued(sample(0), -1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            with soak.Journal(path, mode="simulated") as journal:
                journal.append(value)
            with soak.Journal(path, mode="simulated") as journal:
                recorded = journal.samples[0]
                for key in [
                    "backlog_batches",
                    "backlog_capped",
                    "oldest_pending_received_at",
                    "processing_backlog_reference_wall",
                    "processing_backlog_age_s",
                ]:
                    self.assertEqual(recorded[key], value[key])
                self.assertEqual(soak.assess(journal.samples)["status"], "fail")


if __name__ == "__main__":
    unittest.main()
