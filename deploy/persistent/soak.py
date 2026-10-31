#!/usr/bin/env python3
"""Durable strict 48-hour assessment; simulated unit clocks are not real evidence."""

from __future__ import annotations

import fcntl
import itertools
import json
import math
import os
import stat
from datetime import datetime
from pathlib import Path

DURATION_SECONDS = 172800
CADENCE_SECONDS = 60
MAX_GAP_SECONDS = 180
MIN_COVERAGE = 0.99
MAX_SAMPLES = 4000
MAX_RECORD_BYTES = 16384
_REQUIRED_NUMERIC = (
    "wall",
    "monotonic",
    "boottime",
    "collector_start",
    "helper_start",
    "collector_rss_kib",
    "helper_rss_kib",
    "mem_available_kib",
    "log_used_kib",
    "log_capacity_kib",
    "collector_cpu_ticks",
    "total_cpu_ticks",
    "logical_cpus",
    "freshness_s",
    "backlog_batches",
    "processing_backlog_age_s",
    "processing_backlog_reference_wall",
    "dropped_batches",
    "source_flags",
    "ct_unmapped_flows",
    "ct_unmapped_bytes",
    "dns_parsed_age_s",
)
_IDS = ("host_boot_id", "router_boot_id")
_BOOLS = ("dns_log_quiet", "dns_probe_ok", "backlog_capped")


def _number(value):
    try:
        return (
            type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1e20
        )
    except OverflowError:
        return False


def processing_backlog_age(count, capped, oldest, reference_wall):
    """Unknown is never an invented zero; a future receipt retains its negative age."""
    if (
        type(count) is not int
        or count < 0
        or capped is not False
        or not _number(reference_wall)
    ):
        return None
    if count == 0:
        return 0 if oldest is None else None
    if not isinstance(oldest, str) or len(oldest) > 128 or not oldest.isascii():
        return None
    try:
        received = datetime.fromisoformat(oldest)
        if received.tzinfo is None:
            return None
        return reference_wall - received.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def sample_issues(sample):
    """Return hard failures, absent fields, and collection-quality gates separately."""
    if not isinstance(sample, dict):
        return {"invalid_sample"}, set(), set()
    if sample.get("invalid_record"):
        return {"invalid_metrics"}, set(), set()
    missing = {
        key
        for key in (*_REQUIRED_NUMERIC, *_IDS, *_BOOLS)
        if key not in sample or sample[key] is None
    }
    if "oldest_pending_received_at" not in sample:
        missing.add("oldest_pending_received_at")
    failures = (
        {"invalid_metrics"}
        if any(
            key not in missing and not _number(sample[key]) for key in _REQUIRED_NUMERIC
        )
        else set()
    )
    for key in _IDS:
        if key not in missing and (
            not isinstance(sample[key], str)
            or not 1 <= len(sample[key]) <= 128
            or not sample[key].isascii()
            or not all(c.isalnum() or c == "-" for c in sample[key])
        ):
            failures.add("invalid_metrics")
    for key in _BOOLS:
        if key not in missing and type(sample[key]) is not bool:
            failures.add("invalid_metrics")
    oldest = sample.get("oldest_pending_received_at")
    if oldest is not None and (
        not isinstance(oldest, str) or len(oldest) > 128 or not oldest.isascii()
    ):
        failures.add("invalid_metrics")
    if failures:
        return failures, missing, set()
    expected_age = processing_backlog_age(
        sample.get("backlog_batches"),
        sample.get("backlog_capped"),
        oldest,
        sample.get("processing_backlog_reference_wall"),
    )
    if expected_age is None or "oldest_pending_received_at" in missing:
        missing.add("processing_backlog_age_s")
    elif expected_age < 0 or (
        "processing_backlog_age_s" not in missing
        and abs(sample["processing_backlog_age_s"] - expected_age) > 0.000001
    ):
        failures.add("invalid_metrics")
    if (
        not {"wall", "processing_backlog_reference_wall"} & missing
        and sample["processing_backlog_reference_wall"] < sample["wall"]
    ):
        failures.add("processing_backlog_clock_regression")
    limits = {
        "collector_rss_kib": lambda x: x < 9765,
        "helper_rss_kib": lambda x: x < 65536,
        "mem_available_kib": lambda x: x >= 65536,
        "log_used_kib": lambda x: x <= 20480,
        "log_capacity_kib": lambda x: 0 < x <= 20480,
        "freshness_s": lambda x: x <= 180,
        "processing_backlog_age_s": lambda x: x <= 180,
        "dropped_batches": lambda x: type(x) is int and x == 0,
        "source_flags": lambda x: x == 0,
        "logical_cpus": lambda x: x >= 1 and int(x) == x,
    }
    for key, valid in limits.items():
        if key not in missing and not valid(sample[key]):
            failures.add(key + "_limit")
    if (
        not {"log_used_kib", "log_capacity_kib"} & missing
        and sample["log_used_kib"] > sample["log_capacity_kib"]
    ):
        failures.add("log_used_kib_limit")
    quality = set()
    if sample.get("dns_log_quiet") is True:
        quality.add("dns_log_quiet")
    if sample.get("dns_probe_ok") is False:
        quality.add("dns_probe_failed")
    if "dns_parsed_age_s" not in missing and sample["dns_parsed_age_s"] > 120:
        quality.add("parsed_dns_stale")
    return failures, missing, quality


def assess(samples, *, mode="simulated"):
    """Assess actual recorded elapsed time; no parameter can shorten the 48-hour contract."""
    if mode not in ("real", "simulated"):
        raise ValueError("invalid evidence mode")
    result = {
        "status": "pending",
        "evidence_mode": mode,
        "elapsed_seconds": 0.0,
        "coverage": 0.0,
        "collector_cpu_percent": None,
        "reasons": [],
        "quality_notes": [],
    }
    if not isinstance(samples, list) or len(samples) > MAX_SAMPLES:
        return dict(result, status="fail", reasons=["invalid_sample_count"])
    if not samples:
        return dict(result, reasons=["no_samples"])
    failures, missing_any, quality, notes = set(), set(), set(), set()
    valid_count = 0
    clock_samples = []
    for sample in samples:
        hard, missing, gaps = sample_issues(sample)
        failures |= hard
        missing_any |= missing
        quality |= gaps
        if not hard and not missing and not gaps:
            valid_count += 1
        if (
            isinstance(sample, dict)
            and _number(sample.get("ct_unmapped_flows"))
            and sample["ct_unmapped_flows"] > 0
        ):
            notes.add("unmapped_conntrack")
        if isinstance(sample, dict) and all(
            _number(sample.get(k)) for k in ("wall", "monotonic", "boottime")
        ):
            clock_samples.append(sample)
    if clock_samples:
        first, last = clock_samples[0], clock_samples[-1]
        elapsed = last["monotonic"] - first["monotonic"]
        result["elapsed_seconds"] = max(0, elapsed)
        for before, after in itertools.pairwise(clock_samples):
            dt = after["monotonic"] - before["monotonic"]
            if dt < CADENCE_SECONDS - 0.01:
                failures.add("cadence_or_clock_violation")
            if dt > MAX_GAP_SECONDS:
                failures.add("sample_gap")
            if (
                abs((after["wall"] - before["wall"]) - dt) > 5
                or abs((after["boottime"] - before["boottime"]) - dt) > 5
            ):
                failures.add("clock_skew_or_suspend")
            for key in (*_IDS, "collector_start", "helper_start"):
                if key in before and key in after and before[key] != after[key]:
                    failures.add("boot_or_process_restart")
            if (
                _number(before.get("logical_cpus"))
                and _number(after.get("logical_cpus"))
                and before["logical_cpus"] != after["logical_cpus"]
            ):
                failures.add("cpu_topology_changed")
            for key in ("collector_cpu_ticks", "total_cpu_ticks"):
                if (
                    _number(before.get(key))
                    and _number(after.get(key))
                    and (
                        after[key] < before[key]
                        or (key == "total_cpu_ticks" and after[key] == before[key])
                    )
                ):
                    # An idle process may keep its own counter unchanged; aggregate CPU may not.
                    failures.add("cpu_counter_reset")
        expected = max(1, int(max(0, elapsed) // CADENCE_SECONDS) + 1)
        result["coverage"] = min(1.0, valid_count / expected)
        keys = ("collector_cpu_ticks", "total_cpu_ticks", "logical_cpus")
        if len(clock_samples) > 1 and all(
            _number(s.get(k)) for s in (first, last) for k in keys
        ):
            total = last["total_cpu_ticks"] - first["total_cpu_ticks"]
            process = last["collector_cpu_ticks"] - first["collector_cpu_ticks"]
            if total > 0 and first["logical_cpus"] == last["logical_cpus"]:
                cpu = 100 * process * last["logical_cpus"] / total
                result["collector_cpu_percent"] = cpu
                if cpu > 2:
                    failures.add("collector_cpu_limit")
            else:
                failures.add("cpu_counter_reset")
        if (
            elapsed >= DURATION_SECONDS
            and result["coverage"] < MIN_COVERAGE
            and not missing_any
            and not quality
        ):
            failures.add("sample_coverage")
        if (
            elapsed >= DURATION_SECONDS
            and result["coverage"] >= MIN_COVERAGE
            and not failures
            and not missing_any
            and not quality
        ):
            result["status"] = "pass"
    if failures:
        result["status"] = "fail"
    result["reasons"] = sorted(
        failures | ({"missing_metrics"} if missing_any else set()) | quality
    )
    result["quality_notes"] = sorted(notes)
    return result


class Journal:
    """Append-only, fsynced private JSONL with exclusive writer lock and fail-closed resume."""

    def __init__(self, path: Path, *, mode="real", metadata=None):
        self.path, self.mode, self.metadata = path, mode, metadata or {}
        self.fd = None
        self.samples = []

    def __enter__(self):
        if self.mode not in ("real", "simulated"):
            raise ValueError("invalid evidence mode")
        parent = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or parent.st_mode & 0o077
        ):
            raise ValueError("journal parent must be an owned private directory")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise ValueError("unsafe journal file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd = fd
            if info.st_size > MAX_SAMPLES * MAX_RECORD_BYTES:
                raise ValueError("journal exceeds bound")
            content = os.read(fd, info.st_size)
            if content and not content.endswith(b"\n"):
                raise ValueError("incomplete journal record; retain for investigation")
            lines = content.splitlines()
            if len(lines) > MAX_SAMPLES + 1 or any(
                len(line) > MAX_RECORD_BYTES for line in lines
            ):
                raise ValueError("journal record limit")
            header = {
                "schema": 2,
                "mode": self.mode,
                "duration_seconds": DURATION_SECONDS,
                "metadata": self.metadata,
            }
            if not lines:
                self._write(header)
                # Make the new filename durable, not only its data.
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            else:
                if json.loads(lines[0]) != header:
                    raise ValueError("journal contract/configuration mismatch")
                self.samples = [json.loads(line) for line in lines[1:]]
            return self
        except BaseException:
            os.close(fd)
            self.fd = None
            raise

    def _write(self, record):
        data = (
            json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n"
        ).encode()
        if len(data) > MAX_RECORD_BYTES:
            raise ValueError("journal record too large")
        os.lseek(self.fd, 0, os.SEEK_END)
        view = memoryview(data)
        while view:
            written = os.write(self.fd, view)
            if written == 0:
                raise OSError("journal write made no progress")
            view = view[written:]
        os.fsync(self.fd)

    def append(self, sample):
        if len(self.samples) >= MAX_SAMPLES:
            raise ValueError("sample limit")
        hard, _, _ = sample_issues(sample)
        if hard:
            # Persist a bounded failure marker instead of throwing away an unencodable
            # observation (NaN/huge integers/objects) and allowing a later resume to pass.
            safe = {}
            if isinstance(sample, dict):
                for key in _REQUIRED_NUMERIC:
                    if _number(sample.get(key)):
                        safe[key] = sample[key]
                for key in _IDS:
                    value = sample.get(key)
                    if isinstance(value, str) and len(value) <= 128 and value.isascii():
                        safe[key] = value
                # Preserve bounded raw processing evidence even for an invalid/future sample.
                for key in _BOOLS:
                    if type(sample.get(key)) is bool:
                        safe[key] = sample[key]
                oldest = sample.get("oldest_pending_received_at")
                if "oldest_pending_received_at" in sample and (
                    oldest is None
                    or (
                        isinstance(oldest, str)
                        and len(oldest) <= 128
                        and oldest.isascii()
                    )
                ):
                    safe["oldest_pending_received_at"] = oldest
                age = sample.get("processing_backlog_age_s")
                if type(age) in (float, int):
                    try:
                        if math.isfinite(age) and abs(age) <= 1e20:
                            safe["processing_backlog_age_s"] = age
                    except OverflowError:
                        pass
            sample = dict(safe, invalid_record=True)
        self._write(sample)
        self.samples.append(sample)

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
