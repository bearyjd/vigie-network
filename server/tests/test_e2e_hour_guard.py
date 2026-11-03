"""The e2e promotes a transient after two distinct server-received hours (processor.py
PROMOTE_MIN_HOURS), so a run that straddles a UTC hour boundary flips the rolling-MAC assertion.
hour_guard.sh must report how long to wait so the collect stage stays inside one hour."""

import shutil
import subprocess
from pathlib import Path

BASH = shutil.which("bash") or "/bin/bash"
GUARD = Path(__file__).resolve().parents[2] / "tests" / "e2e" / "hour_guard.sh"


def wait_s(epoch: int, budget: int = 240) -> int:
    script = 'source "$1"; hour_guard_wait_s "$2" "$3"'
    argv = [BASH, "-c", script, "_", str(GUARD), str(epoch), str(budget)]
    out = subprocess.run(argv, capture_output=True, text=True, check=True)  # noqa: S603
    return int(out.stdout)


def test_mid_hour_does_not_wait():
    assert wait_s(3600 * 10 + 600) == 0


def test_just_before_boundary_waits_past_it():
    assert wait_s(3600 * 11 - 70) == 70 + 1


def test_exactly_budget_before_boundary_does_not_wait():
    assert wait_s(3600 * 11 - 240) == 0


def test_just_after_boundary_does_not_wait():
    assert wait_s(3600 * 11 + 1) == 0
