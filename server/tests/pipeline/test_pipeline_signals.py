"""Real signals delivered to a real pipeline process (not a handler called by hand).

The loop runs in a subprocess with a no-op pass so the signal lands while the main thread is inside
the idle wait: the window in which a lock-taking handler (threading.Event.set) can deadlock.
"""

from __future__ import annotations

import os
import random
import signal
import subprocess
import sys
import time

import pytest

# Upper bound for a child to stop after a signal. Stop latency is normally milliseconds but was
# measured up to ~2.3 s on a starved host (load ~220); the generous bound only absorbs load. A
# genuinely hung stop still fails, just later. Kept under the 20 s per-test pytest timeout.
STOP_TIMEOUT_S = 15

SCRIPT = """
import signal, sys, time
from vigie_pipeline import cli
def fake_run(config, should_stop=lambda: False):
    fd = signal.set_wakeup_fd(-1)  # read the installed wakeup fd, then put it back
    signal.set_wakeup_fd(fd)
    print("pass", fd, flush=True)
    time.sleep(float(sys.argv[2]))
cli.run_once = fake_run
sys.exit(cli.main(["run", "--loop", "3600", "--data-dir", sys.argv[1]]))
"""


def start(tmp_path, pass_seconds: float = 0.0) -> subprocess.Popen:
    return subprocess.Popen(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-c", SCRIPT, str(tmp_path), str(pass_seconds)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )


def wait_for_pass(proc) -> int:
    """Waits for the first pass; returns the signal wakeup fd the process had installed."""
    tag, fd = proc.stdout.readline().split()
    assert tag == "pass"
    return int(fd)


def test_wakeup_fd_is_installed_so_a_signal_before_select_is_not_lost(tmp_path):
    """Fails on code without signal.set_wakeup_fd (fd == -1): the Python-level handler runs after
    the eval-loop check, so a signal landing just before select() waited out the loop interval."""
    proc = start(tmp_path)
    assert wait_for_pass(proc) != -1
    proc.send_signal(signal.SIGTERM)
    proc.communicate(timeout=STOP_TIMEOUT_S)
    assert proc.returncode == 0


# Tests that fail on the pre-fix code: the wakeup-fd test above and the mid-drain stop test in
# test_delivery_runner.py. The idle-wait cases below pass on the old code too (regression guards).
@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_signal_in_idle_wait_stops_cleanly_many_times(tmp_path, sig):
    rng = random.Random(7)  # noqa: S311 - timing jitter, not crypto
    for _ in range(40):
        proc = start(tmp_path)
        wait_for_pass(proc)
        time.sleep(rng.uniform(0, 0.03))  # land at varied points around entering the wait
        proc.send_signal(sig)
        try:
            _, err = proc.communicate(timeout=STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            pytest.fail("stop hung: signal did not wake the idle wait")
        assert proc.returncode == 0
        assert '"event":"stopped"' in err


def test_signal_during_a_pass_lets_it_finish_then_exits_zero(tmp_path):
    proc = start(tmp_path, pass_seconds=1.0)
    wait_for_pass(proc)
    began = time.monotonic()
    proc.send_signal(signal.SIGTERM)
    _, err = proc.communicate(timeout=10)
    assert proc.returncode == 0 and '"event":"stopped"' in err
    assert time.monotonic() - began >= 0.8  # the pass was drained, not cut short


def test_second_signal_forces_exit(tmp_path):
    proc = start(tmp_path, pass_seconds=30.0)
    wait_for_pass(proc)
    proc.send_signal(signal.SIGINT)
    time.sleep(0.3)
    assert proc.poll() is None  # first signal: still draining
    proc.send_signal(signal.SIGINT)
    proc.communicate(timeout=STOP_TIMEOUT_S)
    assert proc.returncode not in (0, None)
