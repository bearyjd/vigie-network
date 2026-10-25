"""Real-pidfd lane: tools/gui/preview.py under the native Python, hermetic and port-injected.

The cached uv Python lacks os.pidfd_open, so the scenarios run in `/usr/bin/python3 -I` via
gui_preview_native_lane.py (throwaway sleeper/health children, ephemeral port, private lock).
They are skipped where no native interpreter with pidfd support exists.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

NATIVE = "/usr/bin/python3"
LANE = Path(__file__).with_name("gui_preview_native_lane.py")
PREVIEW = Path(__file__).resolve().parents[3] / "tools/gui/preview.py"


def _native_has_pidfd() -> bool:
    try:
        probe = subprocess.run(  # noqa: S603 -- fixed native interpreter, fixed snippet.
            [NATIVE, "-I", "-c", "import os, signal; os.pidfd_open; signal.pidfd_send_signal"],
            capture_output=True,
            timeout=20,
        )
    except OSError:
        return False
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(not _native_has_pidfd(), reason="needs native Python with pidfd")

SPEC = importlib.util.spec_from_file_location("gui_preview_native", PREVIEW)
assert SPEC is not None and SPEC.loader is not None
preview = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preview)


def lane(tmp_path, scenario):
    root = tmp_path / "synthetic"
    preview.seed(root)
    work = tmp_path / "work"
    work.mkdir()
    done = subprocess.run(  # noqa: S603 -- our reviewed lane script under the native interpreter.
        [NATIVE, "-I", str(LANE), str(PREVIEW), str(root), str(work), scenario],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout)


def test_signal_in_popen_errpipe_read_leaves_a_recoverable_prepared_only_receipt(tmp_path):
    out = lane(tmp_path, "popen-read-interrupt")
    assert out["raised"] == "SystemExit"
    # The fork outcome is unknown, so nothing may claim the child exited or never existed.
    assert out["journal"] == [["prepared", None]]
    assert out["child_alive"] is True and out["status"] == "orphaned"
    assert out["stop"] == "stopped" and out["alive_after_stop"] is False


def test_termination_during_popen_is_deferred_until_the_child_is_bound_and_cleaned(tmp_path):
    out = lane(tmp_path, "signal-during-popen")
    assert out["raised"] == "SystemExit"
    assert out["journal"] == [["prepared", None], ["startup-failed", True]]
    assert out["child_alive"] is False  # TERM worked: the child did not inherit the block mask


def test_orphan_and_spawned_receipts_stop_through_a_real_pidfd(tmp_path):
    out = lane(tmp_path, "stop-real-pidfd")
    assert out["orphan"]["before"] == "orphaned" and out["spawned"]["before"] == "uncertain"
    for name in ("orphan", "spawned"):
        assert out[name]["returncode"] == -15
        assert out[name]["journal"] == ["prepared", "spawned", "stop-requested", "stopped"]


def test_end_to_end_start_stop_uses_real_interpreter_check_isolation_and_clear_signal_mask(
    tmp_path,
):
    out = lane(tmp_path, "start-end-to-end")
    assert out["started"] == "running" and out["argv_flags"] == ["-I", "-B"]
    assert out["sigblk"] == "0000000000000000"
    assert out["journal"] == ["prepared", "spawned", "ready"]
    assert out["stopped"] == "stopped"
    assert out["journal_after"][-2:] == ["stop-requested", "stopped"]
