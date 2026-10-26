"""Fix-round 5: site.py line-splitting parity, lock probe hardening, wedge states, killers.

Throwaway children and ephemeral loopback ports only; nothing signals or binds the fixed preview.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import sys
import threading
import time
from pathlib import Path

import pytest
from test_gui_preview_fixround1 import (  # noqa: F401 -- shared fixtures, same module instance
    _venv,
    attempt,
    listener,
    namespace,
    pidfd_support_for_offline_fixtures,
    preview,
    sandbox_owners,
    serve_argv,
)
from test_gui_preview_fixround3 import _hold_lock, _pth
from test_gui_preview_fixround4 import _refuses
from test_gui_preview_native import end_to_end_unavailable

REAL_LOCK = "/tmp/vigie-gui-preview-18745.lock"  # noqa: S108 -- only ever compared, never opened.

# ------------------------------------ F1: split exactly like site.py (str.splitlines)

SEPARATORS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "]


@pytest.mark.parametrize("sep", SEPARATORS)
def test_unicode_line_separators_hide_nothing_from_the_vet(sandbox_owners, tmp_path, sep):
    root, _, site = _venv(tmp_path)  # site.py 3.12+ splitlines(): '#c<sep>import ...' execs
    _pth(site, "e.pth", f"#c{sep}import os;os.getpid()\n")
    _refuses(root)


@pytest.mark.parametrize("sep", SEPARATORS)
def test_unicode_line_separator_before_a_path_is_refused(sandbox_owners, tmp_path, sep):
    root, _, site = _venv(tmp_path)  # 'zz<sep><dir>' puts <dir> on sys.path
    _pth(site, "e.pth", f"zz{sep}{tmp_path / 'missing'}\n")
    _refuses(root)


def test_a_bare_carriage_return_is_refused_not_split(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # M07: older site.py universal newlines split on a lone \r
    (site / "e.pth").write_bytes(f"{tmp_path / 'missing'}\rimport os\n".encode())
    (site / "e.pth").chmod(0o644)
    _refuses(root)


def test_a_leading_space_directory_line_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # M05
    _pth(site, "e.pth", f" {tmp_path / 'missing'}\n")
    _refuses(root)


# ------------------------------------ F2: the shared probe can neither hang nor traceback


def _status_within(namespace, seconds: float = 3.0) -> BaseException | None:
    """status() on a worker thread; TimeoutError means it was still blocked after `seconds`."""
    box: list[BaseException] = []

    def run() -> None:
        try:
            preview.status(namespace)
        except BaseException as exc:  # noqa: BLE001 -- the test inspects whatever came out
            box.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():  # release a reader blocked in open(2) so the test process can end
        with contextlib.suppress(OSError):
            os.close(os.open(preview.LOCK, os.O_WRONLY | os.O_NONBLOCK))
        return TimeoutError("status blocked in open() on the lock path")
    return box[0] if box else None


def test_a_fifo_at_the_lock_path_cannot_hang_status(namespace):
    os.mkfifo(preview.LOCK, 0o644)  # any local user can do this in a sticky /tmp
    outcome = _status_within(namespace)
    assert isinstance(outcome, preview.UnsafeLock), repr(outcome)
    assert "regular single-link file" in str(outcome)


def test_a_foreign_looking_regular_lock_file_is_a_clear_refusal(namespace):
    preview.LOCK.write_text("")
    preview.LOCK.chmod(0o644)
    with pytest.raises(preview.UnsafeLock, match="mode 0600.*found mode 0644"):
        preview.status(namespace)


def test_an_unreadable_lock_file_is_a_clear_refusal(namespace):
    preview.LOCK.write_text("")
    preview.LOCK.chmod(0)
    if os.access(preview.LOCK, os.R_OK):
        pytest.skip("root reads everything")
    with pytest.raises(preview.UnsafeLock, match="unsafe shared preview lock"):
        preview.status(namespace)


def test_the_cli_turns_an_unsafe_lock_into_a_message_not_a_traceback(
    namespace, monkeypatch, capsys
):
    os.mkfifo(preview.LOCK, 0o644)
    monkeypatch.setattr(preview, "directory", Path)  # tmp_path is not under /tmp/vigie-gui-*
    monkeypatch.setattr(sys, "argv", ["preview", "status", "--directory", str(namespace)])
    assert preview.main() == 2
    assert "unsafe shared preview lock" in capsys.readouterr().err


def test_the_exclusive_lock_still_refuses_an_unsafe_file(namespace):
    preview.LOCK.write_text("")
    preview.LOCK.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe"), preview.manager_lock():
        pass


def test_the_exclusive_lock_cannot_run_unlocked_when_its_directory_is_missing(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(preview, "LOCK", tmp_path / "absent-dir" / "x.lock")  # M21
    with pytest.raises(FileNotFoundError), preview.manager_lock():
        pass


# ------------------------------------ F4: tests never open the user's real lock


def test_the_suite_guard_stops_any_open_of_the_real_preview_lock():
    assert str(preview.LOCK) == REAL_LOCK  # the production default is what the guard protects
    with pytest.raises(AssertionError, match="real preview lock"):
        os.open(REAL_LOCK, os.O_RDONLY)


# ------------------------------------ F5: a wedged holder is named, not hidden as `starting`


def _foreign_holder(content: str, age: float) -> int:
    """Hold the exclusive flock on LOCK with arbitrary holder text and a backdated mtime."""
    fd = os.open(preview.LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.pwrite(fd, content.encode(), 0)
    old = time.time() - age
    os.utime(fd, (old, old))
    return fd


def test_the_holder_line_names_pid_start_ticks_and_boot_id(namespace):
    thread = _hold_lock(1.0)
    try:
        pid, ticks, boot = preview.LOCK.read_text().split()
    finally:
        thread.join(5)
    me = preview.process_identity(os.getpid())
    assert me is not None
    assert (int(pid), ticks, boot) == (os.getpid(), me["start_ticks"], me["boot_id"])


def test_a_fresh_holder_reports_starting_with_its_pid_and_age(namespace):
    thread = _hold_lock(1.0)
    try:
        result = preview.status(namespace)
    finally:
        thread.join(5)
    assert result["state"] == "starting" and result["holder_pid"] == os.getpid()
    assert 0 <= result["lock_age_seconds"] < preview.STARTING_SECONDS


def test_a_verified_holder_older_than_a_minute_is_wedged_with_instructions(namespace):
    me = preview.process_identity(os.getpid())
    assert me is not None
    fd = _foreign_holder(f"{os.getpid()} {me['start_ticks']} {me['boot_id']}\n", 120)
    try:
        result = preview.status(namespace)
    finally:
        os.close(fd)
    assert result["state"] == "wedged-start" and result["managed"] is False
    assert result["holder_pid"] == os.getpid() and result["lock_age_seconds"] >= 120
    assert f"/proc/{os.getpid()}/cmdline" in result["advice"] and "stop" in result["advice"]


@pytest.mark.parametrize(
    "line",
    ["999999999 1 x", "{pid} 1 x", "{pid} {ticks} 01234567-89ab-cdef-0123-456789abcdef", "junk", ""],
)
def test_an_unverifiable_old_holder_is_never_called_wedged(namespace, line):
    me = preview.process_identity(os.getpid())
    assert me is not None
    text = line.format(pid=os.getpid(), ticks=me["start_ticks"])  # reused PID, other boot, ...
    fd = _foreign_holder(text, 600)
    try:
        result = preview.status(namespace)
    finally:
        os.close(fd)
    assert result["state"] == "starting" and "holder_pid" not in result


# ------------------------------------ CODEX-B: a torn receipt row while a writer holds the lock


def _torn_attempt(namespace, listener):
    argv = serve_argv(namespace, listener.fileno())
    journal = attempt(namespace, argv, str(os.fstat(listener.fileno()).st_ino), [])
    with journal.open("ab") as handle:
        handle.write(b'{"state": "spa')  # start/stop is mid-append
    return journal


def test_status_with_a_torn_trailing_row_while_a_writer_holds_the_lock_is_starting(
    namespace, listener
):
    _torn_attempt(namespace, listener)
    thread = _hold_lock(1.0)
    try:
        result = preview.status(namespace)
    finally:
        thread.join(5)
    assert result["state"] == "starting" and result["managed"] is False


def test_a_torn_trailing_row_with_no_writer_is_still_a_retained_failure(namespace, listener):
    _torn_attempt(namespace, listener)
    with pytest.raises(ValueError, match="incomplete manager receipt"):
        preview.status(namespace)


def test_status_reads_the_receipt_under_the_shared_lock(namespace, listener, monkeypatch):
    argv = serve_argv(namespace, listener.fileno())
    attempt(namespace, argv, str(os.fstat(listener.fileno()).st_ino), [])
    probes: list[bool] = []
    real = preview.current_attempt

    def spy(root):
        if not probes:  # the first read; later re-reads are the unlocked mid-scan comparison
            fd = os.open(preview.LOCK, os.O_RDWR)  # a writer cannot lock EX while we read
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    probes.append(False)
                except BlockingIOError:
                    probes.append(True)
            finally:
                os.close(fd)
        return real(root)

    monkeypatch.setattr(preview, "current_attempt", spy)
    with preview.manager_lock():
        pass  # create the lock file: status never does
    preview.status(namespace)
    assert probes[0] is True


# ------------------------------------ M30: the walk bound


def test_the_pth_tree_bound_is_pinned_and_enforced(sandbox_owners, tmp_path, monkeypatch):
    assert preview.MAX_PTH_TREE_ENTRIES == 100_000
    monkeypatch.setattr(preview, "MAX_PTH_TREE_ENTRIES", 5)
    root, _, site = _venv(tmp_path)
    tree = tmp_path / "big"
    tree.mkdir()
    for index in range(6):
        (tree / f"f{index}.py").write_text("")
        (tree / f"f{index}.py").chmod(0o644)
    tree.chmod(0o755)
    _pth(site, "e.pth", f"{tree}\n")
    _refuses(root)
    (tree / "f5.py").unlink()
    preview._interpreter(root / "bin" / "python")  # exactly at the bound is accepted


# ------------------------------------ M12: a sticky group-writable anchor is not trusted


def test_a_sticky_group_writable_missing_target_anchor_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    shared = tmp_path / "grp"
    shared.mkdir()
    shared.chmod(0o1770)
    _pth(site, "e.pth", f"{shared / 'gone'}\n")
    _refuses(root)


# ------------------------------------ M32: the CI guard can fail but never turn into a skip


def test_under_ci_the_unavailable_lane_guard_fails_and_cannot_skip(monkeypatch):
    monkeypatch.setenv("CI", "true")
    with pytest.raises(pytest.fail.Exception, match="CI must exercise"):
        try:
            end_to_end_unavailable("why")
        except pytest.skip.Exception:
            pytest.fail("under CI the lane guard skipped instead of failing", pytrace=False)
