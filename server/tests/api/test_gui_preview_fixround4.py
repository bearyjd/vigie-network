"""Fix-round 4: .pth parsing parity with site.py, dangling targets, lock/status honesty, killers.

Throwaway children and ephemeral loopback ports only; nothing signals or binds the fixed preview.
"""

from __future__ import annotations

import fcntl
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_gui_preview_fixround1 import (  # noqa: F401 -- shared fixtures, same module instance
    _mocked_start,
    _venv,
    attempt,
    listener,
    live,
    namespace,
    pidfd_support_for_offline_fixtures,
    preview,
    sandbox_owners,
    sleeper,
)
from test_gui_preview_fixround3 import UNTRUSTED, _accepts, _editable_target, _hold_lock, _pth
from test_gui_preview_native import end_to_end_unavailable


def _world_writable(tmp_path: Path, name: str = "dirty") -> Path:
    path = tmp_path / name
    path.mkdir()
    path.chmod(0o777)
    return path


def _refuses(root: Path) -> None:
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


# ---------------------------------------- .pth parsing exactly like site.py


def test_indented_hash_line_is_a_directory_for_site_py_not_a_comment(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # F1: site.py only treats '#' in column 0 as a comment
    dirty = _world_writable(tmp_path)
    _pth(site, "x.pth", " #x/" + "../" * len(site.parts) + str(dirty).lstrip("/") + "\n")
    _refuses(root)


def test_a_column_zero_comment_and_blank_whitespace_lines_are_still_skipped(
    sandbox_owners, tmp_path
):
    root, _, site = _venv(tmp_path)
    _pth(site, "x.pth", f"# a comment\n   \n\t\n{_editable_target(tmp_path)}\n")
    assert _accepts(root / "bin" / "python")


@pytest.mark.parametrize("suffix", [" ", "\t", "\x0b", "\x1f"])
def test_trailing_whitespace_on_a_directory_line_is_refused(sandbox_owners, tmp_path, suffix):
    root, _, site = _venv(tmp_path)
    _pth(site, "x.pth", f"{_editable_target(tmp_path)}{suffix}\n")
    _refuses(root)


def test_bom_prefixed_import_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # F2: site.py decodes utf-8-sig, so the BOM is dropped
    (site / "b.pth").write_bytes(b"\xef\xbb\xbfimport evil\n")
    (site / "b.pth").chmod(0o644)
    _refuses(root)


def test_a_bom_before_a_plain_directory_line_is_read_like_site_py(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    dirty = _world_writable(tmp_path)
    (site / "b.pth").write_bytes(b"\xef\xbb\xbf" + str(dirty).encode() + b"\n")
    (site / "b.pth").chmod(0o644)
    _refuses(root)  # the BOM must not hide the directory from the tree check


def test_an_undecodable_pth_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    (site / "b.pth").write_bytes(b"\xff\xfe/nowhere\n")
    (site / "b.pth").chmod(0o644)
    _refuses(root)


def test_second_target_is_vetted_after_a_clean_first(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # kills: only the first target vetted
    _pth(site, "editable.pth", f"{_editable_target(tmp_path)}\n{_world_writable(tmp_path)}\n")
    _refuses(root)


def test_dangling_symlink_target_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # kills: lexists -> exists
    (tmp_path / "dangling").symlink_to(tmp_path / "later")
    _pth(site, "editable.pth", f"{tmp_path / 'dangling'}\n")
    _refuses(root)


def test_base_dist_packages_pth_is_vetted(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)  # kills: dist-packages not vetted
    dist = binary.parent.parent / "lib" / "python3.12" / "dist-packages"
    dist.mkdir()
    dist.chmod(0o700)
    (root / "pyvenv.cfg").write_text(
        f"home = {binary.parent}\ninclude-system-site-packages = true\n"
    )
    assert _accepts(root / "bin" / "python")
    _pth(dist, "evil.pth", "import evil\n")
    _refuses(root)


# ---------------------------------------- F3: a missing target can appear later


def test_missing_target_creatable_by_others_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    shared = tmp_path / "sticky"  # a sticky 1777 dir like /tmp is NOT enough
    shared.mkdir()
    shared.chmod(0o1777)
    _pth(site, "e.pth", f"{shared / 'gone' / 'src'}\n")
    _refuses(root)


def test_missing_target_under_a_group_writable_ancestor_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    shared = tmp_path / "group"
    shared.mkdir()
    shared.chmod(0o770)
    _pth(site, "e.pth", f"{shared / 'gone'}\n")
    _refuses(root)


def test_missing_target_under_an_owned_private_ancestor_is_still_ignored(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    _pth(site, "e.pth", f"{tmp_path / 'gone' / 'src'}\n")
    assert _accepts(root / "bin" / "python")


def test_missing_target_below_an_unsafe_ancestor_chain_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    open_dir = tmp_path / "open"  # a non-sticky 0777 parent could rename our private anchor away
    mine = open_dir / "mine"
    mine.mkdir(parents=True)
    open_dir.chmod(0o777)
    mine.chmod(0o700)
    _pth(site, "e.pth", f"{mine / 'gone'}\n")
    try:
        _refuses(root)
    finally:
        open_dir.chmod(0o700)


def test_a_pth_directory_line_of_slash_is_refused_by_the_bounded_walk(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    _pth(site, "e.pth", "/\n")  # would otherwise walk the whole filesystem under the lock
    _refuses(root)


def test_the_bounded_walk_refuses_past_the_limit_and_accepts_within_it(
    sandbox_owners, tmp_path, monkeypatch
):
    root, _, site = _venv(tmp_path)
    target = _editable_target(tmp_path)
    for number in range(8):
        (target / f"module{number}.py").write_text("")
    _pth(site, "e.pth", f"{target}\n")
    assert _accepts(root / "bin" / "python")
    entries = sum(len(names) + len(files) for _, names, files in os.walk(target))
    monkeypatch.setattr(preview, "MAX_PTH_TREE_ENTRIES", entries)
    assert _accepts(root / "bin" / "python")  # exactly at the limit
    monkeypatch.setattr(preview, "MAX_PTH_TREE_ENTRIES", entries - 1)
    _refuses(root)


# ---------------------------------------- lock: holder PID, shared status probe


def test_a_busy_lock_names_the_holder_pid_and_clears_it_when_released(namespace, monkeypatch):
    monkeypatch.setattr(preview, "LOCK_WAIT_SECONDS", 0.1)
    thread = _hold_lock(1.0)
    try:
        with pytest.raises(BlockingIOError, match=rf"PID {os.getpid()}\b"):
            preview.stop(namespace)
    finally:
        thread.join(5)
    assert preview.LOCK.read_bytes() == b""  # a stale holder must not be advertised
    with preview.manager_lock():
        pass


def test_a_stale_holder_pid_of_a_dead_process_is_not_advertised(namespace, monkeypatch):
    monkeypatch.setattr(preview, "LOCK_WAIT_SECONDS", 0.1)
    preview.LOCK.write_text("4194305\n")  # above pid_max: no such process
    preview.LOCK.chmod(0o600)
    thread = _shared_hold(1.0)
    try:
        with pytest.raises(BlockingIOError) as raised:
            preview.stop(namespace)
    finally:
        thread.join(5)
    assert "another preview command holds the lock; retry shortly" in str(raised.value)


def test_the_documented_wait_is_two_seconds(namespace):
    assert preview.LOCK_WAIT_SECONDS == 2.0
    thread = _hold_lock(3.0)
    started = time.monotonic()
    try:
        with pytest.raises(BlockingIOError):
            preview.stop(namespace)
        elapsed = time.monotonic() - started
    finally:
        thread.join(5)
    assert 1.8 < elapsed < 2.6


def _shared_hold(seconds: float) -> threading.Thread:
    held = threading.Event()

    def hold():
        fd = os.open(preview.LOCK, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            held.set()
            time.sleep(seconds)
        finally:
            os.close(fd)

    thread = threading.Thread(target=hold)
    thread.start()
    assert held.wait(5)
    return thread


def test_concurrent_status_calls_never_make_each_other_report_starting(
    namespace, listener, sleeper
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, [])
    preview.LOCK.touch(mode=0o600)
    thread = _shared_hold(1.0)  # another read-only status is probing right now
    try:
        assert preview.status(namespace)["state"] == "orphaned"
    finally:
        thread.join(5)


def test_a_shared_status_probe_does_not_block_start_or_stop_for_long(namespace):
    preview.LOCK.touch(mode=0o600)
    thread = _shared_hold(0.3)
    started = time.monotonic()
    try:
        assert preview.stop(namespace)["state"] == "stopped"  # waits for the probe, then runs
    finally:
        thread.join(5)
    assert time.monotonic() - started < 2.0


def test_status_never_creates_the_lock_file(namespace, listener, sleeper, monkeypatch):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, [])
    monkeypatch.setattr(preview, "listeners", lambda: {inode})  # not netns-wide tcp/tcp6 counts
    assert not preview.LOCK.exists()
    assert preview.status(namespace)["state"] == "orphaned"
    assert not preview.LOCK.exists()  # "read-only" includes the lock file


# ---------------------------------------- status honesty while a start holds the lock


def test_status_between_spawned_and_ready_reports_starting_not_uncertain(
    namespace, listener, sleeper
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, ["spawned"], identity=identity)
    thread = _hold_lock(1.0)  # start is waiting for readiness
    try:
        result = preview.status(namespace)
    finally:
        thread.join(5)
    assert result["state"] == "starting" and result["managed"] is False
    assert "pid" not in result and "candidate_pids" not in result


def test_a_terminal_receipt_reports_starting_while_a_new_start_holds_the_lock(
    namespace, listener, sleeper
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, ["spawned", "stop-requested", "stopped"], identity=identity)
    thread = _hold_lock(1.0)
    try:
        assert preview.status(namespace)["state"] == "starting"
    finally:
        thread.join(5)


def test_an_unattempted_namespace_reports_starting_while_start_vets_under_the_lock(namespace):
    thread = _hold_lock(1.0)
    try:
        assert preview.status(namespace)["state"] == "starting"
    finally:
        thread.join(5)


def test_a_stuck_spawned_receipt_without_a_lock_holder_stays_uncertain_managed(
    namespace, listener, sleeper
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, ["spawned"], identity=identity)
    result = preview.status(namespace)
    assert result["state"] == "uncertain" and result["managed"] is True
    assert result["pid"] == child.pid


def test_rows_appended_mid_scan_report_starting(namespace, listener, sleeper, monkeypatch):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    journal = attempt(namespace, argv, inode, [])
    real = preview._lookalikes

    def appended(rows):
        found = real(rows)
        with journal.open("a") as handle:  # a concurrent command moved on, same journal name
            handle.write('{"state": "failed-before-spawn"}\n')
        return found

    monkeypatch.setattr(preview, "_lookalikes", appended)
    assert preview.status(namespace)["state"] == "starting"


def test_candidates_are_listed_while_the_port_is_held(namespace, listener, sleeper, monkeypatch):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, [])
    monkeypatch.setattr(preview, "listeners", lambda: {"999999"})
    out = preview.status(namespace)
    assert out["state"] == "uncertain" and out["candidate_pids"] == [child.pid]


# ---------------------------------------- the child environment is the whole boundary


def test_the_child_environment_is_exactly_path_and_lc_all(namespace, monkeypatch):
    child, _ = _mocked_start(namespace, monkeypatch, ready=Mock())
    mocked_popen = preview.subprocess.Popen
    seen = {}

    def spawn(argv, **kwargs):
        seen.update(kwargs["env"])
        return mocked_popen(argv, **kwargs)

    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    monkeypatch.setenv("COVERAGE_PROCESS_START", "/evil/rc")
    monkeypatch.setenv("PYTHONPATH", "/evil")
    preview.start(namespace, Path("/pkg"), Path(sys.executable))
    # a1_coverage.pth is allowlisted only because nothing but these two keys reaches the child
    assert seen == {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}


# ---------------------------------------- the end-to-end lane cannot vanish on CI


def test_an_unavailable_end_to_end_lane_skips_locally_and_fails_under_ci(monkeypatch):
    monkeypatch.delenv("CI", raising=False)
    with pytest.raises(pytest.skip.Exception, match="no clean interpreter"):
        end_to_end_unavailable("no clean interpreter")
    monkeypatch.setenv("CI", "true")
    with pytest.raises(pytest.fail.Exception, match="no clean interpreter"):
        end_to_end_unavailable("no clean interpreter")


def test_the_lane_selects_the_first_interpreter_the_real_trust_check_accepts(
    tmp_path, monkeypatch
):
    import gui_preview_native_lane as lane
    from types import SimpleNamespace

    first, second, third = (tmp_path / name / "bin" / "python3" for name in "abc")
    for path in (first, second, third):
        path.parent.mkdir(parents=True)
        path.write_text("")
    monkeypatch.setattr(lane, "uv_interpreters", lambda: [first, second])
    monkeypatch.setattr(lane, "NATIVE_FALLBACK", third)
    tried = []

    def trust(venv_python):  # stands in for pv._interpreter: refuses all but the third
        tried.append((venv_python.parent / ".." / "pyvenv.cfg").read_text())
        if f"home = {third.parent}" not in tried[-1]:
            raise ValueError("native Python interpreter unavailable or untrusted")
        return venv_python

    pv = SimpleNamespace(_interpreter=trust)
    chosen, reason = lane.child_interpreter(pv, tmp_path / "work")
    assert reason == "" and chosen is not None and chosen.name == "python"
    assert len(tried) == 3
    pv = SimpleNamespace(_interpreter=lambda _p: (_ for _ in ()).throw(ValueError("untrusted")))
    chosen, reason = lane.child_interpreter(pv, tmp_path / "work2")
    assert chosen is None and "untrusted" in reason and "CI" not in reason


def test_docs_describe_the_round_four_behaviour():
    docs = (Path(__file__).resolve().parents[3] / "docs" / "gui-preview.md").read_text()
    for needle in (
        "never creates the lock file",
        "`#` is in column 0",
        "100,000 entries",
        "nearest existing ancestor",
        "kill -CONT <PID>",
        "run `stop`",
        "`CI` environment variable",
        "exactly `PATH` and `LC_ALL`",
    ):
        assert needle in docs, needle
