"""Fix-round 2: H1 spawn-signal safety, M1 non-UTF-8 argv, M3 interpreter trust, L1-L3, survivors.

Throwaway children and ephemeral loopback ports only; nothing signals or binds the fixed preview.
"""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
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
    real_stop_signals,
    sandbox_owners,
    serve_argv,
    settled_identity,
    sleeper,
)

UNTRUSTED = "untrusted"


# ---------------------------------------------------------------- H1


def test_termination_signals_are_blocked_around_popen_and_restored_after(namespace, monkeypatch):
    seen = {}
    child, _ = _mocked_start(namespace, monkeypatch, ready=lambda *args: None)

    def spawn(argv, **kwargs):
        seen["blocked"] = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        seen["argv"] = argv
        return child

    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    monkeypatch.setattr(
        preview,
        "process_identity",
        lambda pid: {
            "pid": pid,
            "uid": os.getuid(),
            "start_ticks": "100",
            "argv": seen["argv"],
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        },
    )
    before = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    preview.start(namespace, Path("/pkg"), Path(sys.executable))
    assert {signal.SIGTERM, signal.SIGHUP, signal.SIGINT} <= seen["blocked"]
    assert signal.pthread_sigmask(signal.SIG_BLOCK, ()) == before


def test_child_side_hook_clears_the_inherited_signal_mask():
    code = (
        "import signal, sys; sys.path.insert(0, sys.argv[1]);"
        "import importlib.util as u;"
        "s = u.spec_from_file_location('pv', sys.argv[2]); m = u.module_from_spec(s);"
        "s.loader.exec_module(m);"
        "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM});"
        "m._unblock_signals(); print(sorted(signal.pthread_sigmask(signal.SIG_BLOCK, ())))"
    )
    out = subprocess.run(  # noqa: S603 -- our interpreter, fixed snippet.
        [sys.executable, "-I", "-c", code, str(Path.cwd()), str(preview.__file__)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == "[]"


def test_unwound_popen_with_unknown_fork_outcome_writes_no_terminal_receipt(namespace, monkeypatch):
    _mocked_start(namespace, monkeypatch, ready=lambda *args: None)
    monkeypatch.setattr(preview.subprocess, "Popen", Mock(side_effect=SystemExit(143)))
    with pytest.raises(SystemExit):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared"]  # the orphan scan can still recover it


def test_popen_oserror_is_a_definite_failed_before_spawn(namespace, monkeypatch):
    _mocked_start(namespace, monkeypatch, ready=lambda *args: None)
    monkeypatch.setattr(preview.subprocess, "Popen", Mock(side_effect=OSError("exec failed")))
    with pytest.raises(RuntimeError, match="retained private log"):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared", "failed-before-spawn"]
    assert rows[-1]["child_exited"] is True and rows[-1]["child_pid"] is None


def test_child_that_cannot_be_reaped_is_recorded_as_not_exited_and_not_terminal(
    namespace, monkeypatch
):
    def failing(*args):
        raise RuntimeError("synthetic readiness failure")

    child, _ = _mocked_start(namespace, monkeypatch, ready=failing)
    child.wait.side_effect = subprocess.TimeoutExpired("preview", 6)
    with pytest.raises(RuntimeError, match="retained private log"):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    _, rows = preview.current_attempt(namespace)
    assert rows[-1]["state"] == "startup-failed"
    assert rows[-1]["child_exited"] is False and rows[-1]["child_pid"] == child.pid


def test_startup_failed_without_exit_proof_still_probes_the_recorded_child(
    namespace, listener, sleeper
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(
        namespace,
        argv,
        inode,
        ["spawned", "startup-failed"],
        identity,
        **{"startup-failed": {"child_exited": False, "child_pid": child.pid}},
    )
    result = preview.status(namespace)
    assert result["managed"] is True and result["pid"] == child.pid
    assert result["state"] == "uncertain"  # not collapsed to a terminal stopped/unmanaged


def test_main_installs_both_sigterm_and_sighup_handlers(namespace, monkeypatch, capsys):
    installed = {}
    monkeypatch.setattr(preview.signal, "signal", lambda n, handler: installed.update({n: handler}))
    monkeypatch.setattr(sys, "argv", ["preview.py", "status", "--directory", str(namespace)])
    monkeypatch.setattr(preview, "directory", lambda value: namespace)
    monkeypatch.setattr(preview, "listeners", lambda: set())
    assert preview.main() == 0
    assert installed == {
        signal.SIGTERM: preview._exit_on_signal,
        signal.SIGHUP: preview._exit_on_signal,
    }
    with pytest.raises(SystemExit) as raised:
        preview._exit_on_signal(signal.SIGHUP, None)
    assert raised.value.code == 128 + signal.SIGHUP


# ---------------------------------------------------------------- M1 non-UTF-8 argv


def test_non_utf8_argv_of_any_process_does_not_break_the_orphan_scan(namespace, listener, sleeper):
    junk = subprocess.Popen(  # noqa: S603 -- throwaway child with deliberately invalid argv.
        [os.fsencode(sys.executable), b"-c", b"import time; time.sleep(60)", b"\xff\xfe"],
        stdin=subprocess.DEVNULL,
    )
    try:
        identity = settled_identity(junk.pid)
        assert identity is not None and identity["argv"][-1] == "\udcff\udcfe"
        child, argv, _, inode = live(namespace, listener, sleeper)
        attempt(namespace, argv, inode, [])  # prepared-only, the scan reads every /proc cmdline
        result = preview.status(namespace)
        assert result["state"] == "orphaned" and result["pid"] == child.pid
    finally:
        junk.kill()
        junk.wait()


def test_non_utf8_argv_does_not_break_a_prepared_only_receipt_with_no_listener(
    namespace, monkeypatch
):
    junk = subprocess.Popen(  # noqa: S603 -- throwaway child with deliberately invalid argv.
        [os.fsencode(sys.executable), b"-c", b"import time; time.sleep(60)", b"\xff\xfe"],
        stdin=subprocess.DEVNULL,
    )
    try:
        attempt(namespace, serve_argv(namespace, 7), "999999", [])
        monkeypatch.setattr(preview, "listeners", lambda: set())
        assert preview.status(namespace)["state"] == "stopped"
    finally:
        junk.kill()
        junk.wait()


# ---------------------------------------------------------------- orphan scan survivors


def test_two_matching_children_are_never_adopted_or_signalled(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    other = sleeper(argv, pass_fds=(listener.fileno(),))
    attempt(namespace, argv, inode, [])
    sender = Mock()
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", sender)
    result = preview.status(namespace)
    assert result["state"] == "uncertain" and result["managed"] is False
    with pytest.raises(ValueError, match="refusing to stop"):
        preview.stop(namespace)
    sender.assert_not_called()
    assert child.poll() is None and other.poll() is None


def test_orphan_requires_the_same_uid(namespace, listener, sleeper, monkeypatch):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, [])
    real = preview.process_identity
    monkeypatch.setattr(
        preview,
        "process_identity",
        lambda pid: (
            {**found, "uid": found["uid"] + 1} if (found := real(pid)) is not None else None
        ),
    )
    assert preview.status(namespace)["state"] == "uncertain"


def test_orphan_requires_the_exact_child_to_hold_the_listener(namespace, listener, sleeper):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, [])  # right argv and UID, but the test owns the socket
    assert preview.status(namespace)["state"] == "uncertain"


def test_orphan_requires_exactly_our_listener_inode_set(namespace, listener, sleeper, monkeypatch):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, [])
    monkeypatch.setattr(preview, "listeners", lambda: {inode, "424242"})
    assert preview.status(namespace)["state"] == "uncertain"


# ---------------------------------------------------------------- L1 / L2


def test_live_child_that_closed_its_listener_is_not_reported_stopped(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, [])
    monkeypatch.setattr(preview, "listeners", lambda: set())  # graceful shutdown closed it
    sender = Mock()
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", sender)
    result = preview.status(namespace)
    assert result["state"] == "uncertain" and result["managed"] is False
    monkeypatch.setattr(preview, "_package", lambda path: path)
    spawn = Mock()
    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    with pytest.raises(ValueError, match="unmanaged listener or uncertain"):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))  # no overlapping start
    spawn.assert_not_called()
    with pytest.raises(ValueError, match="refusing to stop"):
        preview.stop(namespace)
    sender.assert_not_called()
    child.kill()
    child.wait()
    assert preview.status(namespace)["state"] == "stopped"


def test_status_reports_starting_while_start_holds_the_lock(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, [])
    with preview.manager_lock():
        result = preview.status(namespace)
    assert result["state"] == "starting" and result["managed"] is False
    assert "pid" not in result
    assert preview.status(namespace)["state"] == "orphaned"  # lock free: a real crash orphan
    assert result["token_file"] == preview.status(namespace)["token_file"]


# ---------------------------------------------------------------- M3 interpreter trust


def _accepts(path):
    return preview._interpreter(path)


def test_venv_keeps_its_launch_path_and_plain_binary_resolves(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    assert _accepts(root / "bin" / "python") == root / "bin" / "python"
    link = tmp_path / "link"
    link.mkdir()
    link.chmod(0o700)
    (link / "python").symlink_to(binary)
    assert _accepts(link / "python") == binary  # non-venv: exec the RESOLVED path


@pytest.mark.parametrize("lib", ["lib", "lib64"])
@pytest.mark.parametrize("damage", ["writable", "symlink", "dir-writable", "foreign-bin-dir"])
def test_stdlib_below_the_binary_prefix_is_walked(sandbox_owners, tmp_path, lib, damage):
    root, binary, _ = _venv(tmp_path)
    prefix = binary.parent.parent
    if lib == "lib64":  # a clean lib stays: only lib64 is dirty, so only walking it can object
        (prefix / "lib64" / "python3.12").mkdir(parents=True)
        (prefix / "lib64" / "python3.12" / "os.py").write_text("")
        (prefix / "lib64" / "python3.12" / "os.py").chmod(0o644)
        for path in (prefix / "lib64", prefix / "lib64" / "python3.12"):
            path.chmod(0o700)
    stdlib = prefix / lib / "python3.12"
    if damage == "writable":
        (stdlib / "os.py").chmod(0o666)
    elif damage == "symlink":
        (stdlib / "evil.py").symlink_to(stdlib / "os.py")
    elif damage == "dir-writable":
        stdlib.chmod(0o777)
    else:
        (prefix / lib).chmod(0o777)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_interpreter_without_any_stdlib_is_refused(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    (binary.parent.parent / "lib" / "python3.12" / "os.py").unlink()
    (binary.parent.parent / "lib" / "python3.12").rmdir()
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_venv_base_site_packages_is_only_walked_when_it_is_on_sys_path(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    base_site = binary.parent.parent / "lib" / "python3.12" / "site-packages"
    base_site.mkdir()
    base_site.chmod(0o700)
    (base_site / "x.py").write_text("")
    (base_site / "x.py").chmod(0o666)
    (root / "pyvenv.cfg").write_text(
        f"home = {binary.parent}\ninclude-system-site-packages = false\n"
    )
    assert _accepts(root / "bin" / "python")  # explicitly isolated: base packages not imported
    (root / "pyvenv.cfg").write_text(
        f"home = {binary.parent}\ninclude-system-site-packages = true\n"
    )
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


@pytest.mark.parametrize("cfg", ["missing", "mismatch", "relative", "untrusted-prefix"])
def test_venv_home_must_name_exactly_the_resolved_binary_directory(sandbox_owners, tmp_path, cfg):
    root, binary, _ = _venv(tmp_path)
    evil = tmp_path / "evil"
    (evil / "bin").mkdir(parents=True)
    (evil / "lib" / "python3.12").mkdir(parents=True)
    evil.chmod(0o777)
    text = {
        "missing": "include-system-site-packages = false\n",
        "mismatch": f"home = {evil / 'bin'}\n",
        "relative": "home = bin\n",
        "untrusted-prefix": f"home = {evil / 'bin'}\n",
    }[cfg]
    (root / "pyvenv.cfg").write_text(text)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_intermediate_symlink_hop_in_a_writable_directory_is_refused(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    hops = tmp_path / "hops"
    hops.mkdir()
    (hops / "hop").symlink_to(binary)
    (root / "bin" / "python").unlink()
    (root / "bin" / "python").symlink_to(hops / "hop")
    hops.chmod(0o700)
    assert _accepts(root / "bin" / "python") == root / "bin" / "python"
    hops.chmod(0o777)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_symlinked_directory_hop_inside_a_target_is_checked(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    swap = tmp_path / "swap"
    swap.mkdir()
    swap.chmod(0o777)
    (swap / "dirlink").symlink_to(binary.parent, target_is_directory=True)
    (root / "bin" / "python").unlink()
    (root / "bin" / "python").symlink_to(swap / "dirlink" / binary.name)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_non_venv_launch_through_a_symlinked_directory_is_refused(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(binary.parent, target_is_directory=True)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(alias / binary.name)


def test_symlink_loop_is_refused(sandbox_owners, tmp_path):
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(loop)


def test_unreadable_subdirectory_is_refused_not_skipped(sandbox_owners, tmp_path):
    root, binary, site = _venv(tmp_path)
    hidden = site / "hidden"
    hidden.mkdir()
    hidden.chmod(0)
    try:
        with pytest.raises(ValueError, match=UNTRUSTED):
            _accepts(root / "bin" / "python")
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "locked").mkdir()
        (package / "locked").chmod(0)
        with pytest.raises(ValueError, match="unsafe or incomplete|package"):
            preview._trusted_tree(package, "unsafe or incomplete installed package")
    finally:
        hidden.chmod(0o700)
        (tmp_path / "pkg" / "locked").chmod(0o700)


def test_production_system_uids_trust_only_root():
    spec = importlib.util.spec_from_file_location("gui_preview_pristine", preview.__file__)
    assert spec is not None and spec.loader is not None
    pristine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pristine)
    assert pristine.SYSTEM_UIDS == (0,)


def test_child_command_is_isolated_and_package_dir_is_explicit(tmp_path):
    argv = preview.child_argv(Path("/venv/bin/python"), Path("/r"), Path("/pkg"), 9)
    assert argv[:3] == ["/venv/bin/python", "-I", "-B"]
    assert argv[argv.index("--package-dir") + 1] == "/pkg" and argv[-2:] == ["--listen-fd", "9"]


def test_interpreter_check_runs_unbypassed_for_a_clean_layout_and_refuses_a_dirty_one(
    sandbox_owners, tmp_path, namespace, monkeypatch
):
    root, binary, site = _venv(tmp_path)
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview, "listeners", lambda: set())
    monkeypatch.setattr(preview, "_package", lambda path: path)
    spawn = Mock(side_effect=OSError("synthetic"))
    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    site.chmod(0o777)
    with pytest.raises(ValueError, match=UNTRUSTED):
        preview.start(namespace, Path("/pkg"), root / "bin" / "python")
    spawn.assert_not_called()
    assert not list(namespace.glob("managed-*"))
    site.chmod(0o700)
    with pytest.raises(RuntimeError, match="retained private log"):
        preview.start(namespace, Path("/pkg"), root / "bin" / "python")
    assert spawn.call_args.args[0][0] == str(root / "bin" / "python")
