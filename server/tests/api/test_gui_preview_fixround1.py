"""Fix-round 1 regressions: crash-safe start/stop, trusted interpreter, real /proc identity.

These tests use throwaway child processes and ephemeral loopback ports only; PORT/LOCK are
monkeypatched and nothing here ever binds or signals the fixed preview port or process.
"""

from __future__ import annotations

import errno
import importlib.util
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

PREVIEW_PATH = Path(__file__).resolve().parents[3] / "tools/gui/preview.py"
SPEC = importlib.util.spec_from_file_location("gui_preview_fixround1", PREVIEW_PATH)
assert SPEC is not None and SPEC.loader is not None
preview = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preview)
IDENTITY_STATES = {"spawned", "ready", "stop-requested", "stopped"}


@pytest.fixture(autouse=True)
def pidfd_support_for_offline_fixtures(monkeypatch):
    if not hasattr(preview.os, "pidfd_open"):
        monkeypatch.setattr(preview.os, "pidfd_open", Mock(), raising=False)
    if not hasattr(preview.signal, "pidfd_send_signal"):
        monkeypatch.setattr(preview.signal, "pidfd_send_signal", Mock(), raising=False)


@pytest.fixture
def sandbox_owners(monkeypatch):
    # In user-namespace sandboxes /tmp is owned by the unmapped overflow UID, not root.
    monkeypatch.setattr(preview, "SYSTEM_UIDS", (0, Path("/tmp").lstat().st_uid))  # noqa: S108


@pytest.fixture
def namespace(tmp_path, monkeypatch):
    root = tmp_path / "synthetic"
    preview.seed(root)
    monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
    return root


@pytest.fixture
def listener(monkeypatch):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        assert sock.getsockname()[1] != 18745
        monkeypatch.setattr(preview, "PORT", sock.getsockname()[1])
        yield sock


@pytest.fixture
def sleeper(tmp_path, monkeypatch):
    # The child command embeds the manager script path; point it at a script that only sleeps,
    # so a throwaway child carries the exact production argv without serving anything.
    script = tmp_path / "sleeper-preview.py"
    script.write_text("import time\ntime.sleep(120)\n")
    monkeypatch.setattr(preview, "__file__", str(script))
    children = []

    def spawn(argv, pass_fds=()):
        child = subprocess.Popen(  # noqa: S603 -- throwaway test child, argv is ours.
            argv,
            env={"PATH": "/usr/bin:/bin"},
            pass_fds=pass_fds,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        children.append(child)
        return child

    yield spawn
    for child in children:
        if child.poll() is None:
            child.kill()
        child.wait()


def serve_argv(root, fd):
    return preview.child_argv(Path(sys.executable), root, Path("/installed/package"), fd)


def attempt(root, argv, inode, states, identity=None, **extra):
    journal = root / "managed-123-abcd1234.jsonl"
    rows = [
        {
            "state": "prepared",
            "directory": str(root),
            "argv": argv,
            "package_dir": "/installed/package",
            "listener_inode": inode,
            "log": journal.stem + ".log",
            "runtime_limit_seconds": 28800,
            "wall": 1.0,
        }
    ]
    for state in states:
        row = {"state": state, **extra.get(state, {})}
        if state in IDENTITY_STATES:
            row["identity"] = identity
        rows.append(row)
    preview.write_new(journal, b"".join((json.dumps(row) + "\n").encode() for row in rows))
    preview.write_new(root / preview.CURRENT, json.dumps({"journal": journal.name}).encode())
    return journal


def live(root, listener, sleeper, *, hold=True):
    """A real throwaway child with the exact fixed argv; optionally owning the listener."""
    fd = listener.fileno()
    argv = serve_argv(root, fd)
    child = sleeper(argv, pass_fds=(fd,) if hold else ())
    identity = preview.process_identity(child.pid)
    assert identity is not None and identity["argv"] == argv
    return child, argv, identity, str(os.fstat(fd).st_ino)


def real_stop_signals(monkeypatch, child):
    """Stand-in for pidfd_send_signal that signals only the retained throwaway child."""
    fd = os.open(os.devnull, os.O_RDONLY)
    sent = []
    monkeypatch.setattr(preview.os, "pidfd_open", lambda _pid: os.dup(fd))
    monkeypatch.setattr(
        preview.signal,
        "pidfd_send_signal",
        lambda _fd, sig: (sent.append(sig), os.kill(child.pid, sig)),
    )
    monkeypatch.setattr(preview.select, "select", lambda *_args: ([fd], [], []))
    return sent


# ---------------------------------------------------------------- M1 (a): ordering


def test_spawned_receipt_accepts_stop_requested_then_stopped(namespace, listener, sleeper):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, ["spawned", "stop-requested", "stopped"], identity)
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared", "spawned", "stop-requested", "stopped"]


def test_stop_after_interrupted_start_terms_exact_child_and_records_stop(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    journal = attempt(namespace, argv, inode, ["spawned"], identity)  # KeyboardInterrupt here
    sent = real_stop_signals(monkeypatch, child)
    assert preview.status(namespace)["managed"] is True
    preview.stop(namespace)
    child.wait(timeout=10)
    assert sent == [signal.SIGTERM] and child.returncode == -signal.SIGTERM
    states = [json.loads(line)["state"] for line in journal.read_text().splitlines()]
    assert states == ["prepared", "spawned", "stop-requested", "stopped"]


# ---------------------------------------------------------------- M1 (b): terminal receipts


@pytest.mark.parametrize(
    "states,extra",
    [
        (["spawned", "ready", "stop-requested", "stopped"], {}),
        (["spawned", "startup-failed"], {"startup-failed": {"child_exited": True}}),
        (["failed-before-spawn"], {"failed-before-spawn": {"child_exited": True}}),
    ],
)
def test_terminal_receipt_never_probes_a_reused_pid(
    namespace, listener, sleeper, monkeypatch, states, extra
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    reused = {**identity, "start_ticks": str(int(identity["start_ticks"]) + 1)}
    attempt(namespace, argv, inode, states, reused, **extra)
    monkeypatch.setattr(preview, "listeners", lambda: set())
    probe = Mock(side_effect=AssertionError("terminal receipt must not probe a PID"))
    monkeypatch.setattr(preview, "process_identity", probe)
    result = preview.status(namespace)
    assert result["state"] == "stopped" and result["managed"] is False
    probe.assert_not_called()
    monkeypatch.setattr(preview, "listeners", lambda: {"foreign"})
    assert preview.status(namespace)["state"] == "unmanaged-listener"


def test_start_proceeds_after_cleanly_stopped_receipt_with_reused_pid(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    reused = {**identity, "start_ticks": "1"}
    attempt(namespace, argv, inode, ["spawned", "ready", "stop-requested", "stopped"], reused)
    monkeypatch.setattr(preview, "listeners", lambda: set())
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "_interpreter", lambda path: path)
    monkeypatch.setattr(preview, "PORT", 0)
    spawn = Mock(side_effect=OSError("synthetic spawn failure"))
    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    with pytest.raises(RuntimeError, match="retained private log"):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    spawn.assert_called_once()  # not refused as identity-changed


# ---------------------------------------------------------------- M1 (a)/(c): interrupted start


def _mocked_start(namespace, monkeypatch, *, ready):
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "_interpreter", lambda path: path)
    monkeypatch.setattr(preview, "listeners", lambda: set())
    captured = {}
    child = Mock(pid=123456)

    def spawn(argv, **kwargs):
        captured["argv"] = argv
        return child

    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    monkeypatch.setattr(
        preview,
        "process_identity",
        lambda pid: {
            "pid": pid,
            "uid": os.getuid(),
            "start_ticks": "100",
            "argv": captured["argv"],
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        },
    )
    monkeypatch.setattr(preview.os, "pidfd_open", lambda _pid: os.open(os.devnull, os.O_RDONLY))
    sender = Mock()
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", sender)
    monkeypatch.setattr(preview, "_ready", ready)
    return child, sender


def test_keyboard_interrupt_during_readiness_terms_child_records_and_reraises(
    namespace, monkeypatch
):
    def interrupted(*args):
        raise KeyboardInterrupt

    child, sender = _mocked_start(namespace, monkeypatch, ready=interrupted)
    with pytest.raises(KeyboardInterrupt):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    sender.assert_called_once()
    assert sender.call_args.args[1] == signal.SIGTERM
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared", "spawned", "startup-failed"]
    assert rows[-1]["child_exited"] is True and rows[-1]["error_type"] == "KeyboardInterrupt"
    monkeypatch.setattr(preview, "process_identity", lambda _pid: pytest.fail("probed"))
    assert preview.status(namespace)["state"] == "stopped"


def test_interrupt_between_spawn_and_receipt_never_leaves_unregistered_child(
    namespace, monkeypatch
):
    child, _ = _mocked_start(namespace, monkeypatch, ready=lambda *_args: None)
    monkeypatch.setattr(preview.os, "pidfd_open", Mock(side_effect=OSError("no pidfd")))
    waitid = Mock(return_value=None)
    monkeypatch.setattr(preview.os, "waitid", waitid)
    real_event = preview.event

    def event(journal, value):
        if value["state"] == "spawned":
            raise KeyboardInterrupt
        real_event(journal, value)

    monkeypatch.setattr(preview, "event", event)
    with pytest.raises(KeyboardInterrupt):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    child.terminate.assert_called_once_with()
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared", "startup-failed"]
    assert rows[-1]["child_exited"] is True and rows[-1]["child_pid"] == child.pid


def test_log_is_opened_before_any_receipt_or_pointer(namespace, monkeypatch):
    _mocked_start(namespace, monkeypatch, ready=lambda *_args: None)
    real_open = os.open

    def fail_log(path, *args, **kwargs):
        if str(path).endswith(".log"):
            raise OSError(errno.EACCES, "synthetic log failure")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(preview.os, "open", fail_log)
    with pytest.raises(OSError, match="synthetic log failure"):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    assert not list(namespace.glob("managed-*")) and not (namespace / preview.CURRENT).exists()
    assert preview.status(namespace)["state"] == "stopped"


def test_prepared_only_receipt_with_child_holding_listener_is_discoverable_and_stoppable(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    journal = attempt(namespace, argv, inode, [])  # crash between Popen and `spawned`
    result = preview.status(namespace)
    assert result["managed"] is True and result["pid"] == child.pid
    assert result["state"] == "orphaned"
    sent = real_stop_signals(monkeypatch, child)
    preview.stop(namespace)
    child.wait(timeout=10)
    assert sent == [signal.SIGTERM]
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    assert [row["state"] for row in rows] == ["prepared", "spawned", "stop-requested", "stopped"]
    assert rows[1]["identity"]["pid"] == child.pid
    preview.current_attempt(namespace)


def test_prepared_only_receipt_never_adopts_a_look_alike_process(
    namespace, listener, sleeper, monkeypatch
):
    fd = listener.fileno()
    argv = serve_argv(namespace, fd)
    other = argv[:1] + ["-c", "import time; time.sleep(60)"]  # different argv, same listener
    child = sleeper(other, pass_fds=(fd,))
    attempt(namespace, argv, str(os.fstat(fd).st_ino), [])
    sender = Mock()
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", sender)
    assert preview.status(namespace) == {**preview.status(namespace), "managed": False}
    assert preview.status(namespace)["state"] == "uncertain"
    with pytest.raises(ValueError, match="refusing to stop"):
        preview.stop(namespace)
    sender.assert_not_called()
    assert child.poll() is None


def test_prepared_only_receipt_with_no_listener_is_not_a_permanent_wedge(namespace, monkeypatch):
    attempt(namespace, serve_argv(namespace, 7), "999999", [])
    monkeypatch.setattr(preview, "listeners", lambda: set())
    assert preview.status(namespace)["state"] == "stopped"


# ---------------------------------------------------------------- M2: trusted interpreter/package


def _venv(tmp_path, *, name="venv"):
    """prefix/{bin/python3.12, lib/python3.12/os.py} plus a venv whose home is prefix/bin."""
    prefix = tmp_path / "real"
    (prefix / "bin").mkdir(parents=True, exist_ok=True)
    binary = prefix / "bin" / "python3.12"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    stdlib = prefix / "lib" / "python3.12"
    stdlib.mkdir(parents=True, exist_ok=True)
    (stdlib / "os.py").write_text("")
    root = tmp_path / name
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "python").symlink_to(binary)
    (root / "pyvenv.cfg").write_text(f"home = {prefix / 'bin'}\n")
    site = root / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site / "uvicorn.py").write_text("")
    for path in (tmp_path, prefix, prefix / "bin", prefix / "lib", stdlib, root):
        path.chmod(0o700)
    for path in (root / "bin", root / "lib", site.parent, site):
        path.chmod(0o700)
    (stdlib / "os.py").chmod(0o644)
    return root, binary, site


def test_clean_venv_with_symlinked_binary_is_accepted(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    assert preview._interpreter(root / "bin" / "python") == root / "bin" / "python"


@pytest.mark.parametrize("where", ["site", "root", "bin", "target-dir", "payload", "cfg", "link"])
def test_venv_python_with_writable_or_swappable_parts_is_refused(sandbox_owners, tmp_path, where):
    root, binary, site = _venv(tmp_path)
    if where == "site":
        site.chmod(0o777)
    elif where == "root":
        root.chmod(0o777)
    elif where == "bin":
        (root / "bin").chmod(0o777)
    elif where == "target-dir":
        binary.parent.chmod(0o777)
    elif where == "payload":
        (site / "uvicorn.py").chmod(0o666)
    elif where == "cfg":
        (root / "pyvenv.cfg").chmod(0o666)
    else:
        (site / "alias.py").symlink_to(site / "uvicorn.py")
    with pytest.raises(ValueError, match="untrusted"):
        preview._interpreter(root / "bin" / "python")


def test_interpreter_launch_path_with_symlink_directory_is_refused(sandbox_owners, tmp_path):
    root, _, _ = _venv(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="untrusted"):
        preview._interpreter(alias / "bin" / "python")


def test_missing_or_non_executable_interpreter_is_refused(sandbox_owners, tmp_path):
    with pytest.raises(ValueError, match="untrusted"):
        preview._interpreter(tmp_path / "absent")
    plain = tmp_path / "plain"
    plain.write_text("")
    plain.chmod(0o600)
    with pytest.raises(ValueError, match="untrusted"):
        preview._interpreter(plain)


def _package_tree(tmp_path):
    root = tmp_path / "pkg"
    names = [
        "vigie_api/app.py",
        "vigie_api/ui_static.py",
        "vigie_api/extra_module.py",
        "vigie_ingest/db.py",
        "vigie_pipeline/schema.py",
        *(
            "vigie_api/ui/" + n
            for n in ("index.html", "styles.css", "app.js", "client.js", "views.js")
        ),
    ]
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
        path.chmod(0o644)
    for directory in [root, *(p for p in root.rglob("*") if p.is_dir())]:
        directory.chmod(0o755)
    return root


def test_package_accepts_clean_tree_and_checks_every_entry(sandbox_owners, tmp_path):
    root = _package_tree(tmp_path)
    assert preview._package(root) == root
    for victim in ("vigie_api/extra_module.py", "vigie_ingest", "vigie_api/ui/views.js"):
        path = root / victim
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IWGRP)
        with pytest.raises(ValueError, match="unsafe"):
            preview._package(root)
        path.chmod(mode)


def test_package_refuses_extra_symlink_and_unlisted_writable_file(sandbox_owners, tmp_path):
    root = _package_tree(tmp_path)
    (root / "vigie_api" / "sneaky.py").symlink_to(root / "vigie_api" / "app.py")
    with pytest.raises(ValueError, match="unsafe"):
        preview._package(root)


# ---------------------------------------------------------------- L1


def test_health_with_non_object_json_is_unhealthy_not_an_exception(monkeypatch):
    for body in (b"[]", b"3", b'"ok"', b"null"):
        response = Mock(status=200)
        response.read.return_value = body
        response.__enter__ = lambda self: self
        response.__exit__ = lambda *_args: None
        opener = Mock()
        opener.open.return_value = response
        monkeypatch.setattr(preview.urllib.request, "build_opener", lambda *_a, _o=opener: _o)
        assert preview._health() is False


# ---------------------------------------------------------------- M4: surviving mutants


def test_process_identity_reads_real_proc_start_ticks_uid_argv_and_boot(sleeper, tmp_path):
    before = time.time()
    child = sleeper([sys.executable, "-c", "import time; time.sleep(60)"])
    identity = preview.process_identity(child.pid)
    after = time.time()
    raw = Path(f"/proc/{child.pid}/stat").read_text()
    parsed = re.match(r"^\d+ \(.*\) (.*)$", raw, re.S)
    assert parsed is not None
    fields = parsed.group(1).split()
    # Field 22 of proc(5) is starttime; an independent clock check rejects neighbouring fields.
    boot = next(
        int(line.split()[1])
        for line in Path("/proc/stat").read_text().splitlines()
        if line.startswith("btime")
    )
    started = boot + int(identity["start_ticks"]) / os.sysconf("SC_CLK_TCK")
    assert before - 3 <= started <= after + 3
    assert identity["start_ticks"] == fields[19]
    assert identity["uid"] == os.getuid() and identity["pid"] == child.pid
    assert identity["argv"][-2:] == ["-c", "import time; time.sleep(60)"]
    assert identity["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    child.kill()
    child.wait()
    assert preview.process_identity(child.pid) is None


@pytest.mark.parametrize("field", ["start_ticks", "argv", "boot_id"])
def test_status_reports_identity_drift_for_a_live_pid(namespace, listener, sleeper, field):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    drift = {
        "start_ticks": str(int(identity["start_ticks"]) + 1),
        "boot_id": "00000000-0000-0000-0000-000000000000",
        "argv": [*argv[:-1], "99"],
    }
    saved = {**identity, field: drift[field]}
    attempt(namespace, saved["argv"], inode, ["spawned", "ready"], saved)
    result = preview.status(namespace)
    assert result["state"] == "identity-changed" and result["managed"] is False


def test_status_is_running_only_when_child_owns_the_listener(namespace, listener, sleeper):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=True)
    attempt(namespace, argv, inode, ["spawned", "ready"], identity)
    assert preview.status(namespace)["state"] == "running"


def test_status_not_running_when_listener_belongs_to_someone_else(namespace, listener, sleeper):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, ["spawned", "ready"], identity)
    result = preview.status(namespace)  # the test process, not the child, owns the listener
    assert result["state"] == "uncertain" and result["managed"] is True


def test_start_never_adopts_or_replaces_an_identity_changed_process(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(
        namespace,
        argv,
        inode,
        ["spawned", "ready"],
        {**identity, "start_ticks": str(int(identity["start_ticks"]) + 1)},
    )
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "_interpreter", lambda path: path)
    spawn = Mock()
    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    with pytest.raises(ValueError, match="unmanaged listener or uncertain"):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    spawn.assert_not_called()
    assert child.poll() is None


def test_stop_refuses_unmanaged_listener_without_receipt_or_signal(namespace, monkeypatch):
    sender = Mock()
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", sender)
    monkeypatch.setattr(preview, "listeners", lambda: {"foreign"})
    with pytest.raises(ValueError, match="refusing to stop"):
        preview.stop(namespace)
    sender.assert_not_called()


def test_stop_refuses_identity_changed_live_process_without_signalling(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(
        namespace,
        argv,
        inode,
        ["spawned", "ready"],
        {**identity, "start_ticks": str(int(identity["start_ticks"]) + 1)},
    )
    sender = Mock()
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", sender)
    with pytest.raises(ValueError, match="refusing to stop"):
        preview.stop(namespace)
    sender.assert_not_called()
    assert child.poll() is None


@pytest.mark.parametrize("damage", ["uid", "uid-negative"])
def test_receipt_with_foreign_uid_is_rejected(namespace, damage):
    argv = serve_argv(namespace, 7)
    identity = {
        "pid": 4242,
        "uid": os.getuid() + (1 if damage == "uid" else -os.getuid() - 1),
        "start_ticks": "100",
        "argv": argv,
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
    }
    attempt(namespace, argv, "123", ["spawned"], identity)
    with pytest.raises(ValueError, match="invalid child identity receipt"):
        preview.current_attempt(namespace)


def test_lock_refuses_a_symlinked_lock_path_with_eloop(tmp_path, monkeypatch):
    target = tmp_path / "target.lock"
    target.write_text("")
    target.chmod(0o600)
    lock = tmp_path / "shared.lock"
    lock.symlink_to(target)
    monkeypatch.setattr(preview, "LOCK", lock)
    with pytest.raises(OSError) as raised, preview.manager_lock():
        pass
    assert raised.value.errno == errno.ELOOP


def test_lock_refuses_a_lock_swapped_between_open_and_check(tmp_path, monkeypatch):
    lock = tmp_path / "shared.lock"
    monkeypatch.setattr(preview, "LOCK", lock)
    real_open = os.open

    def swap(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if Path(path) == lock:
            lock.rename(
                lock.with_name("moved.lock")
            )  # keeps nlink==1, so only the inode check can object
            real_open(lock, os.O_CREAT | os.O_RDWR, 0o600)  # same type/mode, new inode
        return fd

    monkeypatch.setattr(preview.os, "open", swap)
    with pytest.raises(ValueError, match="unsafe preview lock"), preview.manager_lock():
        pass


def test_serve_starts_the_daemon_eight_hour_timer_and_it_stops_the_server(namespace, monkeypatch):
    import uvicorn

    timers = []

    class Timer:
        def __init__(self, interval, function):
            self.interval, self.function, self.daemon = interval, function, False
            self.started = self.cancelled = False
            timers.append(self)

        def start(self):
            self.started = True

        def cancel(self):
            self.cancelled = True

    class Server:
        should_exit = False

        def __init__(self, config):
            pass

        def run(self, sockets=None):
            assert timers[0].started, "timer must be running before the server blocks"
            timers[0].function()
            assert self.should_exit is True

    monkeypatch.setattr(uvicorn, "Server", Server)
    monkeypatch.setattr(preview.threading, "Timer", Timer)
    preview.serve(namespace)
    (timer,) = timers
    assert timer.interval == 8 * 3600 and timer.daemon is True and timer.cancelled is True
