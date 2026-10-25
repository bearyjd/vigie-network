from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "gui_preview_manager", Path(__file__).resolve().parents[3] / "tools/gui/preview.py"
)
assert SPEC is not None and SPEC.loader is not None
preview = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preview)
REAL_INTERPRETER = preview._interpreter
BOOT = "01234567-89ab-cdef-0123-456789abcdef"


@pytest.fixture(autouse=True)
def pidfd_support_for_offline_fixtures(monkeypatch):
    # The cached uv Python3.12 build omits optional pidfd APIs; the controller
    # runs under native /usr/bin/python3. Unit fixtures always replace signals.
    # Interpreter trust is covered by test_gui_preview_fixround1; these fixtures use sys.executable.
    monkeypatch.setattr(preview, "_interpreter", lambda path: path.absolute())
    if not hasattr(preview.os, "pidfd_open"):
        monkeypatch.setattr(preview.os, "pidfd_open", Mock(), raising=False)
    if not hasattr(preview.signal, "pidfd_send_signal"):
        monkeypatch.setattr(preview.signal, "pidfd_send_signal", Mock(), raising=False)


@pytest.fixture
def namespace(tmp_path):
    root = tmp_path / "synthetic"
    preview.seed(root)
    return root


def receipt(root, state="ready", pid=123456):
    argv = preview.child_argv(Path(sys.executable), root, Path("/installed/package"), 42)
    identity = {"pid": pid, "uid": os.getuid(), "start_ticks": "100", "argv": argv, "boot_id": BOOT}
    journal = root / "managed-123-abcd1234.jsonl"
    rows = [
        {
            "state": "prepared",
            "directory": str(root),
            "argv": argv,
            "listener_inode": "123",
            "log": journal.stem + ".log",
            "package_dir": "/installed/package",
            "runtime_limit_seconds": 28800,
            "wall": 1.0,
        },
        {"state": "spawned", "identity": identity},
    ]
    if state != "spawned":
        rows.append({"state": state, "identity": identity})
    preview.write_new(journal, b"".join((json.dumps(row) + "\n").encode() for row in rows))
    preview.write_new(root / preview.CURRENT, json.dumps({"journal": journal.name}).encode())
    return journal, identity


def test_status_is_readonly_and_never_adopts_existing_unmanaged_listener(namespace, monkeypatch):
    token = (namespace / "read-token.private").read_text().strip()
    before = {path.name: path.read_bytes() for path in namespace.iterdir()}
    monkeypatch.setattr(preview, "listeners", lambda: {"foreign"})
    result = preview.status(namespace)
    assert result["state"] == "unmanaged-listener" and result["managed"] is False
    assert token not in json.dumps(result)
    assert before == {path.name: path.read_bytes() for path in namespace.iterdir()}


def test_malformed_manifest_refuses_cleanly_without_process_or_receipt(namespace, monkeypatch):
    (namespace / "manifest.json").write_text("[]")
    spawn = Mock()
    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    with pytest.raises(ValueError, match="synthetic seed manifest"):
        preview.start(namespace, Path("/unused"), Path(sys.executable))
    spawn.assert_not_called()
    assert not list(namespace.glob("managed-*"))


def test_plain_native_cli_status_needs_no_application_imports_or_pythonpath():
    root = Path("/tmp") / ("vigie-gui-preview-test-" + uuid.uuid4().hex)  # noqa: S108
    preview.seed(root)
    try:
        result = subprocess.run(  # noqa: S603 -- our interpreter and reviewed local script only.
            [sys.executable, "-I", "-S", str(preview.__file__), "status", "--directory", str(root)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(result.stdout)["state"] in {"stopped", "unmanaged-listener"}
        assert (
            root / "read-token.private"
        ).read_text().strip() not in result.stdout + result.stderr
        assert not (root / preview.CURRENT).exists()
    finally:
        shutil.rmtree(root)


def test_foreign_port_refused_without_spawn_or_attempt_files(namespace, monkeypatch, tmp_path):
    with socket.socket() as foreign:
        foreign.bind(("127.0.0.1", 0))
        foreign.listen(1)
        monkeypatch.setattr(preview, "PORT", foreign.getsockname()[1])
        monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
        monkeypatch.setattr(preview, "_package", lambda path: path)
        spawn = Mock()
        monkeypatch.setattr(preview.subprocess, "Popen", spawn)
        with pytest.raises(ValueError, match="unmanaged"):
            preview.start(namespace, Path("/unused"), Path(sys.executable))
        spawn.assert_not_called()
    assert not list(namespace.glob("managed-*"))


def test_missing_native_pidfd_support_refuses_before_spawn_or_receipt(namespace, monkeypatch):
    monkeypatch.delattr(preview.os, "pidfd_open")
    spawn = Mock()
    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    with pytest.raises(ValueError, match="native"):
        preview.start(namespace, Path("/unused"), Path(sys.executable))
    spawn.assert_not_called()
    assert not list(namespace.glob("managed-*"))


def test_shared_port_lock_excludes_other_namespaces_and_remains_same_inode(tmp_path, monkeypatch):
    lock = tmp_path / "shared.lock"
    monkeypatch.setattr(preview, "LOCK", lock)
    with preview.manager_lock():
        inode = lock.stat().st_ino
        with pytest.raises(BlockingIOError), preview.manager_lock():
            pass
    with preview.manager_lock():
        assert lock.stat().st_ino == inode
    assert lock.stat().st_mode & 0o777 == 0o600


def test_symlink_or_incomplete_receipt_refused(namespace, monkeypatch):
    journal, _ = receipt(namespace)
    journal.write_bytes(journal.read_bytes()[:-1])
    with pytest.raises(ValueError, match="incomplete"):
        preview.current_attempt(namespace)
    pointer = namespace / preview.CURRENT
    pointer.rename(namespace / "original-pointer")
    pointer.symlink_to(namespace / "original-pointer")
    with pytest.raises(OSError):
        preview.current_attempt(namespace)


@pytest.mark.parametrize(
    "damage", ["pointer-shape", "row-shape", "listener", "log", "order", "identity"]
)
def test_malformed_receipt_or_changed_identity_cannot_be_adopted(namespace, damage):
    journal, _ = receipt(namespace)
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    if damage == "pointer-shape":
        (namespace / preview.CURRENT).write_text("[]")
    elif damage == "row-shape":
        rows[1] = []
    elif damage == "listener":
        rows[0]["listener_inode"] = 123
    elif damage == "log":
        rows[0]["log"] = "../foreign.log"
    elif damage == "order":
        rows[1]["state"] = "ready"
    else:
        rows[-1]["identity"]["pid"] += 1
    journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(ValueError):
        preview.current_attempt(namespace)


@pytest.mark.parametrize(
    "field,value",
    [("start_ticks", "101"), ("uid", -1), ("argv", ["different"]), ("boot_id", "different")],
)
def test_pidfd_identity_guard_refuses_reuse_owner_command_or_boot_drift(
    namespace,
    monkeypatch,
    field,
    value,
):
    _, identity = receipt(namespace)
    fd = os.open(os.devnull, os.O_RDONLY)
    monkeypatch.setattr(preview.os, "pidfd_open", lambda pid: fd)
    monkeypatch.setattr(preview, "process_identity", lambda pid: {**identity, field: value})
    signal = Mock()
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", signal)
    with pytest.raises(ValueError, match="identity changed"):
        preview.guarded_pidfd(identity)
    signal.assert_not_called()
    with pytest.raises(OSError):
        os.fstat(fd)


def test_readiness_cannot_adopt_a_foreign_health_endpoint(monkeypatch):
    identity = {"pid": 123}
    child = Mock(pid=123)
    child.poll.return_value = None
    monkeypatch.setattr(preview, "process_identity", lambda pid: identity)
    monkeypatch.setattr(preview, "listeners", lambda: {"foreign"})
    health = Mock(return_value=True)
    monkeypatch.setattr(preview, "_health", health)
    with pytest.raises(RuntimeError, match="listener"):
        preview._ready(child, identity, "owned")
    health.assert_not_called()


def test_duplicate_start_does_not_restart_owned_running_preview(namespace, monkeypatch, tmp_path):
    monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(
        preview, "status", lambda root, **_kw: {"state": "running", "managed": True}
    )
    spawn = Mock()
    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    result = preview.start(namespace, Path("/unused"), Path(sys.executable))
    assert result["already_running"] is True
    spawn.assert_not_called()
    assert not list(namespace.glob("managed-*"))


def test_spawn_failure_preserves_private_attempt_and_seed_bytes(namespace, monkeypatch, tmp_path):
    before = {
        name: (namespace / name).read_bytes()
        for name in ["inventory.db", "overrides.db", "read-token.private", "manifest.json"]
    }
    monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "listeners", lambda: set())
    monkeypatch.setattr(
        preview.subprocess, "Popen", Mock(side_effect=OSError("synthetic spawn failure"))
    )
    with pytest.raises(RuntimeError, match="retained private log"):
        preview.start(namespace, Path("/unused"), Path(sys.executable))
    journal, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared", "failed-before-spawn"]
    assert journal.stat().st_mode & 0o777 == 0o600
    assert (namespace / rows[0]["log"]).stat().st_mode & 0o777 == 0o600
    assert before == {name: (namespace / name).read_bytes() for name in before}


def test_start_uses_devnull_clean_environment_private_log_and_passed_listener(
    namespace,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("NEXTDNS_API_KEY", "must-not-pass")
    monkeypatch.setenv("VIGIE_INVENTORY_PATH", "/must-not-open")
    monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview, "_package", lambda path: path)
    states = iter([{"state": "stopped"}, {"state": "running", "managed": True}])
    monkeypatch.setattr(preview, "status", lambda root, **_kw: next(states))
    captured = {}
    child = Mock(pid=123456)

    def spawn(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return child

    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    monkeypatch.setattr(preview.os, "pidfd_open", lambda pid: os.open(os.devnull, os.O_RDONLY))
    monkeypatch.setattr(
        preview,
        "process_identity",
        lambda pid: {
            "pid": pid,
            "uid": os.getuid(),
            "start_ticks": "100",
            "argv": captured["argv"],
            "boot_id": BOOT,
        },
    )
    monkeypatch.setattr(preview, "_ready", lambda *args: None)
    assert (
        preview.start(namespace, Path("/installed/package"), Path(sys.executable))["state"]
        == "running"
    )
    assert captured["stdin"] == subprocess.DEVNULL and captured["start_new_session"] is True
    assert captured["close_fds"] is True and len(captured["pass_fds"]) == 1
    assert captured["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
    assert "must-not-pass" not in json.dumps(captured["env"])
    assert captured["argv"][1:3] == ["-I", "-B"], "isolated child: no env, user site or script dir"
    assert captured["argv"][captured["argv"].index("--package-dir") + 1] == "/installed/package"
    assert captured["preexec_fn"] is preview._unblock_signals
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared", "spawned", "ready"]
    assert rows[0]["runtime_limit_seconds"] == 8 * 3600


def test_pidfd_failure_cleans_only_proven_unreaped_child_and_records_exit(
    namespace,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "status", lambda root, **_kw: {"state": "stopped"})
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
            "boot_id": BOOT,
        },
    )
    monkeypatch.setattr(
        preview.os, "pidfd_open", Mock(side_effect=OSError("synthetic pidfd failure"))
    )
    retained = Mock(return_value=None)
    monkeypatch.setattr(preview.os, "waitid", retained)
    with pytest.raises(RuntimeError, match="retained private log"):
        preview.start(namespace, Path("/installed/package"), Path(sys.executable))
    retained.assert_called_once_with(
        os.P_PID,
        child.pid,
        os.WEXITED | os.WNOWAIT | os.WNOHANG,
    )
    child.terminate.assert_called_once_with()
    child.wait.assert_called_once_with(timeout=6)
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared", "spawned", "startup-failed"]
    assert rows[-1]["child_exited"] is True


def test_cleanup_never_signals_a_child_without_retained_ownership(monkeypatch):
    child = Mock(pid=123456)
    monkeypatch.setattr(preview.os, "waitid", Mock(side_effect=ChildProcessError))
    assert preview.cleanup_startup(child, None) is False
    child.terminate.assert_not_called()
    child.wait.assert_not_called()


def test_fast_child_exit_is_retained_without_untracked_adoption(namespace, monkeypatch, tmp_path):
    monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "status", lambda root, **_kw: {"state": "stopped"})
    child = Mock(pid=123456)
    monkeypatch.setattr(preview.subprocess, "Popen", Mock(return_value=child))
    monkeypatch.setattr(preview, "process_identity", lambda pid: None)
    monkeypatch.setattr(preview.os, "waitid", Mock(return_value=object()))
    with pytest.raises(RuntimeError, match="retained private log"):
        preview.start(namespace, Path("/installed/package"), Path(sys.executable))
    child.terminate.assert_not_called()
    child.wait.assert_called_once_with(timeout=6)
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == ["prepared", "startup-failed"]
    assert rows[-1]["child_exited"] is True and rows[-1]["child_pid"] == child.pid


def test_serve_refuses_inherited_nonloopback_socket_before_app_creation(namespace, monkeypatch):
    import vigie_api.app

    make_app = Mock()
    monkeypatch.setattr(vigie_api.app, "create_app", make_app)
    listener = Mock(family=socket.AF_INET)
    listener.getsockname.return_value = ("0.0.0.0", preview.PORT)  # noqa: S104 -- mocked, never bound.
    listener.getsockopt.return_value = 1
    monkeypatch.setattr(preview.socket, "socket", Mock(return_value=listener))
    with pytest.raises(ValueError, match="fixed loopback"):
        preview.serve(namespace, 123)
    listener.close.assert_called_once_with()
    make_app.assert_not_called()


def test_stop_sends_only_guarded_term_and_preserves_receipt(namespace, monkeypatch, tmp_path):
    journal, identity = receipt(namespace)
    monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
    states = iter([{"state": "running", "managed": True}, {"state": "stopped", "managed": False}])
    monkeypatch.setattr(preview, "status", lambda root, **_kw: next(states))
    fd = os.open(os.devnull, os.O_RDONLY)
    monkeypatch.setattr(preview, "guarded_pidfd", lambda saved: fd)
    sender = Mock()
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", sender)
    monkeypatch.setattr(preview.select, "select", lambda *args: ([fd], [], []))
    assert preview.stop(namespace)["state"] == "stopped"
    sender.assert_called_once_with(fd, preview.signal.SIGTERM)
    _, rows = preview.current_attempt(namespace)
    assert [row["state"] for row in rows] == [
        "prepared",
        "spawned",
        "ready",
        "stop-requested",
        "stopped",
    ]
    assert journal.exists() and rows[1]["identity"] == identity


def test_package_symlink_or_writable_directory_is_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        preview._package(link)
    target.chmod(0o777)
    with pytest.raises(ValueError, match="trusted"):
        preview._package(target)


def test_start_end_to_end_through_the_real_interpreter_check_with_a_throwaway_venv(
    namespace, monkeypatch, tmp_path
):
    """The autouse bypass is undone: a clean venv layout is vetted, then really exec'd."""
    host = Path(sys.executable).resolve()
    monkeypatch.setattr(preview, "SYSTEM_UIDS", (0, Path("/tmp").lstat().st_uid))  # noqa: S108
    try:
        preview._stdlib(host.parent.parent, "host", site_packages=False)
    except ValueError:
        pytest.skip("host interpreter's own stdlib is not root/user-owned and symlink-free")
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(host)
    (venv / "pyvenv.cfg").write_text(f"home = {host.parent}\n")
    (venv / "lib" / "python3" / "site-packages").mkdir(parents=True)
    script = tmp_path / "sleeper-preview.py"
    script.write_text("import time\ntime.sleep(120)\n")
    monkeypatch.setattr(preview, "__file__", str(script))
    monkeypatch.setattr(preview, "_interpreter", REAL_INTERPRETER)
    monkeypatch.setattr(preview, "LOCK", tmp_path / "shared.lock")
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "listeners", lambda: set())
    monkeypatch.setattr(preview, "_ready", lambda *args: None)
    monkeypatch.setattr(preview.os, "pidfd_open", lambda pid: os.open(os.devnull, os.O_RDONLY))
    monkeypatch.setattr(preview.signal, "pidfd_send_signal", Mock())
    seen = {}
    real_popen = subprocess.Popen

    def spawn(argv, **kwargs):
        seen["child"] = real_popen(argv, **{**kwargs, "stdout": subprocess.DEVNULL})
        return seen["child"]

    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    try:
        preview.start(namespace, Path("/installed/package"), venv / "bin" / "python")
        _, rows = preview.current_attempt(namespace)
        assert [row["state"] for row in rows] == ["prepared", "spawned", "ready"]
        argv = rows[0]["argv"]
        assert argv[:3] == [str(venv / "bin" / "python"), "-I", "-B"]
        assert preview.process_identity(seen["child"].pid)["argv"] == argv
    finally:
        child = seen.get("child")
        if child is not None:
            child.kill()
            child.wait()
