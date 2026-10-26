"""Fix-round 6: sticky .pth targets, startup-hook FIFOs, holder honesty, status/lock races.

Throwaway children and ephemeral loopback ports only; nothing signals or binds the fixed preview.
"""

from __future__ import annotations

import builtins
import contextlib
import fcntl
import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from test_gui_preview_fixround1 import (  # noqa: F401 -- shared fixtures, same module instance
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
from test_gui_preview_fixround3 import _pth
from test_gui_preview_fixround4 import _refuses
from test_gui_preview_fixround5 import _foreign_holder

# ------------------------------------ C1: the .pth target directory itself must not be shared


@pytest.mark.parametrize("mode", [0o1777, 0o1770, 0o1707, 0o777])
def test_an_existing_shared_pth_target_directory_is_refused(sandbox_owners, tmp_path, mode):
    root, _, site = _venv(tmp_path)
    target = tmp_path / "editable"
    target.mkdir()
    (target / "mod.py").write_text("")
    (target / "mod.py").chmod(0o644)
    target.chmod(mode)  # sticky does not stop another user planting NEW importable files
    _pth(site, "e.pth", f"{target}\n")
    _refuses(root)


def test_a_private_pth_target_directory_is_still_accepted(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    target = tmp_path / "editable"
    target.mkdir()
    target.chmod(0o755)
    _pth(site, "e.pth", f"{target}\n")
    assert preview._interpreter(root / "bin" / "python")


# ------------------------------------ C2: a startup-hook NAME is never read


def _hang_free_refusal(root: Path, fifo: Path | None) -> None:
    box: list[BaseException | None] = []

    def run() -> None:
        try:
            preview._interpreter(root / "bin" / "python")
            box.append(None)
        except BaseException as exc:  # noqa: BLE001 -- inspected below
            box.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(1.0)
    if worker.is_alive():
        if fifo is not None:  # release a reader blocked in open(2) so the process can end
            with contextlib.suppress(OSError):
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail("the vet hung reading a startup-hook name", pytrace=False)
    assert isinstance(box[0], ValueError) and "untrusted" in str(box[0]), repr(box)


@pytest.mark.parametrize("name", ["sitecustomize.py", "usercustomize.py"])
def test_a_fifo_named_like_a_startup_hook_is_refused_without_hanging(
    sandbox_owners, tmp_path, name
):
    root, _, site = _venv(tmp_path)
    os.mkfifo(site / name, 0o644)
    _hang_free_refusal(root, site / name)


def test_a_symlink_to_a_fifo_named_like_a_startup_hook_is_refused_without_hanging(
    sandbox_owners, tmp_path
):
    root, _, site = _venv(tmp_path)
    os.mkfifo(tmp_path / "pipe", 0o644)
    (site / "sitecustomize.py").symlink_to(tmp_path / "pipe")
    _hang_free_refusal(root, tmp_path / "pipe")


def test_a_symlink_to_dev_zero_named_like_a_startup_hook_is_refused_without_reading(
    sandbox_owners, tmp_path, monkeypatch
):
    root, _, site = _venv(tmp_path)
    (site / "sitecustomize.py").symlink_to("/dev/zero")
    real_read = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: (
            (_ for _ in ()).throw(AssertionError("read a startup hook"))
            if self.name == "sitecustomize.py"
            else real_read(self)
        ),
    )
    _hang_free_refusal(root, None)


@pytest.mark.parametrize("kind", ["fifo", "zero", "huge"])
def test_a_pinned_name_is_still_opened_safely(sandbox_owners, tmp_path, monkeypatch, kind):
    monkeypatch.setattr(preview, "_BENIGN_STARTUP_HOOKS", {"sitecustomize.py": "0" * 64})
    root, _, site = _venv(tmp_path)
    hook = site / "sitecustomize.py"
    if kind == "fifo":
        os.mkfifo(hook, 0o644)
    elif kind == "zero":
        hook.symlink_to("/dev/zero")
    else:
        hook.write_bytes(b"x" * (preview.MAX_HOOK_BYTES + 1))
        hook.chmod(0o644)
    _hang_free_refusal(root, hook if kind == "fifo" else None)


# ------------------------------------ C3: a matching identity is not lock ownership


def _spawn(argv: list[str]) -> subprocess.Popen:
    return subprocess.Popen(  # noqa: S603 -- throwaway test child, argv is ours.
        argv,
        env={"PATH": "/usr/bin:/bin"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@pytest.fixture
def children():
    spawned: list[subprocess.Popen] = []
    yield lambda argv: spawned.append(_spawn(argv)) or spawned[-1]
    for child in spawned:
        child.kill()
        child.wait()


def _line(child) -> str:
    identity = preview.process_identity(child.pid)
    assert identity is not None
    return f"{child.pid} {identity['start_ticks']} {identity['boot_id']}\n"


def test_an_unrelated_live_process_named_in_the_holder_line_is_unverified(namespace, children):
    sleeper = children(["/usr/bin/sleep", "60"])
    fd = _foreign_holder(_line(sleeper), 600)
    try:
        result = preview.status(namespace)
    finally:
        os.close(fd)
    assert result["state"] == "starting" and result["managed"] is False
    assert result["unverified_holder_pid"] == sleeper.pid
    assert "holder_pid" not in result and "advice" not in result


def test_an_unrelated_holder_is_not_named_as_the_owner_in_lock_errors(
    namespace, children, monkeypatch
):
    monkeypatch.setattr(preview, "LOCK_WAIT_SECONDS", 0.1)
    sleeper = children(["/usr/bin/sleep", "60"])
    fd = _foreign_holder(_line(sleeper), 5)
    try:
        with pytest.raises(BlockingIOError) as raised:
            preview.stop(namespace)
    finally:
        os.close(fd)
    assert f"unverified PID {sleeper.pid}" in str(raised.value)
    assert "holder" not in str(raised.value).replace("holds the lock", "")


def _start_shaped(children, action: str):
    code = "import time; time.sleep(60)"
    return children([sys.executable, "-c", code, preview.__file__, action])


@pytest.mark.parametrize("action", ["start", "stop"])
def test_a_real_start_shaped_holder_older_than_a_minute_is_wedged(namespace, children, action):
    holder = _start_shaped(children, action)
    fd = _foreign_holder(_line(holder), 120)
    try:
        result = preview.status(namespace)
    finally:
        os.close(fd)
    assert result["state"] == "wedged-start" and result["holder_pid"] == holder.pid
    assert "unverified_holder_pid" not in result


@pytest.mark.parametrize("action", ["status", "seed", "serve", "reset"])
def test_a_holder_running_another_action_is_unverified(namespace, children, action):
    holder = _start_shaped(children, action)
    fd = _foreign_holder(_line(holder), 120)
    try:
        result = preview.status(namespace)
    finally:
        os.close(fd)
    assert result["state"] == "starting" and result["unverified_holder_pid"] == holder.pid


def test_a_start_shaped_holder_of_another_uid_is_unverified(namespace, children, monkeypatch):
    holder = _start_shaped(children, "start")
    real = preview.process_identity
    monkeypatch.setattr(
        preview,
        "process_identity",
        lambda pid: {**real(pid), "uid": os.getuid() + 1} if pid == holder.pid else real(pid),
    )
    fd = _foreign_holder(_line(holder), 120)
    try:
        result = preview.status(namespace)
    finally:
        os.close(fd)
    assert result["state"] == "starting" and result["unverified_holder_pid"] == holder.pid


def test_the_docs_never_assert_ownership_for_an_unverified_holder():
    docs = (Path(__file__).resolve().parents[3] / "docs" / "gui-preview.md").read_text()
    for needle in ("`unverified_holder_pid`", "does not prove", "cannot remove"):
        assert needle in docs, needle
    assert "remove the file" not in docs


def test_the_exclusive_lock_error_does_not_call_itself_shared(namespace):
    preview.LOCK.write_text("")
    preview.LOCK.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe") as raised, preview.manager_lock():
        pass
    assert "shared preview lock" not in str(raised.value)


# ------------------------------------ C4: status re-checks after any scan-derived result


def _grab_exclusive(scratch_lock: Path) -> int:
    fd = os.open(scratch_lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def _prepared_only(namespace, argv, inode) -> None:
    (namespace / preview.CURRENT).unlink()
    for old in namespace.glob("managed-*.jsonl"):
        old.unlink()
    attempt(namespace, argv, inode, [])


def test_a_terminal_receipt_scan_overtaken_by_a_new_start_reports_starting(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, ["spawned", "stop-requested", "stopped"], identity=identity)
    fds: list[int] = []

    def scan() -> set[str]:
        fds.append(_grab_exclusive(preview.LOCK))  # a start takes the lock mid-scan ...
        _prepared_only(namespace, argv, inode)  # ... and swaps the attempt for `prepared`
        return {inode}  # a listener is up: the stale verdict would be `unmanaged-listener`

    preview.LOCK.touch(mode=0o600)
    monkeypatch.setattr(preview, "listeners", scan)
    try:
        result = preview.status(namespace)
    finally:
        for fd in fds:
            os.close(fd)
    assert result["state"] == "starting" and result["managed"] is False


def test_a_receipt_changed_by_a_finished_start_during_the_scan_reports_starting(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, ["spawned", "stop-requested", "stopped"], identity=identity)

    def scan() -> set[str]:
        _prepared_only(namespace, argv, inode)  # the writer is already gone again
        return {inode}

    monkeypatch.setattr(preview, "listeners", scan)
    assert preview.status(namespace)["state"] == "starting"


def test_a_torn_append_with_a_writer_present_after_the_scan_is_starting(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    journal = attempt(
        namespace, argv, inode, ["spawned", "stop-requested", "stopped"], identity=identity
    )
    fds: list[int] = []

    def scan() -> set[str]:
        fds.append(_grab_exclusive(preview.LOCK))
        with journal.open("ab") as handle:
            handle.write(b'{"state": "sto')
        return {inode}

    preview.LOCK.touch(mode=0o600)
    monkeypatch.setattr(preview, "listeners", scan)
    try:
        result = preview.status(namespace)
    finally:
        for fd in fds:
            os.close(fd)
    assert result["state"] == "starting" and result["managed"] is False


def test_a_torn_append_with_no_writer_after_the_scan_is_the_retained_failure(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    journal = attempt(
        namespace, argv, inode, ["spawned", "stop-requested", "stopped"], identity=identity
    )

    def scan() -> set[str]:
        with journal.open("ab") as handle:
            handle.write(b'{"state": "sto')
        return {inode}

    monkeypatch.setattr(preview, "listeners", scan)
    with pytest.raises(ValueError, match="incomplete manager receipt"):
        preview.status(namespace)


def test_a_quiet_status_is_unchanged_by_the_recheck(namespace, listener, sleeper, monkeypatch):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, ["spawned", "stop-requested", "stopped"], identity=identity)
    monkeypatch.setattr(preview, "listeners", lambda: {inode})
    assert preview.status(namespace)["state"] == "unmanaged-listener"


# ------------------------------------ N4: status never starves start/stop


def test_a_tight_status_loop_cannot_starve_stop(namespace, listener, monkeypatch):
    monkeypatch.setattr(preview, "listeners", lambda: set())
    preview.LOCK.touch(mode=0o600)
    real = preview.current_attempt

    def slow(root):
        time.sleep(0.002)  # a 2 ms receipt read, as in the review
        return real(root)

    monkeypatch.setattr(preview, "current_attempt", slow)
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            with contextlib.suppress(Exception):
                preview.status(namespace)

    workers = [threading.Thread(target=loop, daemon=True) for _ in range(3)]
    for worker in workers:
        worker.start()
    try:
        started = time.monotonic()
        for _ in range(3):
            assert preview.stop(namespace)["state"] == "stopped"
        assert time.monotonic() - started < 1.5
    finally:
        stop.set()
        for worker in workers:
            worker.join(5)


def test_status_never_holds_the_shared_lock_across_a_receipt_read(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, ["spawned", "stop-requested", "stopped"], identity=identity)
    preview.LOCK.touch(mode=0o600)
    real = preview.current_attempt
    held: list[bool] = []

    def spy(root):
        fd = os.open(preview.LOCK, os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.append(False)
            except BlockingIOError:
                held.append(True)
        finally:
            os.close(fd)
        return real(root)

    monkeypatch.setattr(preview, "current_attempt", spy)
    preview.status(namespace)
    assert held and not any(held)


# ------------------------------------ N1: vet the path the child computes


def _deep_lib_venv(tmp_path: Path):
    """The review PoC: venv/lib is a symlink to a directory at a different depth."""
    root, _, site = _venv(tmp_path)
    deep = tmp_path / "deep" / "a" / "b"
    deep.mkdir(parents=True)
    (root / "lib").rename(deep / "lib")
    (root / "lib").symlink_to(deep / "lib")
    for path in (tmp_path / "deep", tmp_path / "deep" / "a", deep, deep / "lib"):
        path.chmod(0o700)
    pub = tmp_path / "pub"
    pub.mkdir()
    pub.chmod(0o1777)
    return root, deep / "lib" / "python3.12" / "site-packages"


def test_a_lib_symlink_to_another_depth_cannot_shift_a_relative_pth_line(sandbox_owners, tmp_path):
    root, site = _deep_lib_venv(tmp_path)
    _pth(site, "e.pth", "../../../../pub/evil\n")  # child appends <tmp>/pub/evil (sticky 1777)
    _refuses(root)


def test_any_lib_symlink_leaving_the_venv_root_is_refused(sandbox_owners, tmp_path):
    root, site = _deep_lib_venv(tmp_path)  # no .pth at all: the layout itself is the problem
    _refuses(root)


@pytest.mark.parametrize("line", ["../escape", "sub/../../escape", "/tmp/../tmp/x"])  # noqa: S108
def test_dotdot_segments_in_pth_lines_are_refused(sandbox_owners, tmp_path, line):
    root, _, site = _venv(tmp_path)
    _pth(site, "e.pth", f"{line}\n")
    _refuses(root)


def test_a_lib64_symlink_to_lib_is_still_accepted(sandbox_owners, tmp_path):
    root, _, _ = _venv(tmp_path)
    (root / "lib64").symlink_to("lib")
    assert preview._interpreter(root / "bin" / "python")


# ------------------------------------ C7: the real-lock guard sees through spelling

SPELLINGS = [
    "/tmp/vigie-gui-preview-18745.lock",  # noqa: S108 -- only compared, never opened.
    "/tmp/./vigie-gui-preview-18745.lock",  # noqa: S108
    "/tmp//vigie-gui-preview-18745.lock",  # noqa: S108
    "/tmp/x/../vigie-gui-preview-18745.lock",  # noqa: S108
    b"/tmp/vigie-gui-preview-18745.lock",  # noqa: S108
    b"/tmp//./vigie-gui-preview-18745.lock",  # noqa: S108
    Path("/tmp/./vigie-gui-preview-18745.lock"),  # noqa: S108
]


@pytest.mark.parametrize("spelling", SPELLINGS, ids=repr)
def test_os_open_of_the_real_lock_is_stopped_in_every_spelling(spelling):
    with pytest.raises(AssertionError, match="real preview lock"):
        os.open(spelling, os.O_RDONLY)


@pytest.mark.parametrize("spelling", SPELLINGS, ids=repr)
@pytest.mark.parametrize("module", [io, builtins], ids=["io.open", "builtins.open"])
def test_python_open_of_the_real_lock_is_stopped_in_every_spelling(spelling, module):
    with pytest.raises(AssertionError, match="real preview lock"):
        module.open(spelling)  # looked up now: the autouse guard patches the attribute


def test_path_open_and_pathlib_io_reach_the_same_guard():
    with pytest.raises(AssertionError, match="real preview lock"):
        Path("/tmp/./vigie-gui-preview-18745.lock").open()  # noqa: S108


def test_a_relative_spelling_from_the_tmp_directory_is_stopped(monkeypatch):
    monkeypatch.chdir("/tmp")  # noqa: S108
    with pytest.raises(AssertionError, match="real preview lock"):
        os.open("vigie-gui-preview-18745.lock", os.O_RDONLY)


def test_unrelated_opens_are_not_blocked(tmp_path):
    (tmp_path / "x").write_text(json.dumps({}))
    assert open(tmp_path / "x").read() == "{}"  # noqa: SIM115
    assert os.close(os.open(tmp_path / "x", os.O_RDONLY)) is None


# ------------------------------------ surviving mutants from the final-gate review


def test_a_holder_line_with_the_wrong_start_ticks_names_nobody(namespace):
    me = preview.process_identity(os.getpid())
    assert me is not None
    fd = _foreign_holder(f"{os.getpid()} 999 {me['boot_id']}\n", 120)  # N17
    try:
        result = preview.status(namespace)
    finally:
        os.close(fd)
    assert result["state"] == "starting"
    assert "holder_pid" not in result and "unverified_holder_pid" not in result


def test_a_verified_holder_is_not_wedged_before_the_sixty_second_threshold(namespace, children):
    holder = _start_shaped(children, "start")
    fd = _foreign_holder(_line(holder), 30)  # N20: 30 s old, threshold is 60 s
    try:
        result = preview.status(namespace)
    finally:
        os.close(fd)
    assert result["state"] == "starting" and result["holder_pid"] == holder.pid
    assert "advice" not in result


def test_a_clean_crlf_directory_line_is_accepted(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # N06/N08
    target = tmp_path / "editable"
    target.mkdir()
    target.chmod(0o755)
    (site / "e.pth").write_bytes(f"# note\r\n{target}\r\n".encode())
    (site / "e.pth").chmod(0o644)
    assert preview._interpreter(root / "bin" / "python")
