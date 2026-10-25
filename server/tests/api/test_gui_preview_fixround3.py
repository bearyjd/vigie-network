"""Fix-round 3: .pth content vetting, venv cfg parsing, hop ownership, lock/status, guards.

Throwaway children and ephemeral loopback ports only; nothing signals or binds the fixed preview.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import Mock

import gui_preview_native_lane as lane
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
    serve_argv,
    sleeper,
)

UNTRUSTED = "untrusted"
VIRTUALENV_PTH = "import _virtualenv"
COVERAGE_PTH = (
    'import sys; exec(\'import os\\n\\nif os.getenv("COVERAGE_PROCESS_START") or '
    'os.getenv("COVERAGE_PROCESS_CONFIG"):\\n try:\\n  import coverage\\n except:\\n  pass\\n '
    'else:\\n  coverage.process_startup(slug="pth")\')\n'
)


def _pth(site: Path, name: str, text: str) -> None:
    (site / name).write_text(text)
    (site / name).chmod(0o644)


def _accepts(path):
    return preview._interpreter(path)


def _editable_target(tmp_path: Path, mode: int = 0o700) -> Path:
    target = tmp_path / "other-worktree" / "server" / "src"
    target.mkdir(parents=True)
    (target / "vigie_api.py").write_text("")
    for path in (target.parent.parent, target.parent, target):
        path.chmod(mode)
    return target


# ---------------------------------------------------------------- M1 .pth content


@pytest.mark.parametrize(
    "text",
    [
        "import os; exec(open('/tmp/x/payload.py').read())\n",
        "import evil\n",
        "import\tevil\n",
        "   # comment\nimport evil\n",
        "/some/dir; print(1)\n",
    ],
    ids=["exec", "import", "import-tab", "import-after-comment", "semicolon-path"],
)
def test_pth_with_executable_or_compound_lines_is_refused(sandbox_owners, tmp_path, text):
    root, _, site = _venv(tmp_path)
    assert _accepts(root / "bin" / "python")
    _pth(site, "evil.pth", text)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_pth_path_line_to_a_writable_directory_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    target = _editable_target(tmp_path, 0o777)
    _pth(site, "editable.pth", f"{target}\n")
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_pth_path_line_whose_tree_holds_a_writable_file_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    target = _editable_target(tmp_path)
    (target / "vigie_api.py").chmod(0o666)
    _pth(site, "editable.pth", f"{target}\n")
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_pth_path_line_through_a_symlink_or_to_a_file_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    target = _editable_target(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    _pth(site, "editable.pth", f"{alias}\n")
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")
    _pth(site, "editable.pth", f"{target / 'vigie_api.py'}\n")
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_pth_relative_path_line_is_resolved_against_site_packages(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    (site / "inner").mkdir()
    (site / "inner").chmod(0o777)
    _pth(site, "relative.pth", "inner\n")
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_clean_editable_style_pth_is_accepted_and_missing_targets_are_ignored(
    sandbox_owners, tmp_path
):
    root, _, site = _venv(tmp_path)
    target = _editable_target(tmp_path)
    _pth(site, "editable.pth", f"# editable\n\n{target}\n{target}\n")
    _pth(site, "gone.pth", f"{tmp_path / 'does-not-exist'}\n")  # site.py ignores absent dirs
    assert _accepts(root / "bin" / "python") == root / "bin" / "python"


@pytest.mark.parametrize(
    ("name", "text"),
    [("_virtualenv.pth", VIRTUALENV_PTH), ("a1_coverage.pth", COVERAGE_PTH)],
)
def test_known_benign_pth_with_exact_content_is_accepted(sandbox_owners, tmp_path, name, text):
    root, _, site = _venv(tmp_path)
    _pth(site, name, text)
    assert _accepts(root / "bin" / "python") == root / "bin" / "python"


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("_virtualenv.pth", "import _virtualenv; import os\n"),  # right name, other content
        ("_virtualenv.pth", "import evil"),
        ("other.pth", VIRTUALENV_PTH),  # right content, other name
        ("a1_coverage.pth", COVERAGE_PTH + "import evil\n"),
    ],
)
def test_allowlist_needs_both_the_name_and_the_exact_content(sandbox_owners, tmp_path, name, text):
    root, _, site = _venv(tmp_path)
    _pth(site, name, text)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_default_style_layout_still_passes(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)
    target = _editable_target(tmp_path)
    _pth(site, "a1_coverage.pth", COVERAGE_PTH)
    _pth(site, "_editable_impl_vigie_ingest.pth", f"{target}\n{target}\n{target}")
    _pth(site, "_virtualenv.pth", VIRTUALENV_PTH)
    assert _accepts(root / "bin" / "python") == root / "bin" / "python"


def test_pth_in_a_walked_base_site_packages_is_vetted_too(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    base_site = binary.parent.parent / "lib" / "python3.12" / "site-packages"
    base_site.mkdir()
    base_site.chmod(0o700)
    (root / "pyvenv.cfg").write_text(
        f"home = {binary.parent}\ninclude-system-site-packages = true\n"
    )
    assert _accepts(root / "bin" / "python")
    _pth(base_site, "evil.pth", "import evil\n")
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


# ---------------------------------------------------------------- M2 include-system-site-packages


def _dirty_base_site(binary: Path) -> None:
    base_site = binary.parent.parent / "lib" / "python3.12" / "site-packages"
    base_site.mkdir()
    base_site.chmod(0o700)
    (base_site / "x.py").write_text("")
    (base_site / "x.py").chmod(0o666)


@pytest.mark.parametrize("value", ["true", "True", "TRUE", "  True  "])
def test_include_system_site_packages_is_case_insensitive_like_site_py(
    sandbox_owners, tmp_path, value
):
    root, binary, _ = _venv(tmp_path)
    _dirty_base_site(binary)
    (root / "pyvenv.cfg").write_text(
        f"home = {binary.parent}\ninclude-system-site-packages = {value}\n"
    )
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


@pytest.mark.parametrize("value", ["false", "False", " FALSE "])
def test_explicit_false_in_any_case_keeps_system_site_packages_unwalked(
    sandbox_owners, tmp_path, value
):
    root, binary, _ = _venv(tmp_path)
    _dirty_base_site(binary)
    (root / "pyvenv.cfg").write_text(
        f"home = {binary.parent}\ninclude-system-site-packages = {value}\n"
    )
    assert _accepts(root / "bin" / "python") == root / "bin" / "python"


def test_absent_key_means_true_like_site_py_and_unknown_values_are_refused(
    sandbox_owners, tmp_path
):
    root, binary, _ = _venv(tmp_path)
    _dirty_base_site(binary)
    with pytest.raises(ValueError, match=UNTRUSTED):  # site.py defaults to "true"
        _accepts(root / "bin" / "python")
    (root / "pyvenv.cfg").write_text(
        f"home = {binary.parent}\ninclude-system-site-packages = yes\n"
    )
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


# ---------------------------------------------------------------- M3 hop ownership


def _sticky_hop(tmp_path, root, binary):
    hops = tmp_path / "hops"
    hops.mkdir()
    (hops / "hop").symlink_to(binary)
    (root / "bin" / "python").unlink()
    (root / "bin" / "python").symlink_to(hops / "hop")
    hops.chmod(0o1777)
    return hops


def _with_owner(monkeypatch, path: Path, uid: int) -> None:
    real = type(path).lstat

    def lstat(self, *args, **kwargs):
        st = real(self, *args, **kwargs)
        if self == path:
            values = list(st)
            values[4] = uid
            return os.stat_result(values)
        return st

    monkeypatch.setattr(type(path), "lstat", lstat)


def test_hop_symlink_owned_by_us_in_a_sticky_directory_is_accepted(sandbox_owners, tmp_path):
    root, binary, _ = _venv(tmp_path)
    _sticky_hop(tmp_path, root, binary)
    assert _accepts(root / "bin" / "python") == root / "bin" / "python"


@pytest.mark.parametrize("uid", [4242424, 0], ids=["foreign-user", "root-in-sticky-dir"])
def test_hop_symlink_not_owned_by_us_in_a_sticky_world_writable_directory_is_refused(
    sandbox_owners, tmp_path, monkeypatch, uid
):
    root, binary, _ = _venv(tmp_path)
    hops = _sticky_hop(tmp_path, root, binary)
    _with_owner(monkeypatch, hops / "hop", uid)
    with pytest.raises(ValueError, match=UNTRUSTED):
        _accepts(root / "bin" / "python")


def test_hop_symlink_with_a_foreign_owner_is_refused_in_any_directory(
    sandbox_owners, tmp_path, monkeypatch
):
    root, binary, _ = _venv(tmp_path)
    hops = tmp_path / "hops"
    hops.mkdir()
    (hops / "hop").symlink_to(binary)
    (root / "bin" / "python").unlink()
    (root / "bin" / "python").symlink_to(hops / "hop")
    hops.chmod(0o700)
    assert _accepts(root / "bin" / "python")
    with monkeypatch.context() as patch:
        _with_owner(patch, hops / "hop", 4242424)
        with pytest.raises(ValueError, match=UNTRUSTED):
            _accepts(root / "bin" / "python")


# ---------------------------------------------------------------- L1 lock / status


def _hold_lock(seconds: float) -> threading.Thread:
    held, done = threading.Event(), threading.Event()

    def hold():
        with preview.manager_lock():
            held.set()
            done.wait(seconds)

    thread = threading.Thread(target=hold)
    thread.start()
    assert held.wait(5)
    return thread


def test_slow_status_never_holds_the_lock_so_start_and_stop_are_not_refused(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, [])
    scanning, release = threading.Event(), threading.Event()
    real = preview._lookalikes

    def slow(rows):
        scanning.set()
        release.wait(10)
        return real(rows)

    monkeypatch.setattr(preview, "_lookalikes", slow)
    seen = {}
    worker = threading.Thread(target=lambda: seen.update(preview.status(namespace)))
    worker.start()
    try:
        assert scanning.wait(5)
        with preview.manager_lock():  # a concurrent start/stop must get the lock at once
            pass
    finally:
        release.set()
        worker.join(10)
    assert seen["state"] in {"uncertain", "stopped", "starting"}


def test_status_after_a_scan_overtaken_by_a_new_attempt_reports_starting(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, [])
    real = preview._lookalikes

    def overtaken(rows):
        found = real(rows)
        (namespace / preview.CURRENT).unlink()  # a start swapped the attempt mid-scan
        return found

    monkeypatch.setattr(preview, "_lookalikes", overtaken)
    assert preview.status(namespace)["state"] == "starting"


def test_stop_waits_briefly_for_a_busy_lock_instead_of_failing_eagain(namespace):
    thread = _hold_lock(0.4)
    started = time.monotonic()
    try:
        assert preview.stop(namespace)["state"] == "stopped"
    finally:
        thread.join(5)
    assert 0.2 < time.monotonic() - started < 2.5


def test_start_waits_briefly_for_a_busy_lock_instead_of_failing_eagain(namespace, monkeypatch):
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "_interpreter", lambda path: path)
    monkeypatch.setattr(preview, "listeners", lambda: set())
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview.subprocess, "Popen", Mock(side_effect=OSError("synthetic")))
    thread = _hold_lock(0.4)
    try:
        with pytest.raises(RuntimeError, match="retained private log"):  # reached the spawn
            preview.start(namespace, Path("/pkg"), Path(sys.executable))
    finally:
        thread.join(5)


def test_a_lock_that_stays_busy_fails_after_the_bounded_wait_with_an_explicit_message(
    namespace, monkeypatch
):
    monkeypatch.setattr(preview, "LOCK_WAIT_SECONDS", 0.2)
    thread = _hold_lock(1.0)
    started = time.monotonic()
    try:
        with pytest.raises(BlockingIOError, match="another preview command"):
            preview.stop(namespace)
        assert time.monotonic() - started < 0.9
    finally:
        thread.join(5)


def test_status_never_waits_for_a_busy_lock(namespace, listener, sleeper):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, [])
    thread = _hold_lock(1.0)
    started = time.monotonic()
    try:
        assert preview.status(namespace)["state"] == "starting"
        assert time.monotonic() - started < 0.5
    finally:
        thread.join(5)


def test_status_with_a_group_readable_lock_file_explains_the_refusal(
    namespace, listener, sleeper, tmp_path
):
    child, argv, identity, inode = live(namespace, listener, sleeper)
    attempt(namespace, argv, inode, [])
    preview.LOCK.touch(mode=0o600)
    preview.LOCK.chmod(0o644)
    with pytest.raises(
        ValueError, match=r"unsafe shared preview lock .*mode 0600.*found mode 0644"
    ):
        preview.status(namespace)
    assert str(preview.LOCK) in _error(lambda: preview.status(namespace))
    preview.LOCK.chmod(0o600)
    assert preview.status(namespace)["state"] == "orphaned"


def _error(call) -> str:
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the message is the assertion
        return str(exc)
    return ""


# ---------------------------------------------------------------- L2 uncertain recovery


def test_uncertain_status_lists_the_matching_pids_and_nothing_secret(
    namespace, listener, sleeper, monkeypatch
):
    child, argv, identity, inode = live(namespace, listener, sleeper, hold=False)
    attempt(namespace, argv, inode, [])
    monkeypatch.setattr(preview, "listeners", lambda: set())
    result = preview.status(namespace)
    assert result["state"] == "uncertain"
    assert result["candidate_pids"] == [child.pid]
    assert "argv" not in json.dumps(result)
    token = (namespace / "read-token.private").read_text().strip()
    assert token not in json.dumps(result)


def test_documented_recovery_exists_for_uncertain_and_starting():
    docs = (Path(__file__).resolve().parents[3] / "docs" / "gui-preview.md").read_text()
    for needle in ("candidate_pids", "`uncertain`", "`starting`", "/proc/<PID>/cmdline", "TERM"):
        assert needle in docs
    assert "each hop" in docs and "sticky" in docs


# ---------------------------------------------------------------- L4 guards


def test_start_after_a_prepared_only_attempt_does_not_see_its_own_lock(namespace, monkeypatch):
    attempt(namespace, serve_argv(namespace, 7), "999999", [])  # an earlier interrupted start
    monkeypatch.setattr(preview, "listeners", lambda: set())
    monkeypatch.setattr(preview, "PORT", 0)
    monkeypatch.setattr(preview, "_package", lambda path: path)
    monkeypatch.setattr(preview, "_interpreter", lambda path: path)
    spawn = Mock(side_effect=OSError("synthetic"))
    monkeypatch.setattr(preview.subprocess, "Popen", spawn)
    with pytest.raises(RuntimeError, match="retained private log"):
        preview.start(namespace, Path("/pkg"), Path(sys.executable))
    spawn.assert_called_once()


@pytest.mark.parametrize(
    "tamper",
    [
        lambda argv: ["-E" if value == "-I" else value for value in argv],
        lambda argv: [*argv[:5], "--directory-x", *argv[6:]],
        lambda argv: [*argv[:8], "/elsewhere", *argv[9:]],
    ],
    ids=["flag-swapped", "option-renamed", "package-dir-differs-from-receipt"],
)
def test_receipt_argv_is_rederived_not_merely_shaped(namespace, tamper):
    argv = serve_argv(namespace, 7)
    attempt(namespace, tamper(argv), "123", [])
    with pytest.raises(ValueError, match="invalid fixed child command"):
        preview.current_attempt(namespace)


# ---------------------------------------------------------------- M1 real serve


def _free_port() -> socket.socket:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    return sock


def _copy_package(src: Path, dest: Path, marker: str) -> Path:
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    with (dest / "vigie_api" / "ui" / "app.js").open("a") as handle:
        handle.write(f"\n// {marker}\n")
    return dest


def test_real_serve_imports_the_vetted_package_dir_ahead_of_every_other_vigie_api(tmp_path):
    """Kills append-instead-of-insert and ignore-package-dir: a decoy copy sits on sys.path via
    a venv .pth, exactly like another worktree's editable install."""
    source = Path(__file__).resolve().parents[2] / "src"
    if not (source / "vigie_api" / "ui" / "app.js").is_file():
        pytest.skip("source tree assets unavailable")
    venv = tmp_path / "venv"
    made = subprocess.run(  # noqa: S603 -- our own interpreter, fixed arguments.
        [sys.executable, "-m", "venv", "--without-pip", str(venv)],
        capture_output=True,
        timeout=120,
    )
    if made.returncode != 0:
        pytest.skip("cannot create a throwaway venv")
    python = venv / "bin" / "python"
    decoy = _copy_package(source, tmp_path / "decoy", "MARK-DECOY")
    vetted = _copy_package(source, tmp_path / "vetted", "MARK-VETTED")
    deps = subprocess.run(  # noqa: S603 -- fixed snippet printing this env's site-packages.
        [sys.executable, "-c", "import site; print(chr(10).join(site.getsitepackages()))"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    (next((venv / "lib").glob("python*/site-packages")) / "decoy.pth").write_text(
        "\n".join([str(decoy), *deps]) + "\n"  # decoy first, then the dependencies
    )
    probe = subprocess.run(  # noqa: S603
        [str(python), "-I", "-B", "-c", "import uvicorn, vigie_api; print(vigie_api.__file__)"],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0 or str(decoy) not in probe.stdout:
        pytest.skip(f"throwaway venv cannot import the app dependencies: {probe.stderr[-200:]}")
    base = tmp_path.resolve()
    root = base / "vigie-gui-preview-r3"
    preview.seed(root)
    sock = _free_port()
    port = sock.getsockname()[1]
    script = tmp_path / "serve_preview.py"
    script.write_text(
        Path(str(preview.__file__))
        .read_text()
        .replace('PREVIEW_PARENT = Path("/tmp")', f"PREVIEW_PARENT = Path({str(base)!r})", 1)
        .replace("PORT = 18745", f"PORT = {port}", 1)
        .replace("port=18745", f"port={port}", 1)
    )
    child = subprocess.Popen(  # noqa: S603 -- throwaway venv interpreter, ephemeral port.
        [
            str(python),
            "-I",
            "-B",
            str(script),
            "serve",
            "--directory",
            str(root),
            "--package-dir",
            str(vetted),
            "--listen-fd",
            str(sock.fileno()),
        ],
        pass_fds=(sock.fileno(),),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
    )
    try:
        body = ""
        for _ in range(100):
            if child.poll() is not None:
                pytest.fail(
                    f"serve exited early: {(child.stdout.read() if child.stdout else b'')[-400:]!r}"
                )
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/ui/app.js", timeout=1) as r:
                    body = r.read().decode()
                break
            except OSError:
                time.sleep(0.1)
        assert "MARK-VETTED" in body and "MARK-DECOY" not in body
    finally:
        child.terminate()
        child.wait(10)
        sock.close()


# ---------------------------------------------------------------- CI portability of the native lane


def _prefix(tmp_path: Path) -> Path:
    stdlib = tmp_path / "prefix" / "lib" / "python3.12"
    (stdlib / "site-packages").mkdir(parents=True)
    (stdlib / "os.py").write_text("")
    return tmp_path / "prefix"


def test_stdlib_symlink_probe_reports_debian_style_symlinks_and_ignores_site_packages(tmp_path):
    prefix = _prefix(tmp_path)
    assert lane.stdlib_symlinks(prefix) == []
    (prefix / "lib" / "python3.12" / "site-packages" / "x.py").symlink_to("/etc/hostname")
    assert lane.stdlib_symlinks(prefix) == []  # a venv never walks the base site-packages
    (prefix / "lib" / "python3.12" / "sitecustomize.py").symlink_to(
        "/etc/python3.12/sitecustomize.py"
    )
    assert lane.stdlib_symlinks(prefix) == [str(prefix / "lib" / "python3.12" / "sitecustomize.py")]
    (prefix / "lib" / "python3.12" / "sitecustomize.py").unlink()
    (prefix / "lib" / "python3.12" / "pkg").symlink_to(tmp_path, target_is_directory=True)
    assert len(lane.stdlib_symlinks(prefix)) == 1


def test_end_to_end_lane_reports_a_skip_with_a_reason_instead_of_failing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        lane, "stdlib_symlinks", lambda prefix: ["/usr/lib/python3/sitecustomize.py"]
    )
    out = lane.start_end_to_end(None, tmp_path, tmp_path)
    assert "sitecustomize.py" in out["skipped"] and "symlinks" in out["skipped"]
