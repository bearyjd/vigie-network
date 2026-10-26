"""Real-pidfd lane for tools/gui/preview.py; NOT a test module (run by test_gui_preview_native.py).

    /usr/bin/python3 -I gui_preview_native_lane.py <preview.py> <seeded-dir> <workdir> <scenario>

Only the native Python has os.pidfd_open/signal.pidfd_send_signal; the cached uv build lacks
them. Everything is hermetic: an ephemeral loopback port replaces the fixed one, the shared
lock lives in <workdir>, and every child is a throwaway that only sleeps or answers /healthz.
Prints one JSON object. It never touches the fixed preview port or any other process.
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SLEEPER = "import time\ntime.sleep(120)\n"
HEALTH = """\
import http.server, json, socket, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"data": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler, bind_and_activate=False)
server.socket = socket.socket(fileno=int(sys.argv[-1]))
server.serve_forever()
"""


def load(preview_path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("pv", preview_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def journal_states(root: Path, pv) -> list:
    path = next(root.glob("managed-*.jsonl"))
    return [
        (row["state"], row.get("child_exited"))
        for row in map(json.loads, path.read_text().splitlines())
    ]


def sigblk(pid: int) -> str:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("SigBlk:"):
            return line.split()[1]
    return "?"


def fresh(root: Path, pv) -> None:
    for path in root.glob("managed-*"):
        path.unlink()
    (root / pv.CURRENT).unlink(missing_ok=True)


def swap_fork_exec(function) -> None:
    private: Any = subprocess  # _fork_exec is CPython-private; the lane targets the native build
    private._fork_exec = function


def popen_interrupt(pv, root: Path, work: Path, *, real_signal: bool) -> dict:
    """A termination lands in Popen's errpipe read after the real fork."""
    fresh(root, pv)
    pv._package = lambda p: p
    pv._interpreter = lambda p: p
    armed = [False]
    forked = []
    real_fork_exec = vars(subprocess)["_fork_exec"]
    real_read = os.read

    def fork_exec(*args, **kwargs):
        pid = real_fork_exec(*args, **kwargs)
        armed[0] = True
        forked.append(pid)
        if real_signal:
            os.kill(os.getpid(), signal.SIGTERM)  # pends while blocked, delivered after bind
        return pid

    def read(fd, count):
        if armed[0] and not real_signal:
            armed[0] = False
            raise SystemExit(143)  # what _exit_on_signal raises if a signal landed here
        return real_read(fd, count)

    if real_signal:
        for number in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, pv._exit_on_signal)
    swap_fork_exec(fork_exec)
    os.read = read
    raised = None
    try:
        pv.start(root, work / "pkg", Path("/usr/bin/python3"))
    except BaseException as exc:  # noqa: BLE001 -- the lane reports whatever escaped.
        raised = type(exc).__name__
    finally:
        os.read = real_read
        swap_fork_exec(real_fork_exec)
    pid = forked[0]
    time.sleep(0.4)
    out = {
        "raised": raised,
        "journal": journal_states(root, pv),
        "child_alive": pv.process_identity(pid) is not None,
    }
    if out["child_alive"]:
        out["child_sigblk"] = sigblk(pid)
        out["status"] = pv.status(root)["state"]
        try:
            out["stop"] = pv.stop(root)["state"]
        except Exception as exc:  # noqa: BLE001
            out["stop"] = f"refused: {exc}"
        time.sleep(0.2)
        out["alive_after_stop"] = pv.process_identity(pid) is not None
        if out["alive_after_stop"]:
            os.kill(pid, signal.SIGKILL)
    return out


def stop_with_real_pidfd(pv, root: Path, work: Path) -> dict:
    """A prepared-only orphan and a spawned-only receipt, each stopped through a real pidfd."""
    out = {}
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        pv.PORT = sock.getsockname()[1]
        fd = sock.fileno()
        argv = pv.child_argv(Path("/usr/bin/python3"), root, Path("/installed/package"), fd)
        inode = str(os.fstat(fd).st_ino)
        for name in ("orphan", "spawned"):
            fresh(root, pv)
            child = subprocess.Popen(  # noqa: S603 -- throwaway sleeper with the exact argv.
                argv, pass_fds=(fd,), env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL
            )
            time.sleep(0.3)
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
            if name == "spawned":
                rows.append({"state": "spawned", "identity": pv.process_identity(child.pid)})
            pv.write_new(journal, b"".join((json.dumps(r) + "\n").encode() for r in rows))
            pv.write_new(root / pv.CURRENT, json.dumps({"journal": journal.name}).encode())
            before = pv.status(root)["state"]
            result = pv.stop(root)["state"]
            out[name] = {
                "before": before,
                "after": result,
                "returncode": child.wait(timeout=10),
                "journal": [state for state, _ in journal_states(root, pv)],
            }
    return out


def uv_interpreters() -> list[Path]:
    """Interpreters uv manages (no distro symlinks in their stdlib); empty without uv."""
    found = []
    for command in (["uv", "python", "find", "3.12"], ["uv", "python", "find"]):
        try:
            done = subprocess.run(  # noqa: S603, S607 -- fixed read-only uv query, no shell.
                command, capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.SubprocessError):
            continue
        path = Path(done.stdout.strip())
        if done.returncode == 0 and path.is_absolute() and path.is_file() and path not in found:
            found.append(path)
    return found


NATIVE_FALLBACK = Path("/usr/bin/python3")


def venv_over(interpreter: Path, venv: Path) -> Path:
    """A venv shell over `interpreter`: the exact shape start() is asked to trust."""
    (venv / "bin").mkdir(parents=True, exist_ok=True)
    (venv / "bin" / "python").unlink(missing_ok=True)
    (venv / "bin" / "python").symlink_to(interpreter)
    (venv / "pyvenv.cfg").write_text(
        f"home = {interpreter.parent}\ninclude-system-site-packages = false\n"
    )
    (venv / "lib" / "python3" / "site-packages").mkdir(parents=True, exist_ok=True)
    return venv / "bin" / "python"


def child_interpreter(pv, work: Path) -> tuple[Path | None, str]:
    """The first candidate venv that preview's own trust check (`pv._interpreter`) accepts.

    Selection uses the very predicate start() applies (ownership, group/world-write bits, symlinks
    in the stdlib), so a candidate is never picked only to be refused later. Returns
    (venv python, "") or (None, reason naming each refusal).
    """
    refusals = []
    for index, candidate in enumerate([*uv_interpreters(), NATIVE_FALLBACK]):
        venv_python = venv_over(candidate.resolve(), work / f"venv{index}")
        try:
            pv._interpreter(venv_python)
        except (OSError, ValueError) as exc:
            refusals.append(f"{candidate}: {exc}")
            continue
        return venv_python, ""
    return None, "no interpreter passes the preview trust check (" + "; ".join(refusals) + ")"


def start_end_to_end(pv, root: Path, work: Path) -> dict:
    """start -> ready -> running -> stop -> stopped through the REAL _interpreter and pidfd."""
    fresh(root, pv)
    pv.PORT = free_port()
    pv._package = lambda p: p
    health = work / "health_preview.py"
    health.write_text(HEALTH)
    pv.__file__ = str(health)
    pv.SYSTEM_UIDS = (0, os.stat("/tmp").st_uid)  # noqa: S108 -- sandboxed /tmp owner
    python, reason = child_interpreter(pv, work)
    if python is None:  # The trust check refuses this host's interpreters by design.
        return {"skipped": reason}
    started = pv.start(root, work / "pkg", python)
    child_pid = started["pid"]
    out = {
        "started": started["state"],
        "argv_flags": pv.process_identity(child_pid)["argv"][1:3],
        "sigblk": sigblk(child_pid),
        "journal": [state for state, _ in journal_states(root, pv)],
    }
    out["stopped"] = pv.stop(root)["state"]
    out["journal_after"] = [state for state, _ in journal_states(root, pv)]
    return out


def main() -> int:
    preview_path, root, work = (Path(arg) for arg in sys.argv[1:4])
    scenario = sys.argv[4]
    pv = load(preview_path)
    pv.LOCK = work / "shared.lock"
    pv.PORT = free_port()
    sleeper = work / "sleeper_preview.py"
    sleeper.write_text(SLEEPER)
    pv.__file__ = str(sleeper)
    scenarios = {
        "popen-read-interrupt": lambda: popen_interrupt(pv, root, work, real_signal=False),
        "signal-during-popen": lambda: popen_interrupt(pv, root, work, real_signal=True),
        "stop-real-pidfd": lambda: stop_with_real_pidfd(pv, root, work),
        "start-end-to-end": lambda: start_end_to_end(pv, root, work),
    }
    print(json.dumps(scenarios[scenario]()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
