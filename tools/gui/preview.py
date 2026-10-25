#!/usr/bin/env python3
"""Isolated synthetic GUI preview; never loads environment-selected production DBs.

Seed writes only a NEW /tmp/vigie-gui-preview-* directory. Serve binds loopback18745,
uses explicit own DB paths and automatically exits after8hours. No live collector.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import math
import os
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

COLLECTOR = "synthetic-preview"
ATTACK_DEVICE = str(uuid.UUID(int=1))
INCIDENT = "synthetic-incident-1"
PREVIEW_SECONDS = 8 * 3600
PREVIEW_PARENT = Path("/tmp")  # noqa: S108 -- absent owned0700 child required; never shared files.
PORT = 18745
LOCK = PREVIEW_PARENT / "vigie-gui-preview-18745.lock"
DEFAULT_PACKAGE = PREVIEW_PARENT / "vigie-gui-wheel-target-attempt3"
DEFAULT_PYTHON = PREVIEW_PARENT / "vigie-pr9-native-server-env/bin/python"
CURRENT = "manager-current.json"
SYSTEM_UIDS = (0,)  # Accepted non-self owners of trusted paths; tests widen it for sandboxed /tmp.


def directory(value: str) -> Path:
    root = Path(value)
    if (
        not root.is_absolute()
        or root.parent != PREVIEW_PARENT
        or not root.name.startswith("vigie-gui-preview-")
        or root.resolve() != root
    ):
        raise ValueError("use a new direct /tmp/vigie-gui-preview-* directory without symlinks")
    return root


def seed(root: Path) -> dict:
    previous = os.umask(0o077)
    try:
        return _seed(root)
    finally:
        os.umask(previous)


def _seed(root: Path) -> dict:
    from vigie_api import tokens
    from vigie_api.schema import open_overrides
    from vigie_ingest.db import iso_utc
    from vigie_pipeline.schema import open_pipeline_inventory

    root.mkdir(mode=0o700)
    now = time.time()
    hour = int(now) // 3600 * 3600
    stamp = iso_utc(now)
    inv = open_pipeline_inventory(root / "inventory.db", migrate=True)
    ov = open_overrides(root / "overrides.db")
    try:
        inv.execute(
            "INSERT INTO collectors(id,key_id,boot_id,last_seq) VALUES (?,?,?,?)",
            (COLLECTOR, "synthetic-key", "synthetic-boot", 3),
        )
        for number in range(1, 56):
            device = str(uuid.UUID(int=number))
            mac = f"02:00:00:00:00:{number:02x}"
            inv.execute(
                "INSERT INTO devices(id,first_seen,last_seen,identity_state,status) "
                "VALUES (?,?,?,'ok','active')",
                (device, iso_utc(now - 86400), stamp),
            )
            inv.execute(
                "INSERT INTO observations(mac,device_id,is_randomized,hostname,link_source,"
                "first_seen,last_seen) VALUES (?,?,0,?,'self',?,?)",
                (mac, device, f"synthetic-host-{number:02d}", iso_utc(now - 86400), stamp),
            )
            name = (
                '<img src=x onerror="window.__guiInjected=1">'
                if number == 1
                else f"Synthetic device {number:02d}"
            )
            ov.execute(
                "INSERT INTO device_overrides(device_id,name,updated_at,updated_by) "
                "VALUES (?,?,?,'synthetic-preview')",
                (device, name, stamp),
            )
            if number % 3:
                address = f"192.0.2.{number}" if number % 3 == 1 else f"2001:db8::{number:x}"
                inv.execute(
                    "INSERT INTO mac_last_ip VALUES (?,?,?,'lease')", (mac, address, int(now))
                )
            for offset in range(1, 6):
                if offset == 3:
                    continue  # Actual missing hour, never zero-filled.
                inv.execute(
                    "INSERT INTO measurements_hourly VALUES (?,?,?,?,?,?,?)",
                    (
                        COLLECTOR,
                        mac,
                        hour - offset * 3600,
                        number * 1024 * offset,
                        number * 2048,
                        number,
                        number * 2,
                    ),
                )
        for offset in (1, 2, 4, 5):
            qualified = 1200 if offset == 2 else 3600
            reasons = '["synthetic_partial"]' if offset == 2 else "[]"
            inv.execute(
                "INSERT INTO coverage_hourly VALUES (?,?,?,?,?)",
                (COLLECTOR, hour - offset * 3600, qualified, qualified, reasons),
            )
        inv.execute(
            "INSERT INTO batches(collector_id,batch_id,received_at,window_start,window_end,"
            "observation_kind,dns_queries,health,truncated,dropped_batches) "
            "VALUES (?,?,?,?,?,'observation',3,?,?,0)",
            (
                COLLECTOR,
                "synthetic-batch",
                stamp,
                int(now) - 60,
                int(now),
                '{"rss_kb":2048,"uptime_s":600,"dns_log_quiet":false}',
                '{"source_flags":8}',
            ),
        )
        inv.execute(
            "INSERT INTO measurement_batches VALUES (?,?,?,?,?,?,?)",
            (
                COLLECTOR,
                "synthetic-batch",
                int(now) - 60,
                int(now),
                stamp,
                hour,
                '["synthetic_degraded_coverage"]',
            ),
        )
        evidence = {
            "reason_code": "large_upload_threshold",
            "hour": hour - 3600,
            "previous_hour": None,
            "observed_bytes": 1073741824,
            "threshold_bytes": 1073741824,
            "baseline_id": None,
            "algorithm": "pooled-median-v1",
            "config_version": "synthetic",
            "coverage_required_seconds": 3420,
            "lineage": "synthetic-lineage",
            "unusual_is_not_malicious": True,
        }
        inv.execute(
            "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
            "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,"
            "evidence) VALUES (?,?,?,'synthetic-lineage','large_upload','open',?,?,?,NULL,?,?,?)",
            (
                INCIDENT,
                COLLECTOR,
                ATTACK_DEVICE,
                hour - 3600,
                hour - 3600,
                stamp,
                1073741824,
                1073741824,
                json.dumps(evidence),
            ),
        )
        _, token = tokens.create_token(ov, "synthetic-gui", scope="read-only")
        with (root / "read-token.private").open("x", encoding="utf-8") as stream:
            stream.write(token + "\n")
        manifest = {
            "synthetic": True,
            "collector_id": COLLECTOR,
            "devices": 55,
            "attack_device_id": ATTACK_DEVICE,
            "incident_id": INCIDENT,
            "seeded_at": stamp,
            "url": "http://127.0.0.1:18745/ui/?preview=synthetic",
            "token_file": str(root / "read-token.private"),
            "expires_after_server_seconds": PREVIEW_SECONDS,
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return manifest
    finally:
        inv.close()
        ov.close()


def validate_namespace(root: Path) -> dict:
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o777 != 0o700:
        raise ValueError("preview directory must be privately owned0700")
    for name in ("inventory.db", "overrides.db", "manifest.json", "read-token.private"):
        path = root / name
        st = path.lstat()
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or st.st_mode & 0o777 != 0o600
            or st.st_nlink != 1
        ):
            raise ValueError("preview files must be owned0600 regular single-link files")
    manifest = read_private(root / "manifest.json", json_value=True)
    if (
        not isinstance(manifest, dict)
        or manifest.get("synthetic") is not True
        or manifest.get("collector_id") != COLLECTOR
        or manifest.get("token_file") != str(root / "read-token.private")
        or manifest.get("url") != "http://127.0.0.1:18745/ui/?preview=synthetic"
    ):
        raise ValueError("explicit synthetic seed manifest required")
    return manifest


def serve(root: Path, listen_fd: int | None = None) -> None:
    import uvicorn

    from vigie_api.app import create_app
    from vigie_api.config import Settings

    validate_namespace(root)
    listener = None if listen_fd is None else socket.socket(fileno=listen_fd)
    if listener is not None and (
        listener.family != socket.AF_INET
        or listener.getsockname() != ("127.0.0.1", PORT)
        or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
    ):
        listener.close()
        raise ValueError("only the fixed loopback preview listener may be inherited")
    settings = Settings(
        data_dir=root,
        inventory_db=root / "inventory.db",
        overrides_db=root / "overrides.db",
    )  # No environment DB/config paths are loaded.
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings),
            host="127.0.0.1",
            port=18745,
            access_log=False,
            log_level="warning",
            limit_concurrency=64,
            timeout_keep_alive=5,
            timeout_graceful_shutdown=5,
        )
    )
    timer = threading.Timer(PREVIEW_SECONDS, lambda: setattr(server, "should_exit", True))
    timer.daemon = True
    timer.start()
    try:
        if listener is None:
            server.run()
        else:
            server.run(sockets=[listener])
    finally:
        timer.cancel()
        if listener is not None:
            listener.close()


def read_private(path: Path, *, json_value: bool = False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_nlink != 1
            or st.st_size > 65536
        ):
            raise ValueError("unsafe manager/preview file")
        raw = os.read(fd, 65537)
        if len(raw) != st.st_size:
            raise ValueError("preview file changed while reading")
        return json.loads(raw) if json_value else raw
    finally:
        os.close(fd)


def write_new(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            raise OSError("short private receipt write")
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def event(journal: Path, value: dict) -> None:
    read_private(journal)  # Refuse symlink/metadata drift before opening for append.
    fd = os.open(journal, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    try:
        raw = (json.dumps({**value, "wall": time.time()}) + "\n").encode()
        if os.write(fd, raw) != len(raw):
            raise OSError("short manager event write")
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def manager_lock():
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        current = LOCK.lstat()
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_nlink != 1
            or (st.st_dev, st.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ValueError("unsafe shared preview lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def listeners() -> set[str]:
    found = set()
    for name in ("tcp", "tcp6"):
        rows = (Path("/proc/net") / name).read_text().splitlines()
        if not rows:
            raise ValueError("listener state unavailable")
        for row in rows[1:]:
            values = row.split()
            if len(values) < 10:
                raise ValueError("incomplete listener state")
            if int(values[1].rsplit(":", 1)[1], 16) == PORT and values[3] == "0A":
                found.add(values[9])
    return found


def process_identity(pid: int) -> dict | None:
    process = Path("/proc") / str(pid)
    try:
        st = process.stat()
        fields = (process / "stat").read_text().rsplit(") ", 1)[1].split()
        if fields[0] == "Z":
            return None
        argv = [x.decode() for x in (process / "cmdline").read_bytes().split(b"\0") if x]
        return {
            "pid": pid,
            "uid": st.st_uid,
            "start_ticks": fields[19],
            "argv": argv,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        }
    except (FileNotFoundError, ProcessLookupError):
        return None


def owns_listener(pid: int, inode: str) -> bool:
    for path in (Path("/proc") / str(pid) / "fd").iterdir():
        try:
            if os.readlink(path) == f"socket:[{inode}]":
                return True
        except FileNotFoundError:
            continue
    return False


def current_attempt(root: Path):
    pointer = root / CURRENT
    if not pointer.exists() and not pointer.is_symlink():
        return None, []
    pointer_value = read_private(pointer, json_value=True)
    if not isinstance(pointer_value, dict) or set(pointer_value) != {"journal"}:
        raise ValueError("invalid current preview pointer")
    name = pointer_value["journal"]
    if not isinstance(name, str):
        raise ValueError("invalid current preview journal name")
    if not re.fullmatch(r"managed-[0-9]+-[0-9a-f]{8}\.jsonl", name):
        raise ValueError("invalid current preview receipt")
    journal = root / name
    raw = read_private(journal)
    if not raw.endswith(b"\n"):
        raise ValueError("incomplete manager receipt; retain it and do not adopt a process")
    rows = [json.loads(line) for line in raw.splitlines()]
    if (
        not rows
        or any(not isinstance(row, dict) for row in rows)
        or rows[0].get("state") != "prepared"
        or rows[0].get("directory") != str(root)
    ):
        raise ValueError("manager receipt does not belong to this synthetic directory")
    required = {
        "state",
        "directory",
        "argv",
        "package_dir",
        "listener_inode",
        "log",
        "runtime_limit_seconds",
        "wall",
    }
    first = rows[0]
    if (
        set(first) != required
        or not isinstance(first["listener_inode"], str)
        or not first["listener_inode"].isdigit()
        or first["log"] != journal.stem + ".log"
        or first["runtime_limit_seconds"] != PREVIEW_SECONDS
        or not isinstance(first["package_dir"], str)
        or not Path(first["package_dir"]).is_absolute()
        or type(first["wall"]) not in (int, float)
        or not math.isfinite(first["wall"])
    ):
        raise ValueError("invalid prepared preview receipt")
    expected = rows[0].get("argv")
    if (
        not isinstance(expected, list)
        or len(expected) != 7
        or any(not isinstance(value, str) or "\0" in value for value in expected)
        or expected[1:5] != [str(Path(__file__).resolve()), "serve", "--directory", str(root)]
        or expected[5] != "--listen-fd"
        or not expected[6].isdigit()
    ):
        raise ValueError("invalid fixed child command in receipt")
    transitions = {
        "prepared": {"spawned", "failed-before-spawn", "startup-failed"},
        "spawned": {"ready", "startup-failed", "stop-requested"},
        "ready": {"stop-requested"},
        "startup-failed": {"stop-requested", "stopped"},
        "stop-requested": {"stop-requested", "stopped"},
        "stopped": set(),
        "failed-before-spawn": set(),
    }
    previous = "prepared"
    born = None
    for row in rows[1:]:
        state = row.get("state")
        if not isinstance(state, str) or state not in transitions[previous]:
            raise ValueError("invalid manager event ordering")
        if "identity" in row:
            identity = row["identity"]
            if (
                not isinstance(identity, dict)
                or set(identity) != {"pid", "uid", "start_ticks", "argv", "boot_id"}
                or type(identity["pid"]) is not int
                or identity["pid"] <= 1
                or type(identity["uid"]) is not int
                or identity["uid"] != os.getuid()
                or not isinstance(identity["start_ticks"], str)
                or not identity["start_ticks"].isdigit()
                or identity["argv"] != expected
                or not isinstance(identity["boot_id"], str)
                or not re.fullmatch(
                    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", identity["boot_id"]
                )
            ):
                raise ValueError("invalid child identity receipt")
            if state == "spawned":
                born = identity
            elif born is None or identity != born:
                raise ValueError("manager events disagree about the original child")
        elif state in {"spawned", "ready", "stop-requested", "stopped"}:
            raise ValueError("manager event missing original child identity")
        if state == "startup-failed" and born is None and row.get("child_exited") is not True:
            raise ValueError("startup child outcome is uncertain; retain the attempt")
        previous = state
    return journal, rows


def _orphan(rows: list, inodes: set[str]) -> dict | None:
    """The one process that is exactly our prepared child: same UID, full argv and listener."""
    inode = rows[0]["listener_inode"]
    if inodes != {inode}:
        return None
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            identity = process_identity(int(entry.name))
            if (
                identity is not None
                and identity["uid"] == os.getuid()
                and identity["argv"] == rows[0]["argv"]
                and owns_listener(identity["pid"], inode)
            ):
                found.append(identity)
        except OSError:
            continue
    return found[0] if len(found) == 1 else None


def status(root: Path) -> dict:
    manifest = validate_namespace(root)
    journal, rows = current_attempt(root)
    common = {
        "url": manifest["url"],
        "token_file": manifest["token_file"],
        "collector_id": COLLECTOR,
    }
    inodes = listeners()
    last = rows[-1] if rows else None
    if last is not None and (
        last["state"] in {"stopped", "failed-before-spawn"}
        or (last["state"] == "startup-failed" and last.get("child_exited") is True)
    ):  # Terminal: the recorded child is gone, so its PID may belong to anyone now.
        return {**common, "state": "unmanaged-listener" if inodes else "stopped", "managed": False}
    saved = next((row["identity"] for row in reversed(rows) if "identity" in row), None)
    if saved is None:
        if not rows:
            return {**common, "state": "unmanaged-listener" if inodes else "stopped", "managed": False}
        orphan = _orphan(rows, inodes)
        if orphan is not None:  # Crash between spawn and the `spawned` receipt.
            return {
                **common,
                "state": "orphaned",
                "managed": True,
                "pid": orphan["pid"],
                "start_ticks": orphan["start_ticks"],
                "journal": str(journal),
                "log": str(root / rows[0]["log"]),
                "runtime_limit_seconds": PREVIEW_SECONDS,
            }
        # Our listener dies with a crashed manager; with none open no child can exist.
        return {**common, "state": "uncertain" if inodes else "stopped", "managed": False}
    actual = process_identity(saved["pid"])
    if actual is None:
        return {**common, "state": "unmanaged-listener" if inodes else "stopped", "managed": False}
    if actual != saved or actual["uid"] != os.getuid():
        return {**common, "state": "identity-changed", "managed": False}
    inode = str(rows[0]["listener_inode"])
    owned = inodes == {inode} and owns_listener(saved["pid"], inode)
    return {
        **common,
        "state": "running" if owned and rows[-1]["state"] == "ready" else "uncertain",
        "managed": True,
        "pid": saved["pid"],
        "start_ticks": saved["start_ticks"],
        "journal": str(journal),
        "log": str(root / rows[0]["log"]),
        "runtime_limit_seconds": PREVIEW_SECONDS,
    }


def guarded_pidfd(identity: dict) -> int:
    require_pidfd()
    fd = os.pidfd_open(identity["pid"])
    try:
        if process_identity(identity["pid"]) != identity or identity["uid"] != os.getuid():
            raise ValueError("preview process identity changed; no signal sent")
        return fd
    except BaseException:
        os.close(fd)
        raise


def require_pidfd() -> None:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise ValueError("use native /usr/bin/python3 with Linux pidfd support for start/stop")


def _owners() -> tuple[int, ...]:
    return (*SYSTEM_UIDS, os.getuid())


def _trusted_chain(path: Path, message: str) -> None:
    for parent in (path, *path.parents):
        st = parent.lstat()
        if st.st_uid not in _owners() or (
            st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX
        ):
            raise ValueError(message)


def _trusted_tree(root: Path, message: str) -> None:
    """Every directory and file below root: no symlink, owned by root/us, not group/world-writable."""
    for current, names, files in os.walk(root, followlinks=False):
        for name in (*names, *files):
            st = (Path(current) / name).lstat()
            if (
                stat.S_ISLNK(st.st_mode)
                or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode))
                or st.st_uid not in _owners()
                or st.st_mode & 0o022
            ):
                raise ValueError(message)


def _package(value: Path) -> Path:
    """Trust the package directory, its ancestors and EVERY entry below it (no symlinks)."""
    root = value.absolute()
    if (
        root.resolve() != root
        or not root.is_dir()
        or root.stat().st_uid not in _owners()
        or root.stat().st_mode & 0o022
    ):
        raise ValueError("installed package directory must be trusted and without symlinks")
    _trusted_chain(root, "writable or foreign package ancestor")
    required = [
        "vigie_api/app.py",
        "vigie_api/ui_static.py",
        "vigie_ingest/db.py",
        "vigie_pipeline/schema.py",
    ]
    required += [
        "vigie_api/ui/" + x for x in ("index.html", "styles.css", "app.js", "client.js", "views.js")
    ]
    for name in required:
        path = root / name
        st = path.lstat()
        if (
            path.resolve() != path
            or not stat.S_ISREG(st.st_mode)
            or st.st_mode & 0o022
            or st.st_uid not in _owners()
        ):
            raise ValueError("unsafe or incomplete installed package")
    _trusted_tree(root, "unsafe or incomplete installed package")
    return root


def _interpreter(value: Path) -> Path:
    """Trust the resolved binary, the directory holding the launch path and any venv it names.

    The venv root (the folder holding pyvenv.cfg) and every lib*/python*/site-packages tree
    below it are checked as _package is: ancestors, owner, no group/world write, no symlinks.
    """
    unavailable = "native Python interpreter unavailable or untrusted; pass --python"
    python = value.absolute()
    try:
        resolved = python.resolve(strict=True)
        if (
            python.parent.resolve() != python.parent
            or not resolved.is_file()
            or not os.access(resolved, os.X_OK)
        ):
            raise ValueError(unavailable)
        _trusted_chain(resolved, unavailable)
        _trusted_chain(python.parent, unavailable)
        for base in (python.parent, python.parent.parent):
            if not os.path.lexists(base / "pyvenv.cfg"):
                continue
            cfg = (base / "pyvenv.cfg").lstat()
            if not stat.S_ISREG(cfg.st_mode) or cfg.st_uid not in _owners() or (
                cfg.st_mode & 0o022
            ):
                raise ValueError(unavailable)
            _trusted_chain(base, unavailable)
            for lib in ("lib", "lib64"):
                if os.path.lexists(base / lib):
                    for site in (base / lib).resolve(strict=True).glob("python*/site-packages"):
                        _trusted_chain(site, unavailable)
                        _trusted_tree(site, unavailable)
            break
    except OSError as exc:
        raise ValueError(unavailable) from exc
    return python


def _health() -> bool:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None

    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with client.open(f"http://127.0.0.1:{PORT}/healthz", timeout=0.5) as response:
        body = json.loads(response.read(16385))
        return response.status == 200 and isinstance(body, dict) and body.get("data") == "ok"


def _ready(child, identity: dict, inode: str) -> None:
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if child.poll() is not None or process_identity(child.pid) != identity:
            raise RuntimeError("preview exited or changed identity during startup")
        if listeners() != {inode} or not owns_listener(child.pid, inode):
            raise RuntimeError("readiness listener does not belong to the exact preview child")
        try:
            if _health():
                return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise RuntimeError("preview readiness timed out")


def cleanup_startup(child, pidfd: int | None) -> bool:
    """Only our retained child; never a guessed PID, process group or forced kill."""
    try:
        if pidfd is not None:
            with contextlib.suppress(ProcessLookupError):
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        else:
            # If pidfd acquisition failed, WNOWAIT proves this PID is still our
            # unreaped child before Popen's ownership-checked TERM operation.
            pending = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if pending is None:
                with contextlib.suppress(ProcessLookupError):
                    child.terminate()
        child.wait(timeout=6)
        return True
    except (ChildProcessError, OSError, subprocess.TimeoutExpired):
        return False


def _spawn_and_wait(journal, log, argv, listener, log_fd, root, package_dir, inode) -> None:
    child = None
    pidfd = None
    try:
        child = subprocess.Popen(  # noqa: S603 -- fixed script/argv; checked interpreter.
            argv,
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            cwd=root,
            start_new_session=True,
            close_fds=True,
            pass_fds=(listener.fileno(),),
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C.UTF-8",
                "PYTHONPATH": str(package_dir),
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        identity = process_identity(child.pid)
        if identity is None or identity["uid"] != os.getuid() or identity["argv"] != argv:
            raise RuntimeError("could not establish exact child identity")
        event(journal, {"state": "spawned", "identity": identity})
        pidfd = guarded_pidfd(identity)
        _ready(child, identity, inode)
        event(journal, {"state": "ready", "identity": identity})
    except BaseException as exc:  # Includes KeyboardInterrupt/SystemExit: never strand the child.
        exited = child is None or cleanup_startup(child, pidfd)
        event(
            journal,
            {
                "state": "failed-before-spawn" if child is None else "startup-failed",
                "error_type": type(exc).__name__,
                "child_exited": exited,
                "child_pid": None if child is None else child.pid,
            },
        )
        if isinstance(exc, OSError | ValueError | RuntimeError):
            raise RuntimeError(f"preview startup failed; retained private log {log}") from exc
        raise
    finally:
        if pidfd is not None:
            os.close(pidfd)


def start(root: Path, package_dir: Path | None, python: Path | None) -> dict:
    require_pidfd()  # Refuse unsupported controller runtimes before a child or receipt exists.
    validate_namespace(root)
    with manager_lock():
        before = status(root)
        if before["state"] == "running":
            return {**before, "already_running": True}
        if before["state"] != "stopped":
            raise ValueError("unmanaged listener or uncertain process; no start/adoption performed")
        _, prior = current_attempt(root)
        package_dir = _package(
            package_dir or Path(prior[0]["package_dir"] if prior else DEFAULT_PACKAGE)
        )
        python = _interpreter(python or Path(prior[0]["argv"][0] if prior else DEFAULT_PYTHON))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", PORT))
            listener.listen(128)
            inode = str(os.fstat(listener.fileno()).st_ino)
            attempt = f"managed-{time.time_ns()}-{uuid.uuid4().hex[:8]}"
            journal, log = root / (attempt + ".jsonl"), root / (attempt + ".log")
            argv = [
                str(python),
                str(Path(__file__).resolve()),
                "serve",
                "--directory",
                str(root),
                "--listen-fd",
                str(listener.fileno()),
            ]
            prepared = {
                "state": "prepared",
                "directory": str(root),
                "argv": argv,
                "package_dir": str(package_dir),
                "listener_inode": inode,
                "log": log.name,
                "runtime_limit_seconds": PREVIEW_SECONDS,
                "wall": time.time(),
            }
            if (root / CURRENT).is_symlink():
                raise ValueError("symlinked manager pointer")
            # The log exists before any receipt: a failure here leaves nothing to recover.
            log_fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                write_new(journal, (json.dumps(prepared) + "\n").encode())
                temporary = root / (CURRENT + "." + uuid.uuid4().hex)
                write_new(temporary, json.dumps({"journal": journal.name}).encode())
                os.replace(temporary, root / CURRENT)
                parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
                _spawn_and_wait(journal, log, argv, listener, log_fd, root, package_dir, inode)
            finally:
                os.close(log_fd)
        return status(root)


def stop(root: Path) -> dict:
    require_pidfd()
    validate_namespace(root)
    with manager_lock():
        before = status(root)
        if before["state"] == "stopped":
            return before
        if not before["managed"]:
            raise ValueError("refusing to stop an unmanaged or changed process")
        journal, rows = current_attempt(root)
        identity = next((row["identity"] for row in reversed(rows) if "identity" in row), None)
        adopted = identity is None
        if adopted:  # Orphaned child: re-verify it, then record it like any spawned child.
            identity = _orphan(rows, listeners())
            if identity is None:
                raise ValueError("refusing to stop an unmanaged or changed process")
        fd = guarded_pidfd(identity)
        try:
            if adopted:
                event(journal, {"state": "spawned", "identity": identity})
            event(journal, {"state": "stop-requested", "identity": identity})
            signal.pidfd_send_signal(fd, signal.SIGTERM)
            if not select.select([fd], [], [], 6)[0]:
                raise RuntimeError("owned preview is stopping; no forced kill; use status")
            event(journal, {"state": "stopped", "identity": identity})
        finally:
            os.close(fd)
        return status(root)


def _exit_on_signal(number: int, frame) -> None:
    raise SystemExit(128 + number)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("seed", "serve", "start", "status", "stop"))
    parser.add_argument("--directory", required=True)
    parser.add_argument(
        "--package-dir", type=Path, help="installed wheel target; remembers prior start"
    )
    parser.add_argument(
        "--python", type=Path, help="child Python; defaults to the existing native3.12 env"
    )
    parser.add_argument("--listen-fd", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, _exit_on_signal)  # Unwind start's cleanup instead of dying mid-spawn.
    try:
        root = directory(args.directory)
        if args.action == "seed":
            print(json.dumps(seed(root)))  # Safe manifest only, never token material.
        elif args.action == "serve":
            serve(root, args.listen_fd)
        elif args.action == "status":
            print(json.dumps(status(root)))
        elif args.action == "start":
            print(json.dumps(start(root, args.package_dir, args.python)))
        else:
            print(json.dumps(stop(root)))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"preview: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
