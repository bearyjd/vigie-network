#!/usr/bin/env python3
"""Real-clock 48-hour runner. No duration override, shell command, notification or scan."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from soak import CADENCE_SECONDS, DURATION_SECONDS, Journal, assess, sample_issues

_LIMIT = 16384
_QUESTION = b"\x07example\x03com\x00\x00\x01\x00\x01"


def private_read(path, limit=_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > limit
        ):
            raise ValueError("unsafe private input file")
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError("private input limit")
        return data
    finally:
        os.close(fd)


def _open_trusted_meter(path):
    """Walk trusted directory inodes without following any ancestor or leaf symlink."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("meter must be an absolute fixed executable")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            next_directory = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
            info = os.fstat(directory)
            # Sticky /tmp is safe for already-owned children; arbitrary writable ancestors
            # are not. The opened descriptor pins each checked inode during traversal.
            if info.st_uid not in (0, os.getuid()) or (
                info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
            ):
                raise ValueError("untrusted meter ancestor")
        return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)


def _sealed_meter(path, expected_digest):
    """Hash the exact copied bytes, then seal them against replacement AND in-place writes."""
    fd = _open_trusted_meter(path)
    snapshot = None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.getuid())
            or info.st_mode & 0o022
            or not info.st_mode & 0o111
            or info.st_size > 16 * 1024 * 1024
        ):
            raise ValueError("unsafe meter executable")
        snapshot = os.memfd_create(
            "vigie-reviewed-meter", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        )
        digest, size = hashlib.sha256(), 0
        while chunk := os.read(fd, 65536):
            size += len(chunk)
            if size > 16 * 1024 * 1024:
                raise ValueError("meter content limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot, view)
                if written == 0:
                    raise OSError("snapshot write made no progress")
                view = view[written:]
        if digest.hexdigest() != expected_digest:
            raise ValueError("meter differs from reviewed digest")
        os.fchmod(snapshot, 0o500)
        fcntl.fcntl(
            snapshot,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(snapshot, 0, os.SEEK_SET)
        result, snapshot = snapshot, None
        return result
    finally:
        os.close(fd)
        if snapshot is not None:
            os.close(snapshot)


def _cleanup_meter(child):
    # WNOWAIT proves this PID is still our child, live or waitable, without reaping it.
    # Its retained PID pins the session/group identity until AFTER group termination.
    # Never call Popen.poll()/wait() or use a reaped numeric PGID before this point.
    os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        child.wait()
        child.stdout.close()


def read_meter(path, expected_digest):
    """Execute one sealed Linux snapshot, supervise its process group, never use an agent."""
    if (
        not sys.platform.startswith("linux")
        or not hasattr(os, "memfd_create")
        or not hasattr(os, "WNOWAIT")
        or not hasattr(fcntl, "F_ADD_SEALS")
        or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
        or threading.active_count() != 1
    ):
        raise ValueError("meter requires Linux sealing and exclusive child supervision")
    snapshot = _sealed_meter(path, expected_digest)
    child = None
    try:
        child = subprocess.Popen(
            [f"/proc/self/fd/{snapshot}"],
            pass_fds=(snapshot,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        )
        data = bytearray()
        deadline = time.monotonic() + 10
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError("meter timeout")
                chunk = os.read(child.stdout.fileno(), 4096)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > _LIMIT:
                    raise ValueError("meter output exceeds bound")
        while True:
            status = os.waitid(
                os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG
            )
            if status is not None:
                break
            if time.monotonic() >= deadline:
                raise ValueError("meter timeout")
            time.sleep(0.01)
        if status.si_code != os.CLD_EXITED or status.si_status != 0:
            raise ValueError("meter failed")
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("meter must return one object")  # noqa: TRY004 -- adapter contract
        return result
    finally:
        try:
            if child is not None:
                _cleanup_meter(child)
        finally:
            os.close(snapshot)


def _dns_name(packet, offset, starts, wire_end=None):
    """Decode bounded wire labels, preserving boundaries; pointers target prior names only."""
    labels, seen, end, expanded = [], set(), None, 1
    wire_end = len(packet) if wire_end is None else wire_end
    for _ in range(128):
        # Inline RDATA bytes stay inside RDLENGTH. A pointer may resolve an
        # already-validated earlier name outside that interval.
        bound = len(packet) if end is not None else wire_end
        if not 12 <= offset < bound or offset in seen:
            raise ValueError("invalid DNS name offset")
        seen.add(offset)
        starts.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= bound:
                raise ValueError("short DNS pointer")
            target = ((size & 0x3F) << 8) | packet[offset + 1]
            if not 12 <= target < offset or target not in starts:
                raise ValueError("invalid DNS pointer target")
            if end is None:
                end = offset + 2
            offset = target
        elif size == 0:
            return tuple(labels), end if end is not None else offset + 1
        elif size <= 63:
            if offset + 1 + size > bound:
                raise ValueError("short DNS label")
            expanded += size + 1
            if expanded > 255:
                raise ValueError("DNS name exceeds wire limit")
            labels.append(packet[offset + 1 : offset + 1 + size].lower())
            offset += 1 + size
        else:
            raise ValueError("invalid DNS label")
    raise ValueError("DNS name traversal bound")


def dns_probe(router_address):
    """One fixed query; success requires a direct IN/A answer owned by example.com."""
    address = ipaddress.IPv4Address(router_address)
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        raise ValueError("invalid router probe address")
    query_id = os.urandom(2)
    packet = query_id + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + _QUESTION
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(3)
            connection.connect((str(address), 53))
            connection.send(packet)
            reply = connection.recv(4097)
        if not 12 <= len(reply) <= 4096 or reply[:2] != query_id:
            return False
        flags, questions, answers, authority, additional = struct.unpack(
            "!5H", reply[2:12]
        )
        if not (
            flags & 0x8000
            and not flags & 0x7A0F
            and questions == 1
            and 0 < answers <= 64
            and answers + authority + additional <= 128
        ):
            return False
        starts = set()
        expected = (b"example", b"com")
        question, offset = _dns_name(reply, 12, starts)
        if question != expected or reply[offset : offset + 4] != b"\0\1\0\1":
            return False
        offset += 4
        found = False
        for index in range(answers + authority + additional):
            owner, offset = _dns_name(reply, offset, starts)
            if offset + 10 > len(reply):
                return False
            kind, dns_class, _ttl, length = struct.unpack(
                "!HHIH", reply[offset : offset + 10]
            )
            offset += 10
            if offset + length > len(reply):
                return False
            if kind == 2 and dns_class == 1:
                # Register NS names for subsequent glue compression, without
                # resolving them or treating glue addresses as the probe answer.
                _, ns_end = _dns_name(reply, offset, starts, offset + length)
                if ns_end != offset + length:
                    return False
            found |= (
                index < answers
                and owner == expected
                and kind == 1
                and dns_class == 1
                and length == 4
            )
            offset += length
        return found and offset == len(reply)
    except (OSError, ValueError):
        return False


def _epoch(value):
    if type(value) in (float, int):
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            return parsed.timestamp() if parsed.tzinfo else None
        except ValueError:
            return None
    return None


def coverage_metrics(collector, now):
    result = {}
    mapping = {
        "collector_rss_kib": "agent_rss_kb",
        "backlog_batches": "backlog_batches",
        "dropped_batches": "dropped_batches_in_retained_detail",
        "source_flags": "source_flags_latest",
        "dns_log_quiet": "dns_log_quiet",
        "ct_unmapped_flows": "ct_unmapped_flows_in_retained_detail",
        "ct_unmapped_bytes": "ct_unmapped_bytes_in_retained_detail",
    }
    for target, source in mapping.items():
        result[target] = collector.get(source)
    for target, source in (
        ("freshness_s", "latest_window_end"),
        ("dns_parsed_age_s", "latest_dns_observation_window_end"),
    ):
        timestamp = _epoch(collector.get(source))
        result[target] = now - timestamp if timestamp is not None else None
    # Exact typed API contract: a capped or absent summary is unknown, never favorable zero.
    if collector.get("backlog_capped") is not False:
        result["backlog_batches"] = None
    if collector.get("summary_capped") is not False:
        for key in ("dropped_batches", "ct_unmapped_flows", "ct_unmapped_bytes"):
            result[key] = None
    return result


def read_coverage(config, now):
    token = private_read(config["api_token_file"], 1024).decode("ascii").strip()
    if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("invalid token file")
    hour = int(now // 3600) * 3600
    query = urllib.parse.urlencode(
        {
            "collector_id": config["collector_id"],
            "from_hour": hour - 3600,
            "to_hour": hour,
        }
    )
    context = ssl.create_default_context(cafile=config["api_ca_file"])
    request = urllib.request.Request(
        f"https://127.0.0.1:{config['api_port']}/coverage?{query}",
        headers={"Authorization": "Bearer " + token},
    )

    # Never follow redirects carrying the bearer token to a different origin.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_):
            return None

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirect()
    )
    with opener.open(request, timeout=10) as response:
        body = response.read(262145)
        if len(body) > 262144:
            raise ValueError("coverage response limit")
    collector = json.loads(body)["data"]["collector"]
    return coverage_metrics(collector, now)


def clock_sample():
    return {
        "wall": time.time(),
        "monotonic": time.monotonic(),
        "boottime": time.clock_gettime(time.CLOCK_BOOTTIME),
        "host_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def collect(config):
    result = clock_sample()
    try:
        meter = read_meter(config["meter_executable"], config["meter_sha256"])
        # Keep only the metric schema, never arbitrary command output/household strings.
        allowed = {
            "router_boot_id",
            "collector_start",
            "helper_start",
            "collector_rss_kib",
            "helper_rss_kib",
            "mem_available_kib",
            "log_used_kib",
            "log_capacity_kib",
            "collector_cpu_ticks",
            "total_cpu_ticks",
            "logical_cpus",
        }
        result.update({key: value for key, value in meter.items() if key in allowed})
    except (OSError, ValueError, subprocess.SubprocessError):
        result["meter_error"] = True
    try:
        api_metrics = read_coverage(config, result["wall"])
        # Historical API health must never replace the independent live resource meter.
        if "collector_rss_kib" in api_metrics:
            api_metrics["api_collector_rss_kib"] = api_metrics.pop("collector_rss_kib")
        result.update(api_metrics)
    except (OSError, ValueError, KeyError, TypeError):
        result["coverage_error"] = True
    result["dns_probe_ok"] = dns_probe(config["router_address"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("journal", type=Path)
    parser.add_argument(
        "--preflight", action="store_true", help="one sample; never a 48-hour pass"
    )
    args = parser.parse_args()
    raw = private_read(args.config)
    config = json.loads(raw)
    required = {
        "api_port",
        "api_token_file",
        "api_ca_file",
        "collector_id",
        "meter_executable",
        "meter_sha256",
        "router_address",
    }
    if (
        not isinstance(config, dict)
        or set(config) != required
        or type(config["api_port"]) is not int
        or not 1024 <= config["api_port"] <= 65535
    ):
        raise ValueError("invalid fixed configuration")
    if not isinstance(config["collector_id"], str) or not re.fullmatch(
        r"[a-zA-Z0-9_-]{1,64}", config["collector_id"]
    ):
        raise ValueError("invalid collector selector")
    if not isinstance(config["meter_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", config["meter_sha256"]
    ):
        raise ValueError("invalid reviewed meter digest")
    # Fail before entering the collection loop for an invalid target, not as a missing metric.
    address = ipaddress.IPv4Address(config["router_address"])
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        raise ValueError("invalid router address")
    first = collect(config)
    failures, missing, quality = sample_issues(first)
    if args.preflight:
        report = assess([first], mode="real")
        print(json.dumps(report))
        return 1 if failures else 2
    if not args.journal.parent.exists():
        args.journal.parent.mkdir(mode=0o700)
    metadata = {"config_sha256": hashlib.sha256(raw).hexdigest()}
    with Journal(args.journal, mode="real", metadata=metadata) as journal:
        journal.append(first)
        # Every resumed observation, including failure or absence, is durable before gates.
        if failures or missing or quality:
            report = assess(journal.samples, mode="real")
            print(json.dumps(report))
            return 1 if report["status"] == "fail" else 2
        try:
            while True:
                report = assess(journal.samples, mode="real")
                if (
                    report["status"] in ("fail", "pass")
                    or report["elapsed_seconds"] >= DURATION_SECONDS
                ):
                    break
                next_time = journal.samples[-1]["monotonic"] + CADENCE_SECONDS
                time.sleep(max(0, next_time - time.monotonic()))
                journal.append(collect(config))
        except KeyboardInterrupt:
            report = assess(journal.samples, mode="real")
            report["interrupted"] = True
        print(json.dumps(report))
        return {"pass": 0, "fail": 1, "pending": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
