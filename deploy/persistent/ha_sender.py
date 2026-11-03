#!/usr/bin/env python3
"""Standalone Home Assistant sender: ships the pipeline's delivery file to an HA webhook.

Usage: ha_sender.py CONFIG.json [--once] [--seed-at-end]

Runs OUTSIDE the pipeline (which stays on Network=none). Reads the JSON-lines file written by
`vigie_pipeline.delivery_publish.FilePublisher`, validates every record, and POSTs one JSON object
per record (delivery_id, sent_at, kind, title, body, link and, if configured, url) to the secret
webhook URL. Delivery is AT LEAST ONCE: a crash between a send and the cursor write can repeat one
message; the automation dedupes on `delivery_id`. A 2xx answer does NOT prove that an automation
ran (PRP-004, H0). Standard library only. See PRP-004 and "Home Assistant delivery" in
docs/monitoring.md.

Exit codes: 0 caught up (or another run holds the lock), 1 unexpected internal error,
2 configuration/cursor/secret-file error (including a missing cursor in an existing cursor
directory, see --seed-at-end), 3 permanent failure (any 4xx other than 408/425/429, a redirect,
an unexpected status; cursor NOT advanced past the record), 4 retryable failure or exhausted run
budget (cursor unchanged). Code 5 of the ntfy sender is not used. Log lines never contain the URL,
webhook id, host, response body or record text.

This file deliberately copies the private-file, cursor, lock and line-reading code of
ntfy_sender.py instead of importing it: the unit runs `python3 -I`, which cannot import a sibling
module, and ntfy_sender.py must stay untouched.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import secrets
import ssl
import stat
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import NoReturn
from urllib.parse import urlsplit

log = logging.getLogger("ha_sender")

EXIT_OK, EXIT_INTERNAL, EXIT_CONFIG, EXIT_PERMANENT, EXIT_RETRY = 0, 1, 2, 3, 4
MAX_LINE = 8192
MAX_CONFIG = 16384
MAX_SECRET = 1024
MAX_CURSOR = 4096
MAX_CA = 65536
MAX_RESPONSE = 4096
MAX_TIMEOUT = 20.0
MAX_BATCH_LIMIT = 1000
SEED_BLOCK = 65536
STALE_TEMP_AGE_S = 3600.0
MAX_SKIP_LOGS = 20  # further skipped records are counted, not logged one by one
RETRY_AFTER_CAP = 60.0
MAX_ATTEMPTS = 4
BACKOFF_BASE = 1.0
RUN_BUDGET_S = 120.0  # total wall-clock budget of one run
RETRY_STATUS = frozenset({408, 425, 429})  # 425 kept for parity with the ntfy sender
HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")
WEBHOOK_PATH_RE = re.compile(r"/api/webhook/[A-Za-z0-9_-]{1,128}")
KEY_NAME_RE = re.compile(r"[a-z_]{1,32}")  # unknown keys are echoed only when they look like this
DELIVERY_ID_RE = re.compile(r"[0-9a-f]{32}")
ALIAS_RE = re.compile(r"Device [a-z]{6}")  # the writer's stable alias; anything else fails closed
# Copied from vigie_pipeline.delivery_publish (the writer); a test asserts they stay equal.
TITLES = {"open": "Vigie: check {label}", "recover": "Vigie: {label} is back to normal"}
BODIES = {
    "open": "{label}: unusual activity detected. Review it here: {link}",
    "recover": "{label}: the activity has returned to normal. Details: {link}",
}
MAX_LABEL = 48
MAX_LINK = 200
LABEL_CHARS = r"[A-Za-z0-9 '’À-ÖØ-öø-ÿ-]"
LINK_PATTERN = r"/ui/#incident=[A-Za-z0-9%._~-]{1," + str(MAX_LINK - 14) + "}"
LIMITS = {"delivery_id": 128, "kind": 16, "title": 120, "body": 1000, "link": 200}
CONFIG_KEYS = frozenset(
    {
        "delivery_file",
        "cursor_file",
        "url_file",
        "allowed_hosts",
        "http_hosts",
        "ca_file",
        "start_at_end",
        "vigie_base_url",
        "timeout_seconds",
        "max_batch",
    }
)


class ConfigError(Exception):
    """Configuration, secret-file or cursor problem (exit 2). Messages carry no secret."""


class RedirectRefused(Exception):
    """The server answered with a redirect; redirects are never followed."""


@dataclass(frozen=True)
class Config:
    delivery_file: str
    cursor_file: str
    url_file: str
    allowed_hosts: tuple[str, ...]
    http_hosts: tuple[str, ...]
    ca_file: str | None
    start_at_end: bool
    vigie_base_url: str | None
    timeout_seconds: float
    max_batch: int


@dataclass(frozen=True)
class Record:
    delivery_id: str
    kind: str
    title: str
    body: str
    link: str


@dataclass(frozen=True)
class Cursor:
    offset: int = 0
    dev: int = 0
    ino: int = 0
    head: str = ""
    discard: bool = False  # inside an oversized line: skip bytes through its next newline


@dataclass(frozen=True)
class Outcome:
    kind: str  # "ok" | "retry" | "permanent"
    retry_after: float | None = None
    detail: str = ""


@dataclass(frozen=True)
class RunResult:
    sent: int
    skipped: int
    code: int


# --- private files -------------------------------------------------------------------------


def read_private_bytes(path: str, what: str, limit: int) -> bytes:
    """Bounded read of a regular file with mode 0600/0400; symlinks are refused.

    The owner must equal the EFFECTIVE uid of this process. Under `podman unshare` that is 0 and
    the host user's files appear as uid 0, so the check holds there; on a plain host it is the
    invoking user."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConfigError(f"cannot open {what}: {exc.strerror}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"{what} is not a regular file")
        if info.st_uid != os.geteuid():
            raise ConfigError(f"{what} is not owned by the effective user of this process")
        if stat.S_IMODE(info.st_mode) not in (0o600, 0o400):
            raise ConfigError(f"{what} must have mode 0600 or 0400")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ConfigError(f"{what} is too large")
    return data


def read_secret(path: str, what: str) -> str:
    data = read_private_bytes(path, what, MAX_SECRET)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{what} is not valid UTF-8") from exc
    text = text[:-1] if text.endswith("\n") else text
    if not text:
        raise ConfigError(f"{what} is empty")
    if any(unicodedata.category(c) == "Cc" for c in text):
        raise ConfigError(f"{what} contains control characters")
    return text


# --- hosts and URLs ------------------------------------------------------------------------


def normalize_host(value: str) -> str | None:
    """Lower-cased host name or canonical IP literal (IPv6 without brackets); None if invalid."""
    host = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host.lower() if HOST_RE.fullmatch(host) else None


def validate_webhook_url(
    value: str, allowed_hosts: tuple[str, ...], http_hosts: tuple[str, ...]
) -> str:
    """The secret webhook URL. Errors name only the failed rule, never host, path or id."""

    def bad(rule: str) -> NoReturn:
        raise ConfigError(f"webhook URL invalid: {rule}")

    if (
        not value
        or not value.isascii()
        or any(ord(c) <= 32 or ord(c) == 127 or c in "\\?#" for c in value)
    ):
        bad("characters")
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
    except ValueError:
        bad("host")
    if parts.scheme not in ("http", "https"):
        bad("scheme")
    if "@" in parts.netloc:
        bad("userinfo")
    host = normalize_host(hostname) if hostname else None
    if host is None:
        bad("host")
    try:
        parts.port  # noqa: B018 -- raises ValueError on a malformed or out-of-range port
    except ValueError:
        bad("port")
    if host not in allowed_hosts:
        bad("host")
    if parts.scheme == "http" and host not in http_hosts:
        bad("scheme")
    if not WEBHOOK_PATH_RE.fullmatch(parts.path):
        bad("path")
    return value


def build_ssl_context(ca_file: str | None) -> ssl.SSLContext:
    """System trust store, plus the optional additional trusted CA bundle (or certificate). Hostname
    checking and verification stay on; there is no way to turn them off."""
    context = ssl.create_default_context()
    if ca_file is None:
        return context
    data = read_private_bytes(ca_file, "CA file", MAX_CA)
    try:
        text = data.decode("ascii")
        if "-----BEGIN CERTIFICATE-----" not in text:
            raise ValueError("no certificate")
        context.load_verify_locations(cadata=text)
    except (UnicodeDecodeError, ValueError, ssl.SSLError) as exc:
        raise ConfigError("CA file is not a valid PEM certificate bundle") from exc
    return context


# --- configuration -------------------------------------------------------------------------


def _base_url(value: object) -> str:
    key = "vigie_base_url"
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ConfigError(f"{key} must be a URL without whitespace or control characters")
    if not value.isascii():
        raise ConfigError(f"{key} must be ASCII (no internationalised host names)")
    if "?" in value or "#" in value or "\\" in value or "@" in urlsplit(value).netloc:
        raise ConfigError(f"{key} must not contain userinfo, query or fragment")
    parts = urlsplit(value)
    try:
        parts.port  # noqa: B018 -- raises ValueError on a malformed port
    except ValueError as exc:
        raise ConfigError(f"{key} has an invalid port") from exc
    if parts.scheme != "https" or not parts.hostname:
        raise ConfigError(f"{key} must be an https URL")
    return value.rstrip("/")


def _abs_path(value: object, key: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise ConfigError(f"{key} must be an absolute path")
    return value


_PRIVATE_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128")
)


def _is_private_literal(host: str) -> bool:
    """RFC 1918 / loopback IPv4 or ULA / loopback IPv6 literal (a host name is never one)."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in net for net in _PRIVATE_NETS if net.version == address.version)


def _hosts(value: object, key: str, *, required: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (required and not value):
        raise ConfigError(f"{key} must be a {'non-empty ' if required else ''}list of hosts")
    hosts = [normalize_host(h) if isinstance(h, str) else None for h in value]
    if any(h is None for h in hosts):
        raise ConfigError(f"{key} must be a list of host names or IP addresses")
    return tuple(h for h in hosts if h is not None)


def _bounded_number(value: object, key: str, maximum: float, *, integer: bool) -> float:
    numeric = isinstance(value, int | float) and not isinstance(value, bool)
    if not numeric or (integer and not isinstance(value, int)) or not 0 < value <= maximum:  # type: ignore[operator]
        raise ConfigError(f"{key} must be a number in (0, {maximum:g}]")
    return float(value)  # type: ignore[arg-type]


def parse_config(raw: object) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("configuration must be a JSON object")
    unknown = sorted(set(raw) - CONFIG_KEYS, key=str)
    if unknown:
        shown = [k for k in unknown if isinstance(k, str) and KEY_NAME_RE.fullmatch(k)]
        hidden = len(unknown) - len(shown)
        extra = f" (and {hidden} with unprintable or oversized names)" if hidden else ""
        raise ConfigError("unknown configuration keys: " + ", ".join(shown) + extra)
    for key in ("delivery_file", "cursor_file", "url_file", "allowed_hosts"):
        if key not in raw:
            raise ConfigError(f"missing configuration key: {key}")
    allowed = _hosts(raw["allowed_hosts"], "allowed_hosts", required=True)
    plain = _hosts(raw.get("http_hosts", []), "http_hosts", required=False)
    if not set(plain) <= set(allowed):
        raise ConfigError("http_hosts must be a subset of allowed_hosts")
    for host in plain:
        if not _is_private_literal(host):
            log.warning(
                "an http_hosts entry is not a private-network address literal; plain HTTP to it "
                "exposes the secret URL and payload to anyone on the path"
            )
    start_at_end = raw.get("start_at_end", True)
    if not isinstance(start_at_end, bool):
        raise ConfigError("start_at_end must be true or false")
    ca, base = raw.get("ca_file"), raw.get("vigie_base_url")
    return Config(
        delivery_file=_abs_path(raw["delivery_file"], "delivery_file"),
        cursor_file=_abs_path(raw["cursor_file"], "cursor_file"),
        url_file=_abs_path(raw["url_file"], "url_file"),
        allowed_hosts=allowed,
        http_hosts=plain,
        ca_file=None if ca is None else _abs_path(ca, "ca_file"),
        start_at_end=start_at_end,
        vigie_base_url=None if base is None else _base_url(base),
        timeout_seconds=_bounded_number(
            raw.get("timeout_seconds", 8), "timeout_seconds", MAX_TIMEOUT, integer=False
        ),
        max_batch=int(
            _bounded_number(raw.get("max_batch", 50), "max_batch", MAX_BATCH_LIMIT, integer=True)
        ),
    )


def load_config(path: str) -> Config:
    data = read_private_bytes(path, "config file", MAX_CONFIG)
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ConfigError("config file is not valid JSON") from exc
    return parse_config(raw)


# --- cursor --------------------------------------------------------------------------------


def load_cursor(path: str) -> Cursor:
    data = read_private_bytes(path, "cursor file", MAX_CURSOR)
    try:
        raw = json.loads(data.decode("utf-8"))
        cursor = Cursor(
            raw["offset"], raw["dev"], raw["ino"], raw["head"], raw.get("discard", False)
        )
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise ConfigError("cursor file is corrupt; inspect or remove it deliberately") from exc
    ints = (cursor.offset, cursor.dev, cursor.ino)
    if (
        not all(type(n) is int and n >= 0 for n in ints)
        or type(cursor.discard) is not bool
        or not re.fullmatch(r"[0-9a-f]{0,16}", str(cursor.head))
    ):
        raise ConfigError("cursor file is corrupt; inspect or remove it deliberately")
    return cursor


def save_cursor(path: str, cursor: Cursor) -> None:
    """Atomic: unique temp file (O_EXCL) + fsync + rename + directory fsync. Mode 0600."""
    payload = json.dumps(
        {
            "offset": cursor.offset,
            "dev": cursor.dev,
            "ino": cursor.ino,
            "head": cursor.head,
            "discard": cursor.discard,
        }
    ).encode()
    tmp = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(tmp, flags, 0o600)  # O_EXCL: never touches a file we did not create
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        except BaseException:
            _unlink_quietly(tmp)
            raise
        _fsync_directory(os.path.dirname(path) or ".")
    except OSError as exc:
        raise ConfigError(f"cannot write cursor file: {exc.strerror}") from exc


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        log.debug("temporary cursor file already gone")


def _fsync_directory(path: str) -> None:
    dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def ensure_cursor_dir(cursor_file: str) -> None:
    """Create the cursor directory (mode 0700, parent must exist) if it is missing."""
    directory = os.path.dirname(cursor_file) or "."
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        return
    except OSError as exc:
        raise ConfigError(f"cannot create cursor directory: {exc.strerror}") from exc


def check_cursor_dir(cursor_file: str) -> None:
    """The cursor directory must be a real directory owned by the effective user and not
    group/world-writable. It must also lie outside every volume the pipeline mounts (documented;
    not detectable here)."""
    directory = os.path.dirname(cursor_file) or "."
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise ConfigError(f"cannot open cursor directory: {exc.strerror}") from exc
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    if info.st_uid != os.geteuid():
        raise ConfigError("cursor directory is not owned by the effective user of this process")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise ConfigError("cursor directory must not be group- or world-writable (use mode 0700)")


def acquire_lock(cursor_file: str) -> int | None:
    """Exclusive non-blocking lock on `<cursor_file>.lock`; None when another run holds it. The
    lock file must be a regular file owned by us with a single link."""
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(cursor_file + ".lock", flags, 0o600)
    except OSError as exc:
        raise ConfigError(f"cannot open lock file: {exc.strerror}") from exc
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        os.close(fd)
        raise ConfigError("lock file must be a regular file we own with a single link")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    except OSError as exc:
        os.close(fd)
        raise ConfigError(f"cannot lock the lock file: {exc.strerror}") from exc
    return fd


def clean_stale_temps(cursor_file: str, max_age: float = STALE_TEMP_AGE_S) -> None:
    """Remove our own leftover `<cursor>.<pid>.<8 hex>.tmp` files older than max_age. Only exact
    name matches, regular files (lstat, never followed) owned by us."""
    directory, base = os.path.split(cursor_file)
    pattern = re.compile(re.escape(base) + r"\.[0-9]+\.[0-9a-f]{8}\.tmp")
    try:
        names = os.listdir(directory or ".")
    except OSError as exc:
        raise ConfigError(f"cannot list cursor directory: {exc.strerror}") from exc
    for name in filter(pattern.fullmatch, names):
        path = os.path.join(directory, name)
        try:
            info = os.lstat(path)
            stale = time.time() - info.st_mtime > max_age
            if stale and stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid():
                os.unlink(path)
                log.info("removed a stale temporary cursor file")
        except OSError:
            log.debug("stale temporary cursor file could not be removed")


# --- delivery file -------------------------------------------------------------------------


@dataclass(frozen=True)
class Chunk:
    data: bytes
    start: int
    dev: int
    ino: int
    head: str
    restarted: bool
    discard: bool = False  # the chunk starts inside an oversized line


def _head_of(prefix: bytes) -> str:
    """Hash of the first line, from at most MAX_LINE + 1 bytes of the file start."""
    end = prefix[: MAX_LINE + 1].find(b"\n")
    return "" if end < 0 else hashlib.sha256(prefix[:end]).hexdigest()[:16]


def _first_line_hash(fd: int) -> str:
    return _head_of(os.pread(fd, MAX_LINE + 1, 0))


def _read_cap(cfg: Config) -> int:
    return cfg.max_batch * (MAX_LINE + 1)


def _open_delivery(cfg: Config) -> int | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        return os.open(cfg.delivery_file, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"cannot open delivery file: {exc.strerror}") from exc


def read_chunk(cfg: Config, cursor: Cursor) -> Chunk | None:
    """Bytes after the cursor, or None if the file does not exist yet. A replaced or truncated
    file (other inode, shorter than the offset, other first line) restarts at 0. The device
    number is ignored: the inode and the first-line hash identify the file."""
    fd = _open_delivery(cfg)
    if fd is None:
        return None
    with os.fdopen(fd, "rb"):
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("delivery file is not a regular file")
        head = _first_line_hash(fd)
        replaced = cursor.offset > 0 and (
            cursor.ino != info.st_ino or info.st_size < cursor.offset or cursor.head != head
        )
        if cursor.offset > 0 and not replaced and cursor.dev != info.st_dev:
            log.warning("device number of the delivery file changed; treating it as the same file")
        start = 0 if replaced else cursor.offset
        data = os.pread(fd, _read_cap(cfg), start)
    if start == 0:  # the file may have changed since the hash above: trust the bytes we read
        head = _head_of(data)
    discard = cursor.discard and not replaced
    return Chunk(data, start, info.st_dev, info.st_ino, head, replaced, discard)


def read_at(cfg: Config, previous: Chunk, offset: int) -> Chunk | None:
    """The next chunk of the SAME file (same inode, not shorter) at offset, else None."""
    fd = _open_delivery(cfg)
    if fd is None:
        return None
    with os.fdopen(fd, "rb"):
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_ino != previous.ino or info.st_size < offset:
            return None
        data = os.pread(fd, _read_cap(cfg), offset)
    return replace(previous, data=data, start=offset, restarted=False)


def split_lines(chunk: Chunk, cap: int) -> Iterator[tuple[bytes, int, bool]]:
    """Complete lines as (line, offset after it, False), produced one at a time. A partial
    trailing line is left alone, except a full chunk with no newline at all: that is the start of
    an oversized line, yielded once as (bytes, offset after them, True). The caller must then
    discard everything through that line's newline."""
    pos = 0
    found = False
    while (end := chunk.data.find(b"\n", pos)) >= 0:
        found = True
        yield chunk.data[pos:end], chunk.start + end + 1, False
        pos = end + 1
    if not found and len(chunk.data) >= cap:
        yield chunk.data, chunk.start + len(chunk.data), True


def _past_newline(chunk: Chunk) -> tuple[Chunk, bool]:
    """Drop the tail of an oversized line: bytes through the first newline. Returns the rest and
    whether we are still inside the line (no newline in this chunk)."""
    index = chunk.data.find(b"\n")
    if index < 0:
        return replace(chunk, data=b"", start=chunk.start + len(chunk.data)), True
    return replace(chunk, data=chunk.data[index + 1 :], start=chunk.start + index + 1), False


def iter_lines(
    cfg: Config, chunk: Chunk, discard: bool = False
) -> Iterator[tuple[bytes, int, bool]]:
    """Every complete line of the file from the chunk on; later chunks are read lazily, so a
    consumer that stops pulling never reads (or holds) more. After an oversized-line item
    (third element True) the rest of that line is dropped here, never parsed as a record. With
    `discard` the chunk starts inside such a line."""
    cap = _read_cap(cfg)
    while True:
        more = len(chunk.data) >= cap
        if discard:
            chunk, discard = _past_newline(chunk)
        last_end = None
        for item in split_lines(chunk, cap):
            last_end, discard = item[1], item[2]
            yield item
        if not more:
            return
        following = read_at(cfg, chunk, chunk.start if last_end is None else last_end)
        if following is None:
            return
        chunk = following


def _after_last_newline(fd: int, size: int) -> int:
    """Offset just after the last complete line in the first `size` bytes (0 if there is none)."""
    end = size
    while end > 0:
        start = max(0, end - SEED_BLOCK)
        index = os.pread(fd, end - start, start).rfind(b"\n")
        if index >= 0:
            return start + index + 1
        end = start
    return 0


def seed_cursor(cfg: Config) -> Cursor:
    """A cursor just after the last COMPLETE line (not the file size: the writer may be
    mid-append, and a partial trailing line must be sent once it completes)."""
    fd = _open_delivery(cfg)
    if fd is None:
        return Cursor()
    with os.fdopen(fd, "rb"):
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("delivery file is not a regular file")
        offset = _after_last_newline(fd, info.st_size)
        return Cursor(offset, info.st_dev, info.st_ino, _first_line_hash(fd) if offset else "")


def _template_regex(template: str) -> re.Pattern[str]:
    out = ""
    for index, part in enumerate(re.split(r"\{(label|link)\}", template)):
        if index % 2 == 0:
            out += re.escape(part)
        else:
            pattern = f"{LABEL_CHARS}{{1,{MAX_LABEL}}}" if part == "label" else LINK_PATTERN
            out += f"(?P<{part}>{pattern})"
    return re.compile(out)


TITLE_RES = {kind: _template_regex(t) for kind, t in TITLES.items()}
BODY_RES = {kind: _template_regex(t) for kind, t in BODIES.items()}


def _text(raw: dict[str, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not 1 <= len(value) <= LIMITS[key] or not value.isprintable():
        raise ValueError(f"invalid {key}")
    return value


def _check_shape(record: Record) -> None:
    """Title and body must be the writer's templates with one label and the record's own link;
    the label must be the stable alias (fail closed: a named device is never sent to HA)."""
    if record.kind not in TITLES or not DELIVERY_ID_RE.fullmatch(record.delivery_id):
        raise ValueError("invalid kind or delivery_id")
    if not re.fullmatch(LINK_PATTERN, record.link):
        raise ValueError("invalid link")
    title = TITLE_RES[record.kind].fullmatch(record.title)
    body = BODY_RES[record.kind].fullmatch(record.body)
    if not title or not body:
        raise ValueError("title or body does not match the message templates")
    if title["label"] != body["label"] or body["link"] != record.link:
        raise ValueError("title, body and link disagree")
    if not ALIAS_RE.fullmatch(title["label"]):
        raise ValueError("label is not a device alias")


def parse_record(line: bytes) -> Record:
    """Schema-validate one line. Raises ValueError with a fixed reason (never record text)."""
    if len(line) > MAX_LINE:
        raise ValueError("line too long")
    try:
        raw = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("not valid UTF-8 JSON") from exc
    except ValueError as exc:
        raise ValueError("not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("not an object")
    record = Record(*(_text(raw, k) for k in ("delivery_id", "kind", "title", "body", "link")))
    _check_shape(record)
    return record


# --- sending -------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> NoReturn:  # type: ignore[override]
        raise RedirectRefused


def build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )


def build_payload(cfg: Config, rec: Record) -> bytes:
    payload = {
        "delivery_id": rec.delivery_id,
        "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "kind": rec.kind,
        "title": rec.title,
        "body": rec.body,
        "link": rec.link,
    }
    if cfg.vigie_base_url:
        payload["url"] = cfg.vigie_base_url + rec.link
    return json.dumps(payload, separators=(",", ":")).encode()


def build_request(cfg: Config, url: str, rec: Record) -> urllib.request.Request:
    return urllib.request.Request(  # noqa: S310 -- scheme and host validated by validate_webhook_url
        url,
        data=build_payload(cfg, rec),
        headers={"Content-Type": "application/json"},
        method="POST",
    )


def parse_retry_after(value: str | None) -> float | None:
    if value is None or not re.fullmatch(r"[0-9]{1,6}", value.strip()):
        return None
    return min(float(value), RETRY_AFTER_CAP)


def classify_status(code: int, retry_after: str | None) -> Outcome:
    if 200 <= code < 300:
        return Outcome("ok")
    if code in RETRY_STATUS or 500 <= code < 600:
        return Outcome("retry", parse_retry_after(retry_after), f"HTTP {code}")
    return Outcome("permanent", None, f"HTTP {code}")


def send_once(
    opener: urllib.request.OpenerDirector, req: urllib.request.Request, timeout: float
) -> Outcome:
    try:
        with opener.open(req, timeout=timeout) as response:  # noqa: S310 -- validated URL
            status = response.status
            try:
                response.read(MAX_RESPONSE)
            except (OSError, http.client.HTTPException):
                log.debug("response body unreadable after the status line")  # status decides
            return classify_status(status, None)
    except urllib.error.HTTPError as exc:
        try:
            exc.read(MAX_RESPONSE)
        except (OSError, http.client.HTTPException):
            log.debug("error response body unreadable")
        return classify_status(exc.code, exc.headers.get("Retry-After"))
    except RedirectRefused:
        return Outcome("permanent", None, "redirect refused")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            return Outcome("permanent", None, "certificate verification failed")
        return Outcome("retry", None, type(exc.reason).__name__)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return Outcome("retry", None, type(exc).__name__)


def send_with_retry(
    opener: urllib.request.OpenerDirector,
    req: urllib.request.Request,
    timeout: float,
    sleep: Callable[[float], None],
    remaining: Callable[[], float],
) -> Outcome:
    """Send with bounded backoff. Each call gets min(timeout, remaining run budget); the budget is
    read before each request and again before each sleep. The budget is checked between
    operations: a single socket operation may still take up to `timeout`, and TimeoutStartSec is
    the hard stop."""
    delay = BACKOFF_BASE
    outcome = Outcome("retry", None, "run budget exhausted")
    for attempt in range(MAX_ATTEMPTS):
        call_timeout = min(timeout, remaining())
        if call_timeout <= 0:
            return Outcome("retry", None, "run budget exhausted")
        outcome = send_once(opener, req, call_timeout)
        if outcome.kind != "retry" or attempt == MAX_ATTEMPTS - 1:
            break
        wait = min(max(delay, outcome.retry_after or 0.0), RETRY_AFTER_CAP)
        if wait >= remaining():  # re-read: the request itself consumed time
            break
        log.warning("retryable failure (%s); retrying in %.0fs", outcome.detail, wait)
        sleep(wait)
        delay *= 2
    return outcome


# --- run -----------------------------------------------------------------------------------


def _drain(cfg: Config, chunk: Chunk, send: Callable[[Record], Outcome]) -> RunResult:
    """Send the records in order, at most max_batch lines per run. Any outcome other than ok
    stops the run with the cursor before that record (there is no per-record skip: PRP-004 D6)."""
    cursor = Cursor(chunk.start, chunk.dev, chunk.ino, chunk.head, chunk.discard)
    sent = skipped = taken = 0
    for line, end, oversized in iter_lines(cfg, chunk, chunk.discard):
        if taken >= cfg.max_batch:
            break
        taken += 1
        try:
            if oversized:
                raise ValueError("line too long")
            record = parse_record(line)
        except ValueError as exc:
            if skipped < MAX_SKIP_LOGS:
                log.warning("skipping invalid record before offset %d: %s", end, exc)
            skipped += 1
            cursor = replace(cursor, offset=end, discard=oversized)
            save_cursor(cfg.cursor_file, cursor)
            continue
        outcome = send(record)
        if outcome.kind != "ok":
            return _stop(outcome, sent, skipped)
        sent += 1
        cursor = replace(cursor, offset=end, discard=False)
        save_cursor(cfg.cursor_file, cursor)
    if skipped > MAX_SKIP_LOGS:
        log.warning(
            "%d records skipped in this run (only the first %d were logged)",
            skipped,
            MAX_SKIP_LOGS,
        )
    if skipped and not sent:
        log.error("every record read in this run was invalid and skipped; nothing was sent")
    if chunk.restarted and cursor.offset == 0:
        save_cursor(cfg.cursor_file, cursor)
    return RunResult(sent, skipped, EXIT_OK)


def _stop(outcome: Outcome, sent: int, skipped: int) -> RunResult:
    if outcome.kind == "permanent":
        log.error(
            "permanent publish failure (%s); stopping, cursor not advanced",
            outcome.detail,
        )
        return RunResult(sent, skipped, EXIT_PERMANENT)
    log.error("publish failed after retries (%s); cursor unchanged", outcome.detail)
    return RunResult(sent, skipped, EXIT_RETRY)


def run(
    cfg: Config,
    *,
    seed_at_end: bool = False,
    ssl_context: ssl.SSLContext | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    budget_seconds: float = RUN_BUDGET_S,
) -> RunResult:
    # Pure reads and validation first: a broken configuration must not leave a cursor directory
    # or lock file behind, nor consume the one-time seed.
    url = validate_webhook_url(
        read_secret(cfg.url_file, "webhook URL file"), cfg.allowed_hosts, cfg.http_hosts
    )
    context = ssl_context or build_ssl_context(cfg.ca_file)
    ensure_cursor_dir(cfg.cursor_file)
    check_cursor_dir(cfg.cursor_file)
    fd = acquire_lock(cfg.cursor_file)
    if fd is None:
        log.info("another run active; exiting")
        return RunResult(0, 0, EXIT_OK)
    try:
        fresh = _is_fresh(cfg.cursor_file, fd)  # decided by the lock winner alone
        cursor = _initial_cursor(cfg, fresh=fresh, seed_at_end=seed_at_end)
        clean_stale_temps(cfg.cursor_file)
        try:
            return _run_locked(cfg, url, context, cursor, sleep, clock, budget_seconds)
        finally:
            _mark_established(cfg.cursor_file, fd)
    finally:
        os.close(fd)


def _is_fresh(cursor_file: str, lock_fd: int) -> bool:
    """True when no run ever established a cursor here: the directory holds nothing but the lock
    file and the lock is unmarked. A lock left by a run that never got a cursor (failed first
    run, or a peer that lost the race) does not count as sender state."""
    try:
        others = set(os.listdir(os.path.dirname(cursor_file) or ".")) - {
            os.path.basename(cursor_file) + ".lock"
        }
        return not others and os.pread(lock_fd, 1, 0) == b""
    except OSError as exc:
        raise ConfigError(f"cannot inspect cursor directory: {exc.strerror}") from exc


def _mark_established(cursor_file: str, lock_fd: int) -> None:
    """Once a cursor exists, mark the lock so that a LATER missing cursor is recognised as lost
    (exit 2) rather than as a first run."""
    if not os.path.lexists(cursor_file):
        return
    try:
        os.pwrite(lock_fd, b"1", 0)
        os.fsync(lock_fd)
    except OSError as exc:
        log.warning(
            "cannot mark the lock file (%s); a lost cursor would be re-seeded", exc.strerror
        )


def _initial_cursor(cfg: Config, *, fresh: bool, seed_at_end: bool) -> Cursor:
    if os.path.lexists(cfg.cursor_file):
        return load_cursor(cfg.cursor_file)
    if not (seed_at_end or (cfg.start_at_end and fresh)):
        if cfg.start_at_end:
            raise ConfigError(
                "cursor file is missing from an existing cursor directory; the backlog would be "
                "dropped. If that is intended, run once with --seed-at-end"
            )
        return Cursor()  # start_at_end is false: replaying history is the owner's choice
    cursor = seed_cursor(cfg)
    save_cursor(cfg.cursor_file, cursor)
    log.warning(
        "cursor seeded at the end of the delivery file; skipped %d bytes of earlier messages",
        cursor.offset,
    )
    return cursor


def _run_locked(
    cfg: Config,
    url: str,
    context: ssl.SSLContext,
    cursor: Cursor,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
    budget_seconds: float,
) -> RunResult:
    opener = build_opener(context)
    chunk = read_chunk(cfg, cursor)
    if chunk is None:
        log.info("delivery file does not exist yet")
        return RunResult(0, 0, EXIT_OK)
    if chunk.restarted:
        log.warning("delivery file was truncated or replaced; restarting from the beginning")
    deadline = clock() + budget_seconds

    def send(record: Record) -> Outcome:
        request = build_request(cfg, url, record)
        return send_with_retry(
            opener, request, cfg.timeout_seconds, sleep, lambda: deadline - clock()
        )

    return _drain(cfg, chunk, send)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ship the Vigie delivery file to Home Assistant.")
    parser.add_argument("config")
    parser.add_argument("--once", action="store_true", help="one pass and exit (the default)")
    parser.add_argument(
        "--seed-at-end",
        action="store_true",
        help="one-shot: seed a missing cursor at the end of the delivery file (drops the backlog)",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        result = run(load_config(args.config), seed_at_end=args.seed_at_end)
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return EXIT_CONFIG
    except Exception as exc:  # noqa: BLE001 -- last resort; class name only, never the message
        log.error("unexpected error: %s", type(exc).__name__)
        return EXIT_INTERNAL
    print(f"ha_sender sent={result.sent} skipped={result.skipped} exit={result.code}")
    return result.code


if __name__ == "__main__":
    sys.exit(main())
