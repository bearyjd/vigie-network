#!/usr/bin/env python3
"""Standalone ntfy sender: ships the pipeline's delivery file to a public ntfy server.

Usage: ntfy_sender.py CONFIG.json [--once]

Runs OUTSIDE the pipeline (which stays on Network=none). Reads the JSON-lines file written by
`vigie_pipeline.delivery_publish.FilePublisher`, validates every record, and POSTs only the
validated Message fields. Delivery is AT LEAST ONCE: a crash between a send and the cursor write
can repeat one notification. Standard library only.

Exit codes: 0 caught up (or another run holds the lock), 1 unexpected internal error,
2 configuration/cursor/secret-file error, 3 permanent publish failure (cursor NOT advanced past
the record), 4 retryable failure or exhausted run budget (cursor unchanged), 5 caught up but a
record the server rejected was skipped. Log lines never contain the URL, topic, token,
response body or record text.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
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
from typing import NoReturn
from urllib.parse import urlsplit

log = logging.getLogger("ntfy_sender")

EXIT_OK, EXIT_INTERNAL, EXIT_CONFIG, EXIT_PERMANENT, EXIT_RETRY, EXIT_REJECTED = 0, 1, 2, 3, 4, 5
MAX_LINE = 8192
MAX_CONFIG = 16384
MAX_SECRET = 1024
MAX_CURSOR = 4096
MAX_RESPONSE = 4096
MAX_TIMEOUT = 20.0
MAX_BATCH_LIMIT = 1000
MIN_BATCH = 2  # a rejected record needs a successor in the same read to be probed
STALE_TEMP_AGE_S = 3600.0
RETRY_AFTER_CAP = 60.0
MAX_ATTEMPTS = 4
BACKOFF_BASE = 1.0
DEFAULT_SERVER = "https://ntfy.sh"
TOPIC_RE = re.compile(r"[A-Za-z0-9_-]{24,64}")  # ntfy.sh allows at most 64 characters
TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{1,512}")
RUN_BUDGET_S = 120.0  # total wall-clock budget of one run
RETRY_STATUS = frozenset({408, 425, 429})
REJECT_STATUS = frozenset({400, 413, 414, 422})
HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")
TAGS = {"open": "warning", "recover": "white_check_mark"}
# Copied from vigie_pipeline.delivery_publish (the writer); a test asserts they stay equal.
TITLES = {"open": "Vigie: check {label}", "recover": "Vigie: {label} is back to normal"}
BODIES = {
    "open": "{label}: unusual activity detected. Review it here: {link}",
    "recover": "{label}: the activity has returned to normal. Details: {link}",
}
MAX_LABEL = 48
MAX_LINK = 200
LABEL_CHARS = r"[A-Za-z0-9 '\u2019\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u00ff-]"
LINK_PATTERN = r"/ui/#incident=[A-Za-z0-9%._~-]{1," + str(MAX_LINK - 14) + "}"
LIMITS = {"delivery_id": 128, "kind": 16, "title": 120, "body": 1000, "link": 200}
CONFIG_KEYS = frozenset(
    {
        "delivery_file",
        "cursor_file",
        "topic_file",
        "token_file",
        "server",
        "allowed_hosts",
        "click_base",
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
    topic_file: str
    token_file: str | None
    server: str
    allowed_hosts: tuple[str, ...]
    click_base: str | None
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


@dataclass(frozen=True)
class Outcome:
    kind: str  # "ok" | "retry" | "permanent" | "rejected" (this one record, not the channel)
    retry_after: float | None = None
    detail: str = ""


@dataclass(frozen=True)
class RunResult:
    sent: int
    skipped: int
    code: int
    rejected: int = 0  # records the server refused and that were skipped after a good probe


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
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"{what} is not a regular file")
        if info.st_uid != os.geteuid():
            raise ConfigError(f"{what} is not owned by the effective user of this process")
        if stat.S_IMODE(info.st_mode) not in (0o600, 0o400):
            raise ConfigError(f"{what} must have mode 0600 or 0400")
        data = stream.read(limit + 1)
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


def load_topic(path: str) -> str:
    topic = read_secret(path, "topic file")
    if not TOPIC_RE.fullmatch(topic):
        raise ConfigError("topic must be 24-64 characters of A-Z a-z 0-9 _ -")
    return topic


def load_token(path: str) -> str:
    token = read_secret(path, "token file")
    if not TOKEN_RE.fullmatch(token):
        raise ConfigError("token must be 1-512 characters of A-Z a-z 0-9 . _ ~ + / = -")
    return token


# --- configuration -------------------------------------------------------------------------


def _https_url(value: object, key: str, *, path_ok: bool) -> str:
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
    if parts.path not in ("", "/") and not path_ok:
        raise ConfigError(f"{key} must not have a path")
    return value.rstrip("/")


def _abs_path(value: object, key: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise ConfigError(f"{key} must be an absolute path")
    return value


def _hosts(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError("allowed_hosts must be a non-empty list of host names")
    hosts = [h for h in value if isinstance(h, str) and HOST_RE.fullmatch(h)]
    if len(hosts) != len(value):
        raise ConfigError("allowed_hosts must be a non-empty list of host names")
    return tuple(h.lower() for h in hosts)


def _bounded_number(value: object, key: str, maximum: float, *, integer: bool) -> float:
    numeric = isinstance(value, int | float) and not isinstance(value, bool)
    if not numeric or (integer and not isinstance(value, int)) or not 0 < value <= maximum:  # type: ignore[operator]
        raise ConfigError(f"{key} must be a number in (0, {maximum:g}]")
    return float(value)  # type: ignore[arg-type]


def _max_batch(value: object) -> int:
    batch = int(_bounded_number(value, "max_batch", MAX_BATCH_LIMIT, integer=True))
    if batch < MIN_BATCH:
        raise ConfigError(f"max_batch must be at least {MIN_BATCH}")
    return batch


def parse_config(raw: object) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("configuration must be a JSON object")
    unknown = sorted(set(raw) - CONFIG_KEYS)
    if unknown:
        raise ConfigError("unknown configuration keys: " + ", ".join(map(str, unknown)))
    for key in ("delivery_file", "cursor_file", "topic_file"):
        if key not in raw:
            raise ConfigError(f"missing configuration key: {key}")
    hosts = _hosts(raw.get("allowed_hosts", ["ntfy.sh"]))
    server = _https_url(raw.get("server", DEFAULT_SERVER), "server", path_ok=False)
    if (urlsplit(server).hostname or "").lower() not in hosts:
        raise ConfigError("server host is not in allowed_hosts")
    click = raw.get("click_base")
    token = raw.get("token_file")
    return Config(
        delivery_file=_abs_path(raw["delivery_file"], "delivery_file"),
        cursor_file=_abs_path(raw["cursor_file"], "cursor_file"),
        topic_file=_abs_path(raw["topic_file"], "topic_file"),
        token_file=None if token is None else _abs_path(token, "token_file"),
        server=server,
        allowed_hosts=hosts,
        click_base=None if click is None else _https_url(click, "click_base", path_ok=True),
        timeout_seconds=float(
            _bounded_number(
                raw.get("timeout_seconds", 8), "timeout_seconds", MAX_TIMEOUT, integer=False
            )
        ),
        max_batch=_max_batch(raw.get("max_batch", 50)),
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
    if not os.path.lexists(path):
        return Cursor()
    data = read_private_bytes(path, "cursor file", MAX_CURSOR)
    try:
        raw = json.loads(data.decode("utf-8"))
        cursor = Cursor(raw["offset"], raw["dev"], raw["ino"], raw["head"])
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise ConfigError("cursor file is corrupt; inspect or remove it deliberately") from exc
    ints = (cursor.offset, cursor.dev, cursor.ino)
    if not all(type(n) is int and n >= 0 for n in ints) or not re.fullmatch(
        r"[0-9a-f]{0,16}", str(cursor.head)
    ):
        raise ConfigError("cursor file is corrupt; inspect or remove it deliberately")
    return cursor


def save_cursor(path: str, cursor: Cursor) -> None:
    """Atomic: unique temp file (O_EXCL) + fsync + rename + directory fsync. Mode 0600."""
    payload = json.dumps(
        {"offset": cursor.offset, "dev": cursor.dev, "ino": cursor.ino, "head": cursor.head}
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


def _first_line_hash(fd: int) -> str:
    prefix = os.pread(fd, MAX_LINE + 1, 0)
    end = prefix.find(b"\n")
    return "" if end < 0 else hashlib.sha256(prefix[:end]).hexdigest()[:16]


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
    return Chunk(data, start, info.st_dev, info.st_ino, head, replaced)


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


def split_lines(chunk: Chunk, cap: int) -> list[tuple[bytes, int]]:
    """Complete lines as (line, offset after it). A partial trailing line is left alone, except a
    full chunk with no newline at all: that is one oversized line and is skipped by the caller."""
    lines: list[tuple[bytes, int]] = []
    pos = 0
    while (end := chunk.data.find(b"\n", pos)) >= 0:
        lines.append((chunk.data[pos:end], chunk.start + end + 1))
        pos = end + 1
    if not lines and len(chunk.data) >= cap:
        lines.append((chunk.data, chunk.start + len(chunk.data)))
    return lines


def iter_lines(cfg: Config, chunk: Chunk) -> Iterator[tuple[bytes, int]]:
    """Every complete line of the file from the chunk on; later chunks are read lazily, so a
    consumer that stops pulling never reads more."""
    cap = _read_cap(cfg)
    while True:
        lines = split_lines(chunk, cap)
        yield from lines
        if not lines or len(chunk.data) < cap:
            return
        following = read_at(cfg, chunk, lines[-1][1])
        if following is None:
            return
        chunk = following


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
    """Title and body must be the writer's templates with one label and the record's own link."""
    if record.kind not in TAGS or " " in record.delivery_id:
        raise ValueError("invalid kind or delivery_id")
    if not re.fullmatch(LINK_PATTERN, record.link):
        raise ValueError("invalid link")
    title = TITLE_RES[record.kind].fullmatch(record.title)
    body = BODY_RES[record.kind].fullmatch(record.body)
    if not title or not body:
        raise ValueError("title or body does not match the message templates")
    if title["label"] != body["label"] or body["link"] != record.link:
        raise ValueError("title, body and link disagree")


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
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )


def ascii_title(title: str) -> str:
    plain = title.replace("\u2019", "'")
    folded = unicodedata.normalize("NFKD", plain).encode("ascii", "ignore").decode("ascii")
    return folded.strip() or "Vigie"


def build_request(
    cfg: Config, topic: str, token: str | None, rec: Record
) -> urllib.request.Request:
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Title": ascii_title(rec.title),
        "Tags": TAGS[rec.kind],
        "Priority": "default",
    }
    if cfg.click_base:
        headers["Click"] = cfg.click_base + rec.link
    if token:
        headers["Authorization"] = "Bearer " + token
    return urllib.request.Request(  # noqa: S310 -- https-only, validated in parse_config
        f"{cfg.server}/{topic}", data=rec.body.encode("utf-8"), headers=headers, method="POST"
    )


def parse_retry_after(value: str | None) -> float | None:
    if value is None or not re.fullmatch(r"[0-9]{1,6}", value.strip()):
        return None
    return min(float(value), RETRY_AFTER_CAP)


def classify_status(code: int, retry_after: str | None) -> Outcome:
    if code == 200:
        return Outcome("ok")
    if code in RETRY_STATUS or 500 <= code < 600:
        return Outcome("retry", parse_retry_after(retry_after), f"HTTP {code}")
    if code in REJECT_STATUS:
        return Outcome("rejected", None, f"HTTP {code}")
    return Outcome("permanent", None, f"HTTP {code}")


def send_once(
    opener: urllib.request.OpenerDirector, req: urllib.request.Request, timeout: float
) -> Outcome:
    try:
        with opener.open(req, timeout=timeout) as response:  # noqa: S310 -- https-only, validated
            response.read(MAX_RESPONSE)
            return classify_status(response.status, None)
    except urllib.error.HTTPError as exc:
        try:
            exc.read(MAX_RESPONSE)
        except (OSError, http.client.HTTPException):
            log.debug("error response body unreadable")
        return classify_status(exc.code, exc.headers.get("Retry-After"))
    except RedirectRefused:
        return Outcome("permanent", None, "redirect refused")
    except UnicodeEncodeError as exc:
        raise ConfigError("request contains characters that cannot be encoded") from exc
    except (OSError, http.client.HTTPException, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return Outcome("retry", None, type(reason).__name__)


def send_with_retry(
    opener: urllib.request.OpenerDirector,
    req: urllib.request.Request,
    timeout: float,
    sleep: Callable[[float], None],
    remaining: Callable[[], float],
) -> Outcome:
    """Send with bounded backoff. Each call gets min(timeout, remaining run budget); the budget is
    read once per attempt. The budget is checked between operations: a single socket operation
    may still take up to `timeout`, and TimeoutStartSec is the hard stop."""
    delay = BACKOFF_BASE
    outcome = Outcome("retry", None, "run budget exhausted")
    for attempt in range(MAX_ATTEMPTS):
        left = remaining()
        call_timeout = min(timeout, left)
        if call_timeout <= 0:
            return Outcome("retry", None, "run budget exhausted")
        outcome = send_once(opener, req, call_timeout)
        if outcome.kind != "retry" or attempt == MAX_ATTEMPTS - 1:
            break
        wait = min(max(delay, outcome.retry_after or 0.0), RETRY_AFTER_CAP)
        if wait >= left:
            break
        log.warning("retryable failure (%s); retrying in %.0fs", outcome.detail, wait)
        sleep(wait)
        delay *= 2
    return outcome


# --- run -----------------------------------------------------------------------------------


def _drain(
    cfg: Config,
    chunk: Chunk,
    send: Callable[[Record], Outcome],
    expired: Callable[[], bool],
) -> RunResult:
    """Send the records in order, at most max_batch lines per run. A record the server REJECTS
    (400/413/414/422) is held back until the next valid record succeeds (a probe), however far
    away it is: then it is skipped for good (exit 5). If the probe is rejected too, or the file
    ends without a valid successor, the run stops with exit 3 and the cursor stays before it."""
    cursor = Cursor(chunk.start, chunk.dev, chunk.ino, chunk.head)
    sent = skipped = rejected = taken = 0
    held: int | None = None  # file offset just after the rejected record
    for line, end in iter_lines(cfg, chunk):
        if held is None and taken >= cfg.max_batch:
            break
        if held is not None and expired():
            return _stop(Outcome("retry", None, "run budget exhausted"), sent, skipped)
        taken += 1
        try:
            record = parse_record(line)
        except ValueError as exc:
            log.warning("skipping invalid record before offset %d: %s", end, exc)
            skipped += 1
            if held is None:
                cursor = replace(cursor, offset=end)
                save_cursor(cfg.cursor_file, cursor)
            continue
        outcome = send(record)
        if outcome.kind == "rejected" and held is None:
            log.error(
                "record before offset %d rejected (%s); probing the next one", end, outcome.detail
            )
            held = end
            continue
        if outcome.kind != "ok":
            return _stop(outcome, sent, skipped)
        if held is not None:
            log.error("record skipped permanently (rejected by the server) before offset %d", held)
            skipped, rejected, held = skipped + 1, rejected + 1, None
        sent += 1
        cursor = replace(cursor, offset=end)
        save_cursor(cfg.cursor_file, cursor)
    if held is not None:
        log.error("rejected record has no valid successor to probe yet; cursor not advanced")
        return RunResult(sent, skipped, EXIT_PERMANENT)
    if chunk.restarted and cursor.offset == 0:
        save_cursor(cfg.cursor_file, cursor)
    return RunResult(sent, skipped, EXIT_REJECTED if rejected else EXIT_OK, rejected)


def _stop(outcome: Outcome, sent: int, skipped: int) -> RunResult:
    if outcome.kind in ("permanent", "rejected"):
        log.error("permanent publish failure (%s); stopping, cursor not advanced", outcome.detail)
        return RunResult(sent, skipped, EXIT_PERMANENT)
    log.error("publish failed after retries (%s); cursor unchanged", outcome.detail)
    return RunResult(sent, skipped, EXIT_RETRY)


def run(
    cfg: Config,
    *,
    ssl_context: ssl.SSLContext | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    budget_seconds: float = RUN_BUDGET_S,
) -> RunResult:
    check_cursor_dir(cfg.cursor_file)
    lock = acquire_lock(cfg.cursor_file)
    if lock is None:
        log.info("another run active; exiting")
        return RunResult(0, 0, EXIT_OK)
    try:
        return _run_locked(cfg, ssl_context, sleep, clock, budget_seconds)
    finally:
        os.close(lock)


def _run_locked(
    cfg: Config,
    ssl_context: ssl.SSLContext | None,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
    budget_seconds: float,
) -> RunResult:
    clean_stale_temps(cfg.cursor_file)
    topic = load_topic(cfg.topic_file)
    token = load_token(cfg.token_file) if cfg.token_file else None
    opener = build_opener(ssl_context or ssl.create_default_context())
    chunk = read_chunk(cfg, load_cursor(cfg.cursor_file))
    if chunk is None:
        log.info("delivery file does not exist yet")
        return RunResult(0, 0, EXIT_OK)
    if chunk.restarted:
        log.warning("delivery file was truncated or replaced; restarting from the beginning")
    deadline = clock() + budget_seconds

    def send(record: Record) -> Outcome:
        request = build_request(cfg, topic, token, record)
        return send_with_retry(
            opener, request, cfg.timeout_seconds, sleep, lambda: deadline - clock()
        )

    return _drain(cfg, chunk, send, lambda: deadline - clock() <= 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ship the Vigie delivery file to ntfy.")
    parser.add_argument("config")
    parser.add_argument("--once", action="store_true", help="one pass and exit (the default)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        result = run(load_config(args.config))
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return EXIT_CONFIG
    except Exception as exc:  # noqa: BLE001 -- last resort; class name only, never the message
        log.error("unexpected error: %s", type(exc).__name__)
        return EXIT_INTERNAL
    print(f"ntfy_sender sent={result.sent} skipped={result.skipped} exit={result.code}")
    return result.code


if __name__ == "__main__":
    sys.exit(main())
