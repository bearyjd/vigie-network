#!/usr/bin/env python3
"""Standalone ntfy sender: ships the pipeline's delivery file to a public ntfy server.

Usage: ntfy_sender.py CONFIG.json [--once]

Runs OUTSIDE the pipeline (which stays on Network=none). Reads the JSON-lines file written by
`vigie_pipeline.delivery_publish.FilePublisher`, validates every record, and POSTs only the
validated Message fields. Delivery is AT LEAST ONCE: a crash between a send and the cursor write
can repeat one notification. Standard library only.

Exit codes: 0 caught up, 1 unexpected internal error, 2 configuration/cursor/secret-file error,
3 permanent publish failure (cursor NOT advanced past the record), 4 retryable failure
(cursor unchanged). Log lines never contain the URL, topic, token, response body or record text.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import logging
import os
import re
import ssl
import stat
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

log = logging.getLogger("ntfy_sender")

EXIT_OK, EXIT_INTERNAL, EXIT_CONFIG, EXIT_PERMANENT, EXIT_RETRY = 0, 1, 2, 3, 4
MAX_LINE = 8192
MAX_CONFIG = 16384
MAX_SECRET = 1024
MAX_CURSOR = 4096
MAX_RESPONSE = 4096
MAX_TIMEOUT = 20.0
MAX_BATCH_LIMIT = 1000
RETRY_AFTER_CAP = 60.0
MAX_ATTEMPTS = 4
BACKOFF_BASE = 1.0
DEFAULT_SERVER = "https://ntfy.sh"
TOPIC_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")  # ntfy.sh allows at most 64 characters
HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")
TAGS = {"open": "warning", "recover": "white_check_mark"}
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
    """Bounded read of a regular file we own with mode 0600/0400; symlinks are refused."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConfigError(f"cannot open {what}: {exc.strerror}") from exc
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"{what} is not a regular file")
        if info.st_uid != os.getuid():
            raise ConfigError(f"{what} is not owned by the current user")
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
        raise ConfigError("topic must be 8-64 characters of A-Z a-z 0-9 _ -")
    return topic


# --- configuration -------------------------------------------------------------------------


def _https_url(value: object, key: str, *, path_ok: bool) -> str:
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ConfigError(f"{key} must be a URL without whitespace or control characters")
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
    ok = isinstance(value, list) and value and all(isinstance(h, str) for h in value)
    if not ok or not all(HOST_RE.fullmatch(h) for h in value):
        raise ConfigError("allowed_hosts must be a non-empty list of host names")
    return tuple(h.lower() for h in value)


def _bounded_number(value: object, key: str, maximum: float, *, integer: bool) -> float:
    kinds = (int,) if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, kinds) or not 0 < value <= maximum:
        raise ConfigError(f"{key} must be a number in (0, {maximum:g}]")
    return value


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
    """Atomic: tmp + fsync + rename + directory fsync. Mode 0600."""
    payload = json.dumps(
        {"offset": cursor.offset, "dev": cursor.dev, "ino": cursor.ino, "head": cursor.head}
    ).encode()
    tmp = path + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        raise ConfigError(f"cannot write cursor file: {exc.strerror}") from exc


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


def read_chunk(cfg: Config, cursor: Cursor) -> Chunk | None:
    """Bytes after the cursor, or None if the file does not exist yet. A replaced or truncated
    file (other inode/device, shorter than the offset, other first line) restarts at 0."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(cfg.delivery_file, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"cannot open delivery file: {exc.strerror}") from exc
    with os.fdopen(fd, "rb"):
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("delivery file is not a regular file")
        head = _first_line_hash(fd)
        replaced = cursor.offset > 0 and (
            (cursor.dev, cursor.ino) != (info.st_dev, info.st_ino)
            or info.st_size < cursor.offset
            or cursor.head != head
        )
        start = 0 if replaced else cursor.offset
        data = os.pread(fd, cfg.max_batch * (MAX_LINE + 1), start)
    return Chunk(data, start, info.st_dev, info.st_ino, head, replaced)


def split_lines(chunk: Chunk, max_batch: int) -> list[tuple[bytes, int]]:
    """Complete lines as (line, offset after it). A partial trailing line is left alone, except a
    full chunk with no newline at all: that is one oversized line and is skipped by the caller."""
    lines: list[tuple[bytes, int]] = []
    pos = 0
    while len(lines) < max_batch:
        end = chunk.data.find(b"\n", pos)
        if end < 0:
            break
        lines.append((chunk.data[pos:end], chunk.start + end + 1))
        pos = end + 1
    if not lines and len(chunk.data) >= max_batch * (MAX_LINE + 1):
        lines.append((chunk.data, chunk.start + len(chunk.data)))
    return lines


def _text(raw: dict, key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not 1 <= len(value) <= LIMITS[key] or not value.isprintable():
        raise ValueError(f"invalid {key}")
    return value


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
    link = record.link
    if record.kind not in TAGS or " " in record.delivery_id:
        raise ValueError("invalid kind or delivery_id")
    if not link.startswith("/") or link.startswith("//") or " " in link or not link.isascii():
        raise ValueError("invalid link")
    return record


# --- sending -------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        raise RedirectRefused


def build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )


def ascii_title(title: str) -> str:
    folded = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode("ascii")
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
    if code == 429 or 500 <= code < 600:
        return Outcome("retry", parse_retry_after(retry_after), f"HTTP {code}")
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
    except (OSError, http.client.HTTPException, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return Outcome("retry", None, type(reason).__name__)


def send_with_retry(
    opener: urllib.request.OpenerDirector,
    req: urllib.request.Request,
    timeout: float,
    sleep: Callable[[float], None],
) -> Outcome:
    delay = BACKOFF_BASE
    outcome = send_once(opener, req, timeout)
    for _ in range(MAX_ATTEMPTS - 1):
        if outcome.kind != "retry":
            break
        wait = min(max(delay, outcome.retry_after or 0.0), RETRY_AFTER_CAP)
        log.warning("retryable failure (%s); retrying in %.0fs", outcome.detail, wait)
        sleep(wait)
        delay *= 2
        outcome = send_once(opener, req, timeout)
    return outcome


# --- run -----------------------------------------------------------------------------------


def _drain(
    cfg: Config,
    chunk: Chunk,
    send: Callable[[Record], Outcome],
) -> RunResult:
    cursor = Cursor(chunk.start, chunk.dev, chunk.ino, chunk.head)
    sent = skipped = 0
    for line, end in split_lines(chunk, cfg.max_batch):
        advanced = replace(cursor, offset=end)
        try:
            record = parse_record(line)
        except ValueError as exc:
            log.warning("skipping invalid record before offset %d: %s", end, exc)
            skipped += 1
            cursor = advanced
            save_cursor(cfg.cursor_file, cursor)
            continue
        outcome = send(record)
        if outcome.kind != "ok":
            return _stop(outcome, sent, skipped)
        sent += 1
        cursor = advanced
        save_cursor(cfg.cursor_file, cursor)
    if chunk.restarted and cursor.offset == 0:
        save_cursor(cfg.cursor_file, cursor)
    return RunResult(sent, skipped, EXIT_OK)


def _stop(outcome: Outcome, sent: int, skipped: int) -> RunResult:
    if outcome.kind == "permanent":
        log.error("permanent publish failure (%s); stopping, cursor not advanced", outcome.detail)
        return RunResult(sent, skipped, EXIT_PERMANENT)
    log.error("publish failed after retries (%s); cursor unchanged", outcome.detail)
    return RunResult(sent, skipped, EXIT_RETRY)


def run(
    cfg: Config,
    *,
    ssl_context: ssl.SSLContext | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> RunResult:
    topic = load_topic(cfg.topic_file)
    token = read_secret(cfg.token_file, "token file") if cfg.token_file else None
    opener = build_opener(ssl_context or ssl.create_default_context())
    chunk = read_chunk(cfg, load_cursor(cfg.cursor_file))
    if chunk is None:
        log.info("delivery file does not exist yet")
        return RunResult(0, 0, EXIT_OK)
    if chunk.restarted:
        log.warning("delivery file was truncated or replaced; restarting from the beginning")

    def send(record: Record) -> Outcome:
        request = build_request(cfg, topic, token, record)
        return send_with_retry(opener, request, cfg.timeout_seconds, sleep)

    return _drain(cfg, chunk, send)


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
