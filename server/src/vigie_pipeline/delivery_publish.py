"""What leaves the box, and the publishers that carry it.

PRIVACY. A message holds a device LABEL and an incident link and nothing else: never a
destination, IP, MAC, domain or byte count. `build_message` takes an allowlist of inputs (delivery
id, kind, incident id, label, device id). A label is accepted verbatim only if it passes the
strict acceptor in `scrub_label`, otherwise a stable alias is sent; all lengths are bounded.
There is no network publisher here: `FakePublisher` records (tests) and `FilePublisher` appends
JSON lines to a local file.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

MAX_LABEL = 48
MAX_DIGITS = 3
MAX_WORD = 20  # a word this long is an opaque token, not a name
MAX_HEX_LETTERS = 12  # squashed hex-looking characters this many or more could be a MAC
MAX_LINK = 200
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
_DIGITS = frozenset("0123456789")
_HEX = frozenset("0123456789abcdef")
_WORD_BREAKS = re.compile("[ '\u2019-]")
TITLES = {"open": "Vigie: check {label}", "recover": "Vigie: {label} is back to normal"}
BODIES = {
    "open": "{label}: unusual activity detected. Review it here: {link}",
    "recover": "{label}: the activity has returned to normal. Details: {link}",
}


class PublishError(RuntimeError):
    """A publisher could not deliver a message (any other exception counts as a failure too)."""


@dataclass(frozen=True)
class Message:
    delivery_id: str
    kind: str  # 'open' | 'recover'
    title: str
    body: str
    link: str


class Publisher(Protocol):
    def publish(self, message: Message, *, timeout_seconds: float) -> None:
        """Deliver or raise PublishError. The runner enforces a hard wall timeout on top."""


def alias(device_id: object) -> str:
    """`Device <6 letters>` from the hash of the device id: stable, letters only (so the acceptor
    below accepts it unchanged)."""
    digest = hashlib.sha256(str(device_id).encode()).digest()
    return "Device " + "".join(chr(ord("a") + b % 26) for b in digest[:6])


def _allowed(c: str) -> bool:
    if c.isascii():
        return c.isalnum() or c in " '-"
    return c == "\u2019" or ("\u00c0" <= c <= "\u00ff" and c not in "\u00d7\u00f7")


def _acceptable(raw: str) -> bool:
    """Checked on the RAW string: nothing is truncated, trimmed, collapsed or NFKC-folded first,
    because any of those can hide content from the checks below."""
    if not 1 <= len(raw) <= MAX_LABEL or raw != raw.strip() or "  " in raw:
        return False
    if not all(_allowed(c) for c in raw) or unicodedata.normalize("NFKC", raw) != raw:
        return False
    if sum(c in _DIGITS for c in raw) > MAX_DIGITS or not any(c.isalpha() for c in raw):
        return False
    if sum(c.lower() in _HEX for c in raw if c.isascii() and c.isalnum()) >= MAX_HEX_LETTERS:
        return False
    return all(len(word) < MAX_WORD for word in _WORD_BREAKS.split(raw))


def scrub_label(raw: object, device_id: object = "") -> str:
    """STRICT ACCEPTOR for the optional free-text label. The string is validated as given and is
    returned verbatim or not at all: ASCII letters and digits, space, `'`, `’`, `-` and the Latin-1
    letters U+00C0-U+00FF (without x and division), at most 48 characters, no leading, trailing or
    doubled space, already NFKC-stable, at most 3 digits, a letter, nothing that looks like a MAC
    once squashed, no word of 20 or more characters. Anything else becomes the stable alias of the
    device. Free text cannot be proven safe, so this is only a defence in depth for the opt-in
    (`VIGIE_DELIVERY_INCLUDE_LABEL`); the default message carries no label at all."""
    text = "" if raw is None else str(raw)
    return text if _acceptable(text) else alias(device_id)


def incident_link(incident_id: object) -> str:
    return "/ui/#incident=" + quote(str(incident_id)[: MAX_LINK - 20], safe="")[: MAX_LINK - 14]


def build_message(
    delivery_id: str, kind: str, incident_id: object, label: object, device_id: object = ""
) -> Message:
    clean, link = scrub_label(label, device_id), incident_link(incident_id)
    fields = {"label": clean, "link": link}
    return Message(
        delivery_id, kind, TITLES[kind].format(**fields), BODIES[kind].format(**fields), link
    )


class FakePublisher:
    """Records messages. `script` is consumed one entry per call: None succeeds, an exception is
    raised, a threading.Event is waited on (a hang, bounded to 60 s so test threads end)."""

    def __init__(self, script: list[object] | tuple[object, ...] = ()) -> None:
        self._script = list(script)
        self._lock = threading.Lock()
        self.attempted: list[Message] = []
        self.sent: list[Message] = []

    def publish(self, message: Message, *, timeout_seconds: float) -> None:
        with self._lock:
            self.attempted.append(message)
            step = self._script.pop(0) if self._script else None
        if isinstance(step, threading.Event):
            step.wait(60)
        elif isinstance(step, BaseException):
            raise step
        with self._lock:
            self.sent.append(message)


class FilePublisher:
    """Appends one JSON line per message to a local file (mode 0600, regular files only)."""

    def __init__(self, path: Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
        self._path = Path(path)
        self._max = max_bytes

    def publish(self, message: Message, *, timeout_seconds: float) -> None:
        record = {
            "delivery_id": message.delivery_id,
            "kind": message.kind,
            "title": message.title,
            "body": message.body,
            "link": message.link,
        }
        line = (json.dumps(record, separators=(",", ":")) + "\n").encode("ascii")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(self._path, flags | os.O_NONBLOCK, 0o600)
        except OSError as exc:
            raise PublishError(f"cannot open delivery file: {exc.strerror}") from exc
        try:
            self._append(fd, line)
        except OSError as exc:
            raise PublishError(f"cannot write delivery file: {exc.strerror}") from exc
        finally:
            os.close(fd)

    def _append(self, fd: int, line: bytes) -> None:
        """Capacity check and write in ONE exclusive flock section (across instances and
        processes). Whatever fails after a partial write, the file is cut back to its old size."""
        fcntl.flock(fd, fcntl.LOCK_EX)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PublishError("delivery file is not a regular file")
        if info.st_size + len(line) > self._max:
            raise PublishError(f"delivery file is full (limit {self._max} bytes)")
        if stat.S_IMODE(info.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
        try:
            pending = memoryview(line)
            while pending:
                written = os.write(fd, pending)
                if written <= 0:
                    raise OSError("write made no progress")
                pending = pending[written:]
            os.fsync(fd)
        except BaseException:
            try:
                os.ftruncate(fd, info.st_size)
            except OSError:
                pass  # the original failure is what the caller must see
            raise
