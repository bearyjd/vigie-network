"""What leaves the box, and the publishers that carry it.

PRIVACY. A message holds a device LABEL and an incident link and nothing else: never a
destination, IP, MAC, domain or byte count. `build_message` takes an allowlist of inputs (delivery
id, kind, incident id, label, device id). A label that could hold an address, MAC, domain or
mailbox is replaced by a stable alias (see `scrub_label`); all lengths are bounded. There is no
network publisher here: `FakePublisher` records (tests) and `FilePublisher` appends JSON lines to
a local file.
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

MAX_LABEL = 64
PRE_CUT = 256  # no regex ever sees more than this: their cost is superlinear on hostile input
MAX_LINK = 200
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
_DOTS = str.maketrans({"\u3002": ".", "\uff61": ".", "\u2024": ".", "\ufe52": "."})
_KEEP = frozenset(" '\u2019-_.&0123456789")
# Suspect-label detectors. Separators are never enumerated: the hex and digit rules run on the
# text squashed down to its letters and digits, so any punctuation or invisible character between
# the octets is irrelevant.
_HOSTNAME = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"(?<![0-9a-z])(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?![0-9a-z])", re.IGNORECASE)
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


def _suspect(text: str) -> bool:
    """Conservative on purpose: anything that could be a MAC, address, domain or mailbox."""
    squashed = "".join(c for c in text if c.isalnum()).lower()
    return (
        len(re.sub("[^0-9a-f]", "", squashed)) >= 12
        or sum(c.isdigit() for c in squashed) >= 8
        or "@" in text
        or "://" in text
        or _HOSTNAME.search(text) is not None
        or _IPV4.search(text) is not None
        or _IPV6.search(text) is not None
    )


def alias(device_id: object) -> str:
    return "Device " + hashlib.sha256(str(device_id).encode()).hexdigest()[:4]


def scrub_label(raw: object, device_id: object = "") -> str:
    """FAIL SAFE. A suspect label is replaced by a stable alias derived from the device id, never
    redacted in part. Over-redaction is intentional: labels are admin-written, and this is a
    defence-in-depth net for a future network publisher. Otherwise only letters of any script,
    ASCII digits and ` '’-_.&` are kept, whitespace is collapsed and the result is cut."""
    head = "" if raw is None else str(raw)[:PRE_CUT]
    text = unicodedata.normalize("NFKC", head).translate(_DOTS)[:PRE_CUT]
    if _suspect(text):
        return alias(device_id)
    kept = "".join(c for c in text if c.isalpha() or c in _KEEP)
    clean = " ".join(kept.split())[:MAX_LABEL].strip()
    if not clean or _suspect(clean):  # dropping characters may have joined a hostname
        return alias(device_id)
    return clean


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
