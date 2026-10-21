"""Collector HMAC authentication."""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_MIN_KEY_BYTES = 32
_MAX_KEY_FILE_BYTES = 1024
# Used when the real key is unavailable so the compare still runs (uniform work).
_DUMMY_KEY = b"\x00" * _MIN_KEY_BYTES


def load_key(secrets_dir: Path, key_id: str) -> bytes | None:
    """Load `collector_key_<key_id>` (hex text, >= 32 bytes). Never reads the database."""
    if not KEY_ID_RE.fullmatch(key_id):
        return None
    path = secrets_dir / f"collector_key_{key_id}"
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_KEY_FILE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_KEY_FILE_BYTES:
        return None
    try:
        key = bytes.fromhex(raw.decode("ascii").strip())
    except ValueError:
        return None
    return key if len(key) >= _MIN_KEY_BYTES else None


def signing_string(
    collector_id: str,
    key_id: str,
    boot_id: str,
    seq: str,
    sent_ts: str,
    batch_id: str,
    body: bytes,
) -> bytes:
    """collector_id|key_id|boot_id|seq|sent_ts|batch_id|hex(SHA256(raw body))."""
    digest = hashlib.sha256(body).hexdigest()
    return "|".join((collector_id, key_id, boot_id, seq, sent_ts, batch_id, digest)).encode()


def sign(key: bytes, *fields: str, body: bytes) -> str:
    message = signing_string(*fields, body=body)  # type: ignore[arg-type]
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify(key: bytes | None, signature_hex: str, message: bytes) -> bool:
    """Constant-time check. Always performs an HMAC + compare, even without a key."""
    expected = hmac.new(key or _DUMMY_KEY, message, hashlib.sha256).hexdigest()
    matches = hmac.compare_digest(expected.encode(), signature_hex.lower().encode("utf-8"))
    return matches and key is not None
