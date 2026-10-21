"""Hostile-string handling: reject on write (name/owner), sanitise on read (everything shown)."""

from __future__ import annotations

import unicodedata
from typing import Any

# Control (C0, DEL, C1, NUL), format (bidi marks/embeddings/isolates, zero-width, soft hyphen,
# BOM, tag characters), line/paragraph separators, surrogates and private use. An ordinary
# space is category Zs and stays allowed.
_BAD_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co"})
# Invisible characters outside those categories: combining grapheme joiner, Hangul/khmer fillers,
# Mongolian free variation selectors.
_BAD_EXTRA = frozenset("͏ᅟᅠ឴឵᠋᠌᠍᠎᠏ㅤﾠ")
DISPLAY_MAX = 256
PROSE_MAX = 1024


def is_forbidden(ch: str) -> bool:
    return ch in _BAD_EXTRA or unicodedata.category(ch) in _BAD_CATEGORIES


def has_forbidden(value: str) -> bool:
    return any(is_forbidden(ch) for ch in value)


def display_text(value: Any, limit: int = DISPLAY_MAX) -> Any:
    """Strip forbidden characters and bound the length; the stored value is never touched."""
    if not isinstance(value, str):
        return value
    cleaned = "".join(ch for ch in value[: limit * 4] if not is_forbidden(ch))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def display_json(value: Any, limit: int = DISPLAY_MAX) -> Any:
    """display_text applied to every string (keys included) inside parsed JSON."""
    if isinstance(value, str):
        return display_text(value, limit)
    if isinstance(value, list):
        return [display_json(v, limit) for v in value]
    if isinstance(value, dict):
        return {display_text(k, limit): display_json(v, limit) for k, v in value.items()}
    return value
