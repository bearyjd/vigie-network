"""Evidence pack building blocks: the Sensitive wrapper and the Pack container.

Every value that can identify a device, a person or a network is wrapped as
`Sensitive(kind, value)` when the pack is assembled. Only `redact()` turns those into plain
values, so a renderer that still finds one knows redaction was skipped and refuses to write.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from vigie_api.textsafe import display_text
from vigie_ingest.db import iso_utc

SCHEMA = "vigie.evidence-pack"
SCHEMA_VERSION = 1
MEDIA_TYPE_JSON = "application/vnd.vigie.evidence-pack+json"
MEDIA_TYPE_MARKDOWN = "text/markdown"
SAFE_ID = re.compile(r"[a-z0-9_.:-]{1,64}")


class UnredactedError(RuntimeError):
    """A renderer was handed a pack that still holds a Sensitive value (fail closed)."""


@dataclass(frozen=True)
class Sensitive:
    kind: str
    value: str | int | float


@dataclass(frozen=True)
class Pack:
    """The pack document as plain nested dicts/lists. Treated as immutable: redact() and the
    truncation step return new Packs and never edit the one they were given."""

    body: dict[str, Any]
    redacted: bool = field(default=False)


def iter_sensitive(node: Any) -> Iterator[Sensitive]:
    if isinstance(node, Sensitive):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from iter_sensitive(value)
    elif isinstance(node, (list, tuple)):
        for value in node:
            yield from iter_sensitive(value)


def find_sensitive(node: Any) -> list[Sensitive]:
    return list(iter_sensitive(node))


def safe_id(value: Any) -> str | None:
    """A Vigie-style identifier or nothing: anything off-pattern is dropped, never echoed."""
    return value if isinstance(value, str) and SAFE_ID.fullmatch(value) else None


def sensitive(kind: str, value: Any, limit: int | None = None) -> Sensitive | None:
    """Wrap a device- or person-derived value after stripping forbidden characters."""
    if value is None:
        return None
    text = display_text(str(value), limit) if limit else display_text(str(value))
    return Sensitive(kind, text) if text else None


def when(value: Any) -> Sensitive | None:
    """A timestamp as a Sensitive `ts` (rounded away at the minimal level)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = iso_utc(value)
    return Sensitive("ts", value) if isinstance(value, str) else None


def make_section(
    status: str, items: Sequence[Any] = (), *, reason: str | None = None, omitted: int = 0
) -> dict[str, Any]:
    return {"status": status, "reason": reason, "omitted_count": omitted, "items": list(items)}


def capped_section(items: Sequence[Any], total: int) -> dict[str, Any]:
    """`items` is already limited; `total` is how many exist."""
    omitted = max(total - len(items), 0)
    if omitted:
        return make_section("truncated", items, omitted=omitted)
    return make_section("present" if items else "absent", items)


def not_available(reason: str) -> dict[str, Any]:
    return make_section("not_available", reason=reason)


def has_table(conn: sqlite3.Connection, name: str) -> bool:
    found = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return found.fetchone() is not None
