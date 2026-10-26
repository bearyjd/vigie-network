"""Evidence pack building blocks: the Sensitive wrapper and the Pack container.

Every value that can identify a device, a person or a network is wrapped as
`Sensitive(kind, value)` when the pack is assembled. Only `redact()` turns those into plain
values, so a renderer that still finds one knows redaction was skipped and refuses to write.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "vigie.evidence-pack"
SCHEMA_VERSION = 1
MEDIA_TYPE_JSON = "application/vnd.vigie.evidence-pack+json"
MEDIA_TYPE_MARKDOWN = "text/markdown"


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
