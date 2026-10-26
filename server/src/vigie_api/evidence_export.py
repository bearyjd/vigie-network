"""Build one evidence export: assemble, redact, render. Shared by the HTTP route and the CLI.

Nothing here writes; the caller records the audit row (evidence_writes) and only then hands the
bytes out.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from vigie_api.errors import ApiError
from vigie_api.evidence_assemble import Limits, assemble
from vigie_api.evidence_redact import LEVELS, SALT_BYTES, redact
from vigie_api.evidence_render import MAX_PACK_BYTES, content_sha256, fit
from vigie_api.evidence_types import (
    MEDIA_TYPE_JSON,
    MEDIA_TYPE_MARKDOWN,
    SCHEMA_VERSION,
)

FORMATS = {
    "json": (MEDIA_TYPE_JSON, "json"),
    "markdown": (MEDIA_TYPE_MARKDOWN, "md"),
}


@dataclass(frozen=True)
class Export:
    data: bytes
    media_type: str
    filename: str
    target: str  # short ref for the audit row and the /events feed
    detail: dict[str, Any]  # audit detail, minus request_id (added by the caller)


def check_request(level: str, confirm_full: bool) -> None:
    if level not in LEVELS:
        raise ApiError(422, "invalid_redaction", f"redaction must be one of {', '.join(LEVELS)}")
    if level == "full" and confirm_full is not True:
        raise ApiError(422, "confirmation_required", "full redaction requires confirm_full=true")


def build_export(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    device_id: str,
    *,
    level: str,
    fmt: str,
    confirm_full: bool,
    now: float,
    vigie_version: str,
    rng: Callable[[int], bytes],
    cap: int = MAX_PACK_BYTES,
) -> Export:
    check_request(level, confirm_full)
    pack = assemble(inv, ov, device_id, now=now, limits=Limits(), vigie_version=vigie_version)
    subject = pack.body["subject"]
    canonical, requested = subject["device_ref"].value, subject["requested_ref"].value
    final, data = fit(redact(pack, level, rng(SALT_BYTES)), fmt, cap)
    sections = final.body["sections"]
    media_type, suffix = FORMATS[fmt]
    detail = {
        "device_id": canonical,
        "requested_id": requested,
        "level": level,
        "format": fmt,
        "schema_version": SCHEMA_VERSION,
        "section_counts": {sid: len(s["items"]) for sid, s in sorted(sections.items())},
        "truncated": any(s["status"] == "truncated" for s in sections.values()),
        "pack_sha256": content_sha256(final),
    }
    target = "dev-" + hashlib.sha256(canonical.encode()).hexdigest()[:8]
    return Export(data, media_type, f"vigie-evidence-pack.{suffix}", target, detail)
