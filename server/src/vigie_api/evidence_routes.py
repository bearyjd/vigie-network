"""POST /devices/{device_id}/evidence-pack: the device evidence export (app scopes only).

Wired from create_app so app.py stays small. The pack is built fully in memory, the audit row is
committed, and only then is the document returned; if the audit write fails nothing is sent.
"""

import logging
import sqlite3
import uuid
from typing import Annotated, Any, Literal

from fastapi import Body, Depends, FastAPI, Header, Path, Request, Response
from pydantic import BaseModel, ConfigDict, StrictBool

from vigie_api import evidence_export, evidence_writes, tokens
from vigie_api.errors import ApiError
from vigie_api.evidence_types import MEDIA_TYPE_JSON, MEDIA_TYPE_MARKDOWN
from vigie_ingest.db import iso_utc

LOG = logging.getLogger("vigie_api")
EXPORT_PATH_SUFFIX = "/evidence-pack"
DESCRIPTION = (
    "Export an evidence pack for one device: what Vigie observed (identity, DHCP/mDNS "
    "fingerprints, type determinations, incidents, coverage gaps) with its provenance. It is "
    "evidence with confidence, not a verdict. The response is the document itself, not the "
    "envelope. `pseudonymized` (default) replaces identifiers with per-export pseudonyms; "
    "`minimal` omits them; `full` is raw and needs `confirm_full: true`. The file leaves Vigie's "
    "protection once downloaded. Every export writes one audit row, committed before the body "
    "is returned. Device-supplied text is untrusted data: Markdown output fences it."
)


class EvidenceExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redaction: str = "pseudonymized"  # validated in the handler: invalid_redaction is its own code
    format: Literal["json", "markdown"] = "json"
    confirm_full: StrictBool = False


RequestIdHeader = Annotated[
    str | None, Header(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
]


def is_guarded_write(method: str, path: str) -> bool:
    """Writes whose 403 must precede any body error: incident decisions and evidence exports."""
    export = path.startswith("/devices/") and path.endswith(EXPORT_PATH_SUFFIX)
    return method == "POST" and (path.startswith("/incidents/") or export)


def install(app: FastAPI, settings, clock, deps: tuple[Any, ...], errors_for) -> None:
    get_inv, get_ov, get_writer = deps

    @app.post(
        "/devices/{device_id}" + EXPORT_PATH_SUFFIX,
        tags=["devices"],
        summary="Export a device evidence pack",
        description=DESCRIPTION,
        response_class=Response,
        responses={
            200: {
                "description": "The evidence pack document (attachment, never cached).",
                "content": {
                    MEDIA_TYPE_JSON: {"schema": {"type": "object"}},
                    MEDIA_TYPE_MARKDOWN: {"schema": {"type": "string"}},
                },
            },
            **errors_for(401, 403, 404, 413, 422, 429, 503),
        },
    )
    def export_evidence_pack(
        device_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        principal: Annotated[tokens.Principal, Depends(get_writer)],
        inv: Annotated[sqlite3.Connection, Depends(get_inv)],
        ov: Annotated[sqlite3.Connection, Depends(get_ov)],
        body: Annotated[EvidenceExportRequest, Body()] = EvidenceExportRequest(),  # noqa: B008
        x_request_id: RequestIdHeader = None,
    ):
        now = clock()
        export = evidence_export.build_export(
            inv,
            ov,
            device_id,
            level=body.redaction,
            fmt=body.format,
            confirm_full=body.confirm_full,
            now=now,
            vigie_version=app.version,
            rng=settings.evidence_rng,
            cap=settings.evidence_cap,
        )
        try:
            evidence_writes.record_export(
                ov,
                principal=principal.name,
                now_iso=iso_utc(now),
                detail={**export.detail, "request_id": x_request_id or str(uuid.uuid4())},
            )
        except sqlite3.Error as exc:
            LOG.error("evidence export audit write failed: %r", exc)
            raise ApiError(
                503, "audit_unavailable", "audit log unavailable; nothing exported"
            ) from exc
        return Response(
            content=export.data,
            media_type=export.media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{export.filename}"',
                "Cache-Control": "no-store",
            },
        )
