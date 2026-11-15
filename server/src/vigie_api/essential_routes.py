"""Essential-device routes (owner opt-in, record only), wired from create_app.

The essential ETag is its own counter (`essential_devices.version`); it is not interchangeable
with the `device_overrides` ETag of PATCH /devices/{id}.
"""

import sqlite3
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Path, Response

from vigie_api import essential, tokens, writes
from vigie_api.errors import envelope
from vigie_api.evidence_routes import RequestIdHeader
from vigie_api.models import (
    EssentialListResponse,
    EssentialPut,
    EssentialResultResponse,
    EssentialStateResponse,
)
from vigie_ingest.db import iso_utc

ESSENTIAL_SUFFIX = "/essential"
ETAG_HEADER = {
    "headers": {
        "ETag": {
            "description": "Essential version of the device; send it back as If-Match.",
            "schema": {"type": "string"},
        }
    }
}
PUT_DESCRIPTION = (
    "Records the owner's opt-in only; nothing is monitored yet. `absent_after_s` has no default: "
    f"{essential.MIN_S} to {essential.MAX_S}. At most {essential.MAX_ESSENTIAL} devices; a "
    "merged alias is refused (mark the canonical device). If-Match is the current essential "
    "version (0 if never marked); it is its own counter, not the device override ETag."
)


def install(app: FastAPI, clock, deps: tuple[Any, ...], errors_for) -> None:
    get_inv, get_ov, get_principal, get_writer = deps
    DeviceId = Annotated[str, Path(min_length=1, max_length=64)]
    Inv = Annotated[sqlite3.Connection, Depends(get_inv)]
    Ov = Annotated[sqlite3.Connection, Depends(get_ov)]
    Principal = Annotated[tokens.Principal, Depends(get_principal)]
    Writer = Annotated[tokens.Principal, Depends(get_writer)]
    IfMatch = Annotated[str | None, Header()]

    def write(
        inv,
        ov,
        principal,
        response,
        device_id,
        if_match,
        request_id,
        absent_after_s,  # noqa: ANN001
    ) -> dict[str, Any]:
        result = essential.set_essential(
            inv,
            ov,
            device_id=device_id,
            expected_version=writes.parse_if_match(if_match),
            absent_after_s=absent_after_s,
            principal=principal.name,
            now_iso=iso_utc(clock()),
            request_id=request_id,
        )
        response.headers["ETag"] = writes.etag(result["version"])
        return envelope(result)

    @app.get(
        "/devices/{device_id}" + ESSENTIAL_SUFFIX,
        tags=["devices"],
        summary="Essential-device mark (owner opt-in)",
        description="`version` is the ETag; send it back as If-Match on PUT/DELETE.",
        response_model=EssentialStateResponse,
        responses={200: ETAG_HEADER, **errors_for(401, 404, 422, 429, 503)},
    )
    def get_essential(
        device_id: DeviceId, _: Principal, inv: Inv, ov: Ov, response: Response
    ) -> dict[str, Any]:
        state = essential.get_state(inv, ov, device_id)
        response.headers["ETag"] = writes.etag(state["version"])
        return envelope(state)

    @app.put(
        "/devices/{device_id}" + ESSENTIAL_SUFFIX,
        tags=["devices"],
        summary="Mark a device essential",
        description=PUT_DESCRIPTION,
        response_model=EssentialResultResponse,
        responses={
            200: ETAG_HEADER,
            **errors_for(400, 401, 403, 404, 409, 412, 413, 422, 428, 429, 503),
        },
    )
    def put_essential(
        device_id: DeviceId,
        body: EssentialPut,
        principal: Writer,
        inv: Inv,
        ov: Ov,
        response: Response,
        if_match: IfMatch = None,
        x_request_id: RequestIdHeader = None,
    ) -> dict[str, Any]:
        return write(
            inv, ov, principal, response, device_id, if_match, x_request_id, body.absent_after_s
        )

    @app.delete(
        "/devices/{device_id}" + ESSENTIAL_SUFFIX,
        tags=["devices"],
        summary="Unmark an essential device",
        description=(
            "Sets the mark to null (the row is kept so the version never resets). Works for a "
            "device that was merged after it was marked."
        ),
        response_model=EssentialResultResponse,
        responses={
            200: ETAG_HEADER,
            **errors_for(400, 401, 403, 404, 409, 412, 422, 428, 429, 503),
        },
    )
    def delete_essential(
        device_id: DeviceId,
        principal: Writer,
        inv: Inv,
        ov: Ov,
        response: Response,
        if_match: IfMatch = None,
        x_request_id: RequestIdHeader = None,
    ) -> dict[str, Any]:
        return write(inv, ov, principal, response, device_id, if_match, x_request_id, None)

    @app.get(
        "/essential-devices",
        tags=["devices"],
        summary=f"List essential devices (at most {essential.MAX_ESSENTIAL})",
        response_model=EssentialListResponse,
        responses=errors_for(401, 429, 503),
    )
    def list_essential_devices(_: Principal, ov: Ov) -> dict[str, Any]:
        return envelope(essential.list_essential(ov))
