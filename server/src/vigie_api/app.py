"""vigie-api: the app principal's HTTP surface (PRP section 6)."""

import logging
import sqlite3
import time
from collections.abc import Callable, Iterator
from typing import Annotated, Any, Literal, Self

from fastapi import Depends, FastAPI, Header, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from vigie_api import effective, feeds, tokens, writes
from vigie_api.bodylimit import BodyLimitMiddleware
from vigie_api.config import Settings
from vigie_api.errors import ApiError, envelope, error_envelope
from vigie_api.schema import open_inventory_ro, open_overrides
from vigie_ingest.db import iso_utc
from vigie_ingest.ratelimit import RateLimiter

DeviceType = Literal["phone", "tv", "iot", "camera", "laptop", "console", "unknown"]
IdentityState = Literal["ok", "conflict", "pending_confirm"]
DeviceStatus = Literal["active", "transient", "retired"]
SuggestionState = Literal["pending", "accepted", "rejected", "expired"]
DeviceId = Annotated[str, Path(min_length=1, max_length=64)]
Limit = Annotated[int, Query(ge=1, le=500)]
VERSION = "0.1.0"
LOG = logging.getLogger("vigie_api")


class DevicePatch(BaseModel):
    """Only fields present in the body change; an explicit null clears the field."""

    model_config = ConfigDict(extra="forbid")

    name: Annotated[str | None, Field(max_length=128)] = None
    owner: Annotated[str | None, Field(max_length=128)] = None
    type: DeviceType | None = None
    group_id: Annotated[str | None, Field(max_length=32)] = None

    @model_validator(mode="after")
    def _non_empty(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("body must set at least one of name, owner, type, group_id")
        return self


def _unauthorized() -> ApiError:
    return ApiError(401, "unauthorized", "authentication required", {"WWW-Authenticate": "Bearer"})


def _bearer(authorization: str | None) -> str:
    scheme, _, credential = (authorization or "").partition(" ")
    return credential.strip() if scheme.lower() == "bearer" else ""


def create_app(settings: Settings, clock: Callable[[], float] = time.time) -> FastAPI:
    app = FastAPI(
        title="Vigie API",
        version=VERSION,
        summary="App-principal API for the Vigie network device inventory.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    token_limit = RateLimiter(settings.rate_limit_per_window, settings.rate_limit_window_s, clock)
    failure_limit = RateLimiter(settings.rate_limit_per_window, settings.rate_limit_window_s, clock)
    open_overrides(settings.overrides_path).close()  # create + migrate at startup
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            error_envelope(exc.code, exc.message), status_code=exc.status, headers=exc.headers
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
        return JSONResponse(error_envelope(code, str(exc.detail)), status_code=exc.status_code)

    @app.exception_handler(sqlite3.Error)
    async def _storage_error(request: Request, exc: sqlite3.Error) -> JSONResponse:
        LOG.error("storage error on %s %s: %r", request.method, request.url.path, exc)
        return JSONResponse(error_envelope("internal_error", "internal error"), status_code=500)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        detail = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        return JSONResponse(error_envelope("validation_error", detail), status_code=422)

    def get_ov() -> Iterator[sqlite3.Connection]:
        conn = open_overrides(settings.overrides_path)
        try:
            yield conn
        finally:
            conn.close()

    def get_inv() -> Iterator[sqlite3.Connection]:
        conn = open_inventory_ro(settings.inventory_path)
        if conn is None:
            raise ApiError(503, "inventory_unavailable", "inventory is not available yet")
        try:
            yield conn
        finally:
            conn.close()

    Ov = Annotated[sqlite3.Connection, Depends(get_ov)]
    Inv = Annotated[sqlite3.Connection, Depends(get_inv)]

    def authenticate(
        request: Request,
        ov: Ov,
        authorization: Annotated[str | None, Header()] = None,
    ) -> tokens.Principal:
        principal = tokens.verify_token(ov, _bearer(authorization))
        if principal is None:
            source = request.client.host if request.client else "unknown"
            if not failure_limit.allow(source):
                raise ApiError(429, "rate_limited", "too many requests")
            raise _unauthorized()
        if not token_limit.allow(principal.token_id):
            raise ApiError(429, "rate_limited", "too many requests")
        return principal

    Principal = Annotated[tokens.Principal, Depends(authenticate)]

    @app.get("/healthz", tags=["health"], summary="Liveness (unauthenticated)")
    def healthz() -> dict[str, Any]:
        return envelope("ok")

    @app.get("/devices", tags=["devices"], summary="List devices (effective view)")
    def list_devices(
        _: Principal,
        inv: Inv,
        ov: Ov,
        type: DeviceType | None = None,  # noqa: A002
        group: Annotated[str | None, Query(max_length=32)] = None,
        identity_state: IdentityState | None = None,
        status: DeviceStatus | None = None,
        updated_since: Annotated[str | None, Query(max_length=64)] = None,
        include_transient: bool = False,
        include_retired: bool = False,
        include_aliases: bool = False,
        cursor: Annotated[str | None, Query(max_length=256)] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        items, nxt = effective.list_devices(
            inv,
            ov,
            type_=type,
            group=group,
            identity_state=identity_state,
            status=status,
            updated_since=updated_since,
            include_transient=include_transient,
            include_retired=include_retired,
            include_aliases=include_aliases,
            cursor=cursor,
            limit=limit,
        )
        return envelope(items, page={"next_cursor": nxt})

    @app.get("/devices/{device_id}", tags=["devices"], summary="Device detail")
    def get_device(device_id: DeviceId, _: Principal, inv: Inv, ov: Ov) -> JSONResponse:
        detail = effective.device_detail(inv, ov, device_id)
        return JSONResponse(
            envelope(detail), headers={"ETag": writes.etag(detail["override_version"])}
        )

    @app.patch("/devices/{device_id}", tags=["devices"], summary="Set or clear overrides")
    def patch_device(
        device_id: DeviceId,
        body: DevicePatch,
        principal: Principal,
        inv: Inv,
        ov: Ov,
        if_match: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        result = writes.patch_override(
            inv,
            ov,
            device_id=device_id,
            expected_version=writes.parse_if_match(if_match),
            changes={f: getattr(body, f) for f in body.model_fields_set},
            principal=principal.name,
            now_iso=iso_utc(clock()),
        )
        return JSONResponse(envelope(result), headers={"ETag": writes.etag(result["version"])})

    @app.get("/macs/{mac}", tags=["devices"], summary="Resolve a MAC to its canonical device")
    def get_mac(mac: Annotated[str, Path(min_length=1, max_length=32)], _: Principal, inv: Inv,
                ov: Ov) -> dict[str, Any]:  # fmt: skip
        return envelope(effective.resolve_mac(inv, ov, mac))

    @app.get("/events", tags=["events"], summary="Events feed (inventory + human actions)")
    def get_events(
        _: Principal,
        inv: Inv,
        ov: Ov,
        since: Annotated[str | None, Query(max_length=256)] = None,
        kind: Annotated[str | None, Query(max_length=64)] = None,
        severity: Annotated[str | None, Query(max_length=32)] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        items, nxt = feeds.list_events(
            inv, ov, since=since, kind=kind, severity=severity, limit=limit
        )
        return envelope(items, page={"next_cursor": nxt})

    @app.get("/suggestions", tags=["suggestions"], summary="Suggestions (read-only)")
    def get_suggestions(
        _: Principal,
        inv: Inv,
        ov: Ov,
        state: SuggestionState | None = None,
        cursor: Annotated[str | None, Query(max_length=256)] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        items, nxt = feeds.list_suggestions(
            inv, ov, now_iso=iso_utc(clock()), state=state, cursor=cursor, limit=limit
        )
        return envelope(items, page={"next_cursor": nxt})

    return app
