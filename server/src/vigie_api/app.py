"""vigie-api: the app principal's HTTP surface (PRP section 6)."""

import logging
import sqlite3
import time
from collections.abc import Callable, Iterator
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Path, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from vigie_api import effective, feeds, tokens, writes
from vigie_api.bodylimit import BodyLimitMiddleware
from vigie_api.config import Settings
from vigie_api.errors import ApiError, envelope, error_envelope
from vigie_api.models import (
    DevicePatch,
    DeviceResponse,
    DevicesResponse,
    DeviceStatus,
    DeviceType,
    ErrorEnvelope,
    EventsResponse,
    HealthResponse,
    IdentityState,
    MacResponse,
    PatchResponse,
    SuggestionsResponse,
    SuggestionState,
)
from vigie_api.ratelimit import FailureLimiter
from vigie_api.schema import open_inventory_ro, open_overrides
from vigie_ingest.db import iso_utc
from vigie_ingest.ratelimit import RateLimiter

DeviceId = Annotated[str, Path(min_length=1, max_length=64)]
Limit = Annotated[int, Query(ge=1, le=500)]
VERSION = "0.1.0"
LOG = logging.getLogger("vigie_api")
ERROR_TEXT = {
    400: "Malformed cursor, If-Match or updated_since",
    401: "Unauthorized (uniform for every authentication failure)",
    404: "Not found",
    409: "device_merged: the device was merged into another; patch the canonical one",
    412: "version_mismatch: If-Match does not match; the current ETag is sent back",
    413: "Request body too large",
    422: "Validation error",
    428: "If-Match header missing",
    429: "Rate limited; see Retry-After",
    503: "inventory_unavailable: inventory.db does not exist yet",
}
ETAG_HEADER = {
    "headers": {
        "ETag": {
            "description": "Override version of the device; send it back as If-Match.",
            "schema": {"type": "string"},
        }
    }
}


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {c: {"model": ErrorEnvelope, "description": ERROR_TEXT[c]} for c in codes}


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
    failure_limit = FailureLimiter(
        settings.rate_limit_per_window, settings.rate_limit_window_s, clock
    )
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

    def check_auth(request: Request, authorization: str | None):
        """Limiter pre-check, then token verification.

        The limiter counts failed authentications only and never blocks a valid token. A blocked
        source that presents nothing token-shaped is refused without opening any database; one
        that does present a plausible token costs a single indexed lookup, so that a valid token
        keeps working from a shared (NAT / dual-stack) address.
        """
        source = request.client.host if request.client else "unknown"
        wait = failure_limit.retry_after(source)
        presented = _bearer(authorization)
        if wait is not None and not tokens.TOKEN_RE.fullmatch(presented):
            raise _rate_limited(wait)
        conn = open_overrides(settings.overrides_path)
        try:
            principal = tokens.verify_token(conn, presented)
        finally:
            conn.close()
        if principal is None:
            if wait is not None:
                raise _rate_limited(wait)
            failure_limit.record(source)
            LOG.warning("authentication failed from %s", source)  # never the credential
            raise _unauthorized()
        if not token_limit.allow(principal.token_id):
            raise _rate_limited(settings.rate_limit_window_s)
        request.state.authenticated = True
        return principal

    def _rate_limited(wait: int | float) -> ApiError:
        return ApiError(429, "rate_limited", "too many requests", {"Retry-After": str(wait)})

    def reject_if_unauthenticated(request: Request) -> None:
        check_auth(request, request.headers.get("authorization"))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # A body that fails to parse is rejected before FastAPI runs the auth dependency;
        # authenticate here so an anonymous caller always sees the uniform 401, never a 422.
        if not getattr(request.state, "authenticated", False) and request.url.path != "/healthz":
            try:
                await run_in_threadpool(reject_if_unauthenticated, request)
            except ApiError as err:
                return await _api_error(request, err)
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
        request: Request, authorization: Annotated[str | None, Header()] = None
    ) -> tokens.Principal:
        return check_auth(request, authorization)

    Principal = Annotated[tokens.Principal, Depends(authenticate)]

    @app.get(
        "/healthz", tags=["health"], summary="Liveness (unauthenticated)",
        response_model=HealthResponse,
    )  # fmt: skip
    def healthz() -> dict[str, Any]:
        return envelope("ok")

    @app.get(
        "/devices",
        tags=["devices"],
        summary="List devices (effective view)",
        description=(
            "Aliases (devices merged into another) are hidden unless `include_aliases=1`, and an "
            "alias shows its canonical device's override. Retired and transient devices are "
            "hidden unless `include_retired=1` / `include_transient=1` (or `status=` is given)."
        ),
        response_model=DevicesResponse,
        responses=_errors(400, 401, 422, 429, 503),
    )
    def list_devices(
        _: Principal,
        inv: Inv,
        ov: Ov,
        type: DeviceType | None = None,  # noqa: A002
        group: Annotated[str | None, Query(max_length=32)] = None,
        identity_state: IdentityState | None = None,
        status: DeviceStatus | None = None,
        updated_since: Annotated[
            str | None,
            Query(max_length=64, description="ISO-8601 UTC, e.g. 2026-01-01T00:00:00Z"),
        ] = None,
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

    @app.get(
        "/devices/{device_id}",
        tags=["devices"],
        summary="Device detail",
        response_model=DeviceResponse,
        responses={200: ETAG_HEADER, **_errors(401, 404, 422, 429, 503)},
    )
    def get_device(
        device_id: DeviceId, _: Principal, inv: Inv, ov: Ov, response: Response
    ) -> dict[str, Any]:
        detail = effective.device_detail(inv, ov, device_id, now_iso=iso_utc(clock()))
        response.headers["ETag"] = writes.etag(detail["override_version"])
        return envelope(detail)

    @app.patch(
        "/devices/{device_id}",
        tags=["devices"],
        summary="Set or clear overrides",
        response_model=PatchResponse,
        responses={200: ETAG_HEADER, **_errors(400, 401, 404, 409, 412, 413, 422, 428, 429, 503)},
    )
    def patch_device(
        device_id: DeviceId,
        body: DevicePatch,
        principal: Principal,
        inv: Inv,
        ov: Ov,
        response: Response,
        if_match: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        result = writes.patch_override(
            inv,
            ov,
            device_id=device_id,
            expected_version=writes.parse_if_match(if_match),
            changes={f: getattr(body, f) for f in body.model_fields_set},
            principal=principal.name,
            now_iso=iso_utc(clock()),
        )
        response.headers["ETag"] = writes.etag(result["version"])
        return envelope(result)

    @app.get(
        "/macs/{mac}",
        tags=["devices"],
        summary="Resolve a MAC to its canonical device",
        response_model=MacResponse,
        responses=_errors(401, 404, 422, 429, 503),
    )
    def get_mac(
        mac: Annotated[str, Path(min_length=1, max_length=32)], _: Principal, inv: Inv, ov: Ov
    ) -> dict[str, Any]:
        return envelope(effective.resolve_mac(inv, ov, mac))

    @app.get(
        "/events",
        tags=["events"],
        summary="Events feed (inventory + human actions)",
        description=(
            "Paged by insertion order, so an event that arrives late with an older `ts` is never "
            "skipped. Items within a page are sorted by `ts` for display only. `since` is the "
            "opaque `page.next_cursor` of a previous response: the resume point, i.e. the last "
            "row included per source. An empty page returns the `since` you sent."
        ),
        response_model=EventsResponse,
        responses=_errors(400, 401, 422, 429, 503),
    )
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

    @app.get(
        "/suggestions",
        tags=["suggestions"],
        summary="Suggestions (read-only)",
        response_model=SuggestionsResponse,
        responses=_errors(400, 401, 422, 429, 503),
    )
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
