"""FastAPI app: POST /v1/batch (collector principal only)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from vigie_ingest import auth, store
from vigie_ingest.config import Settings
from vigie_ingest.db import connect, open_inventory
from vigie_ingest.lock import exclusive_data_dir
from vigie_ingest.models import Batch
from vigie_ingest.ratelimit import RateLimiter
from vigie_ingest.retention import run_maintenance

log = logging.getLogger("vigie.ingest")
MAINTENANCE_INTERVAL_S = 3600
TRUSTED_PEERS_PER_COLLECTOR = 4

_UINT_RE = re.compile(r"^\d{1,19}$")
_IDENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_UUID_RE = re.compile(r"^[0-9a-f-]{36}$")
_SIG_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class BodyTooLarge(Exception):
    pass


class BodyTimeout(Exception):
    pass


@dataclass(frozen=True)
class Envelope:
    """Signed fields, taken from headers (the body cannot be parsed before HMAC verification)."""

    collector_id: str
    key_id: str
    boot_id: str
    seq: str
    sent_ts: str
    batch_id: str
    signature: str


def _unauthorized() -> Response:
    # Uniform on purpose: no detail distinguishing bad HMAC / unknown / revoked / bad headers.
    return JSONResponse({"error": "unauthorized"}, status_code=401)


def _parse_envelope(headers: Mapping[str, str]) -> Envelope | None:
    values = {
        "collector_id": (headers.get("x-vigie-collector-id", ""), _IDENT_RE),
        "key_id": (headers.get("x-vigie-key-id", ""), _IDENT_RE),
        "boot_id": (headers.get("x-vigie-boot-id", ""), _IDENT_RE),
        "seq": (headers.get("x-vigie-seq", ""), _UINT_RE),
        "sent_ts": (headers.get("x-vigie-sent-ts", ""), _UINT_RE),
        "batch_id": (headers.get("x-vigie-batch-id", ""), _UUID_RE),
        "signature": (headers.get("x-vigie-signature", ""), _SIG_RE),
    }
    if not all(pattern.fullmatch(value) for value, pattern in values.values()):
        return None
    return Envelope(**{name: value for name, (value, _) in values.items()})


async def read_limited_body(request: Request, cap: int, timeout_s: float) -> bytes:
    """Read the body, aborting when it exceeds `cap` bytes or `timeout_s` seconds."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > cap):
        raise BodyTooLarge
    chunks: list[bytes] = []
    total = 0
    try:
        async with asyncio.timeout(timeout_s):
            async for chunk in request.stream():
                total += len(chunk)
                if total > cap:
                    raise BodyTooLarge
                chunks.append(chunk)
    except TimeoutError as exc:
        raise BodyTimeout from exc
    return b"".join(chunks)


def _matches_envelope(batch: Batch, env: Envelope) -> bool:
    return (
        batch.collector_id == env.collector_id
        and batch.key_id == env.key_id
        and batch.boot_id == env.boot_id
        and str(batch.seq) == env.seq
        and str(batch.sent_ts) == env.sent_ts
        and batch.batch_id == env.batch_id
    )


def process_batch(
    settings: Settings,
    env: Envelope,
    body: bytes,
    now: float,
    collector_allow: Callable[[str], bool] | None = None,
    on_verified: Callable[[], None] | None = None,
) -> tuple[int, dict[str, object]]:
    """PRP section 4 checks after size cap and rate limit. Sync; runs in a worker thread.

    The HMAC is verified before any database connection is opened, so unauthenticated
    requests cost no database work. `collector_allow` is the per-collector rate limiter; it is
    charged only after the HMAC verifies, so unauthenticated requests never touch its table.
    `on_verified` runs right after the HMAC verifies (the peer allowlist hook).
    """
    key = auth.load_key(settings.secrets_dir, env.key_id)
    message = auth.signing_string(
        env.collector_id, env.key_id, env.boot_id, env.seq, env.sent_ts, env.batch_id, body
    )
    if not auth.verify(key, env.signature, message):
        return 401, {"error": "unauthorized"}
    if on_verified is not None:
        on_verified()
    if collector_allow is not None and not collector_allow(env.collector_id):
        return 429, {"error": "rate_limited"}

    conn = connect(settings.inventory_path)
    try:
        collector = store.get_collector(conn, env.collector_id)
        if collector is None or collector.key_id != env.key_id or collector.revoked:
            return 401, {"error": "unauthorized"}

        rejection = store.check_state(
            conn,
            collector,
            env.batch_id,
            env.boot_id,
            int(env.seq),
            int(env.sent_ts),
            now,
            settings.max_clock_skew_s,
        )
        if rejection:
            return _rejection_response(rejection)

        try:
            batch = Batch.model_validate_json(
                body, context={"max_spool_age_s": settings.max_spool_age_s}
            )
        except (ValidationError, ValueError):
            store.record_parse_failure(conn, env.collector_id)
            return 422, {"error": "invalid_batch"}
        if not _matches_envelope(batch, env):
            store.record_parse_failure(conn, env.collector_id)
            return 422, {"error": "envelope_mismatch"}
        if len(store.rows_by_day(batch)) > settings.max_shard_days:
            store.record_parse_failure(conn, env.collector_id)
            return 422, {"error": "too_many_shard_days"}
    finally:
        conn.close()

    outcome = store.apply_batch(
        settings.inventory_path, settings.data_dir, batch, now, settings.max_clock_skew_s
    )
    if outcome == "applied":
        return 200, {"duplicate": False}
    if outcome == "revoked":
        return 401, {"error": "unauthorized"}
    return _rejection_response(outcome)


def _rejection_response(rejection: store.Rejection) -> tuple[int, dict[str, object]]:
    if rejection == "duplicate":
        return 200, {"duplicate": True}
    if rejection == "bad_ts":
        return 400, {"error": "sent_ts_out_of_range"}
    return 409, {"error": "seq_regression"}


def create_app(
    settings: Settings,
    clock: Callable[[], float] = time.time,
    lock_data_dir: bool = True,
) -> FastAPI:
    """`lock_data_dir=False` only for a caller (the CLI) that already holds the data-dir flock."""
    # Pre-auth: keyed by peer address only (a CPU guard; the claimed collector id is untrusted).
    peer_limiter = RateLimiter(
        settings.rate_limit_preauth_per_min,
        settings.rate_limit_window_s,
        clock,
        ipv6_prefix=settings.rate_limit_ipv6_prefix,
    )
    # Post-auth: keyed by collector id, charged only once the HMAC has verified.
    collector_limiter = RateLimiter(
        settings.rate_limit_per_window, settings.rate_limit_window_s, clock
    )

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        with contextlib.ExitStack() as stack:
            if lock_data_dir:
                stack.enter_context(exclusive_data_dir(settings.data_dir))
            settings.data_dir.mkdir(parents=True, exist_ok=True)
            active = _require_keys(settings)
            peer_limiter.set_trusted_capacity(active * TRUSTED_PEERS_PER_COLLECTOR)
            task = asyncio.create_task(_maintenance_loop(settings, clock))
            try:
                yield
            finally:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(
        title="vigie-ingest", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None
    )

    app.state.peer_limiter = peer_limiter
    app.state.collector_limiter = collector_limiter

    @app.post("/v1/batch")
    async def post_batch(request: Request) -> Response:
        env = _parse_envelope(request.headers)
        peer = request.client.host if request.client else "?"
        if not peer_limiter.allow(peer):
            return JSONResponse({"error": "rate_limited"}, status_code=429)
        if env is None:
            return _unauthorized()  # before the body is read or any other work is done
        try:
            body = await read_limited_body(
                request, settings.max_body_bytes, settings.body_timeout_s
            )
        except BodyTooLarge:
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        except BodyTimeout:
            return JSONResponse({"error": "body_timeout"}, status_code=408)
        status, payload = await run_in_threadpool(
            process_batch,
            settings,
            env,
            body,
            clock(),
            collector_limiter.allow,
            lambda: peer_limiter.mark_verified(peer),
        )
        return JSONResponse(payload, status_code=status)

    return app


def _require_keys(settings: Settings) -> int:
    """Fail fast: every non-revoked collector must have a usable key file. Returns their count."""
    conn = open_inventory(settings.inventory_path)
    try:
        active = list(store.active_collectors(conn))
        missing = [c.id for c in active if auth.load_key(settings.secrets_dir, c.key_id) is None]
    finally:
        conn.close()
    if missing:
        raise RuntimeError(f"no valid key file (>=32 bytes hex) for collectors: {missing}")
    return len(active)


async def _maintenance_loop(settings: Settings, clock: Callable[[], float]) -> None:
    while True:
        try:
            await run_in_threadpool(run_maintenance, settings, clock())
        except Exception:
            log.exception("maintenance failed")
        await asyncio.sleep(MAINTENANCE_INTERVAL_S)
