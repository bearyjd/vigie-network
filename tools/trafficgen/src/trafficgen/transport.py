"""Sign and POST emissions using the ingest service's own signing code."""

from __future__ import annotations

import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
from vigie_ingest import auth

from . import tls
from .model import Emission

PostFn = Callable[[bytes, dict[str, str]], tuple[int, dict[str, Any]]]


def build_request(
    batch: dict[str, Any], key: bytes, header_overrides: dict[str, str] | None = None
) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(batch, separators=(",", ":")).encode()
    fields = tuple(
        str(batch[k]) for k in ("collector_id", "key_id", "boot_id", "seq", "sent_ts", "batch_id")
    )
    headers = {
        "X-Vigie-Collector-Id": fields[0],
        "X-Vigie-Key-Id": fields[1],
        "X-Vigie-Boot-Id": fields[2],
        "X-Vigie-Seq": fields[3],
        "X-Vigie-Sent-Ts": fields[4],
        "X-Vigie-Batch-Id": fields[5],
        "X-Vigie-Signature": auth.sign(key, *fields, body=body),
        "Content-Type": "application/json",
    }
    return body, {**headers, **(header_overrides or {})}


@dataclass(frozen=True)
class Result:
    emission: Emission
    status: int
    payload: dict[str, Any]

    @property
    def ok(self) -> bool:
        dup = self.emission.expect_duplicate
        return self.status == self.emission.expect_status and (
            dup is None or self.payload.get("duplicate") == dup
        )


def run(
    emissions: list[Emission],
    key: bytes,
    post: PostFn,
    on_arrival: Callable[[int], None] | None = None,
) -> list[Result]:
    """POST each emission in order; on_arrival(ts) lets a caller move a fake server clock."""
    results = []
    for em in emissions:
        if on_arrival:
            on_arrival(em.arrival_ts)
        body, headers = build_request(em.batch, key, em.header_overrides)
        status, payload = post(body, headers)
        results.append(Result(em, status, payload))
    return results


def http_post(
    url: str,
    timeout: float = 10.0,
    ca_file: str | None = None,
    pin_sha256: str | None = None,
) -> tuple[PostFn, httpx.Client]:
    """POST callable for a live server (caller closes the returned client).

    TLS verification is always on. `ca_file` replaces the trust anchors; `pin_sha256` additionally
    pins the server's SPKI (checked on every new connection, before any request is sent). Raises
    tls.TlsError on any TLS problem.
    """
    verify: ssl.SSLContext | bool = True
    if url.lower().startswith("https://"):
        verify = tls.make_context(ca_file, pin_sha256)
    client = httpx.Client(base_url=url, timeout=timeout, verify=verify)

    def post(body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        resp = client.post("/v1/batch", content=body, headers=headers)
        try:
            payload = resp.json()
        except ValueError:
            payload = {"raw": resp.text[:200]}
        return resp.status_code, payload if isinstance(payload, dict) else {"raw": payload}

    return post, client
