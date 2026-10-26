"""Response envelope {ok, data, error, page} and the API error type."""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}
        self.extra = extra or {}


def envelope(
    data: Any = None, *, page: dict[str, Any] | None = None, error: dict[str, str] | None = None
) -> dict[str, Any]:
    return {"ok": error is None, "data": data, "error": error, "page": page}


def error_envelope(code: str, message: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return envelope(error={"code": code, "message": message, **(extra or {})})
