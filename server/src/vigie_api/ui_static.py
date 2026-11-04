"""Packaged, allowlisted readonly GUI shell; JSON authentication stays in the API."""

from pathlib import Path

from fastapi import FastAPI
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.responses import RedirectResponse, Response
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

UI_DIR = Path(__file__).resolve().parent / "ui"
ASSETS = frozenset({"index.html", "styles.css", "app.js", "client.js", "views.js"})
CSP = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "img-src 'self'",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    ]
)


class UiHeaders:
    """Apply policy to UI responses including mount redirects and handled errors."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or not (path in {"/", "/ui"} or path.startswith("/ui/")):
            await self.app(scope, receive, send)
            return

        async def protected(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = CSP
                headers["Cache-Control"] = "private, no-store"
                headers["Referrer-Policy"] = "no-referrer"
                headers["X-Content-Type-Options"] = "nosniff"
            await send(message)

        await self.app(scope, receive, protected)


class UiFiles(StaticFiles):
    def get_path(self, scope: Scope) -> str:
        path = scope.get("path", "")
        if "\\" in path or any(part in {".", ".."} for part in path.split("/")):
            raise HTTPException(404)
        return super().get_path(scope)

    async def get_response(self, path: str, scope: Scope) -> Response:
        if scope["method"] not in {"GET", "HEAD"}:
            raise HTTPException(405)
        selected = "index.html" if path in {"", "."} else path
        if selected not in ASSETS:
            raise HTTPException(404)
        return await super().get_response(selected, scope)


def mount_ui(app: FastAPI) -> None:
    app.add_middleware(UiHeaders)

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    def root() -> RedirectResponse:
        # Constant relative target: never built from Host/X-Forwarded-*/query, so no open redirect.
        return RedirectResponse("/ui/", status_code=307)

    @app.api_route("/ui", methods=["GET", "HEAD"], include_in_schema=False)
    def ui_slash() -> RedirectResponse:
        # Replaces Starlette's Mount slash redirect, which echoes the Host header and scheme.
        return RedirectResponse("/ui/", status_code=307)

    app.mount(
        "/ui",
        UiFiles(directory=UI_DIR, html=False, check_dir=False, follow_symlink=False),
        name="ui",
    )
