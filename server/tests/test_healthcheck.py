"""deploy/healthcheck.py: 5xx is never healthy; freshness follows the pipeline's heartbeat."""

from __future__ import annotations

import http.server
import importlib.util
import os
import ssl
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "healthcheck.py"
spec = importlib.util.spec_from_file_location("vigie_healthcheck", SCRIPT)
assert spec and spec.loader
hc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hc)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        code = {"/ok": 200, "/nope": 405, "/missing": 404, "/boom": 500, "/down": 503}[self.path]
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def tls_port(tmp_path_factory: pytest.TempPathFactory) -> Iterator[int]:
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(  # noqa: S603
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",  # noqa: S607
         "-nodes", "-keyout", str(d / "k"), "-out", str(d / "c"), "-days", "1", "-subj", "/CN=x"],
        check=True, capture_output=True,
    )  # fmt: skip
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c", d / "k")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def test_200_is_healthy_without_flags(tls_port: int) -> None:
    assert hc.check_http(tls_port, "/ok", False) is True


def test_4xx_is_unhealthy_unless_accepted(tls_port: int) -> None:
    assert hc.check_http(tls_port, "/nope", False) is False
    assert hc.check_http(tls_port, "/nope", True) is True
    assert hc.check_http(tls_port, "/missing", True) is True


@pytest.mark.parametrize("path", ["/boom", "/down"])
def test_5xx_is_never_healthy(tls_port: int, path: str) -> None:
    assert hc.check_http(tls_port, path, False) is False
    assert hc.check_http(tls_port, path, True) is False


def test_the_old_any_status_flag_is_gone() -> None:
    assert "--any-status" not in SCRIPT.read_text()


def test_fresh_follows_three_intervals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    beat = tmp_path / "ok"
    monkeypatch.setenv("VIGIE_PIPELINE_INTERVAL_S", "10")
    assert hc.check_fresh(str(beat)) is False  # never ran
    beat.touch()
    assert hc.check_fresh(str(beat)) is True
    os.utime(beat, (time.time() - 29, time.time() - 29))
    assert hc.check_fresh(str(beat)) is True
    os.utime(beat, (time.time() - 31, time.time() - 31))
    assert hc.check_fresh(str(beat)) is False


def test_fresh_rejects_a_garbage_interval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    beat = tmp_path / "ok"
    beat.touch()
    monkeypatch.setenv("VIGIE_PIPELINE_INTERVAL_S", "nope")
    assert hc.check_fresh(str(beat)) is False
