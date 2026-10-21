"""TLS options for `post`: --ca-file, --pin-sha256 (SPKI), SSL_CERT_FILE. Verification stays on."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from trafficgen import DEFAULT_KEY, tls
from trafficgen.cli import main

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")


def _openssl(*args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        ["openssl", *args],
        input=stdin,
        capture_output=True,
        check=True,
    ).stdout


def _make_cert(tmp_path, name: str, kind: str):
    key, crt = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
    newkey = "ec" if kind == "ec" else "rsa:2048"
    extra = ["-pkeyopt", "ec_paramgen_curve:prime256v1"] if kind == "ec" else []
    _openssl("req", "-x509", "-newkey", newkey, *extra, "-nodes", "-keyout", str(key),
             "-out", str(crt), "-days", "2", "-subj", f"/CN={name}",
             "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost")  # fmt: skip
    return key, crt


def _openssl_pin(crt) -> str:
    """The deploy/gen-certs.sh recipe: SHA-256 over the SPKI DER, lowercase hex."""
    pub = _openssl("x509", "-in", str(crt), "-pubkey", "-noout")
    der = _openssl("pkey", "-pubin", "-outform", "der", stdin=pub)
    return hashlib.sha256(der).hexdigest()


class _Server:
    def __init__(self, key, crt) -> None:
        outer = self
        self.hits = 0

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                self.rfile.read(int(self.headers["Content-Length"]))
                outer.hits += 1
                body = json.dumps({"duplicate": False}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(crt), str(key))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture(params=["ec", "rsa"])
def tls_server(request, tmp_path):
    key, crt = _make_cert(tmp_path, "srv", request.param)
    srv = _Server(key, crt)
    yield SimpleNamespace(srv=srv, crt=crt, pin=_openssl_pin(crt))
    srv.close()


def _post(tmp_path, url, *extra):
    kf = tmp_path / "key"
    kf.write_text(DEFAULT_KEY.hex())
    return main(["post", "--profile", "baseline", "--windows", "4", "--no-pace", "--url", url,
                 "--key-file", str(kf), *extra])  # fmt: skip


def test_spki_pin_matches_openssl_recipe(tls_server):
    der = ssl.PEM_cert_to_DER_cert(tls_server.crt.read_text())
    assert tls.spki_sha256_hex(der) == tls_server.pin
    assert tls_server.pin == tls_server.pin.lower() and len(tls_server.pin) == 64


def test_ca_file_and_correct_pin_post_succeeds(tls_server, tmp_path, capsys):
    rc = _post(tmp_path, tls_server.srv.url, "--ca-file", str(tls_server.crt),
               "--pin-sha256", tls_server.pin)  # fmt: skip
    assert capsys.readouterr().err == ""
    assert rc == 0 and tls_server.srv.hits == 4


def test_uppercase_pin_accepted(tls_server, tmp_path):
    rc = _post(tmp_path, tls_server.srv.url, "--ca-file", str(tls_server.crt),
               "--pin-sha256", tls_server.pin.upper())  # fmt: skip
    assert rc == 0


def test_wrong_pin_refused_before_anything_is_sent(tls_server, tmp_path, capsys):
    rc = _post(tmp_path, tls_server.srv.url, "--ca-file", str(tls_server.crt),
               "--pin-sha256", "0" * 64)  # fmt: skip
    assert rc == 2 and tls_server.srv.hits == 0
    assert "pin mismatch" in capsys.readouterr().err


def test_self_signed_without_ca_file_fails_verification_nothing_sent(
    tls_server, tmp_path, capsys, monkeypatch
):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    assert _post(tmp_path, tls_server.srv.url) == 2
    assert tls_server.srv.hits == 0
    assert "certificate" in capsys.readouterr().err.lower()


def test_pin_alone_does_not_bypass_chain_verification(tls_server, tmp_path, monkeypatch):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    assert _post(tmp_path, tls_server.srv.url, "--pin-sha256", tls_server.pin) == 2
    assert tls_server.srv.hits == 0


def test_ca_file_for_other_cert_fails(tls_server, tmp_path):
    _, other = _make_cert(tmp_path, "other", "ec")
    assert _post(tmp_path, tls_server.srv.url, "--ca-file", str(other)) == 2
    assert tls_server.srv.hits == 0


def test_ssl_cert_file_env_route(tls_server, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.crt))
    assert _post(tmp_path, tls_server.srv.url) == 0


def test_missing_ca_file_clean_error(tmp_path, capsys):
    assert _post(tmp_path, "https://127.0.0.1:9", "--ca-file", str(tmp_path / "nope")) == 2
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("pin", ["abc", "g" * 64, "0" * 63])
def test_malformed_pin_is_usage_error(tmp_path, pin):
    with pytest.raises(SystemExit) as exc:
        _post(tmp_path, "https://127.0.0.1:9", "--pin-sha256", pin)
    assert exc.value.code == 2


def test_tls_options_on_plain_http_refused(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        _post(tmp_path, "http://127.0.0.1:9", "--pin-sha256", "0" * 64)
    assert exc.value.code == 2


def test_pin_compared_in_constant_time(tls_server, monkeypatch):
    calls = []
    real = tls.hmac.compare_digest
    monkeypatch.setattr(tls.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    der = ssl.PEM_cert_to_DER_cert(tls_server.crt.read_text())
    tls.require_pin(der, tls_server.pin)
    assert calls
    with pytest.raises(tls.TlsError):
        tls.require_pin(der, "1" * 64)


def test_every_new_connection_is_pinned(tls_server):
    """The check lives in the TLS socket, so reconnects are covered, not only the first one."""
    ctx = tls.make_context(str(tls_server.crt), "1" * 64)
    host, port = tls_server.srv.url.removeprefix("https://").split(":")
    for _ in range(2):
        with (
            socket.create_connection((host, int(port))) as raw,
            pytest.raises(ssl.SSLError, match="pin mismatch"),
        ):
            ctx.wrap_socket(raw, server_hostname=host)
    good = tls.make_context(str(tls_server.crt), tls_server.pin)
    with socket.create_connection((host, int(port))) as raw:
        good.wrap_socket(raw, server_hostname=host).close()


def test_context_never_disables_verification(tls_server):
    ctx = tls.make_context(str(tls_server.crt))
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert tls.make_context(None).verify_mode == ssl.CERT_REQUIRED
