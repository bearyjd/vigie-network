"""Contracts for the standalone ntfy sender (a local fake HTTPS server, no real network)."""

from __future__ import annotations

import http.server
import importlib.util
import json
import logging
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "ntfy_sender", Path(__file__).parents[1] / "persistent" / "ntfy_sender.py"
)
ns = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ns
SPEC.loader.exec_module(ns)

OPENSSL = str(shutil.which("openssl"))
PERSISTENT = Path(__file__).parents[1] / "persistent"
TOPIC = "Zk3-test_topic_0123456789abcdef"
TOKEN = "tk-secret.token~value"
pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")


TITLES = {"open": "Vigie: check {label}", "recover": "Vigie: {label} is back to normal"}
BODIES = {
    "open": "{label}: unusual activity detected. Review it here: {link}",
    "recover": "{label}: the activity has returned to normal. Details: {link}",
}


def record(n: int = 1, label: str | None = None, **over: object) -> dict:
    kind = str(over.get("kind", "open"))
    template = kind if kind in TITLES else "open"
    name = label or f"Device abc{n}"
    link = f"/ui/#incident=i{n}"
    rec = {
        "delivery_id": f"d{n}",
        "kind": kind,
        "title": TITLES[template].format(label=name),
        "body": BODIES[template].format(label=name, link=over.get("link", link)),
        "link": link,
    }
    rec.update(over)
    return rec


def line(rec: dict) -> bytes:
    return (json.dumps(rec, separators=(",", ":")) + "\n").encode()


class FakeNtfy:
    """HTTPS server. `script` entries: dict(status, headers, delay, body); default is 200."""

    def __init__(self, cert: Path, key: Path) -> None:
        self.script: list[dict] = []
        self.requests: list[dict] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                step = outer.script.pop(0) if outer.script else {}
                outer.requests.append(
                    {"path": self.path, "headers": dict(self.headers), "body": body}
                )
                time.sleep(step.get("delay", 0))
                try:
                    self.send_response(step.get("status", 200))
                    for k, v in step.get("headers", {}).items():
                        self.send_header(k, v)
                    payload = step.get("body", b"{}")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except OSError:
                    pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "c.pem", d / "k.pem"
    subprocess.run(  # noqa: S603
        [
            OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(cert), "-days", "2", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True, capture_output=True,
    )  # fmt: skip
    return cert, key


@pytest.fixture
def server(cert: tuple[Path, Path]):
    srv = FakeNtfy(*cert)
    yield srv
    srv.httpd.shutdown()
    srv.httpd.server_close()


@pytest.fixture
def ctx(cert: tuple[Path, Path]) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(cert[0]))


def private(path: Path, text: str | bytes) -> Path:
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    path.chmod(0o600)
    return path


class Env:
    def __init__(self, tmp: Path, server: FakeNtfy, ssl_ctx: ssl.SSLContext) -> None:
        self.tmp, self.server, self.ctx = tmp, server, ssl_ctx
        self.delivery = tmp / "delivery.jsonl"
        self.cursor = tmp / "cursor.json"
        self.topic = private(tmp / "topic", TOPIC + "\n")
        self.token = private(tmp / "token", TOKEN)
        self.sleeps: list[float] = []

    def raw_config(self, **over: object) -> dict:
        cfg = {
            "delivery_file": str(self.delivery),
            "cursor_file": str(self.cursor),
            "topic_file": str(self.topic),
            "server": self.server.url,
            "allowed_hosts": ["127.0.0.1"],
            "timeout_seconds": 5,
        }
        cfg.update(over)
        return {k: v for k, v in cfg.items() if v is not None}

    def run(self, _run: dict | None = None, **over: object):
        cfg = ns.parse_config(self.raw_config(**over))
        kwargs = {"ssl_context": self.ctx, "sleep": self.sleeps.append, **(_run or {})}
        return ns.run(cfg, **kwargs)

    def write(self, *lines: bytes) -> None:
        with self.delivery.open("ab") as f:
            f.write(b"".join(lines))

    def cursor_offset(self) -> int:
        return json.loads(self.cursor.read_text())["offset"] if self.cursor.exists() else 0


@pytest.fixture
def env(tmp_path: Path, server: FakeNtfy, ctx: ssl.SSLContext) -> Env:
    return Env(tmp_path, server, ctx)


# --- success, cursor, headers -----------------------------------------------------------------


def test_success_sends_fields_and_advances_cursor(env: Env) -> None:
    env.write(line(record(1)), line(record(2, kind="recover")))
    result = env.run()
    assert (result.sent, result.skipped, result.code) == (2, 0, 0)
    first, second = env.server.requests
    assert first["path"] == "/" + TOPIC
    assert first["body"] == record(1)["body"].encode()
    assert first["headers"]["Title"] == record(1)["title"]
    assert first["headers"]["Tags"] == "warning"
    assert second["headers"]["Tags"] == "white_check_mark"
    assert env.cursor_offset() == env.delivery.stat().st_size
    assert oct(env.cursor.stat().st_mode & 0o777) == "0o600"
    assert env.run().sent == 0 and len(env.server.requests) == 2


def test_no_click_header_without_click_base(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    assert "Click" not in env.server.requests[0]["headers"]
    assert "Authorization" not in env.server.requests[0]["headers"]


def test_click_and_bearer_when_configured(env: Env) -> None:
    env.write(line(record(1)))
    env.run(click_base="https://vigie.example.invalid/", token_file=str(env.token))
    headers = env.server.requests[0]["headers"]
    assert headers["Click"] == "https://vigie.example.invalid/ui/#incident=i1"
    assert headers["Authorization"] == "Bearer " + TOKEN


def test_only_validated_fields_are_forwarded(env: Env) -> None:
    env.write(line(record(1, secret_extra="LEAKME", ip="203.0.113.9")))
    env.run()
    sent = json.dumps(env.server.requests[0], default=str)
    assert "LEAKME" not in sent and "203.0.113.9" not in sent


def test_non_ascii_title_is_folded_to_ascii(env: Env) -> None:
    env.write(line(record(1, label="Café")))
    assert env.run().code == 0
    assert env.server.requests[0]["headers"]["Title"] == "Vigie: check Cafe"


def test_missing_delivery_file_is_caught_up(env: Env) -> None:
    assert env.run().code == 0 and not env.server.requests


# --- reading ------------------------------------------------------------------------------


def test_partial_trailing_line_waits(env: Env) -> None:
    full = line(record(2))
    env.write(line(record(1)), full[:20])
    assert env.run().sent == 1
    offset = env.cursor_offset()
    assert env.run().sent == 0 and env.cursor_offset() == offset
    env.write(full[20:])
    assert env.run().sent == 1 and len(env.server.requests) == 2


def test_truncation_restarts_from_zero(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    env.write(line(record(1)), line(record(2)))
    env.run()
    env.delivery.write_bytes(line(record(3)))
    with caplog.at_level(logging.WARNING):
        assert env.run().sent == 1
    assert env.server.requests[-1]["body"] == record(3)["body"].encode()
    assert "restarting" in caplog.text


def test_replacement_with_new_inode_restarts(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    env.delivery.unlink()
    env.write(line(record(7)), line(record(8)))
    assert env.run().sent == 2


def test_replacement_with_larger_file_new_first_line_restarts(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    inode = env.delivery.stat().st_ino
    env.delivery.write_bytes(line(record(5)) + line(record(6)) + line(record(9)))
    assert env.delivery.stat().st_ino == inode  # same inode, larger, other first line
    assert env.run().sent == 3


def test_shrunk_file_with_same_first_line_restarts(env: Env) -> None:
    env.write(line(record(1)), line(record(2)), line(record(3)))
    env.run()
    env.delivery.write_bytes(line(record(1)) + line(record(4)))
    assert env.run().sent == 2


def test_replacement_with_same_content_prefix_but_new_inode_restarts(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    fresh = env.tmp / "fresh.jsonl"
    fresh.write_bytes(line(record(1)) + line(record(2)))
    os.replace(fresh, env.delivery)
    assert env.run().sent == 2  # restarted: record 1 is repeated, never lost


def test_response_read_is_bounded() -> None:
    reads: list[int] = []

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self, n: int = -1) -> bytes:
            reads.append(n)
            return b""

    class Opener:
        def open(self, req: object, timeout: float) -> Resp:
            return Resp()

    assert ns.send_once(Opener(), object(), 1.0).kind == "ok"
    assert reads == [ns.MAX_RESPONSE]


@pytest.mark.parametrize(
    "bad",
    [
        b"not json\n",
        b"[1,2]\n",
        b"[" * 6000 + b"\n",
        b'{"delivery_id":"x"}\n',
        b"\xff\xfe\n",
        line(record(1, kind="other")),
        line(record(1, title="a\u0007b")),
        line(record(1, title="line\r\nInjected: 1")),
        line(record(1, body="x" * 1001)),
        line(record(1, link="ui/no-slash")),
        line(record(1, link="//evil.example/x")),
        line(record(1, link="/has space")),
        line(record(1, delivery_id=5)),
        b'{"delivery_id":"d","kind":"open","title":"t","body":"b","link":"/'
        + b"a" * 9000
        + b'"}\n',
    ],
)
def test_bad_records_are_skipped_not_sent(env: Env, bad: bytes) -> None:
    env.write(bad, line(record(2)))
    result = env.run()
    assert (result.sent, result.skipped, result.code) == (1, 1, 0)
    assert [r["body"] for r in env.server.requests] == [record(2)["body"].encode()]
    assert env.cursor_offset() == env.delivery.stat().st_size


def test_trailing_bad_line_advances_cursor(env: Env) -> None:
    env.write(line(record(1)), b"garbage\n")
    env.run()
    assert env.cursor_offset() == env.delivery.stat().st_size


def test_header_injection_never_reaches_the_wire(env: Env) -> None:
    env.write(line(record(1, title="ok\r\nX-Evil: 1")))
    env.run()
    assert env.server.requests == []


def test_oversized_line_without_newline_is_skipped_in_chunks(env: Env) -> None:
    env.write(b"x" * 20000 + b"\n", line(record(2)))
    for _ in range(6):
        env.run(max_batch=1)
    assert [r["body"] for r in env.server.requests] == [record(2)["body"].encode()]


# --- errors -------------------------------------------------------------------------------


@pytest.mark.parametrize("status", [401, 402, 403, 404, 405, 418, 204, 304])
def test_permanent_4xx_stops_without_advancing(env: Env, status: int) -> None:
    env.write(line(record(1)), line(record(2)))
    env.server.script = [{"status": status}]
    result = env.run()
    assert (result.sent, result.code) == (0, 3)
    assert env.cursor_offset() == 0 and len(env.server.requests) == 1
    assert env.sleeps == []


def test_permanent_stop_keeps_earlier_progress(env: Env) -> None:
    env.write(line(record(1)), line(record(2)))
    env.server.script = [{}, {"status": 403}]
    result = env.run()
    assert (result.sent, result.code) == (1, 3)
    assert env.cursor_offset() == len(line(record(1)))


@pytest.mark.parametrize("status", [408, 425, 429, 500, 503])
def test_retryable_status_backs_off_then_exits_4(env: Env, status: int) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": status}] * 4
    result = env.run()
    assert result.code == 4 and env.cursor_offset() == 0
    assert len(env.server.requests) == ns.MAX_ATTEMPTS
    assert env.sleeps == [1.0, 2.0, 4.0]


def test_retry_after_is_honoured_and_capped(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [
        {"status": 429, "headers": {"Retry-After": "7"}},
        {"status": 429, "headers": {"Retry-After": "9999"}},
        {"status": 503, "headers": {"Retry-After": "soon"}},
        {},
    ]
    assert env.run().code == 0
    assert env.sleeps == [7.0, 60.0, 4.0]


def test_recovery_after_transient_failure(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": 500}]
    assert env.run().code == 0 and env.cursor_offset() > 0


def test_redirect_is_refused(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": 302, "headers": {"Location": "https://other.invalid/x"}}]
    result = env.run()
    assert result.code == 3 and env.cursor_offset() == 0 and len(env.server.requests) == 1


def test_timeout_is_retryable(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"delay": 1.0}] * 4
    result = env.run(timeout_seconds=0.3)
    assert result.code == 4 and env.cursor_offset() == 0


def test_response_body_is_capped(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"body": b"A" * 5_000_000}]
    assert env.run().code == 0


def test_untrusted_certificate_is_retryable_and_quiet(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    env.write(line(record(1)))
    env.ctx = ssl.create_default_context()  # system roots: the self-signed cert must fail
    with caplog.at_level(logging.DEBUG):
        assert env.run().code == 4
    assert env.server.requests == []
    assert "127.0.0.1" not in caplog.text and TOPIC not in caplog.text


def test_crash_between_send_and_cursor_write_duplicates_once(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.write(line(record(1)), line(record(2)))
    real = ns.save_cursor
    calls = []

    def crash(path: str, cursor: object) -> None:
        calls.append(1)
        if len(calls) == 2:
            raise ns.ConfigError("simulated crash")
        real(path, cursor)

    monkeypatch.setattr(ns, "save_cursor", crash)
    with pytest.raises(ns.ConfigError):
        env.run()
    monkeypatch.setattr(ns, "save_cursor", real)
    assert len(env.server.requests) == 2  # record 2 was sent, its cursor write was lost
    assert env.run().sent == 1  # at-least-once: record 2 repeats exactly once
    assert env.run().sent == 0
    assert len(env.server.requests) == 3


# --- secrets and config -------------------------------------------------------------------


def test_secret_symlink_refused(env: Env) -> None:
    link = env.tmp / "topic-link"
    link.symlink_to(env.topic)
    with pytest.raises(ns.ConfigError):
        ns.read_secret(str(link), "topic file")


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o700, 0o666])
def test_secret_wrong_mode_refused(env: Env, mode: int) -> None:
    env.topic.chmod(mode)
    with pytest.raises(ns.ConfigError, match="mode"):
        ns.read_secret(str(env.topic), "topic file")


def test_secret_mode_0400_accepted(env: Env) -> None:
    env.topic.chmod(0o400)
    assert ns.read_secret(str(env.topic), "topic file") == TOPIC


def test_secret_wrong_owner_refused(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    other = os.geteuid() + 1
    monkeypatch.setattr(ns.os, "geteuid", lambda: other)
    with pytest.raises(ns.ConfigError, match="owned"):
        ns.read_secret(str(env.topic), "topic file")


def test_secret_control_chars_refused(env: Env) -> None:
    private(env.topic, "abcdefgh\x07ijkl")
    with pytest.raises(ns.ConfigError, match="control"):
        ns.read_secret(str(env.topic), "topic file")
    private(env.topic, "abcdefgh\nijkl\n")
    with pytest.raises(ns.ConfigError, match="control"):
        ns.read_secret(str(env.topic), "topic file")


def test_secret_oversize_and_empty_refused(env: Env) -> None:
    private(env.topic, "a" * 5000)
    with pytest.raises(ns.ConfigError, match="large"):
        ns.read_secret(str(env.topic), "topic file")
    private(env.topic, "\n")
    with pytest.raises(ns.ConfigError, match="empty"):
        ns.read_secret(str(env.topic), "topic file")


def test_secret_strips_exactly_one_newline(env: Env) -> None:
    private(env.topic, "abcdefghij\n")
    assert ns.read_secret(str(env.topic), "t") == "abcdefghij"


@pytest.mark.parametrize(
    "topic",
    ["short", "a" * 23, "a" * 65, "has space" + "1" * 20, "slash/" + "1" * 20, "dot." + "1" * 24],
)
def test_topic_validation(env: Env, topic: str) -> None:
    private(env.topic, topic)
    with pytest.raises(ns.ConfigError, match="topic"):
        ns.load_topic(str(env.topic))


def test_config_unknown_keys_rejected(env: Env) -> None:
    with pytest.raises(ns.ConfigError, match="unknown"):
        ns.parse_config(env.raw_config(delivery_enabled=True))


@pytest.mark.parametrize(
    "over",
    [
        {"server": "http://ntfy.sh", "allowed_hosts": ["ntfy.sh"]},
        {"server": "https://user:pw@ntfy.sh", "allowed_hosts": ["ntfy.sh"]},
        {"server": "https://ntfy.sh?x=1", "allowed_hosts": ["ntfy.sh"]},
        {"server": "https://ntfy.sh/path", "allowed_hosts": ["ntfy.sh"]},
        {"server": "https://evil.example", "allowed_hosts": ["ntfy.sh"]},
        {"server": "https://ntfy.sh:bad", "allowed_hosts": ["ntfy.sh"]},
        {"click_base": "http://vigie.example"},
        {"click_base": "https://u@vigie.example"},
        {"click_base": "https://vigie.example/?q=1"},
        {"click_base": "https://vigie.example/#f"},
        {"timeout_seconds": 21},
        {"timeout_seconds": 0},
        {"timeout_seconds": True},
        {"max_batch": 0},
        {"max_batch": 1.5},
        {"delivery_file": "relative/path"},
        {"allowed_hosts": []},
    ],
)
def test_config_value_validation(env: Env, over: dict) -> None:
    with pytest.raises(ns.ConfigError):
        ns.parse_config(env.raw_config(**over))


def test_config_defaults() -> None:
    cfg = ns.parse_config({"delivery_file": "/a", "cursor_file": "/b", "topic_file": "/c"})
    assert cfg.server == "https://ntfy.sh" and cfg.allowed_hosts == ("ntfy.sh",)
    assert (cfg.timeout_seconds, cfg.max_batch, cfg.click_base) == (8.0, 50, None)


def test_config_file_must_be_private(tmp_path: Path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text("{}")
    path.chmod(0o644)
    with pytest.raises(ns.ConfigError, match="mode"):
        ns.load_config(str(path))


def test_corrupt_cursor_is_a_config_error(env: Env) -> None:
    private(env.cursor, "{broken")
    env.write(line(record(1)))
    with pytest.raises(ns.ConfigError, match="cursor"):
        env.run()
    assert env.server.requests == []


# --- no secret in logs ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "script", [[{"status": 403, "body": TOKEN.encode()}], [{"status": 503}] * 4]
)
def test_logs_never_contain_secrets(
    env: Env, caplog: pytest.LogCaptureFixture, script: list[dict]
) -> None:
    env.write(b"junk " + TOKEN.encode() + b"\n", line(record(1)))
    env.server.script = list(script)
    with caplog.at_level(logging.DEBUG):
        env.run(token_file=str(env.token), click_base="https://vigie.example.invalid")
    for needle in (TOPIC, TOKEN, "127.0.0.1", str(env.server.port), "Bearer", "vigie.example"):
        assert needle not in caplog.text


def test_cli_exit_codes_and_result_line(
    env: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_path = private(env.tmp / "cfg.json", json.dumps(env.raw_config()))
    env.write(line(record(1)))
    monkeypatch.setattr(ns, "run", lambda cfg: ns.RunResult(1, 0, ns.EXIT_OK))
    assert ns.main([str(cfg_path), "--once"]) == 0
    assert capsys.readouterr().out.strip() == "ntfy_sender sent=1 skipped=0 exit=0"
    cfg_path.chmod(0o644)
    assert ns.main([str(cfg_path)]) == 2


# --- unit templates -------------------------------------------------------------------------


def _active(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_unit_templates_run_under_podman_unshare_and_are_compatible() -> None:
    service = (PERSISTENT / "ntfy-sender.service").read_text()
    timer = (PERSISTENT / "ntfy-sender.timer").read_text()
    active = _active(service)
    exec_line = next(ln for ln in active if ln.startswith("ExecStart="))
    assert exec_line.startswith("ExecStart=/usr/bin/podman unshare /usr/bin/python3 -I ")
    assert exec_line.endswith(" --once")
    keys = {ln.split("=", 1)[0] for ln in active}
    # these break rootless podman (setuid newuidmap, user namespaces) and must stay absent
    assert not keys & {"NoNewPrivileges", "RestrictNamespaces", "CapabilityBoundingSet"}
    assert not keys & {"SystemCallFilter", "PrivateDevices", "MemoryDenyWriteExecute"}
    for needle in (
        "PrivateTmp=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "ProtectKernelModules=yes",
        "ProtectClock=yes",
        "ProtectHostname=yes",
        "Type=oneshot",
    ):
        assert needle in active
    assert any(ln.startswith("ReadWritePaths=/ABSOLUTE/PATH/TO/CURSOR_DIRECTORY") for ln in active)
    assert "# OnFailure=" in service  # documented placeholder, never active
    assert not any(ln.startswith("OnFailure=") for ln in active)
    assert "OnUnitActiveSec=60s" in timer and "Persistent=no" in timer


def test_docs_describe_unshare_and_host_mountpoint() -> None:
    text = (Path(__file__).parents[2] / "docs" / "monitoring.md").read_text()
    section = text[text.index("### Incident delivery to ntfy") :]
    for needle in (
        "podman unshare",
        "podman unshare test -r",
        "podman volume inspect",
        "{{.Mountpoint}}",
        "exit code 5",
        "OnFailure",
    ):
        assert needle in section
    assert "run the sender again" not in section


# --- fix round 1 --------------------------------------------------------------------------


def test_owner_check_is_the_effective_uid_not_the_real_uid(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under `podman unshare` the process is uid 0 and host-user files appear as uid 0."""
    monkeypatch.setattr(ns.os, "getuid", lambda: 99999)  # real uid is irrelevant
    assert ns.read_secret(str(env.topic), "topic file") == TOPIC
    mine = os.geteuid()
    monkeypatch.setattr(ns.os, "geteuid", lambda: mine + 1)
    with pytest.raises(ns.ConfigError, match="owned"):
        ns.read_secret(str(env.topic), "topic file")


# M1: rejected records


@pytest.mark.parametrize("status", [400, 413, 414, 422])
def test_rejected_record_is_skipped_after_a_successful_probe(
    env: Env, caplog: pytest.LogCaptureFixture, status: int
) -> None:
    env.write(line(record(1)), line(record(2)))
    env.server.script = [{"status": status}, {}]
    with caplog.at_level(logging.INFO):
        result = env.run()
    assert (result.sent, result.skipped, result.code) == (1, 1, 5)
    assert env.cursor_offset() == env.delivery.stat().st_size
    assert len(env.server.requests) == 2 and env.sleeps == []
    assert "rejected" in caplog.text and "Device abc1" not in caplog.text


def test_two_consecutive_rejections_stop_without_advancing(env: Env) -> None:
    env.write(line(record(1)), line(record(2)), line(record(3)))
    env.server.script = [{"status": 400}, {"status": 422}]
    result = env.run()
    assert (result.sent, result.code) == (0, 3)
    assert env.cursor_offset() == 0 and len(env.server.requests) == 2


def test_rejected_last_record_waits_for_a_successor(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": 400}]
    assert env.run().code == 3 and env.cursor_offset() == 0
    env.write(line(record(2)))
    env.server.script = [{"status": 400}, {}]
    result = env.run()
    assert (result.sent, result.skipped, result.code) == (1, 1, 5)
    assert env.cursor_offset() == env.delivery.stat().st_size


def test_probe_failure_leaves_the_rejected_record_in_place(env: Env) -> None:
    env.write(line(record(1)), line(record(2)))
    env.server.script = [{"status": 400}] + [{"status": 503}] * 4
    result = env.run()
    assert result.code == 4 and env.cursor_offset() == 0


def test_probe_permanent_failure_exits_3(env: Env) -> None:
    env.write(line(record(1)), line(record(2)))
    env.server.script = [{"status": 400}, {"status": 403}]
    assert env.run().code == 3 and env.cursor_offset() == 0


def test_invalid_line_between_rejected_and_probe(env: Env) -> None:
    env.write(line(record(1)), b"garbage\n", line(record(3)))
    env.server.script = [{"status": 400}, {}]
    result = env.run()
    assert (result.sent, result.skipped, result.code) == (1, 2, 5)
    assert env.cursor_offset() == env.delivery.stat().st_size


def test_exit_5_is_not_used_for_schema_skips(env: Env) -> None:
    env.write(b"garbage\n", line(record(2)))
    assert env.run().code == 0


# M2: serialisation


def test_overlapping_runs_do_not_double_send(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"delay": 1.5}]
    first: list = []
    thread = threading.Thread(target=lambda: first.append(env.run()))
    thread.start()
    deadline = time.monotonic() + 10
    while not env.server.requests and time.monotonic() < deadline:
        time.sleep(0.01)
    second = env.run()
    thread.join(timeout=15)
    assert (second.sent, second.code) == (0, 0)
    assert first[0].sent == 1 and len(env.server.requests) == 1


def test_lock_file_is_private_and_blocks_a_second_holder(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    lock = Path(str(env.cursor) + ".lock")
    assert oct(lock.stat().st_mode & 0o777) == "0o600"


def test_lock_file_symlink_is_refused(env: Env) -> None:
    Path(str(env.cursor) + ".lock").symlink_to(env.tmp / "elsewhere")
    with pytest.raises(ns.ConfigError, match="lock"):
        env.run()


def test_stray_temp_files_do_not_corrupt_the_cursor(env: Env) -> None:
    (env.tmp / "cursor.json.tmp").write_text("garbage")
    (env.tmp / "cursor.json.1.deadbeef.tmp").symlink_to(env.tmp / "nowhere")
    env.write(line(record(1)), line(record(2)))
    assert env.run().sent == 2
    assert json.loads(env.cursor.read_text())["offset"] == env.delivery.stat().st_size
    assert env.run().sent == 0


def test_cursor_temp_file_is_removed_when_the_rename_fails(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ns.os, "replace", boom)
    with pytest.raises(ns.ConfigError, match="cursor"):
        ns.save_cursor(str(env.cursor), ns.Cursor(5, 1, 2, "ab"))
    assert [p.name for p in env.tmp.iterdir() if p.name.endswith(".tmp")] == []


# M3: device number


def test_changed_device_number_is_ignored_when_inode_and_head_match(
    env: Env, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    env.write(line(record(1)))
    env.run()
    env.write(line(record(2)))
    real = os.fstat

    class Stat:
        def __init__(self, r: os.stat_result) -> None:
            self.st_mode, self.st_size, self.st_ino = r.st_mode, r.st_size, r.st_ino
            self.st_uid, self.st_dev = r.st_uid, r.st_dev + 1

    monkeypatch.setattr(ns.os, "fstat", lambda fd: Stat(real(fd)))
    with caplog.at_level(logging.WARNING):
        assert env.run().sent == 1  # only the new record, no restart
    assert "device" in caplog.text


# L1: production defaults


def test_default_tls_context_rejects_the_self_signed_server(env: Env) -> None:
    env.write(line(record(1)))
    cfg = ns.parse_config(env.raw_config())
    result = ns.run(cfg, sleep=env.sleeps.append)  # no ssl_context injected
    assert result.code == 4 and env.server.requests == [] and env.cursor_offset() == 0


def test_proxy_environment_is_ignored(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")  # nothing listens there
    env.write(line(record(1)))
    assert env.run().sent == 1 and len(env.server.requests) == 1


def test_symlinked_delivery_file_is_refused(env: Env) -> None:
    real = env.tmp / "real.jsonl"
    real.write_bytes(line(record(1)))
    env.delivery.symlink_to(real)
    with pytest.raises(ns.ConfigError, match="delivery"):
        env.run()
    assert env.server.requests == []


# L2


@pytest.mark.parametrize("token", ["bad token", "tk!x", "a" * 513, "caf\u00e9", "a;b"])
def test_token_charset_is_enforced(env: Env, token: str) -> None:
    private(env.token, token)
    env.write(line(record(1)))
    with pytest.raises(ns.ConfigError, match="token"):
        env.run(token_file=str(env.token))
    assert env.server.requests == []


def test_click_base_must_be_ascii(env: Env) -> None:
    with pytest.raises(ns.ConfigError):
        ns.parse_config(env.raw_config(click_base="https://vigie.ex\u00e4mple.invalid"))


def test_encoding_errors_are_config_errors_not_retries() -> None:
    class Opener:
        def open(self, _req: object, timeout: float) -> None:
            raise UnicodeEncodeError("ascii", "\u00e9", 0, 1, "ordinal not in range")

    with pytest.raises(ns.ConfigError):
        ns.send_once(Opener(), object(), 1.0)


# L5: strict record shape


def _writer_module():
    path = Path(__file__).parents[2] / "server/src/vigie_pipeline/delivery_publish.py"
    spec = importlib.util.spec_from_file_location("writer_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_sender_templates_equal_the_writers_templates() -> None:
    writer = _writer_module()
    assert ns.TITLES == writer.TITLES and ns.BODIES == writer.BODIES
    assert ns.MAX_LABEL == writer.MAX_LABEL and ns.MAX_LINK == writer.MAX_LINK


def test_sender_label_charset_equals_the_writers_acceptor() -> None:
    writer = _writer_module()
    label = ns.re.compile(ns.LABEL_CHARS)
    for code in range(0x20, 0x3000):
        char = chr(code)
        assert bool(label.fullmatch(char)) == writer._allowed(char), hex(code)


def test_writer_output_is_accepted_by_the_sender() -> None:
    writer = _writer_module()
    for kind in ("open", "recover"):
        for name in ("Living room TV", "Caf\u00e9 d\u2019Anne", "Device abc"):
            msg = writer.build_message("d1", kind, "inc/1 &x", name, "dev")
            rec = {
                "delivery_id": msg.delivery_id,
                "kind": msg.kind,
                "title": msg.title,
                "body": msg.body,
                "link": msg.link,
            }
            assert ns.parse_record(line(rec).rstrip(b"\n")).link == msg.link
    long_id = writer.build_message("d1", "open", "x" * 500, "", "dev")
    assert ns.parse_record(json.dumps(long_id.__dict__).encode()).link == long_id.link


@pytest.mark.parametrize(
    "bad",
    [
        record(1, title="Vigie: check Device abc1 http://evil.invalid"),
        record(1, title="Hello there"),
        record(1, body="Click this: /ui/#incident=i1"),
        record(1, body=BODIES["open"].format(label="Other name", link="/ui/#incident=i1")),
        record(1, body=BODIES["open"].format(label="Device abc1", link="/ui/#incident=i2")),
        record(1, link="/ui/#incident=i1?x=1", body="x"),
        record(1, link="/other/path"),
        record(1, link="/ui/#incident=" + "a" * 187),
        record(1, label="a;b", title="Vigie: check a;b"),
        record(1, label="x" * 49),
    ],
)
def test_loose_records_are_rejected_by_the_sender(bad: dict) -> None:
    with pytest.raises(ValueError):
        ns.parse_record(line(bad).rstrip(b"\n"))


def test_label_consistency_between_title_and_body(env: Env) -> None:
    env.write(line(record(1, body=BODIES["open"].format(label="Zzz", link="/ui/#incident=i1"))))
    assert env.run().skipped == 1 and env.server.requests == []


# L6: budget and folding


def test_apostrophe_survives_ascii_folding() -> None:
    assert ns.ascii_title("Vigie: check Anne\u2019s TV") == "Vigie: check Anne's TV"


def test_total_run_budget_stops_backoff(env: Env) -> None:
    now = [0.0]

    def sleep(seconds: float) -> None:
        env.sleeps.append(seconds)
        now[0] += seconds

    env.write(line(record(1)))
    env.server.script = [{"status": 503}] * 4
    result = env.run({"sleep": sleep, "clock": lambda: now[0], "budget_seconds": 2.0})
    assert result.code == 4 and len(env.server.requests) == 2
    assert env.sleeps == [1.0]


def test_total_run_budget_is_checked_between_sends(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]

    def slow_send(_opener: object, _req: object, _timeout: float) -> object:
        now[0] += 70
        return ns.Outcome("ok")

    monkeypatch.setattr(ns, "send_once", slow_send)
    env.write(line(record(1)), line(record(2)), line(record(3)))
    result = env.run({"clock": lambda: now[0], "budget_seconds": 120.0})
    assert (result.sent, result.code) == (2, 4)


def test_each_call_gets_the_smaller_of_timeout_and_remaining_budget() -> None:
    timeouts: list[float] = []

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self, _n: int = -1) -> bytes:
            return b""

    class Opener:
        def open(self, _req: object, timeout: float) -> Resp:
            timeouts.append(timeout)
            return Resp()

    out = ns.send_with_retry(Opener(), object(), 8.0, lambda _s: None, lambda: 3.0)
    assert out.kind == "ok" and timeouts == [3.0]
    out = ns.send_with_retry(Opener(), object(), 8.0, lambda _s: None, lambda: 0.0)
    assert out.kind == "retry" and timeouts == [3.0]


def test_invalid_line_after_rejected_record_does_not_advance_past_it(env: Env) -> None:
    env.write(line(record(1)), b"garbage\n", line(record(3)))
    env.server.script = [{"status": 400}] + [{"status": 503}] * 4
    assert env.run().code == 4
    assert env.cursor_offset() == 0


def test_cursor_temp_file_is_created_exclusively(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ns.secrets, "token_hex", lambda _n: "fixed")
    victim = env.tmp / f"cursor.json.{os.getpid()}.fixed.tmp"
    victim.write_text("precious")
    with pytest.raises(ns.ConfigError, match="cursor"):
        ns.save_cursor(str(env.cursor), ns.Cursor(1, 1, 1, ""))
    assert victim.read_text() == "precious"
