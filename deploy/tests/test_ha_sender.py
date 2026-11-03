"""Contracts for the standalone Home Assistant webhook sender (PRP-004, H1).

A local fake webhook server (HTTP and HTTPS) stands in for Home Assistant; no real network and no
real URL, id or address appear anywhere. All values below are placeholders.
"""

from __future__ import annotations

import ast
import fcntl
import http.server
import importlib.util
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
from pathlib import Path

import pytest

PERSISTENT = Path(__file__).parents[1] / "persistent"
REPO = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("ha_sender", PERSISTENT / "ha_sender.py")
ha = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ha
SPEC.loader.exec_module(ha)

OPENSSL = shutil.which("openssl")
WEBHOOK_ID = "Zk3-test_webhook_id_0123456789"
HEX_RE = re.compile(r"[0-9a-f]{32}")

TITLES = {"open": "Vigie: check {label}", "recover": "Vigie: {label} is back to normal"}
BODIES = {
    "open": "{label}: unusual activity detected. Review it here: {link}",
    "recover": "{label}: the activity has returned to normal. Details: {link}",
}


def record(n: int = 1, label: str | None = None, **over: object) -> dict:
    kind = str(over.get("kind", "open"))
    template = kind if kind in TITLES else "open"
    name = label or f"Device abcde{chr(96 + n)}"
    link = f"/ui/#incident=i{n}"
    rec = {
        "delivery_id": f"{n:032x}",
        "kind": kind,
        "title": TITLES[template].format(label=name),
        "body": BODIES[template].format(label=name, link=over.get("link", link)),
        "link": link,
    }
    rec.update(over)
    return rec


def line(rec: dict) -> bytes:
    return (json.dumps(rec, separators=(",", ":")) + "\n").encode()


class FakeHA:
    """Webhook stub. `script` entries: dict(status, headers, delay, body); `default` after that."""

    def __init__(self, cert: tuple[Path, Path] | None = None) -> None:
        self.script: list[dict] = []
        self.default: dict = {}
        self.requests: list[dict] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                step = outer.script.pop(0) if outer.script else outer.default
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body,
                    }
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
        self.scheme = "http"
        if cert is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}"

    @property
    def webhook(self) -> str:
        return f"{self.url}/api/webhook/{WEBHOOK_ID}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def make_cert(directory: Path, name: str) -> tuple[Path, Path]:
    if OPENSSL is None:
        pytest.skip("needs openssl")
    cert, key = directory / f"{name}.pem", directory / f"{name}.key"
    subprocess.run(  # noqa: S603
        [
            OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(cert), "-days", "2", "-subj", f"/CN={name}",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True, capture_output=True,
    )  # fmt: skip
    return cert, key


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[Path, Path]]:
    d = tmp_path_factory.mktemp("tls")
    return {"good": make_cert(d, "good"), "other": make_cert(d, "other")}


@pytest.fixture
def http_server():
    srv = FakeHA()
    yield srv
    srv.close()


@pytest.fixture
def tls_server(certs):
    srv = FakeHA(certs["good"])
    yield srv
    srv.close()


def private(path: Path, text: str | bytes) -> Path:
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    path.chmod(0o600)
    return path


class Env:
    def __init__(self, tmp: Path, server: FakeHA, ctx: ssl.SSLContext | None) -> None:
        self.tmp, self.server, self.ctx = tmp, server, ctx
        self.delivery = tmp / "delivery.jsonl"
        self.state = tmp / "state"
        self.state.mkdir(mode=0o700)
        self.cursor = self.state / "cursor.json"
        self.url_file = private(tmp / "webhook-url", server.webhook + "\n")
        self.sleeps: list[float] = []

    def raw_config(self, **over: object) -> dict:
        cfg = {
            "delivery_file": str(self.delivery),
            "cursor_file": str(self.cursor),
            "url_file": str(self.url_file),
            "allowed_hosts": ["127.0.0.1"],
            "http_hosts": ["127.0.0.1"] if self.server.scheme == "http" else None,
            "start_at_end": False,
            "timeout_seconds": 5,
        }
        cfg.update(over)
        return {k: v for k, v in cfg.items() if v is not None}

    def run(self, _run: dict | None = None, seed: bool = False, **over: object):
        cfg = ha.parse_config(self.raw_config(**over))
        kwargs = {
            "ssl_context": self.ctx,
            "sleep": self.sleeps.append,
            "seed_at_end": seed,
            **(_run or {}),
        }
        return ha.run(cfg, **kwargs)

    def write(self, *lines: bytes) -> None:
        with self.delivery.open("ab") as f:
            f.write(b"".join(lines))

    def cursor_offset(self) -> int:
        return json.loads(self.cursor.read_text())["offset"] if self.cursor.exists() else 0


@pytest.fixture
def env(tmp_path: Path, tls_server: FakeHA, certs) -> Env:
    return Env(tmp_path, tls_server, ssl.create_default_context(cafile=str(certs["good"][0])))


@pytest.fixture
def henv(tmp_path: Path, http_server: FakeHA) -> Env:
    return Env(tmp_path, http_server, None)


# --- success, payload, cursor --------------------------------------------------------------


def test_success_posts_json_payload_and_advances_cursor(env: Env) -> None:
    env.write(line(record(1)), line(record(2, kind="recover")))
    result = env.run()
    assert (result.sent, result.skipped, result.code) == (2, 0, 0)
    first, second = env.server.requests
    assert first["method"] == "POST" and first["path"] == f"/api/webhook/{WEBHOOK_ID}"
    assert first["headers"]["Content-Type"] == "application/json"
    payload = json.loads(first["body"])
    assert set(payload) == {"delivery_id", "sent_at", "kind", "title", "body", "link"}
    for key in ("delivery_id", "kind", "title", "body", "link"):
        assert payload[key] == record(1)[key]
    assert HEX_RE.fullmatch(payload["delivery_id"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|\+00:00)", payload["sent_at"])
    assert json.loads(second["body"])["kind"] == "recover"
    assert env.cursor_offset() == env.delivery.stat().st_size
    assert oct(env.cursor.stat().st_mode & 0o777) == "0o600"
    assert env.run().sent == 0 and len(env.server.requests) == 2


def test_only_validated_fields_are_forwarded(env: Env) -> None:
    env.write(line(record(1, secret_extra="LEAKME", ip="203.0.113.9")))
    env.run()
    assert b"LEAKME" not in env.server.requests[0]["body"]
    assert b"203.0.113.9" not in env.server.requests[0]["body"]


def test_no_url_field_without_vigie_base_url(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    assert "url" not in json.loads(env.server.requests[0]["body"])


def test_vigie_base_url_adds_absolute_url(env: Env) -> None:
    env.write(line(record(1)))
    env.run(vigie_base_url="https://vigie.example.invalid/")
    assert json.loads(env.server.requests[0]["body"])["url"] == (
        "https://vigie.example.invalid/ui/#incident=i1"
    )


def test_missing_delivery_file_is_caught_up(env: Env) -> None:
    assert env.run().code == 0 and not env.server.requests


def test_max_batch_limits_one_run(env: Env) -> None:
    env.write(line(record(1)), line(record(2)), line(record(3)))
    assert env.run(max_batch=2).sent == 2
    assert env.run(max_batch=2).sent == 1


@pytest.mark.parametrize("status", [200, 201, 202, 204])
def test_any_2xx_is_success(env: Env, status: int) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": status}]
    assert env.run().code == 0 and env.cursor_offset() == env.delivery.stat().st_size


def test_wrong_webhook_id_answered_200_counts_as_delivered(env: Env) -> None:
    """KNOWN LIMIT (PRP-004 H0): HA likely answers 2xx for an unknown id. The sender cannot tell,
    so it advances the cursor. This pins the behaviour; the end-to-end canary lives in HA."""
    private(env.url_file, f"{env.server.url}/api/webhook/some_other_id\n")
    env.write(line(record(1)))
    env.server.default = {"status": 200}
    assert env.run().sent == 1
    assert env.server.requests[0]["path"] == "/api/webhook/some_other_id"
    assert env.cursor_offset() == env.delivery.stat().st_size


# --- status classification -----------------------------------------------------------------


@pytest.mark.parametrize("code", [200, 201, 204, 299])
def test_classify_success(code: int) -> None:
    assert ha.classify_status(code, None).kind == "ok"


@pytest.mark.parametrize("code", [408, 425, 429, 500, 502, 503, 599])
def test_classify_retryable(code: int) -> None:
    assert ha.classify_status(code, None).kind == "retry"


@pytest.mark.parametrize("code", [301, 302, 304, 400, 401, 403, 404, 410, 413, 414, 422])
def test_classify_permanent(code: int) -> None:
    assert ha.classify_status(code, None).kind == "permanent"


def test_425_parity_with_ntfy_is_retryable_and_pinned(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": 425}]
    result = env.run()
    assert result.sent == 1 and len(env.server.requests) == 2


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 422])
def test_4xx_is_permanent_and_blocks_the_queue(env: Env, status: int) -> None:
    env.write(line(record(1)), line(record(2)))
    env.server.script = [{"status": status}]
    result = env.run()
    assert (result.sent, result.code) == (0, 3)
    assert len(env.server.requests) == 1  # no retry, no probe of the next record
    assert env.cursor_offset() == 0


def test_5xx_retries_with_backoff_then_exits_4(env: Env) -> None:
    env.write(line(record(1)))
    env.server.default = {"status": 503}
    result = env.run()
    assert result.code == 4 and len(env.server.requests) == 4
    assert env.sleeps == [1.0, 2.0, 4.0] and env.cursor_offset() == 0


def test_5xx_then_success_advances(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": 500}, {"status": 200}]
    assert env.run().sent == 1 and env.cursor_offset() > 0


def test_retry_after_is_honoured_and_capped(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": 429, "headers": {"Retry-After": "9999"}}]
    assert env.run().sent == 1
    assert env.sleeps == [60.0]


def test_timeout_is_retryable(env: Env) -> None:
    env.write(line(record(1)))
    env.server.default = {"delay": 0.6}
    result = env.run(timeout_seconds=0.2)
    assert result.code == 4 and env.cursor_offset() == 0


def test_connection_refused_is_retryable(env: Env) -> None:
    env.write(line(record(1)))
    env.server.close()
    assert env.run().code == 4


def test_redirect_is_never_followed(env: Env) -> None:
    env.write(line(record(1)))
    env.server.script = [{"status": 302, "headers": {"Location": "/api/webhook/elsewhere"}}]
    result = env.run()
    assert (result.sent, result.code) == (0, 3)
    assert len(env.server.requests) == 1 and env.cursor_offset() == 0


def test_run_budget_exhaustion_is_retryable(env: Env) -> None:
    env.write(line(record(1)))
    env.server.default = {"status": 503}
    ticks = iter(range(0, 10_000, 100))
    result = env.run(_run={"clock": lambda: float(next(ticks)), "budget_seconds": 150.0})
    assert result.code == 4 and env.cursor_offset() == 0


# --- first-run seed ------------------------------------------------------------------------


def test_new_cursor_directory_seeds_at_last_newline_and_sends_nothing(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    full = line(record(3))
    complete = line(record(1)) + line(record(2))
    env.write(complete, full[:20])
    fresh = env.tmp / "fresh-dir"  # does not exist yet
    env.cursor = fresh / "cursor.json"
    with caplog.at_level(logging.WARNING):
        result = env.run(start_at_end=True)
    assert (result.sent, result.code) == (0, 0) and not env.server.requests
    assert env.cursor_offset() == len(complete)
    assert oct(env.cursor.stat().st_mode & 0o777) == "0o600"
    assert f"{len(complete)} bytes" in caplog.text
    assert "Device" not in caplog.text and "incident=" not in caplog.text
    env.write(full[20:])  # the partial line completes and is sent later
    assert env.run(start_at_end=True).sent == 1
    assert json.loads(env.server.requests[0]["body"])["link"] == "/ui/#incident=i3"


def test_empty_existing_directory_also_seeds(env: Env) -> None:
    env.write(line(record(1)))
    assert env.run(start_at_end=True).sent == 0
    assert env.cursor_offset() == env.delivery.stat().st_size


def test_seed_with_missing_delivery_file_still_creates_cursor(env: Env) -> None:
    assert env.run(start_at_end=True).code == 0
    assert env.cursor.exists() and env.cursor_offset() == 0
    env.write(line(record(1)))
    assert env.run(start_at_end=True).sent == 1  # not an exit-2 trap on the second run


def test_seed_when_file_has_no_complete_line_starts_at_zero(env: Env) -> None:
    full = line(record(1))
    env.write(full[:30])
    assert env.run(start_at_end=True).sent == 0 and env.cursor_offset() == 0
    env.write(full[30:])
    assert env.run(start_at_end=True).sent == 1


def test_existing_directory_without_cursor_exits_2_and_flag_seeds(env: Env) -> None:
    env.write(line(record(1)))
    assert env.run().sent == 1  # start_at_end false: creates cursor and lock
    env.cursor.unlink()  # cursor lost; lock file remains in the directory
    env.write(line(record(2)))
    with pytest.raises(ha.ConfigError, match="seed-at-end"):
        env.run(start_at_end=True)
    assert len(env.server.requests) == 1  # nothing replayed, backlog not silently dropped
    assert not env.cursor.exists()
    assert env.run(start_at_end=True, seed=True).sent == 0
    assert env.cursor_offset() == env.delivery.stat().st_size
    env.write(line(record(3)))
    assert env.run(start_at_end=True).sent == 1


def test_seed_flag_is_ignored_when_a_cursor_exists(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    env.write(line(record(2)))
    assert env.run(seed=True, start_at_end=True).sent == 1


def test_start_at_end_false_replays_history(env: Env) -> None:
    env.write(line(record(1)), line(record(2)))
    assert env.run(start_at_end=False).sent == 2


def test_start_at_end_defaults_to_true() -> None:
    cfg = ha.parse_config({"delivery_file": "/a", "cursor_file": "/b", "url_file": "/c",
                           "allowed_hosts": ["ha.example.invalid"]})  # fmt: skip
    assert cfg.start_at_end is True


# --- cursor, truncate, replace, lock -------------------------------------------------------


def test_partial_trailing_line_waits(env: Env) -> None:
    full = line(record(2))
    env.write(line(record(1)), full[:20])
    assert env.run().sent == 1
    offset = env.cursor_offset()
    assert env.run().sent == 0 and env.cursor_offset() == offset
    env.write(full[20:])
    assert env.run().sent == 1 and len(env.server.requests) == 2


def test_crash_resume_repeats_at_most_the_unsaved_record(env: Env) -> None:
    env.write(line(record(1)), line(record(2)))
    env.server.script = [{"status": 200}, {"status": 500}] + [{"status": 500}] * 3
    assert env.run().code == 4
    assert env.cursor_offset() == len(line(record(1)))
    assert env.run().sent == 1


def test_truncation_restarts_from_zero(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    env.write(line(record(1)), line(record(2)))
    env.run()
    env.delivery.write_bytes(line(record(3)))
    with caplog.at_level(logging.WARNING):
        assert env.run().sent == 1
    assert json.loads(env.server.requests[-1]["body"])["link"] == "/ui/#incident=i3"
    assert "restarting" in caplog.text


def test_replacement_with_new_inode_restarts(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    env.delivery.unlink()
    env.write(line(record(7)), line(record(8)))
    assert env.run().sent == 2


def test_corrupt_cursor_is_a_config_error(env: Env) -> None:
    private(env.cursor, "{broken")
    env.write(line(record(1)))
    with pytest.raises(ha.ConfigError, match="cursor"):
        env.run()
    assert env.server.requests == []


def test_second_run_exits_zero_while_lock_is_held(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    env.write(line(record(1)))
    env.run()
    env.write(line(record(2)))
    fd = os.open(str(env.cursor) + ".lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with caplog.at_level(logging.INFO):
            result = env.run()
    finally:
        os.close(fd)
    assert (result.sent, result.code) == (0, 0) and len(env.server.requests) == 1
    assert "another run active" in caplog.text
    assert env.run().sent == 1


def test_lock_held_on_first_run_is_not_an_error(env: Env) -> None:
    env.cursor = env.state / "new.json"
    private(Path(str(env.cursor) + ".lock"), b"")
    fd = os.open(str(env.cursor) + ".lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert env.run(start_at_end=True).code == 0
    finally:
        os.close(fd)


def test_cursor_directory_must_not_be_group_writable(env: Env) -> None:
    env.state.chmod(0o770)
    with pytest.raises(ha.ConfigError, match="writable"):
        env.run()


def test_stale_temp_files_are_removed(env: Env) -> None:
    stale = env.state / "cursor.json.123.deadbeef.tmp"
    private(stale, b"x")
    old = time.time() - 7200
    os.utime(stale, (old, old))
    env.run()
    assert not stale.exists()


# --- records: shape, label fail-closed, delivery_id ----------------------------------------


def _writer_module():
    path = REPO / "server/src/vigie_pipeline/delivery_publish.py"
    spec = importlib.util.spec_from_file_location("writer_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_sender_templates_equal_the_writers_templates() -> None:
    writer = _writer_module()
    assert ha.TITLES == writer.TITLES and ha.BODIES == writer.BODIES
    assert ha.MAX_LABEL == writer.MAX_LABEL and ha.MAX_LINK == writer.MAX_LINK


def test_writer_alias_output_is_accepted() -> None:
    writer = _writer_module()
    for kind in ("open", "recover"):
        msg = writer.build_message("a" * 32, kind, "inc/1 &x", "", "dev")
        rec = {k: getattr(msg, k) for k in ("delivery_id", "kind", "title", "body", "link")}
        assert ha.parse_record(line(rec).rstrip(b"\n")).link == msg.link


@pytest.mark.parametrize(
    "label",
    [
        "Living room TV",
        "Device abc",
        "Device abcdefg",
        "Device ABCDEF",
        "Device abc1de",
    ],
)
def test_named_device_label_is_skipped_never_sent(
    env: Env, caplog: pytest.LogCaptureFixture, label: str
) -> None:
    env.write(line(record(1, label=label)), line(record(2)))
    with caplog.at_level(logging.DEBUG):
        result = env.run()
    assert (result.sent, result.skipped, result.code) == (1, 1, 0)
    assert label not in caplog.text
    assert json.loads(env.server.requests[0]["body"])["link"] == "/ui/#incident=i2"


@pytest.mark.parametrize(
    "delivery_id",
    [
        "d1",
        "A" * 32,
        "a" * 31,
        "a" * 33,
        "g" * 32,
        "a" * 31 + "\n",
        "",
        "a" * 16 + " " + "a" * 15,
    ],
)
def test_bad_delivery_id_is_skipped(env: Env, delivery_id: str) -> None:
    env.write(line(record(1, delivery_id=delivery_id)), line(record(2)))
    assert env.run().skipped == 1 and len(env.server.requests) == 1


@pytest.mark.parametrize(
    "bad",
    [
        record(1, title="Vigie: check Device abcdef http://evil.invalid"),
        record(1, body="Click this: /ui/#incident=i1"),
        record(1, link="/other/path"),
        record(1, link="/ui/#incident=i1?x=1", body="x"),
        record(1, kind="boom"),
    ],
)
def test_shape_violations_are_skipped(env: Env, bad: dict) -> None:
    env.write(line(bad), b"not json\n", b"[1]\n", b"\xff\xfe\n", line(record(2)))
    result = env.run()
    assert (result.sent, result.skipped) == (1, 4)


def test_oversized_line_is_skipped(env: Env) -> None:
    env.write(b"x" * 9000 + b"\n", line(record(2)))
    result = env.run()
    assert (result.sent, result.skipped) == (1, 1)


# --- configuration -------------------------------------------------------------------------


def test_config_defaults() -> None:
    cfg = ha.parse_config(
        {
            "delivery_file": "/a",
            "cursor_file": "/b",
            "url_file": "/c",
            "allowed_hosts": ["H.Ex"],
        }
    )
    assert cfg.allowed_hosts == ("h.ex",) and cfg.http_hosts == ()
    assert (cfg.ca_file, cfg.vigie_base_url) == (None, None)
    assert (cfg.timeout_seconds, cfg.max_batch, cfg.start_at_end) == (8.0, 50, True)


@pytest.mark.parametrize(
    "over",
    [
        {"topic_file": "/x"},  # an ntfy key
        {"surprise": 1},
        {"allowed_hosts": []},
        {"allowed_hosts": None},
        {"allowed_hosts": ["bad host"]},
        {"allowed_hosts": ["127.0.0.1"], "http_hosts": ["10.0.0.9"]},  # not a subset
        {"http_hosts": "127.0.0.1"},
        {"start_at_end": "yes"},
        {"start_at_end": 1},
        {"ca_file": "relative.pem"},
        {"vigie_base_url": "http://vigie.example.invalid"},
        {"vigie_base_url": "https://u:p@vigie.example.invalid"},
        {"vigie_base_url": "https://vigie.example.invalid/?q=1"},
        {"timeout_seconds": 21},
        {"timeout_seconds": 0},
        {"timeout_seconds": True},
        {"max_batch": 0},
        {"max_batch": 1.5},
        {"max_batch": 1001},
        {"delivery_file": "relative/path"},
        {"url_file": 5},
    ],
)
def test_config_value_validation(env: Env, over: dict) -> None:
    raw = env.raw_config()
    raw.update(over)
    raw = {k: v for k, v in raw.items() if v is not None}
    with pytest.raises(ha.ConfigError):
        ha.parse_config(raw)


@pytest.mark.parametrize("key", ["delivery_file", "cursor_file", "url_file", "allowed_hosts"])
def test_required_keys(env: Env, key: str) -> None:
    raw = env.raw_config()
    del raw[key]
    with pytest.raises(ha.ConfigError, match=key):
        ha.parse_config(raw)


def test_ip_literals_are_valid_hosts() -> None:
    cfg = ha.parse_config(
        {
            "delivery_file": "/a", "cursor_file": "/b", "url_file": "/c",
            "allowed_hosts": ["192.0.2.7", "fd00::1", "[FD00::2]"], "http_hosts": ["fd00::1"],
        }
    )  # fmt: skip
    assert cfg.allowed_hosts == ("192.0.2.7", "fd00::1", "fd00::2")
    assert cfg.http_hosts == ("fd00::1",)


def test_config_file_must_be_private(tmp_path: Path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text("{}")
    path.chmod(0o644)
    with pytest.raises(ha.ConfigError, match="mode"):
        ha.load_config(str(path))


def test_config_file_must_be_json(tmp_path: Path) -> None:
    with pytest.raises(ha.ConfigError, match="JSON"):
        ha.load_config(str(private(tmp_path / "cfg.json", "{nope")))


# --- webhook URL validation ----------------------------------------------------------------

ALLOWED = ("ha.example.invalid", "192.0.2.7", "fd00::1")
HTTP_OK = ("192.0.2.7", "fd00::1")


@pytest.mark.parametrize(
    "url",
    [
        "https://ha.example.invalid/api/webhook/abc_DEF-123",
        "https://ha.example.invalid:8123/api/webhook/abc",
        "HTTPS://HA.Example.Invalid/api/webhook/abc",
        "http://192.0.2.7:8123/api/webhook/abc",
        "http://[fd00::1]:8123/api/webhook/abc",
        "https://[fd00::1]/api/webhook/abc",
    ],
)
def test_valid_webhook_urls(url: str) -> None:
    assert ha.validate_webhook_url(url, ALLOWED, HTTP_OK) == url


@pytest.mark.parametrize(
    ("url", "rule"),
    [
        ("ftp://ha.example.invalid/api/webhook/SECRETID", "scheme"),
        (
            "http://ha.example.invalid/api/webhook/SECRETID",
            "scheme",
        ),  # http but not in http_hosts
        ("https://other.example.invalid/api/webhook/SECRETID", "host"),
        ("https://[fd00::2]/api/webhook/SECRETID", "host"),
        ("https://ha.example.invalid.evil.invalid/api/webhook/SECRETID", "host"),
        ("https://user:pw@ha.example.invalid/api/webhook/SECRETID", "userinfo"),
        ("https://ha.example.invalid/api/webhook/SECRETID?x=1", "characters"),
        ("https://ha.example.invalid/api/webhook/SECRETID#f", "characters"),
        (
            "https://ha.example.invalid\\@evil.invalid/api/webhook/SECRETID",
            "characters",
        ),
        ("https://ha.example.invalid/api/webhook/", "path"),
        ("https://ha.example.invalid/api/webhook/SECRETID/", "path"),
        ("https://ha.example.invalid/api/webhook/SECRET/ID", "path"),
        ("https://ha.example.invalid/api/webhook/SECRET%2fID", "path"),
        ("https://ha.example.invalid/api/webhook/SECRET.ID", "path"),
        ("https://ha.example.invalid/x/api/webhook/SECRETID", "path"),
        ("https://ha.example.invalid/api/webhook/" + "a" * 129, "path"),
        ("https://ha.example.invalid", "path"),
        ("https://ha.example.invalid:99999/api/webhook/SECRETID", "port"),
        ("https://ha.example.invalid:abc/api/webhook/SECRETID", "port"),
        ("https://[fd00::1/api/webhook/SECRETID", "host"),
        ("https://ha.example.invalid/api/webhook/SECRETID ", "characters"),
        ("https://ha.example.invalid/api/webhook/SECRET\tID", "characters"),
        ("https://ha.example.invalid/api/webhook/SÉCRET", "characters"),
        ("", "characters"),
    ],
)
def test_invalid_webhook_urls_name_only_the_rule(url: str, rule: str) -> None:
    with pytest.raises(ha.ConfigError) as info:
        ha.validate_webhook_url(url, ALLOWED, HTTP_OK)
    message = str(info.value)
    assert message == f"webhook URL invalid: {rule}", message
    for secret in (
        "SECRET",
        "example",
        "192.0.2",
        "fd00",
        "evil",
        "8123",
        "api/webhook",
    ):
        assert secret not in message


def test_http_host_must_also_be_named_in_http_hosts(henv: Env) -> None:
    henv.write(line(record(1)))
    with pytest.raises(ha.ConfigError, match="webhook URL invalid: scheme"):
        henv.run(http_hosts=None)
    assert henv.server.requests == []


def test_invalid_url_file_in_a_run_does_not_leak_or_seed(env: Env, caplog) -> None:
    private(env.url_file, f"{env.server.url}/not/a/webhook/SECRETID\n")
    env.write(line(record(1)))
    with pytest.raises(ha.ConfigError) as info, caplog.at_level(logging.DEBUG):
        env.run(start_at_end=True)
    assert "SECRETID" not in str(info.value) + caplog.text
    assert not env.cursor.exists() and env.server.requests == []


# --- private files -------------------------------------------------------------------------


def test_url_file_permissions_symlink_size_and_type(env: Env) -> None:
    env.write(line(record(1)))
    env.url_file.chmod(0o644)
    with pytest.raises(ha.ConfigError, match="mode"):
        env.run()
    env.url_file.chmod(0o400)
    assert env.run().sent == 1  # 0400 is accepted
    env.url_file.chmod(0o600)
    link = env.tmp / "link"
    link.symlink_to(env.url_file)
    with pytest.raises(ha.ConfigError):
        env.run(url_file=str(link))
    private(env.tmp / "big", b"https://" + b"a" * 2000)
    with pytest.raises(ha.ConfigError, match="too large"):
        env.run(url_file=str(env.tmp / "big"))
    with pytest.raises(ha.ConfigError, match="regular"):
        env.run(url_file=str(env.tmp))
    private(env.tmp / "empty", b"\n")
    with pytest.raises(ha.ConfigError, match="empty"):
        env.run(url_file=str(env.tmp / "empty"))
    private(env.tmp / "ctl", b"https://a\x07b")
    with pytest.raises(ha.ConfigError, match="control"):
        env.run(url_file=str(env.tmp / "ctl"))


def test_url_file_owner_must_be_the_effective_user(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(ha.ConfigError, match="owned"):
        ha.read_secret(str(env.url_file), "webhook URL file")


# --- TLS and ca_file -----------------------------------------------------------------------


def test_ca_file_verifies_a_private_ca(env: Env, certs) -> None:
    env.write(line(record(1)))
    ca = private(env.tmp / "ca.pem", certs["good"][0].read_bytes())
    result = env.run(_run={"ssl_context": None}, ca_file=str(ca))
    assert result.sent == 1


def test_private_ca_is_not_trusted_without_ca_file(env: Env) -> None:
    env.write(line(record(1)))
    result = env.run(_run={"ssl_context": None})
    assert result.code == 3 and env.server.requests == [] and env.cursor_offset() == 0


def test_wrong_certificate_fails_verification(env: Env, certs) -> None:
    env.write(line(record(1)))
    ca = private(env.tmp / "ca.pem", certs["other"][0].read_bytes())
    result = env.run(_run={"ssl_context": None}, ca_file=str(ca))
    assert result.code == 3 and env.server.requests == []


@pytest.mark.parametrize("content", [b"not a pem", b"", b"-----BEGIN CERTIFICATE-----\nAAAA\n"])
def test_bad_ca_file_is_a_config_error(env: Env, content: bytes) -> None:
    ca = private(env.tmp / "ca.pem", content)
    with pytest.raises(ha.ConfigError, match="CA"):
        env.run(_run={"ssl_context": None}, ca_file=str(ca))


def test_ca_file_must_be_a_private_file(env: Env, certs) -> None:
    ca = env.tmp / "ca.pem"
    ca.write_bytes(certs["good"][0].read_bytes())
    ca.chmod(0o644)
    with pytest.raises(ha.ConfigError, match="mode"):
        env.run(_run={"ssl_context": None}, ca_file=str(ca))


def test_ssl_context_verifies_and_keeps_system_roots() -> None:
    ctx = ha.build_ssl_context(None)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_no_code_path_disables_verification() -> None:
    source = (PERSISTENT / "ha_sender.py").read_text()
    for needle in (
        "CERT_NONE", "check_hostname = False", "_create_unverified_context",
        "_create_default_https_context", "verify=False", "PROTOCOL_TLS_CLIENT",
    ):  # fmt: skip
        assert needle not in source, needle


# --- plain HTTP ----------------------------------------------------------------------------


def test_plain_http_works_for_listed_http_hosts(henv: Env) -> None:
    henv.write(line(record(1)))
    assert henv.run().sent == 1
    assert henv.server.requests[0]["path"] == f"/api/webhook/{WEBHOOK_ID}"


# --- no secret in logs or output -----------------------------------------------------------


@pytest.mark.parametrize(
    "script",
    [
        [{"status": 404, "body": WEBHOOK_ID.encode()}],
        [{"status": 503, "body": WEBHOOK_ID.encode()}] * 4,
        [{"status": 302, "headers": {"Location": f"/api/webhook/{WEBHOOK_ID}"}}],
    ],
)
def test_logs_never_contain_url_id_host_or_record_text(
    env: Env, caplog: pytest.LogCaptureFixture, capsys, script: list[dict]
) -> None:
    env.write(
        b"junk " + WEBHOOK_ID.encode() + b"\n",
        line(record(1)),
        line(record(2, label="Bob")),
    )
    env.server.script = list(script)
    with caplog.at_level(logging.DEBUG):
        env.run(vigie_base_url="https://vigie.example.invalid")
    out = caplog.text + capsys.readouterr().out
    for needle in (
        WEBHOOK_ID, "127.0.0.1", str(env.server.port), "api/webhook", "vigie.example",
        "Device abcde", "Bob", "incident=", "unusual activity",
    ):  # fmt: skip
        assert needle not in out, needle


def test_unexpected_exception_logs_class_only(
    env: Env, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, capsys
) -> None:
    cfg_path = private(env.tmp / "cfg.json", json.dumps(env.raw_config()))

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError(env.server.webhook)

    monkeypatch.setattr(ha, "run", boom)
    with caplog.at_level(logging.DEBUG):
        assert ha.main([str(cfg_path), "--once"]) == 1
    assert WEBHOOK_ID not in caplog.text + capsys.readouterr().out
    assert "RuntimeError" in caplog.text


def test_config_error_message_has_no_secret(
    env: Env, caplog: pytest.LogCaptureFixture, capsys
) -> None:
    private(env.url_file, f"{env.server.url}/api/webhook/SECRETID?x=1\n")
    cfg_path = private(env.tmp / "cfg.json", json.dumps(env.raw_config()))
    with caplog.at_level(logging.DEBUG):
        assert ha.main([str(cfg_path)]) == 2
    out = caplog.text + capsys.readouterr().out
    assert "SECRETID" not in out and "127.0.0.1" not in out


# --- CLI -----------------------------------------------------------------------------------


def test_cli_exit_codes_and_result_line(
    henv: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_path = private(henv.tmp / "cfg.json", json.dumps(henv.raw_config()))
    henv.write(line(record(1)))
    monkeypatch.setattr(ha, "run", lambda cfg, **kw: ha.RunResult(1, 0, ha.EXIT_OK))
    assert ha.main([str(cfg_path), "--once"]) == 0
    assert capsys.readouterr().out.strip() == "ha_sender sent=1 skipped=0 exit=0"
    cfg_path.chmod(0o644)
    assert ha.main([str(cfg_path)]) == 2


def test_main_passes_seed_flag(henv: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_path = private(henv.tmp / "cfg.json", json.dumps(henv.raw_config()))
    seen: dict = {}
    monkeypatch.setattr(
        ha, "run", lambda cfg, **kw: seen.update(kw) or ha.RunResult(0, 0, ha.EXIT_OK)
    )
    ha.main([str(cfg_path), "--seed-at-end"])
    assert seen["seed_at_end"] is True
    ha.main([str(cfg_path)])
    assert seen["seed_at_end"] is False


def test_script_runs_isolated_end_to_end(henv: Env) -> None:
    cfg_path = private(henv.tmp / "cfg.json", json.dumps(henv.raw_config()))
    henv.write(line(record(1)))
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(PERSISTENT / "ha_sender.py"), str(cfg_path), "--once"],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ha_sender sent=1 skipped=0 exit=0"
    assert WEBHOOK_ID not in proc.stdout + proc.stderr
    bad = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(PERSISTENT / "ha_sender.py"), str(henv.tmp / "missing")],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert bad.returncode == 2


def test_standard_library_only() -> None:
    tree = ast.parse((PERSISTENT / "ha_sender.py").read_text())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            names.add((node.module or "").split(".")[0])
    assert names <= set(sys.stdlib_module_names), names - set(sys.stdlib_module_names)


# --- unit templates and docs ---------------------------------------------------------------


def _active(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_unit_templates_mirror_the_ntfy_ones() -> None:
    service = (PERSISTENT / "ha-sender.service").read_text()
    timer = (PERSISTENT / "ha-sender.timer").read_text()
    ntfy = _active((PERSISTENT / "ntfy-sender.service").read_text())
    active = _active(service)
    exec_line = next(ln for ln in active if ln.startswith("ExecStart="))
    assert exec_line.startswith("ExecStart=/usr/bin/podman unshare /usr/bin/python3 -I ")
    assert "/deploy/persistent/ha_sender.py " in exec_line and exec_line.endswith(" --once")
    assert not any("--seed-at-end" in ln for ln in active)  # never baked into a unit
    keys = {ln.split("=", 1)[0] for ln in active}
    forbidden = {
        "PrivateTmp", "ProtectSystem", "ProtectHome", "ReadWritePaths", "ReadOnlyPaths",
        "InaccessiblePaths", "PrivateMounts", "MountFlags", "ProtectKernelModules",
        "ProtectKernelLogs", "ProtectKernelTunables", "ProtectControlGroups", "ProtectClock",
        "ProtectHostname", "ProtectProc", "PrivateDevices", "NoNewPrivileges",
        "RestrictNamespaces", "CapabilityBoundingSet", "SystemCallFilter", "MemoryDenyWriteExecute",
    }  # fmt: skip
    assert not keys & forbidden
    hardening = [
        ln for ln in ntfy if not ln.startswith(("ExecStart=", "Description=", "Documentation="))
    ]
    assert [ln for ln in active if ln in hardening] == hardening
    assert "# OnFailure=" in service and not any(ln.startswith("OnFailure=") for ln in active)
    assert "OnUnitActiveSec=60s" in timer and "Persistent=no" in timer
    assert "Unit=ha-sender.service" in timer
    assert "ntfy" not in "\n".join(_active(service) + _active(timer))
    for text in (service, timer):
        assert "/ABSOLUTE/PATH" in text or "TEMPLATE" in text


def test_docs_have_the_home_assistant_delivery_section() -> None:
    text = (REPO / "docs" / "monitoring.md").read_text()
    section = text[text.index("### Home Assistant delivery") :]
    section = section.split("\n## ", 1)[0]
    for needle in (
        "ha_sender.py", "allowed_hosts", "http_hosts", "ca_file", "start_at_end",
        "--seed-at-end", "--once", "delivery_id", "sent_at", "podman unshare", "OnFailure",
        "ha-sender.timer", "does not prove", "canary", "Exit codes",
    ):  # fmt: skip
        assert needle in section, needle
    assert "/ABSOLUTE/PATH" in section
    assert not re.search(r"https?://(?!vigie\.example\.invalid|ha\.example\.invalid)\S+", section)


# --- fix round 1 ---------------------------------------------------------------------------

EMBEDDED = record(9)


def _oversized(size: int) -> bytes:
    """One physical line: filler of `size` bytes followed by a VALID record, then the newline."""
    return b"x" * size + json.dumps(EMBEDDED, separators=(",", ":")).encode() + b"\n"


def _bodies(env: Env) -> list[str]:
    return [json.loads(r["body"])["link"] for r in env.server.requests]


def test_oversized_line_is_discarded_through_its_newline_across_runs(env: Env) -> None:
    env.write(_oversized(ha.MAX_LINE + 1), line(record(2)))
    first = env.run(max_batch=1)
    assert (first.sent, first.skipped) == (0, 1)
    while env.run(max_batch=1).sent == 0 and env.cursor_offset() < env.delivery.stat().st_size:
        pass
    assert _bodies(env) == ["/ui/#incident=i2"]  # the embedded record was never sent


def test_oversized_line_is_discarded_within_one_run_across_chunks(env: Env) -> None:
    cap = 2 * (ha.MAX_LINE + 1)
    env.write(_oversized(cap + 5000), line(record(2)))
    result = env.run(max_batch=2)
    assert (result.sent, result.skipped) == (1, 1)
    assert _bodies(env) == ["/ui/#incident=i2"]


def test_oversized_line_still_being_written_keeps_discarding(env: Env) -> None:
    cap = ha.MAX_LINE + 1
    env.write(b"x" * cap)  # no newline yet
    assert env.run(max_batch=1).skipped == 1
    env.write(b"y" * 100)  # still no newline
    env.run(max_batch=1)
    env.write(json.dumps(EMBEDDED).encode() + b"\n", line(record(2)))
    for _ in range(5):
        env.run(max_batch=1)
    assert _bodies(env) == ["/ui/#incident=i2"]


def test_cursor_discard_flag_survives_in_the_cursor_file(env: Env) -> None:
    env.write(b"x" * (ha.MAX_LINE + 1))
    env.run(max_batch=1)
    assert json.loads(env.cursor.read_text())["discard"] is True
    private(env.cursor, json.dumps({"offset": 0, "dev": 0, "ino": 0, "head": "", "discard": 1}))
    with pytest.raises(ha.ConfigError, match="cursor"):
        env.run(max_batch=1)


def test_failed_first_run_leaves_nothing_so_the_corrected_run_seeds(env: Env) -> None:
    env.write(line(record(1)))
    fresh = env.tmp / "fresh-state"
    env.cursor = fresh / "cursor.json"
    good = env.url_file.read_text()
    private(env.url_file, f"{env.server.url}/not/a/webhook\n")
    with pytest.raises(ha.ConfigError):
        env.run(start_at_end=True)
    assert not fresh.exists()
    private(env.url_file, good)
    assert env.run(start_at_end=True).code == 0
    assert env.cursor_offset() == env.delivery.stat().st_size and not env.server.requests


def test_failed_run_in_existing_empty_dir_leaves_no_lock(env: Env) -> None:
    env.write(line(record(1)))
    private(env.url_file, "https://nope.example.invalid/api/webhook/x\n")
    with pytest.raises(ha.ConfigError):
        env.run(start_at_end=True)
    assert list(env.state.iterdir()) == []


def test_unmarked_leftover_lock_does_not_block_seeding(env: Env) -> None:
    env.write(line(record(1)))
    private(Path(str(env.cursor) + ".lock"), b"")  # a peer or crashed run that never got a cursor
    assert env.run(start_at_end=True).code == 0
    assert env.cursor_offset() == env.delivery.stat().st_size


def test_two_concurrent_first_runs_seed_exactly_once(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.write(line(record(1)))
    calls: list[int] = []
    entered, release = threading.Event(), threading.Event()
    real = ha.seed_cursor

    def slow_seed(cfg: ha.Config) -> ha.Cursor:
        calls.append(1)
        entered.set()
        assert release.wait(20)
        return real(cfg)

    monkeypatch.setattr(ha, "seed_cursor", slow_seed)
    results: dict[str, object] = {}
    winner = threading.Thread(
        target=lambda: results.update(a=env.run(start_at_end=True)), daemon=True
    )
    winner.start()
    assert entered.wait(20)
    second = env.run(start_at_end=True)  # the lock is held: exits 0, never exit 2, never seeds
    release.set()
    winner.join(20)
    assert second.code == 0 and results["a"].code == 0 and calls == [1]
    assert env.cursor_offset() == env.delivery.stat().st_size


def test_proxy_environment_is_ignored(henv: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    henv.write(line(record(1)))
    assert henv.run().sent == 1 and len(henv.server.requests) == 1


def test_in_place_truncate_and_regrow_with_other_first_line_restarts(env: Env) -> None:
    env.write(line(record(1)), line(record(2)))
    env.run()
    inode = env.delivery.stat().st_ino
    with env.delivery.open("r+b") as f:
        f.truncate(0)
        f.write(line(record(5)) + line(record(6)) + line(record(7)))
    assert env.delivery.stat().st_ino == inode
    assert env.run().sent == 3


def test_lock_file_must_be_a_regular_single_link_file_we_own(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = Path(str(env.cursor) + ".lock")
    other = private(env.tmp / "other", b"")
    os.link(other, lock)
    with pytest.raises(ha.ConfigError, match="single link"):
        ha.acquire_lock(str(env.cursor))
    lock.unlink()
    lock.symlink_to(other)
    with pytest.raises(ha.ConfigError, match="lock"):
        ha.acquire_lock(str(env.cursor))
    lock.unlink()
    os.mkfifo(lock)
    with pytest.raises(ha.ConfigError, match="regular"):
        ha.acquire_lock(str(env.cursor))
    lock.unlink()
    private(lock, b"")
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(ha.ConfigError, match="we own"):
        ha.acquire_lock(str(env.cursor))


def test_cursor_directory_owner_is_checked(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(ha.ConfigError, match="owned"):
        ha.check_cursor_dir(str(env.cursor))


@pytest.mark.parametrize("start_at_end", [False, True])
def test_delivery_file_must_be_a_regular_file(env: Env, start_at_end: bool) -> None:
    os.mkfifo(env.delivery)
    with pytest.raises(ha.ConfigError, match="regular"):
        env.run(start_at_end=start_at_end)


def test_unknown_config_keys_are_not_echoed(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    url_key = "https://ha.example.invalid/api/webhook/SECRETID"
    raw = env.raw_config()
    raw.update({url_key: 1, "good_name": 1, "Bad Key": 2})
    with pytest.raises(ha.ConfigError) as info:
        ha.parse_config(raw)
    assert "SECRETID" not in str(info.value) and "good_name" in str(info.value)
    cfg_path = private(env.tmp / "cfg.json", json.dumps(raw))
    assert ha.main([str(cfg_path)]) == 2
    assert "SECRETID" not in capsys.readouterr().out


def test_all_invalid_run_logs_one_error_and_keeps_the_exit_table(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    env.write(b"junk\n", b"[1]\n", line(record(1, label="Bob")))
    with caplog.at_level(logging.ERROR):
        result = env.run()
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert (result.sent, result.skipped, result.code) == (0, 3, 0) and len(errors) == 1
    assert "Bob" not in caplog.text


def test_body_read_error_after_2xx_is_still_success() -> None:
    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

        def read(self, _n: int) -> bytes:
            raise TimeoutError

    class Opener:
        def open(self, _req: object, timeout: float) -> Response:
            return Response()

    assert ha.send_once(Opener(), object(), 1.0).kind == "ok"


def test_certificate_verification_failure_is_permanent(env: Env) -> None:
    env.write(line(record(1)))
    result = env.run(_run={"ssl_context": None})  # private CA, no ca_file
    assert (result.code, env.server.requests) == (3, []) and env.sleeps == []


def test_non_private_http_host_logs_a_warning_without_the_host(
    caplog: pytest.LogCaptureFixture,
) -> None:
    base = {"delivery_file": "/a", "cursor_file": "/b", "url_file": "/c"}
    with caplog.at_level(logging.WARNING):
        ha.parse_config({**base, "allowed_hosts": ["127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "fd12::1", "::1"],
                         "http_hosts": ["127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1",
                                        "fd12::1", "::1"]})  # fmt: skip
    assert caplog.text == ""
    with caplog.at_level(logging.WARNING):
        ha.parse_config({**base, "allowed_hosts": ["203.0.113.9", "ha.example.invalid"],
                         "http_hosts": ["203.0.113.9", "ha.example.invalid"]})  # fmt: skip
    assert caplog.text.count("http_hosts") == 2
    assert "203.0.113" not in caplog.text and "example" not in caplog.text


# --- fix round 2 ---------------------------------------------------------------------------


def _cursor_state(env: Env) -> tuple[int, bool]:
    raw = json.loads(env.cursor.read_text())
    return raw["offset"], raw["discard"]


def test_discarded_tail_with_no_following_record_still_reaches_caught_up(env: Env) -> None:
    env.write(b"x" * (ha.MAX_LINE + 500) + b"\n")
    size = env.delivery.stat().st_size
    for _ in range(3):
        assert env.run(max_batch=1).code == 0
        assert _cursor_state(env) == (size, False)
    assert env.server.requests == []


def test_long_discard_is_bounded_per_run_but_always_progresses(env: Env) -> None:
    cap = 2 * (ha.MAX_LINE + 1)
    env.write(b"x" * (cap * 4 + 7) + b"\n", line(record(2)))
    size = env.delivery.stat().st_size
    env.run(max_batch=2)
    offset, discarding = _cursor_state(env)
    assert discarding and 0 < offset < size  # bounded: stopped part-way, progress saved
    seen = [offset]
    for _ in range(10):
        env.run(max_batch=2)
        seen.append(_cursor_state(env)[0])
    assert seen == sorted(seen) and _cursor_state(env) == (size, False)
    assert _bodies(env) == ["/ui/#incident=i2"]


def _lock_marked(env: Env) -> bool:
    return Path(str(env.cursor) + ".lock").read_bytes() == b"1"


def test_lock_is_marked_before_any_network_work(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.write(line(record(1)))

    seen: list[bool] = []

    def killed(*_a: object, **_k: object) -> None:
        seen.append(_lock_marked(env))  # at the moment network work would start
        raise KeyboardInterrupt

    monkeypatch.setattr(ha, "_run_locked", killed)
    with pytest.raises(KeyboardInterrupt):
        env.run(start_at_end=True)
    assert seen == [True]


def test_lock_is_marked_after_the_first_cursor_save_of_a_run(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.write(line(record(1)), line(record(2)))
    calls: list[int] = []
    marked: list[bool] = []

    def flaky(*_a: object, **_k: object) -> ha.Outcome:
        calls.append(1)
        if len(calls) == 2:
            marked.append(_lock_marked(env))  # state a SIGKILL here would leave behind
            raise KeyboardInterrupt
        return ha.Outcome("ok")

    monkeypatch.setattr(ha, "send_with_retry", flaky)
    with pytest.raises(KeyboardInterrupt):
        env.run()
    assert marked == [True]


def test_existing_cursor_with_unmarked_lock_is_marked_so_loss_is_detected(env: Env) -> None:
    env.write(line(record(1)))
    env.run()
    Path(str(env.cursor) + ".lock").write_bytes(b"")  # round-1-style leftover
    env.run()
    assert _lock_marked(env)
    env.cursor.unlink()
    with pytest.raises(ha.ConfigError, match="seed-at-end"):
        env.run(start_at_end=True)


def _cert_error(code: int) -> Exception:
    err = ssl.SSLCertVerificationError(1, "verify failed")
    err.verify_code = code
    return urllib.error.URLError(err)


@pytest.mark.parametrize(("code", "kind"), [(9, "retry"), (10, "retry"), (18, "permanent"),
                                            (19, "permanent"), (62, "permanent")])  # fmt: skip
def test_certificate_clock_errors_are_retryable_others_permanent(code: int, kind: str) -> None:
    class Opener:
        def open(self, _req: object, timeout: float) -> None:
            raise _cert_error(code)

    assert ha.send_once(Opener(), object(), 1.0).kind == kind
