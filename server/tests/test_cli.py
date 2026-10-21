from __future__ import annotations

from pathlib import Path

import pytest

from vigie_ingest import cli


@pytest.fixture
def uvicorn_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    calls: list[dict] = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda app, **kw: calls.append(kw))
    monkeypatch.setenv("VIGIE_DATA_DIR", "/nonexistent-never-created")
    monkeypatch.delenv("VIGIE_INSECURE_DEV", raising=False)
    monkeypatch.delenv("VIGIE_TLS_CERT", raising=False)
    monkeypatch.delenv("VIGIE_TLS_KEY", raising=False)
    return calls


def test_refuses_to_start_without_tls(uvicorn_calls: list[dict]) -> None:
    assert cli.main([]) == 2
    assert uvicorn_calls == []


def test_refuses_when_only_one_of_cert_and_key(uvicorn_calls: list[dict], tmp_path: Path) -> None:
    cert = tmp_path / "c.pem"
    cert.write_text("x")
    assert cli.main(["--tls-cert", str(cert)]) == 2
    assert uvicorn_calls == []


def test_refuses_when_tls_files_are_missing(uvicorn_calls: list[dict], tmp_path: Path) -> None:
    args = ["--tls-cert", str(tmp_path / "no.pem"), "--tls-key", str(tmp_path / "no.key")]
    assert cli.main(args) == 2
    assert uvicorn_calls == []


def test_starts_with_tls(uvicorn_calls: list[dict], tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("x")
    key.write_text("x")
    assert cli.main(["--tls-cert", str(cert), "--tls-key", str(key), "--port", "9443"]) == 0
    call = uvicorn_calls[0]
    assert call["ssl_certfile"] == str(cert) and call["ssl_keyfile"] == str(key)
    assert call["port"] == 9443
    assert call["limit_concurrency"] and call["timeout_keep_alive"]


def test_insecure_dev_flag_allows_plain_http(uvicorn_calls: list[dict]) -> None:
    assert cli.main(["--insecure-dev"]) == 0
    assert uvicorn_calls[0]["ssl_certfile"] is None
    assert uvicorn_calls[0]["ssl_keyfile"] is None


def test_insecure_dev_env_allows_plain_http(
    uvicorn_calls: list[dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIE_INSECURE_DEV", "1")
    assert cli.main([]) == 0
    assert len(uvicorn_calls) == 1
