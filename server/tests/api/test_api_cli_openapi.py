from __future__ import annotations

import json
from pathlib import Path

import pytest
import uvicorn

from vigie_api import cli
from vigie_api.openapi_export import render
from vigie_api.schema import open_overrides
from vigie_api.tokens import verify_token


@pytest.fixture
def uvicorn_calls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[dict]:
    calls: list[dict] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("VIGIE_TLS_CERT", raising=False)
    monkeypatch.delenv("VIGIE_TLS_KEY", raising=False)
    return calls


def test_refuses_without_tls(uvicorn_calls: list[dict], capsys) -> None:
    assert cli.main([]) == 2
    assert "TLS is required" in capsys.readouterr().err and not uvicorn_calls


def test_refuses_cert_without_key_and_missing_files(
    uvicorn_calls: list[dict], tmp_path: Path
) -> None:
    assert cli.main(["--tls-cert", "c.pem"]) == 2
    assert cli.main(["--tls-cert", "c.pem", "--tls-key", "k.pem"]) == 2
    assert not uvicorn_calls


def test_starts_with_tls_files(uvicorn_calls: list[dict], tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("x")
    key.write_text("y")
    assert cli.main(["--tls-cert", str(cert), "--tls-key", str(key)]) == 0
    assert uvicorn_calls[0]["ssl_certfile"] == str(cert)
    assert uvicorn_calls[0]["limit_concurrency"] == 64


def test_insecure_dev_flag_and_env(
    uvicorn_calls: list[dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert cli.main(["--insecure-dev"]) == 0
    assert uvicorn_calls[0]["ssl_certfile"] is None
    monkeypatch.setenv("VIGIE_INSECURE_DEV", "1")
    assert cli.main([]) == 0  # env default is read when the parser is built


def test_tokens_create_and_revoke(tmp_path: Path, capsys) -> None:
    assert cli.main(["tokens", "--data-dir", str(tmp_path), "create", "--id", "app1"]) == 0
    token = capsys.readouterr().out.strip()
    conn = open_overrides(tmp_path / "overrides.db")
    assert verify_token(conn, token) is not None
    assert cli.main(["tokens", "--data-dir", str(tmp_path), "revoke", "app1"]) == 0
    assert verify_token(conn, token) is None
    assert cli.main(["tokens", "--data-dir", str(tmp_path), "revoke", "app1x"]) == 1


def test_tokens_create_errors(tmp_path: Path) -> None:
    base = ["tokens", "--data-dir", str(tmp_path), "create"]
    assert cli.main([*base, "--id", "bad id"]) == 2
    assert cli.main([*base, "--id", "dup"]) == 0
    assert cli.main([*base, "--id", "dup"]) == 2


def test_tokens_create_generates_id_and_stores_hash_only(tmp_path: Path, capsys) -> None:
    assert cli.main(["tokens", "--data-dir", str(tmp_path), "create"]) == 0
    out = capsys.readouterr()
    token = out.out.strip()
    stored = (
        open_overrides(tmp_path / "overrides.db")
        .execute("SELECT token_hash FROM api_tokens")
        .fetchone()[0]
    )
    assert token.startswith("vgt_") and token not in stored and "token id:" in out.err


def test_committed_openapi_matches_app() -> None:
    committed = Path(__file__).resolve().parents[3] / "api" / "openapi.yaml"
    assert committed.read_text(encoding="utf-8") == render(), (
        "run: uv run python -m vigie_api.openapi_export"
    )


def test_openapi_is_3_1_with_expected_surface() -> None:
    spec = json.loads(render())
    assert spec["openapi"].startswith("3.1")
    assert set(spec["paths"]) == {
        "/healthz", "/devices", "/devices/{device_id}", "/macs/{mac}", "/events", "/suggestions",
        "/suggestions/{suggestion_id}/accept", "/suggestions/{suggestion_id}/reject",
        "/identity/merges/{merge_id}/undo", "/identity/rules", "/identity/rules/{rule_id}",
        "/identity/candidates/{candidate_id}/clear-veto",
    }  # fmt: skip
    patch = spec["paths"]["/devices/{device_id}"]["patch"]
    assert any(p["name"] == "if-match" and p["required"] for p in patch["parameters"])
    assert {"412", "428"} <= set(patch["responses"])
    assert "security" not in spec["paths"]["/healthz"]["get"]


EXPECTED_ERRORS = {
    ("get", "/devices"): {"400", "401", "422", "429", "503"},
    ("get", "/devices/{device_id}"): {"401", "404", "422", "429", "503"},
    ("patch", "/devices/{device_id}"): {
        "400",
        "401",
        "403",
        "404",
        "409",
        "412",
        "413",
        "422",
        "428",
        "429",
        "503",
    },  # fmt: skip
    ("get", "/macs/{mac}"): {"401", "404", "422", "429", "503"},
    ("get", "/events"): {"400", "401", "422", "429", "503"},
    ("get", "/suggestions"): {"400", "401", "422", "429", "503"},
}


def test_every_route_declares_its_error_responses() -> None:
    spec = json.loads(render())
    for (method, path), codes in EXPECTED_ERRORS.items():
        responses = spec["paths"][path][method]["responses"]
        assert codes <= set(responses), (method, path, codes - set(responses))
        for code in codes:
            ref = responses[code]["content"]["application/json"]["schema"]["$ref"]
            assert ref.endswith("/ErrorEnvelope"), (method, path, code)


def test_every_2xx_has_a_typed_schema_and_etag_where_expected() -> None:
    spec = json.loads(render())
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            ok = operation["responses"]["200"]["content"]["application/json"]["schema"]
            assert "$ref" in ok, (method, path)
    for method, path in (("get", "/devices/{device_id}"), ("patch", "/devices/{device_id}")):
        assert "ETag" in spec["paths"][path][method]["responses"]["200"]["headers"]


def test_untrusted_text_fields_are_marked_in_the_schema() -> None:
    schemas = json.loads(render())["components"]["schemas"]
    expected = {
        "DeviceOut": ["name", "owner"],
        "MacOut": ["hostname"],
        "RecentEvent": ["summary"],
        "EventOut": ["summary"],
        "Explanation": ["reason_text"],
        "SuggestionOut": ["reason_text"],
        "DevicePatch": ["name", "owner"],
    }
    for schema, fields in expected.items():
        for field in fields:
            prop = schemas[schema]["properties"][field]
            text = prop.get("description") or next(
                (o["description"] for o in prop.get("anyOf", []) if "description" in o), ""
            )
            assert "UNTRUSTED" in text, (schema, field)
    assert "label" in schemas["SuggestionOut"]["properties"]["reason_text"]["description"]
