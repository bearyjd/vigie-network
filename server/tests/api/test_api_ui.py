from __future__ import annotations

from pathlib import Path

import pytest
from api_helpers import Env, env  # noqa: F401
from fastapi.testclient import TestClient

from vigie_api import cli, tokens
from vigie_api.app import create_app
from vigie_api.config import Settings
from vigie_api.schema import open_overrides


@pytest.fixture
def ui_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from vigie_api import ui_static

    assets = tmp_path / "assets"
    assets.mkdir()
    for name in ("index.html", "styles.css", "app.js", "client.js", "views.js"):
        (assets / name).write_text("<h1>Vigie</h1>" if name.endswith("html") else "/* asset */")
    (assets / "private.txt").write_text("not public")
    monkeypatch.setattr(ui_static, "UI_DIR", assets)
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        yield client


def test_shell_assets_are_public_and_json_remains_authenticated(ui_client):
    assert ui_client.get("/ui/").status_code == 200
    for name in ("index.html", "styles.css", "app.js", "client.js", "views.js"):
        response = ui_client.get("/ui/" + name)
        assert response.status_code == 200
        assert ui_client.head("/ui/" + name).status_code == 200
    assert ui_client.get("/devices").status_code == 401
    assert ui_client.get("/coverage?collector_id=synthetic-preview").status_code == 401


@pytest.mark.parametrize("path", ["/ui/", "/ui/app.js", "/ui/private.txt", "/ui"])
def test_ui_assets_errors_and_redirects_have_security_headers(ui_client, path):
    response = ui_client.get(path, follow_redirects=False)
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    policy = response.headers["content-security-policy"]
    for directive in (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "base-uri 'none'",
    ):
        assert directive in policy
    assert "unsafe-inline" not in policy and "unsafe-eval" not in policy


@pytest.mark.parametrize(
    "path",
    [
        "/ui/private.txt",
        "/ui/other.html",
        "/ui/nested/app.js",
        "/ui/.env",
        "/ui/%2e%2e/overrides.db",
        "/ui/%2e%2e/app.js",
        "/ui/%252e%252e/app.js",
        "/ui/app.js%00",
        "/ui/..%5coverrides.db",
        "/ui/%2e/app.js",
    ],
)
def test_allowlist_and_encoded_traversal_refuse_other_files(ui_client, path):
    assert ui_client.get(path).status_code == 404


def test_ui_has_no_write_or_spa_fallback(ui_client):
    assert ui_client.post("/ui/app.js", content="x").status_code == 405
    assert ui_client.get("/ui/inventory/unknown-id").status_code == 404
    assert "/ui/" not in ui_client.app.openapi()["paths"]


def test_external_symlink_cannot_replace_allowlisted_asset(ui_client, tmp_path):
    outside = tmp_path / "secret"
    outside.write_text("private material")
    asset = tmp_path / "assets/app.js"
    asset.unlink()
    asset.symlink_to(outside)
    response = ui_client.get("/ui/app.js")
    assert response.status_code == 404
    assert "private material" not in response.text


def test_cli_readonly_token_reads_but_cannot_mutate(env: Env, capsys):
    env.device("readonly-target")
    command = ["tokens", "--data-dir", str(env.root), "create", "--id", "gui", "--read-only"]
    assert cli.main(command) == 0
    token = capsys.readouterr().out.strip()
    headers = {"Authorization": "Bearer " + token}
    principal = tokens.verify_token(env.ov, token)
    assert principal is not None and principal.scope == "read-only"
    assert env.client.get("/devices", headers=headers).status_code == 200
    headers["If-Match"] = '"0"'
    response = env.client.patch(
        "/devices/readonly-target", headers=headers, json={"name": "changed"}
    )
    assert response.status_code == 403
    assert env.get("/devices/readonly-target").json()["data"]["name"] is None


def test_readonly_and_rules_write_flags_are_mutually_exclusive(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["tokens", "--data-dir", str(tmp_path), "create", "--read-only", "--rules-write"])
    assert exc.value.code == 2
    assert not (tmp_path / "overrides.db").exists()
    assert "not allowed" in capsys.readouterr().err


def test_cli_existing_default_and_rules_flags_keep_scope(tmp_path, capsys):
    for label, flags, scope in [
        ("old-default", [], tokens.SCOPE_APP),
        ("old-rules", ["--rules-write"], tokens.SCOPE_RULES),
    ]:
        command = ["tokens", "--data-dir", str(tmp_path), "create", "--id", label, *flags]
        assert cli.main(command) == 0
        token = capsys.readouterr().out.strip()
        conn = open_overrides(tmp_path / "overrides.db")
        try:
            assert tokens.verify_token(conn, token).scope == scope
        finally:
            conn.close()


def test_root_redirects_to_ui_relative_and_public(ui_client):
    for method in ("get", "head"):
        response = getattr(ui_client, method)("/", follow_redirects=False)
        assert response.status_code == 307
        assert response.headers["location"] == "/ui/"
        assert response.headers["cache-control"] == "private, no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in response.headers["content-security-policy"]
    landed = ui_client.get("/")
    assert landed.status_code == 200
    assert landed.headers["content-type"].startswith("text/html")
    assert str(landed.url).endswith("/ui/")


def test_root_redirect_ignores_host_forwarding_and_query(ui_client):
    response = ui_client.get(
        "/?next=https://evil.example/&x=1",
        headers={
            "Host": "evil.example",
            "X-Forwarded-Host": "evil.example",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Prefix": "/x",
            "Forwarded": "host=evil.example;proto=https",
        },
        follow_redirects=False,
    )
    assert response.headers["location"] == "/ui/"


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_root_non_get_does_not_redirect(ui_client, method):
    response = getattr(ui_client, method)("/", follow_redirects=False)
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"
    assert "location" not in response.headers
    assert response.json()["ok"] is False


def test_unknown_paths_keep_json_404_and_root_is_not_in_openapi(ui_client):
    response = ui_client.get("/nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
    from vigie_api.openapi_export import render

    assert '"/":' not in render() and "\n  /:" not in render()


@pytest.mark.parametrize("method", ["get", "head"])
def test_ui_without_slash_redirects_relative_ignoring_host_spoofs(ui_client, method):
    response = getattr(ui_client, method)(
        "/ui",
        headers={
            "Host": "evil.example",
            "X-Forwarded-Host": "evil.example",
            "X-Forwarded-Proto": "http",
        },
        follow_redirects=False,
    )
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/"
    assert response.headers["cache-control"] == "private, no-store"


def test_ui_without_slash_post_behaviour(ui_client):
    response = ui_client.post("/ui", follow_redirects=False)
    assert response.status_code == 405
    assert "location" not in response.headers
