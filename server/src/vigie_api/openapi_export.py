"""Generate api/openapi.yaml (OpenAPI 3.1) from the app.

Usage: python -m vigie_api.openapi_export [path]

The document is emitted as sorted-key, 2-space-indented JSON: valid YAML 1.2, deterministic,
and needs no YAML dependency.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from vigie_api.app import create_app
from vigie_api.config import Settings

DEFAULT_PATH = Path(__file__).resolve().parents[3] / "api" / "openapi.yaml"


def render() -> str:
    with tempfile.TemporaryDirectory() as scratch:
        app = create_app(Settings(data_dir=Path(scratch)))
        spec = app.openapi()
    spec["servers"] = [{"url": "/", "description": "TLS-terminated app API"}]
    spec.setdefault("components", {}).setdefault("securitySchemes", {})["bearer"] = {
        "type": "http",
        "scheme": "bearer",
        "description": (
            "App token from `python -m vigie_api tokens create`. Rule approval requires "
            "the control app's explicit --rules-write grant (rules:write). The control app "
            "obtains human approval; person-id semantics remain pending (D6). Service, "
            "integration, and read-only tokens cannot approve rules."
        ),
    }
    for path, item in spec["paths"].items():
        if path == "/healthz":
            continue
        for method, operation in item.items():
            operation["security"] = [{"bearer": []}]
            if method == "patch":
                _document_if_match(operation)
    return json.dumps(spec, indent=2, sort_keys=True) + "\n"


def _document_if_match(operation: dict) -> None:
    for param in operation["parameters"]:
        if param["name"] == "if-match":
            param["required"] = True
            param["description"] = (
                "Override version from the last ETag (0 when the device has no override yet)."
            )


def main(argv: list[str]) -> int:
    target = Path(argv[1]) if len(argv) > 1 else DEFAULT_PATH
    target.write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
