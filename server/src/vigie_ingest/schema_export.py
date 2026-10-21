"""Generate api/batch.schema.json from the pydantic models.

Usage: python -m vigie_ingest.schema_export [path]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from vigie_ingest.models import Batch

DEFAULT_PATH = Path(__file__).resolve().parents[3] / "api" / "batch.schema.json"


def render() -> str:
    schema = Batch.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://vigie.invalid/api/batch.schema.json"
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    target = Path(argv[1]) if len(argv) > 1 else DEFAULT_PATH
    target.write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
