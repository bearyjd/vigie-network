"""Validate batches against api/batch.schema.json and the strict ingest model."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from vigie_ingest.models import Batch


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    override = os.environ.get("VIGIE_BATCH_SCHEMA")
    candidates = (
        [Path(override)]
        if override
        else [parent / "api" / "batch.schema.json" for parent in Path(__file__).resolve().parents]
    )
    for path in candidates:
        if path.is_file():
            schema = json.loads(path.read_text())
            Draft202012Validator.check_schema(schema)
            return Draft202012Validator(schema)
    raise FileNotFoundError("api/batch.schema.json not found (set VIGIE_BATCH_SCHEMA)")


def validate_batch(batch: dict[str, Any]) -> None:
    """Raise jsonschema.ValidationError / pydantic.ValidationError if the batch is invalid."""
    _validator().validate(batch)
    Batch.model_validate(batch)
