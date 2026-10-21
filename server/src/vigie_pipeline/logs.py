"""Structured logging. Fields are explicit key/values; raw qnames are never passed in."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime


def log(logger: logging.Logger, level: int, event: str, **fields: object) -> None:
    logger.log(level, event, extra={"fields": fields})


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
            **getattr(record, "fields", {}),
        }
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("vigie_pipeline")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
