"""Pipeline hook for incident delivery: DEFAULT OFF, one watermark, never fails the pass."""

from __future__ import annotations

import logging
from collections.abc import Callable
from sqlite3 import Connection

from vigie_ingest.db import immediate
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.delivery_publish import FilePublisher, Publisher
from vigie_pipeline.delivery_runner import RunReport, run_delivery
from vigie_pipeline.delivery_types import tick_floor
from vigie_pipeline.logs import log

logger = logging.getLogger("vigie_pipeline")
WATERMARK_KEY = "delivery_eligible_since"
LOG_EVERY = 20  # a failing stage is logged on its first occurrence and every 20th after
_failures = 0


def _watermark(inv: Connection, now: float) -> int:
    """Set once, at the first enabled run, and never moved: older incidents stay unannounced."""
    with immediate(inv):
        inv.execute(
            "INSERT OR IGNORE INTO pipeline_meta (key, value) VALUES (?, ?)",
            (WATERMARK_KEY, str(tick_floor(now))),
        )
        row = inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (WATERMARK_KEY,))
        return int(row.fetchone()[0])


def _report_failure(exc: Exception) -> None:
    global _failures
    if _failures % LOG_EVERY == 0:
        log(logger, logging.ERROR, "delivery_stage_failed", error=type(exc).__name__,
            detail=str(exc)[:300], occurrences=_failures + 1)  # fmt: skip
    _failures += 1


def run_delivery_stage(
    inv: Connection,
    overrides: Connection | None,
    config: PipelineConfig,
    clock: Callable[[], float],
    publisher: Publisher | None = None,
) -> RunReport | None:
    """Disabled: do nothing at all. Enabled: any exception is contained and logged."""
    settings = config.delivery
    if not settings.enabled:
        return None
    try:
        since = _watermark(inv, clock())
        return run_delivery(
            inv,
            overrides,
            publisher or FilePublisher(settings.file),
            settings.delivery_config(since),
            clock,
            max_per_run=settings.max_per_run,
            max_abandoned=settings.max_abandoned,
        )
    except Exception as exc:  # noqa: BLE001 - delivery must never fail the pipeline pass
        _report_failure(exc)
        return None
