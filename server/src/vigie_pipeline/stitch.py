"""Identity stitching (PRP section 8; docs/stitching.md): candidates, ambiguity, overlap veto,
immutable merge suggestions, and application of human-approved standing rules.

Two phases per run (docs/stitching-design.md): COMPUTE in a read-only transaction that never
blocks writers, then APPLY under one short, count-bounded BEGIN IMMEDIATE that re-validates each
decision. The pipeline never writes overrides.db and never creates trust: it applies a rule only
when it is an active, non-blank-creator rule read from overrides.db. That the creator is a human
is NOT checkable here (created_by is just a principal name): the API must be the sole writer of
identity_rules and must reject non-human principals.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable

from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.logs import log
from vigie_pipeline.snapshot import Snapshot
from vigie_pipeline.stitch_apply import apply_plan
from vigie_pipeline.stitch_compute import compute_plan
from vigie_pipeline.stitch_types import StitchStats

logger = logging.getLogger("vigie_pipeline")

__all__ = ["StitchStats", "stitch"]


def stitch(
    inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float,
    clock: Callable[[], float] | None = None, overrides: sqlite3.Connection | None = None,
) -> StitchStats:  # fmt: skip
    """One stitching pass over inventory.db. With a live `clock`, `now` is read from it and rule
    expiry is re-checked against it under the lock; `overrides` (read-only) is re-read under the
    lock before any attach."""
    stamp = clock() if clock else now
    plan = compute_plan(inv, snap, cfg, stamp)
    stats = apply_plan(inv, snap, cfg, stamp, clock or (lambda: stamp), overrides, plan)
    log(logger, logging.INFO, "stitch_complete", **stats.__dict__)
    return stats
