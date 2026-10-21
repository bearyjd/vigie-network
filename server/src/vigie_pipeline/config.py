"""Pipeline settings. Frozen; built once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

TRANSIENT_WINDOW_DEFAULT_S = 24 * 3600
TRANSIENT_MIN_DWELL_DEFAULT_S = 2 * 3600
PROMOTION_CAP_DEFAULT = 20


@dataclass(frozen=True)
class PipelineConfig:
    data_dir: Path
    transient_window_s: int = TRANSIENT_WINDOW_DEFAULT_S
    transient_min_dwell_s: int = TRANSIENT_MIN_DWELL_DEFAULT_S
    promotion_cap_per_hour: int = PROMOTION_CAP_DEFAULT
    migrate: bool = False  # let the pipeline apply ingest-owned migrations (bootstrap)

    def __post_init__(self) -> None:
        if self.transient_window_s < 1:
            raise ValueError("transient_window_s must be positive")
        if self.transient_min_dwell_s < 0 or self.promotion_cap_per_hour < 0:
            raise ValueError("transient_min_dwell_s and promotion_cap_per_hour must be >= 0")

    @property
    def inventory_path(self) -> Path:
        return self.data_dir / "inventory.db"

    @property
    def overrides_path(self) -> Path:
        return self.data_dir / "overrides.db"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> PipelineConfig:
        source = os.environ if env is None else env
        return cls(
            data_dir=Path(source.get("VIGIE_DATA_DIR", "/var/lib/vigie")),
            transient_window_s=int(
                source.get("VIGIE_TRANSIENT_WINDOW_S", TRANSIENT_WINDOW_DEFAULT_S)
            ),
            transient_min_dwell_s=int(
                source.get("VIGIE_TRANSIENT_MIN_DWELL_S", TRANSIENT_MIN_DWELL_DEFAULT_S)
            ),
            promotion_cap_per_hour=int(
                source.get("VIGIE_PROMOTION_CAP_PER_HOUR", PROMOTION_CAP_DEFAULT)
            ),
        )
