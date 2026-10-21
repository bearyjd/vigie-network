"""Pipeline settings. Frozen; built once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

TRANSIENT_WINDOW_DEFAULT_S = 24 * 3600


@dataclass(frozen=True)
class PipelineConfig:
    data_dir: Path
    transient_window_s: int = TRANSIENT_WINDOW_DEFAULT_S

    def __post_init__(self) -> None:
        if self.transient_window_s < 1:
            raise ValueError("transient_window_s must be positive")

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
        )
