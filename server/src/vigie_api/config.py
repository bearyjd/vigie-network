"""API service settings. Frozen; built once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MAX_BODY_BYTES = 16 * 1024


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    max_body_bytes: int = MAX_BODY_BYTES
    rate_limit_per_window: int = 120
    rate_limit_window_s: int = 60

    def __post_init__(self) -> None:
        if min(self.max_body_bytes, self.rate_limit_per_window, self.rate_limit_window_s) < 1:
            raise ValueError("max_body_bytes and rate limit values must be positive")

    @property
    def inventory_path(self) -> Path:
        return self.data_dir / "inventory.db"

    @property
    def overrides_path(self) -> Path:
        return self.data_dir / "overrides.db"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        return cls(
            data_dir=Path(source.get("VIGIE_DATA_DIR", "/var/lib/vigie")),
            max_body_bytes=int(source.get("VIGIE_API_MAX_BODY_BYTES", MAX_BODY_BYTES)),
            rate_limit_per_window=int(source.get("VIGIE_API_RATE_LIMIT", 120)),
            rate_limit_window_s=int(source.get("VIGIE_API_RATE_WINDOW_S", 60)),
        )
