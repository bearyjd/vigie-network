"""Service settings. Frozen; built once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MAX_BODY_BYTES = 512 * 1024
SHARD_RETENTION_DEFAULT_DAYS = 7
SHARD_RETENTION_MAX_DAYS = 30
BATCH_RETENTION_DAYS = 7


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    secrets_dir: Path
    max_body_bytes: int = MAX_BODY_BYTES
    rate_limit_per_window: int = 60
    rate_limit_window_s: int = 60
    max_clock_skew_s: int = 300
    body_timeout_s: float = 10.0
    max_spool_age_s: int = 86400
    shard_retention_days: int = SHARD_RETENTION_DEFAULT_DAYS
    batch_retention_days: int = BATCH_RETENTION_DAYS

    def __post_init__(self) -> None:
        if not 1 <= self.shard_retention_days <= SHARD_RETENTION_MAX_DAYS:
            raise ValueError(f"shard_retention_days must be 1..{SHARD_RETENTION_MAX_DAYS}")
        if self.body_timeout_s <= 0 or self.max_spool_age_s < 1:
            raise ValueError("body_timeout_s and max_spool_age_s must be positive")
        if self.max_body_bytes < 1 or self.rate_limit_per_window < 1:
            raise ValueError("max_body_bytes and rate_limit_per_window must be positive")

    @property
    def inventory_path(self) -> Path:
        return self.data_dir / "inventory.db"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        return cls(
            data_dir=Path(source.get("VIGIE_DATA_DIR", "/var/lib/vigie")),
            secrets_dir=Path(source.get("VIGIE_SECRETS_DIR", "/run/secrets")),
            body_timeout_s=float(source.get("VIGIE_BODY_TIMEOUT_S", 10.0)),
            shard_retention_days=int(
                source.get("VIGIE_SHARD_RETENTION_DAYS", SHARD_RETENTION_DEFAULT_DAYS)
            ),
        )
