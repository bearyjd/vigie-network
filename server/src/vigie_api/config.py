"""API service settings. Frozen; built once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MAX_BODY_BYTES = 16 * 1024
MAX_MERGE_ALIASES = 256
MAX_MERGE_OBSERVATIONS = 1024
MAX_MERGE_ACTIVITY_ROWS = 8192
MAX_MERGE_FLATTEN_WRITES = 256
INCIDENT_SNOOZE_MAX_S = 7 * 24 * 3600


def _opt_path(value: str | None) -> Path | None:
    return Path(value) if value else None


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    max_body_bytes: int = MAX_BODY_BYTES
    rate_limit_per_window: int = 120
    rate_limit_window_s: int = 60
    # Direct locations (VIGIE_INVENTORY_PATH / VIGIE_OVERRIDES_PATH). None = under data_dir.
    # Deployments set them so overrides.db is addressed on its own volume, never through a
    # path inside a directory another service can write (no symlink to swap).
    inventory_db: Path | None = None
    overrides_db: Path | None = None
    max_merge_aliases: int = MAX_MERGE_ALIASES
    max_merge_observations: int = MAX_MERGE_OBSERVATIONS
    max_merge_activity_rows: int = MAX_MERGE_ACTIVITY_ROWS
    max_merge_flatten_writes: int = MAX_MERGE_FLATTEN_WRITES
    incident_snooze_max_s: int = INCIDENT_SNOOZE_MAX_S

    def __post_init__(self) -> None:
        if min(self.max_body_bytes, self.rate_limit_per_window, self.rate_limit_window_s) < 1:
            raise ValueError("max_body_bytes and rate limit values must be positive")
        if (
            min(
                self.max_merge_aliases,
                self.max_merge_observations,
                self.max_merge_activity_rows,
                self.max_merge_flatten_writes,
            )
            < 1
        ):
            raise ValueError("merge limits must be positive")
        if self.incident_snooze_max_s < 1:
            raise ValueError("incident_snooze_max_s must be positive")

    @property
    def inventory_path(self) -> Path:
        return self.inventory_db or self.data_dir / "inventory.db"

    @property
    def overrides_path(self) -> Path:
        return self.overrides_db or self.data_dir / "overrides.db"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        return cls(
            data_dir=Path(source.get("VIGIE_DATA_DIR", "/var/lib/vigie")),
            max_body_bytes=int(source.get("VIGIE_API_MAX_BODY_BYTES", MAX_BODY_BYTES)),
            rate_limit_per_window=int(source.get("VIGIE_API_RATE_LIMIT", 120)),
            rate_limit_window_s=int(source.get("VIGIE_API_RATE_WINDOW_S", 60)),
            inventory_db=_opt_path(source.get("VIGIE_INVENTORY_PATH")),
            overrides_db=_opt_path(source.get("VIGIE_OVERRIDES_PATH")),
            max_merge_aliases=int(source.get("VIGIE_API_MAX_MERGE_ALIASES", MAX_MERGE_ALIASES)),
            max_merge_observations=int(
                source.get("VIGIE_API_MAX_MERGE_OBSERVATIONS", MAX_MERGE_OBSERVATIONS)
            ),
            max_merge_activity_rows=int(
                source.get("VIGIE_API_MAX_MERGE_ACTIVITY_ROWS", MAX_MERGE_ACTIVITY_ROWS)
            ),
            max_merge_flatten_writes=int(
                source.get("VIGIE_API_MAX_MERGE_FLATTEN_WRITES", MAX_MERGE_FLATTEN_WRITES)
            ),
            incident_snooze_max_s=int(
                source.get("VIGIE_API_INCIDENT_SNOOZE_MAX_S", INCIDENT_SNOOZE_MAX_S)
            ),
        )
