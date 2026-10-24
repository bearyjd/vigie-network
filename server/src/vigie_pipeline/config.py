"""Pipeline settings. Frozen; built once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

TRANSIENT_WINDOW_DEFAULT_S = 24 * 3600
TRANSIENT_MIN_DWELL_DEFAULT_S = 2 * 3600
PROMOTION_CAP_DEFAULT = 20

# Identity stitching (docs/stitching.md). Weights sum to 1.0; a candidate additionally REQUIRES
# opt55 AND opt60 AND (hostname OR mdns_name) equal, so with these weights every structurally
# valid candidate scores >= 0.8 and hostname alone can never reach a candidate.
SIGNAL_WEIGHTS: dict[str, float] = {
    "opt55": 0.3,
    "opt60": 0.3,
    "mdns_name": 0.2,
    "hostname": 0.2,
}
SUGGEST_THRESHOLD_DEFAULT = 0.8
OVERLAP_GRACE_DEFAULT_S = 600
# A peer's interval is presumed to last one activity gap past its last stamp only when it is an
# established presence: longer than this many grace windows (so minutes-long rollers are not).
PEER_TAIL_MIN_GRACE_MULT = 2
ACTIVITY_GAP_DEFAULT_S = 300
ACTIVITY_RETENTION_DEFAULT_S = 7 * 86400
ACTIVITY_SKEW_S = 300  # a row stamp may lead the batch receipt by this much (collector clock skew)
# Collector stamps are untrusted. Stitching only counts a MAC's activity from this long before the
# SERVER time it was first received (mac_first_received): older stamps are back-fill and count
# neither toward maturity nor toward the time apart from a peer.
ACTIVITY_MAX_REPORT_LAG_S = 3600
SUGGESTION_TTL_DEFAULT_S = 7 * 86400

# ---- bounds (docs/stitching.md section 3; every one holds by construction) -----------------
# Subjects (self MACs; rule-attached MACs) examined per round-robin per pass.
MACS_PER_PASS = 256
# Wall-clock budget of the read-only COMPUTE phase; it stops between subjects, the cursor persists.
STITCH_COMPUTE_BUDGET_S = 5.0
# Rows one indexed neighbourhood lookup may return; one more means the evidence is incomplete.
BUCKET_ROWS = 1024
# Distinct (opt55, opt60, name) keys a target identity may contribute; more is incomplete evidence.
TARGET_KEYS = 16
# mac_activity rows kept per MAC (the closest intervals are coalesced at fold time: conservative).
INTERVALS_PER_MAC = 64
# Maximum retention rows deleted (or maturity anchors examined) per table per pass.
PRUNE_BATCH_ROWS = 1000
# A merge component (devices that are one identity) larger than this is not decided automatically.
MAX_ALIAS_IDS = 5000
# A name group / compatible pool with more LIVE self MACs than this is a flood (nothing attaches).
MAX_SIGNATURE_BUCKET = 64
# Candidate + suggestion rows written per APPLY (a decision is reserved whole or not written).
MAX_ROWS_PER_PASS = 200
# Rule attaches per APPLY.
MAX_ATTACHES_PER_PASS = 20
# Open merge suggestions pointing INTO one device; more wait (bounds the orphan cleanup at attach).
MAX_OPEN_SUGGESTIONS_PER_DEVICE = 64
# The orphan cleanup after an attach (dismissals, suggestion expiry) may use at most this share
# of MAX_ROWS_PER_PASS per pass; the rest stays for vetoes, candidates and suggestions.
CLEANUP_ROWS_SHARE = 0.5
# The re-check robin may use at most this share of the compute budget; the rest is the self
# robin's, so expensive re-checks never starve rules and candidates (and vice versa).
RECHECK_BUDGET_SHARE = 0.5


def _opt_path(value: str | None) -> Path | None:
    return Path(value) if value else None


@dataclass(frozen=True)
class PipelineConfig:
    data_dir: Path
    transient_window_s: int = TRANSIENT_WINDOW_DEFAULT_S
    transient_min_dwell_s: int = TRANSIENT_MIN_DWELL_DEFAULT_S
    promotion_cap_per_hour: int = PROMOTION_CAP_DEFAULT
    migrate: bool = False  # let the pipeline apply ingest-owned migrations (bootstrap)
    # Direct locations (VIGIE_INVENTORY_PATH / VIGIE_OVERRIDES_PATH); None = under data_dir.
    inventory_db: Path | None = None
    overrides_db: Path | None = None
    monitoring_large_upload_bytes: int = 1024 * 1024 * 1024
    # Identity stitching
    suggest_threshold: float = SUGGEST_THRESHOLD_DEFAULT
    overlap_grace_s: int = OVERLAP_GRACE_DEFAULT_S
    activity_gap_s: int = ACTIVITY_GAP_DEFAULT_S  # silence longer than this splits an interval
    activity_retention_s: int = ACTIVITY_RETENTION_DEFAULT_S
    suggestion_ttl_s: int = SUGGESTION_TTL_DEFAULT_S

    def __post_init__(self) -> None:
        if not 1 <= self.monitoring_large_upload_bytes <= 2**50:
            raise ValueError("monitoring_large_upload_bytes outside supported bounds")
        if self.transient_window_s < 1:
            raise ValueError("transient_window_s must be positive")
        if self.transient_min_dwell_s < 0 or self.promotion_cap_per_hour < 0:
            raise ValueError("transient_min_dwell_s and promotion_cap_per_hour must be >= 0")
        if not 0 < self.suggest_threshold <= 1:
            raise ValueError("suggest_threshold must be in (0, 1]")
        if min(self.overlap_grace_s, self.activity_gap_s) < 0 or self.activity_retention_s < 1:
            raise ValueError("overlap_grace_s/activity_gap_s must be >= 0, retention positive")
        if self.suggestion_ttl_s < 1:
            raise ValueError("suggestion_ttl_s must be positive")

    @property
    def inventory_path(self) -> Path:
        return self.inventory_db or self.data_dir / "inventory.db"

    @property
    def overrides_path(self) -> Path:
        return self.overrides_db or self.data_dir / "overrides.db"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> PipelineConfig:
        source = os.environ if env is None else env
        return cls(
            data_dir=Path(source.get("VIGIE_DATA_DIR", "/var/lib/vigie")),
            monitoring_large_upload_bytes=int(
                source.get("VIGIE_MONITORING_LARGE_UPLOAD_BYTES", 1024**3)
            ),
            transient_window_s=int(
                source.get("VIGIE_TRANSIENT_WINDOW_S", TRANSIENT_WINDOW_DEFAULT_S)
            ),
            transient_min_dwell_s=int(
                source.get("VIGIE_TRANSIENT_MIN_DWELL_S", TRANSIENT_MIN_DWELL_DEFAULT_S)
            ),
            promotion_cap_per_hour=int(
                source.get("VIGIE_PROMOTION_CAP_PER_HOUR", PROMOTION_CAP_DEFAULT)
            ),
            inventory_db=_opt_path(source.get("VIGIE_INVENTORY_PATH")),
            overrides_db=_opt_path(source.get("VIGIE_OVERRIDES_PATH")),
            suggest_threshold=float(
                source.get("VIGIE_STITCH_THRESHOLD", SUGGEST_THRESHOLD_DEFAULT)
            ),
            overlap_grace_s=int(source.get("VIGIE_OVERLAP_GRACE_S", OVERLAP_GRACE_DEFAULT_S)),
            activity_gap_s=int(source.get("VIGIE_ACTIVITY_GAP_S", ACTIVITY_GAP_DEFAULT_S)),
        )
