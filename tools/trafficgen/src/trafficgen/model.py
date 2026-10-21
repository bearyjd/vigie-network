"""Shared data types: one Emission is one HTTP POST the generator wants made."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Test-only key (same bytes the ingest test suite uses). Never use outside tests.
DEFAULT_KEY = bytes(range(32))
PRP_BATCH_CAP_BYTES = 256 * 1024  # PRP section 4: collector batch cap
WINDOW_S = 60
DEFAULT_START = 1_791_990_000  # 15:00 UTC, minute-aligned: phones are "awake"
MAX_DNS_SKEW_S = 300


@dataclass(frozen=True)
class Emission:
    """A batch plus how it should be delivered and what the server should answer."""

    label: str
    batch: dict[str, Any]
    arrival_ts: int  # server-side "now" when this POST arrives (monotonic across a stream)
    expect_status: int = 200
    expect_duplicate: bool | None = None
    header_overrides: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "arrival_ts": self.arrival_ts,
            "expect": {"status": self.expect_status, "duplicate": self.expect_duplicate},
            "header_overrides": self.header_overrides,
            "batch": self.batch,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Emission:
        return cls(
            label=raw["label"],
            batch=raw["batch"],
            arrival_ts=raw["arrival_ts"],
            expect_status=raw["expect"]["status"],
            expect_duplicate=raw["expect"]["duplicate"],
            header_overrides=dict(raw["header_overrides"]),
        )


@dataclass(frozen=True)
class Scenario:
    emissions: list[Emission]
    manifest: dict[str, Any]


def shift_batch(batch: dict[str, Any], delta: int) -> dict[str, Any]:
    """Return a copy with every timestamp moved by delta seconds."""
    moved = {k: batch[k] + delta for k in ("window_start", "window_end", "sent_ts")}
    dns = [{**q, "ts": q["ts"] + delta} for q in batch["dns"]]
    return {**batch, **moved, "dns": dns}


def shift_emission(em: Emission, delta: int) -> Emission:
    overrides = {
        k: str(int(v) + delta) if k == "X-Vigie-Sent-Ts" else v
        for k, v in em.header_overrides.items()
    }
    return Emission(
        label=em.label,
        batch=shift_batch(em.batch, delta),
        arrival_ts=em.arrival_ts + delta,
        expect_status=em.expect_status,
        expect_duplicate=em.expect_duplicate,
        header_overrides=overrides,
    )


def emissions_to_jsonl(emissions: list[Emission]) -> str:
    return "".join(json.dumps(e.to_dict(), separators=(",", ":")) + "\n" for e in emissions)
