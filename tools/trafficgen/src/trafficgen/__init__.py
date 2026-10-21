"""Deterministic synthetic collector traffic for Vigie (PRP-001 section 11)."""

from .generator import generate, load_emissions
from .model import DEFAULT_KEY, PRP_BATCH_CAP_BYTES, Emission, Scenario
from .roster import PROFILES
from .validate import validate_batch

__all__ = [
    "DEFAULT_KEY",
    "PRP_BATCH_CAP_BYTES",
    "PROFILES",
    "Emission",
    "Scenario",
    "generate",
    "load_emissions",
    "validate_batch",
]
