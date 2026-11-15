"""Fixed-message input error for the replay harness: never carries a path or an input value."""

from __future__ import annotations


class ReplayInputError(ValueError):
    "Raised with a fixed, value-free message; the CLI prints it verbatim."
