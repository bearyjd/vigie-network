"""Human review decisions on monitoring incidents (an overrides.db overlay; inventory stays ro)."""

from __future__ import annotations

from typing import Any

STATUSES = ("acknowledged", "snoozed", "expected")
QUIET_STATUSES = frozenset({"acknowledged", "expected"})


def attention(state: str, review: dict[str, Any] | None, now: float) -> bool:
    """An incident needs a human only while the pipeline holds it open and no decision covers it.

    A snooze covers it strictly before `snooze_until`; at or after that instant it is back.
    """
    if state != "open":
        return False
    if review is None:
        return True
    if review["status"] in QUIET_STATUSES:
        return False
    return not (review["status"] == "snoozed" and now < review["snooze_until"])
