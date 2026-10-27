"""The one write an evidence export makes: a single audit_log row in overrides.db.

The row carries counts, the level and the pack's hash, never pack contents, hostnames or MACs.
It is committed before the pack is returned, so an export that cannot be audited is not sent.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

AUDIT_ACTION = "device.evidence_export"


def record_export(
    ov: sqlite3.Connection,
    *,
    principal: str,
    now_iso: str,
    detail: dict[str, Any],
) -> None:
    ov.execute("BEGIN IMMEDIATE")
    try:
        ov.execute(
            "INSERT INTO audit_log (id,ts,principal,action,target,detail) VALUES (?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                now_iso,
                principal,
                AUDIT_ACTION,
                None,  # the target would be an identifier; the detail holds redacted refs
                json.dumps(detail, sort_keys=True, separators=(",", ":")),
            ),
        )
        ov.execute("COMMIT")
    except BaseException:
        if ov.in_transaction:
            ov.execute("ROLLBACK")
        raise
