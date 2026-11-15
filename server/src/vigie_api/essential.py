"""Owner-marked essential devices (PUT/DELETE /devices/{id}/essential). overrides.db only.

Nothing here reads or changes the monitoring pipeline: F6-a only records the owner's opt-in.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from vigie_api.errors import ApiError
from vigie_api.writes import check_target, etag

MIN_S = 3600  # the schema CHECK in vigie_api.schema repeats these two literals (tested)
MAX_S = 604800
MAX_ESSENTIAL = 32


def get_state(inv: sqlite3.Connection, ov: sqlite3.Connection, device_id: str) -> dict[str, Any]:
    if inv.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise ApiError(404, "not_found", "device not found")
    row = ov.execute("SELECT * FROM essential_devices WHERE device_id=?", (device_id,)).fetchone()
    return {
        "device_id": device_id,
        "essential": bool(row and row["absent_after_s"] is not None),
        "absent_after_s": row["absent_after_s"] if row else None,
        "version": row["version"] if row else 0,
        "updated_at": row["updated_at"] if row else None,
        "updated_by": row["updated_by"] if row else None,
    }


def list_essential(ov: sqlite3.Connection) -> list[dict[str, Any]]:
    cursor = ov.execute(
        "SELECT device_id, absent_after_s, version, updated_at FROM essential_devices"
        " WHERE absent_after_s IS NOT NULL ORDER BY device_id LIMIT ?",
        (MAX_ESSENTIAL,),
    )
    return [dict(r) for r in cursor]


def set_essential(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    *,
    device_id: str,
    expected_version: int,
    absent_after_s: int | None,
    principal: str,
    now_iso: str,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Mark (int) or unmark (None) a device iff the essential version still matches."""
    ov.execute("BEGIN IMMEDIATE")  # the cap check and the write share one write lock
    try:
        if absent_after_s is None:  # clearing must work for a since-merged alias: exists only
            if inv.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
                raise ApiError(404, "not_found", "device not found")
        else:
            check_target(inv, ov, device_id, action="mark")
        row = ov.execute(
            "SELECT absent_after_s, version FROM essential_devices WHERE device_id=?", (device_id,)
        ).fetchone()
        current = row["version"] if row else 0
        before = row["absent_after_s"] if row else None
        if current != expected_version:
            raise ApiError(
                412,
                "version_mismatch",
                "essential version does not match If-Match",
                {"ETag": etag(current)},
            )
        if absent_after_s is None and before is None:
            raise ApiError(409, "not_essential", "device is not marked essential")
        if absent_after_s is not None and before is None:
            marked = ov.execute(
                "SELECT COUNT(*) FROM essential_devices WHERE absent_after_s IS NOT NULL"
            ).fetchone()[0]
            if marked >= MAX_ESSENTIAL:
                raise ApiError(
                    409,
                    "too_many_essential",
                    f"at most {MAX_ESSENTIAL} devices can be essential; unmark one first",
                )
        version = current + 1
        ov.execute(
            "INSERT INTO essential_devices (device_id, absent_after_s, updated_at, updated_by,"
            " version) VALUES (?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET"
            " absent_after_s=excluded.absent_after_s, updated_at=excluded.updated_at,"
            " updated_by=excluded.updated_by, version=excluded.version",
            (device_id, absent_after_s, now_iso, principal, version),
        )
        detail = {
            "request_id": request_id or str(uuid.uuid4()),
            "before": before,
            "after": absent_after_s,
            "version": version,
        }
        action = "device.essential.set" if absent_after_s is not None else "device.essential.clear"
        ov.execute(
            "INSERT INTO audit_log (id, ts, principal, action, target, detail)"
            " VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), now_iso, principal, action, device_id, json.dumps(detail)),
        )
        ov.execute("COMMIT")
    except BaseException:
        if ov.in_transaction:
            ov.execute("ROLLBACK")
        raise
    return {"device_id": device_id, "absent_after_s": absent_after_s, "version": version}
