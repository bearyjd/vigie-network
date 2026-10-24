"""Human override writes (PATCH /devices/{id}). overrides.db is the only file written."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from typing import Any

from vigie_api.effective import DEVICE_TYPES, link_map, rows
from vigie_api.errors import ApiError

FIELDS = ("name", "owner", "type", "group_id")


_IF_MATCH_RE = re.compile(r'(?:"([0-9]{1,12})"|([0-9]{1,12}))')


def parse_if_match(header: str | None) -> int:
    """`If-Match: "<n>"` or bare `<n>` (RFC 9110 strong tag). Required: 428 when absent.

    Weak tags (`W/`), lists, `*` and malformed quoting are rejected: a weak validator must never
    satisfy a write precondition.
    """
    if header is None or not header.strip():
        raise ApiError(428, "precondition_required", "If-Match (override version) is required")
    match = _IF_MATCH_RE.fullmatch(header)
    if match is None:
        raise ApiError(400, "invalid_if_match", "If-Match must be one override version number")
    return int(match.group(1) or match.group(2))


def etag(version: int) -> str:
    return f'"{version}"'


def _current_version(conn: sqlite3.Connection, device_id: str) -> int:
    row = conn.execute(
        "SELECT version FROM device_overrides WHERE device_id=?", (device_id,)
    ).fetchone()
    return row["version"] if row else 0


def _validate(conn: sqlite3.Connection, changes: dict[str, Any]) -> None:
    if changes.get("type") is not None and changes["type"] not in DEVICE_TYPES:
        raise ApiError(422, "invalid_type", f"type must be one of {', '.join(DEVICE_TYPES)}")
    group = changes.get("group_id")
    if group is not None and not rows(conn, "SELECT 1 FROM groups WHERE id=?", (group,)):
        raise ApiError(422, "unknown_group", "group does not exist")


def _check_target(inv: sqlite3.Connection, ov: sqlite3.Connection, device_id: str) -> None:
    if not rows(inv, "SELECT 1 FROM devices WHERE id=?", (device_id,)):
        raise ApiError(404, "not_found", "device not found")
    into = link_map(ov).get(device_id)
    if into is not None:
        raise ApiError(409, "device_merged", f"device was merged into {into}; patch that device")


def patch_override(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    *,
    device_id: str,
    expected_version: int,
    changes: dict[str, Any],
    principal: str,
    now_iso: str,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Apply `changes` (None clears a field) iff the override version still matches."""
    ov.execute("BEGIN IMMEDIATE")
    try:
        # inside the write lock: a merge or group change cannot land between check and write
        _check_target(inv, ov, device_id)
        _validate(ov, changes)
        current = _current_version(ov, device_id)
        if current != expected_version:
            raise ApiError(
                412,
                "version_mismatch",
                "override version does not match If-Match",
                {"ETag": etag(current)},
            )
        before = _before(ov, device_id)
        new_version = current + 1
        _apply(ov, device_id, changes, new_version, principal, now_iso)
        _audit(ov, device_id, changes, before, new_version, principal, now_iso, request_id)
        ov.execute("COMMIT")
    except BaseException:
        if ov.in_transaction:
            ov.execute("ROLLBACK")
        raise
    return {"device_id": device_id, "version": new_version}


def _before(conn: sqlite3.Connection, device_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM device_overrides WHERE device_id=?", (device_id,)).fetchone()
    return {f: (row[f] if row else None) for f in FIELDS}


def _apply(conn, device_id, changes, version, principal, now_iso) -> None:  # noqa: ANN001
    if version == 1:
        values = {f: changes.get(f) for f in FIELDS}
        conn.execute(
            "INSERT INTO device_overrides (device_id, name, owner, type, group_id, version,"
            " updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?)",
            (device_id, *values.values(), version, now_iso, principal),
        )
        return
    sets = "".join(f"{f}=?," for f in changes)
    conn.execute(
        f"UPDATE device_overrides SET {sets} version=?, updated_at=?, updated_by=?"  # noqa: S608
        " WHERE device_id=?",
        (*changes.values(), version, now_iso, principal, device_id),
    )


def _audit(conn, device_id, changes, before, version, principal, now_iso, request_id=None) -> None:  # noqa: ANN001
    detail = {
        "request_id": request_id or str(uuid.uuid4()),
        "before": before,
        "after": {**before, **changes},
        "version": version,
        "changes": {f: {"from": before[f], "to": v} for f, v in changes.items()},
    }
    conn.execute(
        "INSERT INTO audit_log (id, ts, principal, action, target, detail) VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), now_iso, principal, "device.patch", device_id, json.dumps(detail)),
    )
