"""Effective device view: inventory facts + human overrides + identity links (computed on read)."""

from __future__ import annotations

import base64
import binascii
import re
import sqlite3
from collections.abc import Iterator
from typing import Any

from vigie_api.errors import ApiError

DEVICE_TYPES = ("phone", "tv", "iot", "camera", "laptop", "console", "unknown")
MAX_LINK_DEPTH = 32
RECENT_EVENTS = 20
_MAC_RE = re.compile(r"^[0-9a-f]{12}$")
_MAC_SEPARATORS = re.compile(r"[:.\-]")


def rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """Run a read query; a table the pipeline has not created yet reads as empty."""
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return []
        raise


def encode_cursor(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> str:
    try:
        standard = cursor.replace("-", "+").replace("_", "/") + "=" * (-len(cursor) % 4)
        return base64.b64decode(standard, validate=True).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ApiError(400, "invalid_cursor", "malformed cursor") from exc


def normalize_mac(raw: str) -> str:
    """Any case/separator (`AA-BB-..`, `aabb.ccdd.eeff`, `aabbccddeeff`) -> `aa:bb:cc:dd:ee:ff`."""
    flat = _MAC_SEPARATORS.sub("", raw.strip().lower())
    if not _MAC_RE.fullmatch(flat):
        raise ApiError(422, "invalid_mac", "not a valid MAC address")
    return ":".join(flat[i : i + 2] for i in range(0, 12, 2))


def link_map(ov: sqlite3.Connection) -> dict[str, str]:
    return {r["from_device"]: r["into_device"] for r in rows(ov, "SELECT * FROM identity_links")}


def resolve(links: dict[str, str], device_id: str) -> str:
    """Follow from_device -> into_device to the canonical device (bounded, cycle-safe)."""
    seen = {device_id}
    current = device_id
    for _ in range(MAX_LINK_DEPTH):
        nxt = links.get(current)
        if nxt is None or nxt in seen:
            return current
        seen.add(nxt)
        current = nxt
    return current


def override_map(ov: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    return {r["device_id"]: r for r in rows(ov, "SELECT * FROM device_overrides")}


def _type_and_provenance(device: sqlite3.Row, override: sqlite3.Row | None) -> tuple[str, dict]:
    if override is not None and override["type"]:
        return override["type"], {"source": "human", "confidence": 1.0}
    if device["inferred_type"]:
        return device["inferred_type"], {
            "source": device["inferred_source"],
            "confidence": device["inferred_confidence"],
        }
    return "unknown", {"source": None, "confidence": None}


def effective_device(
    device: sqlite3.Row, override: sqlite3.Row | None, links: dict[str, str]
) -> dict[str, Any]:
    etype, provenance = _type_and_provenance(device, override)
    canonical = resolve(links, device["id"])
    updated = max(
        device["last_seen"],
        override["updated_at"] if override else "",
        device["inferred_updated_at"] or "",
    )
    return {
        "id": device["id"],
        "name": override["name"] if override else None,
        "owner": override["owner"] if override else None,
        "type": etype,
        "type_provenance": provenance,
        # group comes ONLY from the human override; inferred data never assigns a group
        "group_id": override["group_id"] if override else None,
        "identity_state": device["identity_state"],
        "status": device["status"],
        "first_seen": device["first_seen"],
        "last_seen": device["last_seen"],
        "updated_at": updated,
        "override_version": override["version"] if override else 0,
        "merged_into": canonical if canonical != device["id"] else None,
    }


def iter_devices(
    inv: sqlite3.Connection,
    *,
    after: str,
    status: str | None,
    identity_state: str | None,
    include_transient: bool,
) -> Iterator[sqlite3.Row]:
    clauses, params = ["id > ?"], [after]
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    elif not include_transient:
        clauses.append("status <> 'transient'")
    if identity_state is not None:
        clauses.append("identity_state = ?")
        params.append(identity_state)
    sql = f"SELECT * FROM devices WHERE {' AND '.join(clauses)} ORDER BY id"  # noqa: S608
    yield from inv.execute(sql, tuple(params))


def list_devices(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    *,
    type_: str | None,
    group: str | None,
    identity_state: str | None,
    status: str | None,
    updated_since: str | None,
    include_transient: bool,
    cursor: str | None,
    limit: int,
) -> tuple[list[dict[str, Any]], str | None]:
    after = decode_cursor(cursor) if cursor else ""
    overrides, links = override_map(ov), link_map(ov)
    out: list[dict[str, Any]] = []
    more = False
    for row in iter_devices(
        inv,
        after=after,
        status=status,
        identity_state=identity_state,
        include_transient=include_transient,
    ):
        item = effective_device(row, overrides.get(row["id"]), links)
        if type_ is not None and item["type"] != type_:
            continue
        if group is not None and (item["group_id"] or "unassigned") != group:
            continue
        if updated_since is not None and item["updated_at"] < updated_since:
            continue
        if len(out) == limit:
            more = True
            break
        out.append(item)
    return out, (encode_cursor(out[-1]["id"]) if more else None)


def _device_row(inv: sqlite3.Connection, device_id: str) -> sqlite3.Row:
    found = rows(inv, "SELECT * FROM devices WHERE id=?", (device_id,))
    if not found:
        raise ApiError(404, "not_found", "device not found")
    return found[0]


def device_detail(inv: sqlite3.Connection, ov: sqlite3.Connection, device_id: str) -> dict:
    links = link_map(ov)
    canonical = resolve(links, device_id)
    row = _device_row(inv, canonical)
    override = override_map(ov).get(canonical)
    item = effective_device(row, override, links)
    members = [canonical, *(f for f in links if f != canonical and resolve(links, f) == canonical)]
    marks = ",".join("?" * len(members))
    obs = rows(
        inv,
        f"SELECT * FROM observations WHERE device_id IN ({marks}) ORDER BY last_seen DESC, mac",  # noqa: S608
        tuple(members),
    )
    newest = obs[0]["last_seen"] if obs else None
    events = rows(
        inv,
        f"SELECT id, ts, kind, severity, summary FROM events WHERE device_id IN ({marks})"  # noqa: S608
        " ORDER BY ts DESC, id DESC LIMIT ?",
        (*members, RECENT_EVENTS),
    )
    return {
        **item,
        "merged_into": canonical if canonical != device_id else None,
        "requested_id": device_id,
        "macs": [
            {
                "mac": o["mac"],
                "hostname": o["hostname"],
                "first_seen": o["first_seen"],
                "last_seen": o["last_seen"],
                "current": o["last_seen"] == newest,
                "link_source": o["link_source"],
                "link_rule_id": o["link_rule_id"],
            }
            for o in obs
        ],
        "recent_events": [dict(e) for e in events],
        "explanation": {
            "reason_code": row["inferred_reason_code"],
            "reason_text": row["inferred_reason_text"],  # informational only
            "model_version": row["inferred_model_version"],
        },
    }


def resolve_mac(inv: sqlite3.Connection, ov: sqlite3.Connection, raw_mac: str) -> dict[str, Any]:
    mac = normalize_mac(raw_mac)
    found = rows(inv, "SELECT * FROM observations WHERE mac=?", (mac,))
    if not found:
        raise ApiError(404, "not_found", "unknown MAC")
    canonical = resolve(link_map(ov), found[0]["device_id"])
    device = _device_row(inv, canonical)
    return {
        "mac": mac,
        "device_id": canonical,
        "observed_device_id": found[0]["device_id"],
        "link_source": found[0]["link_source"],
        "identity_state": device["identity_state"],
    }
