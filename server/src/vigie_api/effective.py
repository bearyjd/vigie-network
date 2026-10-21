"""Effective device view: inventory facts + human overrides + identity links (computed on read)."""

from __future__ import annotations

import base64
import binascii
import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from typing import Any

from vigie_api.errors import ApiError

DEVICE_TYPES = ("phone", "tv", "iot", "camera", "laptop", "console", "unknown")
MAX_LINK_DEPTH = 32
RECENT_EVENTS = 20
_MAC_RE = re.compile(r"^[0-9a-f]{12}$")
_MAC_SEPARATORS = re.compile(r"[:.\-]")
_ISO_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
_STATE_RANK = {"ok": 0, "pending_confirm": 1, "conflict": 2}


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
    device: sqlite3.Row, overrides: dict[str, sqlite3.Row], links: dict[str, str]
) -> dict[str, Any]:
    """The view of one device. An alias shows its CANONICAL device's override: whatever the
    alias had before the merge is superseded, never leaked into list results."""
    canonical = resolve(links, device["id"])
    override = overrides.get(canonical)
    etype, provenance = _type_and_provenance(device, override)
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


def worst_state(states: Iterable[str]) -> str:
    """ok < pending_confirm < conflict; an unrecognised state outranks them all."""
    return max(states, key=lambda s: _STATE_RANK.get(s, len(_STATE_RANK)), default="ok")


def parse_updated_since(raw: str) -> str:
    """Strict ISO-8601 UTC (`...Z`), normalised to the stored `YYYY-MM-DDTHH:MM:SSZ` form."""
    if not _ISO_UTC_RE.fullmatch(raw):
        raise ApiError(400, "invalid_updated_since", "updated_since must be ISO-8601 UTC (…Z)")
    try:
        moment = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as exc:
        raise ApiError(400, "invalid_updated_since", "updated_since is not a valid time") from exc
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _members_of(links: dict[str, str]) -> dict[str, list[str]]:
    members: dict[str, list[str]] = {}
    for alias in links:
        members.setdefault(resolve(links, alias), []).append(alias)
    return members


def _ids_where(
    overrides: dict[str, sqlite3.Row],
    links: dict[str, str],
    pred: Callable[[sqlite3.Row], bool],
) -> str:
    """JSON array of every device (canonical + its aliases) whose canonical override matches."""
    members = _members_of(links)
    found: list[str] = []
    for device_id, row in overrides.items():
        if resolve(links, device_id) == device_id and pred(row):
            found += [device_id, *members.get(device_id, ())]
    return json.dumps(found)


def iter_devices(
    inv: sqlite3.Connection,
    overrides: dict[str, sqlite3.Row],
    links: dict[str, str],
    *,
    after: str,
    type_: str | None,
    group: str | None,
    identity_state: str | None,
    status: str | None,
    updated_since: str | None,
    include_transient: bool,
    include_retired: bool,
    include_aliases: bool,
) -> Iterator[sqlite3.Row]:
    """Filters run in SQL (override-derived ones through json_each id sets), so a flood of
    devices costs one indexed scan, not one Python-side effective view per device."""
    clauses, params = ["id > :after"], {"after": after}
    in_set = "id IN (SELECT value FROM json_each(:{}))"
    if status is not None:
        clauses.append("status = :status")
        params["status"] = status
    else:
        hidden = [s for s, on in (("transient", include_transient), ("retired", include_retired))
                  if not on]  # fmt: skip
        clauses += [f"status <> '{s}'" for s in hidden]  # noqa: S608 - fixed literals
    if identity_state is not None:
        clauses.append("identity_state = :identity_state")
        params["identity_state"] = identity_state
    if not include_aliases:
        clauses.append("id NOT IN (SELECT value FROM json_each(:aliases))")
        params["aliases"] = json.dumps(list(links))
    if type_ is not None:
        params["type_has"] = _ids_where(overrides, links, lambda r: bool(r["type"]))
        params["type_eq"] = _ids_where(overrides, links, lambda r: r["type"] == type_)
        params["type"] = type_
        clauses.append(
            f"({in_set.format('type_eq')} OR (NOT {in_set.format('type_has')}"
            " AND COALESCE(NULLIF(inferred_type, ''), 'unknown') = :type))"
        )
    if group is not None:
        if group == "unassigned":
            params["group_any"] = _ids_where(overrides, links, lambda r: bool(r["group_id"]))
            clauses.append(f"NOT {in_set.format('group_any')}")
        else:
            params["group_eq"] = _ids_where(overrides, links, lambda r: r["group_id"] == group)
            clauses.append(in_set.format("group_eq"))
    if updated_since is not None:
        params["since"] = updated_since
        params["ov_since"] = _ids_where(
            overrides, links, lambda r: r["updated_at"] >= updated_since
        )
        clauses.append(
            "(last_seen >= :since OR COALESCE(inferred_updated_at, '') >= :since"
            f" OR {in_set.format('ov_since')})"
        )
    sql = f"SELECT * FROM devices WHERE {' AND '.join(clauses)} ORDER BY id"  # noqa: S608
    yield from inv.execute(sql, params)


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
    include_retired: bool,
    include_aliases: bool,
    cursor: str | None,
    limit: int,
) -> tuple[list[dict[str, Any]], str | None]:
    after = decode_cursor(cursor) if cursor else ""
    since = parse_updated_since(updated_since) if updated_since is not None else None
    overrides, links = override_map(ov), link_map(ov)
    out: list[dict[str, Any]] = []
    more = False
    for row in iter_devices(
        inv,
        overrides,
        links,
        after=after,
        type_=type_,
        group=group,
        identity_state=identity_state,
        status=status,
        updated_since=since,
        include_transient=include_transient,
        include_retired=include_retired,
        include_aliases=include_aliases,
    ):
        if len(out) == limit:
            more = True
            break
        out.append(effective_device(row, overrides, links))
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
    item = effective_device(row, override_map(ov), links)
    members = [canonical, *(f for f in links if f != canonical and resolve(links, f) == canonical)]
    marks = ",".join("?" * len(members))
    states = rows(
        inv,
        f"SELECT identity_state FROM devices WHERE id IN ({marks})",  # noqa: S608
        tuple(members),
    )
    item["identity_state"] = worst_state(r["identity_state"] for r in states)
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
    observed = rows(inv, "SELECT identity_state FROM devices WHERE id=?", (found[0]["device_id"],))
    states = [device["identity_state"], *(r["identity_state"] for r in observed)]
    return {
        "mac": mac,
        "device_id": canonical,
        "observed_device_id": found[0]["device_id"],
        "link_source": found[0]["link_source"],
        "identity_state": worst_state(states),
    }
