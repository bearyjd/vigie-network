"""Assemble an unredacted evidence pack for one device from existing, read-only API paths.

Pure and read-only: it opens nothing, writes nothing and has no network code. Every value that
can identify a device, person or network is wrapped as Sensitive; redaction decides its fate.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from vigie_api import effective
from vigie_api.evidence_determinations import (
    DETERMINISTIC,
    determinations_section,
    incidents_section,
)
from vigie_api.evidence_types import (
    SCHEMA,
    SCHEMA_VERSION,
    Pack,
    capped_section,
    choice,
    has_table,
    not_available,
    safe_id,
    sensitive,
    when,
)
from vigie_ingest.db import iso_utc
from vigie_pipeline.characterization import MODEL_VERSION

CANDIDATE_STATES = ("open", "suggested", "dismissed", "vetoed", "cleared", "attached")
LINK_SOURCES = ("self", "rule", "human")
IDENTITY_STATES = ("ok", "pending_confirm", "conflict")
DEVICE_STATUSES = ("active", "transient", "retired")
# Field names the stitcher writes into identity_candidates.evidence; any other key is counted,
# never emitted (a stored key could be an identifier).
EVIDENCE_KEYS = ("from_mac", "into_mac", "opt55", "opt60", "hostname", "mdns_name", "signals",
                 "rule_ids")  # fmt: skip


@dataclass(frozen=True)
class Limits:
    max_macs: int = 32
    max_candidates: int = 20
    max_incidents: int = 50
    max_gaps: int = 50


def _epoch(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def _scalar(conn: sqlite3.Connection, sql: str) -> Any:
    found = effective.rows(conn, sql)
    return found[0][0] if found else None


def _provenance(inv, ov, vigie_version: str) -> dict[str, Any]:
    return {
        "vigie_version": vigie_version,
        "pipeline_schema": _scalar(inv, "SELECT MAX(version) FROM pipeline_schema"),
        "api_schema": ov.execute("PRAGMA user_version").fetchone()[0],
        "characterization_model": MODEL_VERSION,
        "inventory_newest_batch": when(_scalar(inv, "SELECT MAX(received_at) FROM batches")),
    }


def _subject(detail: dict[str, Any], requested: str) -> dict[str, Any]:
    provenance = detail["type_provenance"]
    confidence = provenance["confidence"]
    subject = {
        "device_ref": sensitive("device_id", detail["id"]),
        "requested_ref": sensitive("device_id", requested),
        "identity_state": choice(detail["identity_state"], IDENTITY_STATES),
        "status": choice(detail["status"], DEVICE_STATUSES),
        "first_seen": when(detail["first_seen"]),
        "last_seen": when(detail["last_seen"]),
        "type": choice(detail["type"], effective.DEVICE_TYPES) or "unknown",
        "type_provenance": {
            "source": safe_id(provenance["source"]),
            "confidence": None
            if provenance["source"] == DETERMINISTIC
            else (confidence if isinstance(confidence, float) else None),
        },
        "name": sensitive("name", detail["name"]),
        "owner": sensitive("owner", detail["owner"]),
        "last_observed_ip": sensitive("ip", detail["last_observed_ip"]),
        "last_observed_ip_at": when(detail["last_observed_ip_at"]),
    }
    return {k: v for k, v in subject.items() if v is not None}


def _observations(inv: sqlite3.Connection, macs: list[str]) -> dict[str, sqlite3.Row]:
    marks = ",".join("?" * len(macs))
    found = effective.rows(
        inv,
        "SELECT mac, is_randomized, dhcp_fingerprint, vendor_class, hostname, mdns_name"  # noqa: S608
        f" FROM observations WHERE mac IN ({marks})",
        tuple(macs),
    )
    return {r["mac"]: r for r in found}


def _identity_item(mac: dict[str, Any], obs: sqlite3.Row) -> dict[str, Any]:
    randomized = bool(obs["is_randomized"])
    item = {
        "mac": sensitive("mac", mac["mac"]),
        "randomized": randomized,
        "link_source": choice(mac["link_source"], LINK_SOURCES),
        "link_rule_id": sensitive("rule_ref", mac["link_rule_id"]),
        "first_seen": when(mac["first_seen"]),
        "last_seen": when(mac["last_seen"]),
        "current": bool(mac["current"]),
    }
    if not randomized:
        item["oui"] = sensitive("oui", mac["mac"].replace(":", "")[:6])
    return item


def _fingerprint_item(mac: dict[str, Any], obs: sqlite3.Row) -> dict[str, Any]:
    item = {
        "mac": sensitive("mac", mac["mac"]),
        "opt55": sensitive("opt55", obs["dhcp_fingerprint"], 255),
        "opt60": sensitive("opt60", obs["vendor_class"], 64),
        "hostname": sensitive("hostname", obs["hostname"], 128),
        "mdns_name": sensitive("mdns", obs["mdns_name"], 128),
    }
    return {k: v for k, v in item.items() if v is not None}


def _mac_sections(inv, detail: dict[str, Any], limits: Limits):
    macs = detail["macs"][: limits.max_macs]
    seen = _observations(inv, [m["mac"] for m in macs])
    pairs = [(m, seen[m["mac"]]) for m in macs if m["mac"] in seen]
    total = len(detail["macs"])
    identity = capped_section([_identity_item(m, o) for m, o in pairs], total)
    prints = capped_section([_fingerprint_item(m, o) for m, o in pairs], total)
    return identity, prints, [o for _, o in pairs]


def members_of(ov: sqlite3.Connection, canonical: str) -> list[str]:
    links = effective.link_map(ov)
    return [canonical, *(f for f in links if effective.resolve(links, f) == canonical)]


def _rule_ids(evidence: Any) -> list[Any]:
    ids = evidence.get("rule_ids") if isinstance(evidence, dict) else None
    refs = (sensitive("rule_ref", r) for r in (ids if isinstance(ids, list) else []))
    return sorted((r for r in refs if r), key=lambda r: r.value)


def _candidate_item(row: sqlite3.Row, members: set[str]) -> dict[str, Any]:
    try:
        evidence = json.loads(row["evidence"])
    except ValueError:
        evidence = None
    keys = evidence if isinstance(evidence, dict) else {}
    other = row["device_b"] if row["device_a"] in members else row["device_a"]
    return {
        "other_device": sensitive("device_id", other),
        "score": row["score"],
        "state": choice(row["state"], CANDIDATE_STATES),
        "evidence_keys": sorted(k for k in keys if k in EVIDENCE_KEYS),
        "unrecognized_key_count": sum(1 for k in keys if k not in EVIDENCE_KEYS),
        "rule_ids": _rule_ids(evidence),
    }


def _candidates(inv, members: list[str], limits: Limits) -> dict[str, Any]:
    if not has_table(inv, "identity_candidates"):
        return not_available("identity_candidates_table_missing")
    marks = ",".join("?" * len(members))
    where = f"device_a IN ({marks}) OR device_b IN ({marks})"
    params = (*members, *members)
    total = inv.execute(
        f"SELECT COUNT(*) FROM identity_candidates WHERE {where}",  # noqa: S608
        params,
    ).fetchone()[0]
    found = inv.execute(
        f"SELECT * FROM identity_candidates WHERE {where} ORDER BY score DESC, id LIMIT ?",  # noqa: S608
        (*params, limits.max_candidates),
    ).fetchall()
    return capped_section([_candidate_item(r, set(members)) for r in found], total)


def _gap_items(inv, detail: dict[str, Any], limits: Limits) -> tuple[list[dict], int]:
    where = '"end" >= ? AND start <= ?'
    span = (_epoch(detail["first_seen"]), _epoch(detail["last_seen"]))
    total = inv.execute(f"SELECT COUNT(*) FROM evidence_gaps WHERE {where}", span).fetchone()[0]  # noqa: S608
    found = inv.execute(
        f'SELECT start, "end" FROM evidence_gaps WHERE {where} ORDER BY start DESC LIMIT ?',  # noqa: S608
        (*span, limits.max_gaps),
    ).fetchall()
    items = [
        {"kind": "evidence_gap", "start": when(r["start"]), "end": when(r["end"])} for r in found
    ]
    return items, total


def _unavailable_items(inv, members: list[str], limits: Limits) -> tuple[list[dict], int]:
    marks = ",".join("?" * len(members))
    total = inv.execute(
        f"SELECT COUNT(*) FROM monitoring_unavailable WHERE device_id IN ({marks})",  # noqa: S608
        tuple(members),
    ).fetchone()[0]
    found = inv.execute(
        "SELECT collector_id, reason, retry_at FROM monitoring_unavailable"  # noqa: S608
        f" WHERE device_id IN ({marks}) ORDER BY collector_id, device_id LIMIT ?",
        (*members, limits.max_gaps),
    ).fetchall()
    items = [
        {
            "kind": "monitoring_unavailable",
            "collector_id": sensitive("collector_id", r["collector_id"]),
            "reason": safe_id(r["reason"]),
            "retry_at": when(r["retry_at"]),
        }
        for r in found
    ]
    return items, total


def _gaps(inv, members: list[str], detail: dict[str, Any], limits: Limits) -> dict[str, Any]:
    gaps, unavailable = (has_table(inv, t) for t in ("evidence_gaps", "monitoring_unavailable"))
    if not (gaps or unavailable):
        return not_available("coverage_tables_missing")
    items: list[dict[str, Any]] = []
    total = 0
    if gaps:
        found, count = _gap_items(inv, detail, limits)
        items, total = items + found, total + count
    if unavailable:
        found, count = _unavailable_items(inv, members, limits)
        items, total = items + found, total + count
    return capped_section(items, total)


def _unknowns(observed: list[sqlite3.Row]) -> list[str]:
    codes = {"no_firmware_version", "dns_coverage_not_assessed", "counterevidence_not_recorded"}
    if any(not o["is_randomized"] for o in observed):
        codes.add("oui_is_nic_vendor_not_product")
    if any(o["is_randomized"] for o in observed):
        codes.add("randomized_mac")
    return sorted(codes)


def assemble(inv, ov, device_id: str, *, now: float, limits: Limits, vigie_version: str) -> Pack:
    detail = effective.device_detail(inv, ov, device_id, now_iso=iso_utc(now))
    canonical = detail["id"]
    members = members_of(ov, canonical)
    identity, prints, observed = _mac_sections(inv, detail, limits)
    sections = {
        "identity": identity,
        "identity_candidates": _candidates(inv, members, limits),
        "fingerprints": prints,
        "determinations": determinations_section(inv, ov, canonical, detail),
        "incidents": incidents_section(inv, ov, members, now, limits.max_incidents),
        "coverage_gaps": _gaps(inv, members, detail, limits),
    }
    return Pack(
        {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "generated_at": when(iso_utc(now)),
            "redaction": {},
            "provenance": _provenance(inv, ov, vigie_version),
            "datasets": [],
            "subject": _subject(detail, device_id),
            "sections": sections,
            "unknowns": _unknowns(observed),
            "search_queries": [],
        }
    )
