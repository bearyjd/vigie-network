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
from vigie_api.evidence_determinations import determinations_section, incidents_section
from vigie_api.evidence_types import (
    SCHEMA,
    SCHEMA_VERSION,
    Pack,
    capped_section,
    has_table,
    not_available,
    safe_id,
    sensitive,
    when,
)
from vigie_ingest.db import iso_utc
from vigie_pipeline.characterization import MODEL_VERSION


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
        "identity_state": safe_id(detail["identity_state"]),
        "status": safe_id(detail["status"]),
        "first_seen": when(detail["first_seen"]),
        "last_seen": when(detail["last_seen"]),
        "type": safe_id(detail["type"]) or "unknown",
        "type_provenance": {
            "source": safe_id(provenance["source"]),
            "confidence": confidence if isinstance(confidence, float) else None,
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
        "link_source": safe_id(mac["link_source"]),
        "link_rule_id": safe_id(mac["link_rule_id"]),
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


def _members(ov: sqlite3.Connection, canonical: str) -> list[str]:
    links = effective.link_map(ov)
    return [canonical, *(f for f in links if effective.resolve(links, f) == canonical)]


def _rule_ids(evidence: Any) -> list[str]:
    ids = evidence.get("rule_ids") if isinstance(evidence, dict) else None
    return sorted(r for r in map(safe_id, ids if isinstance(ids, list) else []) if r)


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
        "state": safe_id(row["state"]),
        "evidence_keys": sorted(k for k in keys if safe_id(k)),
        "rule_ids": _rule_ids(evidence),
    }


def _candidates(inv, ov, canonical: str, limits: Limits) -> dict[str, Any]:
    if not has_table(inv, "identity_candidates"):
        return not_available("identity_candidates_table_missing")
    members = _members(ov, canonical)
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


def _gaps(inv, canonical: str, detail: dict[str, Any], limits: Limits) -> dict[str, Any]:
    gaps, unavailable = (has_table(inv, t) for t in ("evidence_gaps", "monitoring_unavailable"))
    if not (gaps or unavailable):
        return not_available("coverage_tables_missing")
    items: list[dict[str, Any]] = []
    if gaps:
        found = inv.execute(
            'SELECT start, "end" FROM evidence_gaps WHERE "end" >= ? AND start <= ?'
            " ORDER BY start DESC LIMIT ?",
            (_epoch(detail["first_seen"]), _epoch(detail["last_seen"]), limits.max_gaps),
        ).fetchall()
        items += [
            {"kind": "evidence_gap", "start": when(r["start"]), "end": when(r["end"])}
            for r in found
        ]
    if unavailable:
        found = inv.execute(
            "SELECT collector_id, reason, retry_at FROM monitoring_unavailable WHERE device_id=?"
            " ORDER BY collector_id LIMIT ?",
            (canonical, limits.max_gaps),
        ).fetchall()
        items += [
            {
                "kind": "monitoring_unavailable",
                "collector_id": sensitive("collector_id", r["collector_id"]),
                "reason": safe_id(r["reason"]),
                "retry_at": when(r["retry_at"]),
            }
            for r in found
        ]
    return capped_section(items, len(items))


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
    identity, prints, observed = _mac_sections(inv, detail, limits)
    sections = {
        "identity": identity,
        "identity_candidates": _candidates(inv, ov, canonical, limits),
        "fingerprints": prints,
        "determinations": determinations_section(inv, ov, canonical, detail),
        "incidents": incidents_section(inv, ov, canonical, now, limits.max_incidents),
        "coverage_gaps": _gaps(inv, canonical, detail, limits),
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
