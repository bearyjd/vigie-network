"""Evidence pack sections for device-type determinations and device-scoped incidents.

Both reuse the API's own read paths (device_detail's explanation, monitoring.incident_row), so
their sanitising and withholding rules apply unchanged: reason_text stays withheld while a
trust suggestion is pending, a stale lineage reads as insufficient_evidence, an expired result as
expired_evidence, and characterization confidence is always null.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from vigie_api import incident_decisions, monitoring
from vigie_api.effective import override_map, rows
from vigie_api.evidence_redact import SERVICE_RE
from vigie_api.evidence_types import (
    capped_section,
    choice,
    has_table,
    make_section,
    not_available,
    safe_id,
    sensitive,
    when,
)

DETERMINISTIC = "deterministic-services"
REASON_CODES = (
    "large_upload_threshold",
    "two_qualified_upload_hours",
    "two_qualified_upload_hours_in_cohort",
)
DETECTORS = ("large_upload", "upload_deviation")
INCIDENT_STATES = ("open", "resolved", "superseded")
REVIEW_STATUSES = ("acknowledged", "snoozed", "expected")
_INT = "int"
# Allowlist of incident evidence fields, mirroring models.IncidentEvidence; anything else a
# stored row carries is dropped.
EVIDENCE_FIELDS = {
    "reason_code": "reason",
    "hour": _INT,
    "previous_hour": _INT,
    "observed_bytes": _INT,
    "threshold_bytes": _INT,
    "baseline_id": "baseline",
    "algorithm": "id",
    "config_version": "id",
    "coverage_required_seconds": _INT,
    "lineage": "lineage",
    "unusual_is_not_malicious": "true",
    "baseline_median_upload_bytes": "number",
    "multiplier": _INT,
    "minimum_bytes": _INT,
    "sample_hours": _INT,
    "distinct_days": _INT,
}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _evidence_value(kind: str, value: Any) -> Any:
    if kind == _INT:
        return value if _is_int(value) else None
    if kind == "number":
        return value if _is_int(value) or isinstance(value, float) else None
    if kind == "true":
        return True if value is True else None
    if kind in ("lineage", "baseline"):
        return sensitive(kind, value) if isinstance(value, str) else None
    if kind == "reason":
        return choice(value, REASON_CODES)
    return safe_id(value)


def allowlisted_evidence(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}
    kept = {k: _evidence_value(kind, evidence.get(k)) for k, kind in EVIDENCE_FIELDS.items()}
    return {k: v for k, v in kept.items() if v is not None}


def _review(review: dict[str, Any] | None) -> dict[str, Any] | None:
    if review is None:
        return None
    return {
        "status": choice(review["status"], REVIEW_STATUSES),
        "snooze_until": when(review["snooze_until"]),
        "decided_at": when(review["decided_at"]),
        "version": review["version"],
    }


def _incident_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": sensitive("incident_id", row["id"]),
        "collector_id": sensitive("collector_id", row["collector_id"]),
        "lineage": sensitive("lineage", row["lineage"]),
        "current_lineage": bool(row["current_lineage"]),
        "detector": choice(row["detector"], DETECTORS),
        "state": choice(row["state"], INCIDENT_STATES),
        "episode_start": row["episode_start"],
        "last_hour": row["last_hour"],
        "detected_at": when(row["detected_at"]),
        "observed_bytes": row["observed_bytes"],
        "threshold_bytes": row["threshold_bytes"],
        "baseline_id": sensitive("baseline_id", row["baseline_id"]),
        "evidence": allowlisted_evidence(row["evidence"]),
        "review": _review(row["review"]),
        "decision_version": row["decision_version"],
        "attention": bool(row["attention"]),
    }


def incidents_section(
    inv: sqlite3.Connection, ov: sqlite3.Connection, members: list[str], now: float, limit: int
) -> dict[str, Any]:
    if not has_table(inv, "monitoring_incidents"):
        return not_available("monitoring_incidents_table_missing")
    marks = ",".join("?" * len(members))
    total = inv.execute(
        f"SELECT COUNT(*) FROM monitoring_incidents WHERE device_id IN ({marks})",  # noqa: S608
        tuple(members),
    ).fetchone()[0]
    found = inv.execute(
        f"SELECT * FROM monitoring_incidents WHERE device_id IN ({marks})"  # noqa: S608
        " ORDER BY seq DESC LIMIT ?",
        (*members, limit),
    ).fetchall()
    reviews = incident_decisions.reviews_for(ov, [r["id"] for r in found])
    items = [
        _incident_item(monitoring.incident_row(inv, ov, r, reviews.get(r["id"]), now))
        for r in found
    ]
    return capped_section(items, total)


def _signal(evidence: dict[str, Any]) -> dict[str, Any]:
    service = evidence.get("service")
    return {
        "kind": safe_id(evidence.get("kind")),
        "ref": service if isinstance(service, str) and SERVICE_RE.fullmatch(service) else None,
        "observed_at": when(evidence.get("observed_at")),
    }


def _determination(**fields: Any) -> dict[str, Any]:
    return {
        "id": "device_type",
        "signals": [],
        "rule_ids": [],
        "counterevidence": {"recorded": False, "items": []},
        **fields,
    }


def _reason_text(text: str | None, withheld: bool) -> dict[str, Any]:
    if withheld:
        return {"reason_text_status": "withheld"}
    if not text:
        return {"reason_text_status": "absent"}
    return {"reason_text_status": "present", "reason_text": sensitive("prose", text)}


def _inferred(row: sqlite3.Row, char: dict[str, Any] | None, detail: dict[str, Any]) -> Any:
    text = detail["explanation"]["reason_text"]
    withheld = text is None and row["inferred_reason_text"] is not None
    texts = _reason_text(text, withheld)
    if char is not None and row["inferred_source"] == DETERMINISTIC:
        return _determination(
            value=safe_id(char["inferred_type"]) or "unknown",
            source=safe_id(DETERMINISTIC),
            strength=safe_id(char["strength"]),
            confidence=None,  # never filled in: a rule match is not a probability
            rule_ids=[r for r in map(safe_id, char["rule_ids"]) if r],
            signals=[_signal(e) for e in char["evidence"]],
            reason=safe_id(char["reason"]),
            valid_until=when(char["valid_until"]),
            model_version=safe_id(char["model_version"]),
            **texts,
        )
    if row["inferred_type"] is None:
        return None
    deterministic = row["inferred_source"] == DETERMINISTIC
    confidence = row["inferred_confidence"]
    return _determination(
        value=safe_id(row["inferred_type"]) or "unknown",
        source=safe_id(row["inferred_source"]),
        strength=None,
        confidence=None if deterministic or not isinstance(confidence, float) else confidence,
        reason=safe_id(row["inferred_reason_code"]),
        valid_until=when(row["inferred_valid_until"]),
        model_version=safe_id(row["inferred_model_version"]),
        **texts,
    )


def determinations_section(
    inv: sqlite3.Connection, ov: sqlite3.Connection, canonical: str, detail: dict[str, Any]
) -> dict[str, Any]:
    row = rows(inv, "SELECT * FROM devices WHERE id=?", (canonical,))[0]
    char = detail["explanation"]["characterization"]
    inferred = _inferred(row, char, detail)
    override = override_map(ov).get(canonical)
    items: list[dict[str, Any]] = []
    if override is not None and override["type"]:
        human = _determination(
            value=safe_id(override["type"]),
            source="human",
            strength="human",
            confidence=None,
            reason="human_override",
            valid_until=None,
            model_version=None,
            reason_text_status="absent",
        )
        items.append(human)
        if inferred is not None and inferred["value"] != human["value"]:
            items.append({**inferred, "superseded_by": "human"})
    elif inferred is not None:
        items.append(inferred)
    return capped_section(items, len(items)) if items else make_section("absent")
