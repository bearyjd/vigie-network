"""Atomic human decisions. Inventory is read-only; every mutation and receipt lives in overrides."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from vigie_api import writes
from vigie_api.config import Settings
from vigie_api.effective import link_map, resolve
from vigie_api.errors import ApiError
from vigie_api.models import DevicePatch
from vigie_api.textsafe import display_json, has_forbidden
from vigie_ingest.db import iso_utc
from vigie_pipeline.activity import (
    load_activity,
    load_first_received,
    merge_intervals,
    overlap_seconds,
)
from vigie_pipeline.snapshot import MalformedRule, parse_rule, rule_active
from vigie_pipeline.stitch_types import fold


def dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def validate_signature(signature: dict[str, Any]) -> dict[str, str]:
    allowed = {"opt55", "opt60", "hostname", "mdns_name"}
    if not signature or signature.keys() - allowed:
        raise ValueError("signature has unknown fields")
    for key, value in signature.items():
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 128
            or has_forbidden(value)
        ):
            raise ValueError(
                f"signature {key} must be a nonblank plain string of at most 128 characters"
            )
    try:
        rule = parse_rule(
            {
                "id": "validation",
                "device_id": "validation",
                "signature": dump(signature),
                "expires_at": None,
            }
        )
    except MalformedRule as exc:
        raise ValueError(str(exc)) from exc
    if rule is None:
        raise ValueError("signature requires opt55, opt60 and hostname and/or mdns_name")
    # This is the same Unicode name equivalence used by the pipeline's indexed evidence.
    normalized = {
        key: fold(value) if key in {"hostname", "mdns_name"} else value
        for key, value in signature.items()
    }
    if any(len(value) > 128 for value in normalized.values()):
        raise ValueError("normalized signature fields must be at most 128 characters")
    return normalized


def _date(value: str) -> float:
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC).timestamp()
    except (TypeError, ValueError):
        raise ApiError(
            422, "invalid_timestamp", "timestamp must be an ISO-8601 instant with timezone"
        ) from None


def _versions(ov, ids, body, *, basis=None):
    expected = body.expected_versions
    if expected is None:
        if len(ids) != 1:
            raise ApiError(422, "versions_required", "expected_versions must cover every device")
        expected = {ids[0]: body.expected_version}
    if set(expected) != set(ids):
        raise ApiError(
            422, "versions_required", "expected_versions must cover exactly the involved devices"
        )
    current = {device: writes._current_version(ov, device) for device in ids}
    if current != expected or (basis is not None and current != basis):
        raise ApiError(409, "version_mismatch", "override versions no longer match")
    return current


def _targets(inv, ov, ids, *, canonical=True):
    links = link_map(ov) if canonical else {}
    for device in ids:
        row = inv.execute("SELECT status FROM devices WHERE id=?", (device,)).fetchone()
        if row is None or row["status"] == "retired":
            raise ApiError(409, "orphaned_device", "a device is missing or retired")
        if canonical and resolve(links, device) != device:
            raise ApiError(409, "device_merged", "a device is no longer canonical")


def _snapshot(ov, ids):
    return {
        device: {**writes._before(ov, device), "version": writes._current_version(ov, device)}
        for device in ids
    }


def _bump(ov, ids, principal, now):
    versions = {}
    for device in ids:
        versions[device] = writes._current_version(ov, device) + 1
        writes._apply(ov, device, {}, versions[device], principal, now)
    return versions


class Replay(Exception):
    def __init__(self, result):
        self.result = result


def atomic(ov, *, principal, action, target, body, request_id, now, operation: Callable):
    """Stable receipts make retries side-effect free, including retries after later changes."""
    fingerprint = dump(body.model_dump())
    key = hashlib.sha256(
        dump([principal, action, target, request_id or fingerprint]).encode()
    ).hexdigest()
    ov.execute("BEGIN IMMEDIATE")
    try:
        receipt = ov.execute(
            "SELECT fingerprint,result FROM api_write_receipts WHERE id=?", (key,)
        ).fetchone()
        if receipt:
            if receipt["fingerprint"] != fingerprint:
                raise ApiError(
                    409, "idempotency_conflict", "request id already used with a different body"
                )
            ov.execute("ROLLBACK")
            return json.loads(receipt["result"])
        result, before, after = operation()
        detail = {"request_id": request_id or str(uuid.uuid4()), "before": before, "after": after}
        ov.execute(
            "INSERT INTO audit_log (id,ts,principal,action,target,detail) VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), now, principal, action, target, dump(detail)),
        )
        ov.execute(
            "INSERT INTO api_write_receipts (id,fingerprint,result) VALUES (?,?,?)",
            (key, fingerprint, dump(result)),
        )
        ov.execute("COMMIT")
        return result
    except Replay as replay:
        ov.execute("ROLLBACK")
        return replay.result
    except BaseException:
        if ov.in_transaction:
            ov.execute("ROLLBACK")
        raise


def _candidate(inv, candidate_id, ids):
    row = inv.execute("SELECT * FROM identity_candidates WHERE id=?", (candidate_id,)).fetchone()
    if row is None or {row["device_a"], row["device_b"]} != set(ids):
        raise ApiError(
            409, "invalid_candidate", "suggestion candidate does not match the device pair"
        )
    return row


def _too_large(kind):
    raise ApiError(409, "merge_too_large", f"merge exceeds configured {kind} limit")


def _merge_component(ov, source, target, limits):
    """Indexed incoming edges, with one sentinel row beyond the configured budget."""
    roots = {}
    for device in (source, target):
        row = ov.execute("SELECT * FROM identity_links WHERE from_device=?", (device,)).fetchone()
        roots[device] = dict(row) if row else None
        if row and row["revoked_at"] is None:
            raise ApiError(409, "device_merged", "a device is no longer canonical")
    owners = {source: source, target: target}
    edges = {}
    pending = [source, target]
    for device in pending:
        rows = ov.execute(
            "SELECT * FROM identity_links WHERE into_device=? AND revoked_at IS NULL"
            " ORDER BY from_device LIMIT ?",
            (device, limits.max_merge_aliases - len(owners) + 1),
        ).fetchall()
        for row in rows:
            alias = row["from_device"]
            if alias in owners:
                raise ApiError(409, "merge_changed", "identity component contains a cycle")
            owners[alias] = owners[device]
            edges[alias] = dict(row)
            if len(owners) > limits.max_merge_aliases:
                _too_large("component size")
            pending.append(alias)
    if len(owners) > limits.max_merge_aliases:
        _too_large("component size")
    flattened = {d: row["into_device"] for d, row in edges.items() if owners[d] == source}
    if len(flattened) + 1 > limits.max_merge_flatten_writes:
        _too_large("flatten writes")
    return {"owners": owners, "edges": edges, "roots": roots, "flattened": flattened}


def _overlap(inv, component, source, target, config, now, limits):
    owners = component["owners"]
    devices = list(owners)
    observations = []
    for start in range(0, len(devices), 400):
        chunk = devices[start : start + 400]
        observations.extend(
            inv.execute(
                "SELECT mac,device_id FROM observations WHERE device_id IN "  # noqa: S608
                f"({','.join('?' * len(chunk))}) LIMIT ?",  # noqa: S608
                [*chunk, limits.max_merge_observations - len(observations) + 1],
            ).fetchall()
        )
        if len(observations) > limits.max_merge_observations:
            _too_large("observations")
    a = [r["mac"] for r in observations if owners[r["device_id"]] == source]
    b = [r["mac"] for r in observations if owners[r["device_id"]] == target]
    macs = a + b
    activity_rows = 0
    for start in range(0, len(macs), 400):
        chunk = macs[start : start + 400]
        activity_rows += len(
            inv.execute(
                "SELECT mac FROM mac_activity WHERE mac IN "  # noqa: S608
                f"({','.join('?' * len(chunk))}) LIMIT ?",  # noqa: S608
                [*chunk, limits.max_merge_activity_rows - activity_rows + 1],
            ).fetchall()
        )
        if activity_rows > limits.max_merge_activity_rows:
            _too_large("activity rows")
    activity = load_activity(
        inv,
        macs,
        min_width_s=config.activity_gap_s,
        min_end=int(_date(now)) - config.activity_retention_s,
        first_received=load_first_received(inv, macs),
    )
    peer = []
    for mac in b:
        for start, end in activity.get(mac, []):
            tail = config.activity_gap_s if end - start > 2 * config.overlap_grace_s else 0
            peer.append((start, end + tail))
    peers = merge_intervals(peer)
    for mac in a:
        own = activity.get(mac, [])
        duration = sum(end - start for start, end in own)
        overlap = overlap_seconds(own, peers)
        if overlap > config.overlap_grace_s or (
            overlap
            and (
                overlap >= duration
                or (
                    duration > config.overlap_grace_s
                    and 2 * (duration - overlap) < config.activity_gap_s
                )
            )
        ):
            raise ApiError(409, "active_overlap", "devices have conflicting concurrent activity")


@contextmanager
def _prepare_merge(inv, ov, *, sid, accept, body, principal, now, request_id, config, limits):
    """Keep evidence in one inventory snapshot; release overrides reads before writer lock."""
    fingerprint = dump(body.model_dump())
    key = hashlib.sha256(
        dump(
            [
                principal,
                "suggestion.accept" if accept else "suggestion.reject",
                sid,
                request_id or fingerprint,
            ]
        ).encode()
    ).hexdigest()
    if (
        not accept
        or ov.execute("SELECT 1 FROM api_write_receipts WHERE id=?", (key,)).fetchone()
        or ov.execute("SELECT 1 FROM suggestion_decisions WHERE suggestion_id=?", (sid,)).fetchone()
    ):
        yield None
        return
    inv.execute("BEGIN")
    try:
        row = inv.execute("SELECT * FROM suggestions WHERE id=?", (sid,)).fetchone()
        prepared = None
        if row and row["action"] == "merge_identity":
            try:
                ids, payload = json.loads(row["device_ids"]), json.loads(row["payload"])
                source, target = payload.get("from_device"), payload.get("into_device")
                if (
                    not isinstance(ids, list)
                    or len(ids) != 2
                    or not all(isinstance(d, str) for d in ids)
                    or not isinstance(source, str)
                    or not isinstance(target, str)
                    or source == target
                    or {source, target} != set(ids)
                ):
                    raise ValueError
            except (TypeError, ValueError, AttributeError):
                raise ApiError(409, "invalid_suggestion", "merge endpoints do not match") from None
            ov.execute("BEGIN")
            try:
                _targets(inv, ov, ids, canonical=False)
                _versions(ov, ids, body)
                prepared = _merge_component(ov, source, target, limits)
                _overlap(inv, prepared, source, target, config, now, limits)
            finally:
                ov.execute("ROLLBACK")
        yield prepared
    finally:
        inv.execute("ROLLBACK")


def decide(inv, ov, *, sid, accept, body, principal, now, request_id, config, merge_limits=None):
    principal.require_write(rules=bool(accept and body.remember))
    action = "suggestion.accept" if accept else "suggestion.reject"
    limits = merge_limits or Settings(data_dir=config.data_dir)

    def operation():
        old = ov.execute(
            "SELECT * FROM suggestion_decisions WHERE suggestion_id=?", (sid,)
        ).fetchone()
        if old:
            if old["state"] != ("accepted" if accept else "rejected"):
                raise ApiError(409, "already_decided", "suggestion already decided")
            raise Replay(json.loads(old["applied"]))
        row = inv.execute("SELECT * FROM suggestions WHERE id=?", (sid,)).fetchone()
        if row is None:
            raise ApiError(404, "not_found", "suggestion not found")
        if accept and _date(row["expires_at"]) <= _date(now):
            raise ApiError(410, "suggestion_expired", "suggestion expired")
        try:
            ids, payload, basis = (
                json.loads(row[key]) for key in ("device_ids", "payload", "basis")
            )
            if (
                not isinstance(ids, list)
                or len(ids) not in {1, 2}
                or len(set(ids)) != len(ids)
                or not all(isinstance(d, str) for d in ids)
                or not isinstance(payload, dict)
                or not isinstance(basis, dict)
                or any(type(v) is not int for v in basis.values())
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise ApiError(
                409, "invalid_suggestion", "suggestion has invalid structured data"
            ) from None
        _targets(inv, ov, ids, canonical=prepared is None)
        _versions(ov, ids, body, basis=basis)
        before = _snapshot(ov, ids)
        result = {"suggestion_id": sid, "state": "accepted" if accept else "rejected"}
        if accept:
            kind = row["action"]
            if kind == "merge_identity":
                source, target = payload.get("from_device"), payload.get("into_device")
                if len(ids) != 2 or {source, target} != set(ids):
                    raise ApiError(409, "invalid_suggestion", "merge endpoints do not match")
                summary = payload.get("evidence_summary")
                cid = summary.get("candidate_id") if isinstance(summary, dict) else None
                if not isinstance(cid, str):
                    raise ApiError(409, "invalid_candidate", "merge requires a candidate id")
                candidate = _candidate(inv, cid, ids)
                if candidate["state"] not in {"open", "suggested"}:
                    raise ApiError(409, "invalid_candidate", "candidate is no longer open")
                if prepared is None or _merge_component(ov, source, target, limits) != prepared:
                    raise ApiError(
                        409, "merge_changed", "identity component changed during approval"
                    )
                merge_id = str(uuid.uuid4())
                flattened = prepared["flattened"]
                for device in flattened:
                    ov.execute(
                        "UPDATE identity_links SET into_device=? WHERE from_device=? AND"
                        " revoked_at IS NULL",
                        (target, device),
                    )
                ov.execute(
                    "INSERT INTO identity_links"
                    " (from_device,into_device,merge_id,created_at,created_by,revoked_at)"
                    " VALUES (?,?,?,?,?,NULL) ON CONFLICT(from_device) DO UPDATE SET"
                    " into_device=excluded.into_device,"
                    " merge_id=excluded.merge_id,created_at=excluded.created_at,"
                    "created_by=excluded.created_by,revoked_at=NULL",
                    (source, target, merge_id, now, principal.name),
                )
                versions = _bump(ov, ids, principal.name, now)
                history = {"overrides": before, "flattened_links": flattened, "versions": versions}
                ov.execute(
                    "INSERT INTO identity_merges"
                    " (id,ts,from_device,into_device,prior_overrides,suggestion_id,decided_by)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (merge_id, now, source, target, dump(history), sid, principal.name),
                )
                result.update(merge_id=merge_id, versions=versions)
                if body.remember:
                    try:
                        evidence = json.loads(candidate["evidence"])
                        signature = evidence.get("signature")
                        if signature is None:
                            signature = {
                                key: evidence[key]
                                for key in ("opt55", "opt60", "hostname", "mdns_name")
                                if key in evidence and evidence[key] is not None
                            }
                        signature = validate_signature(signature)
                    except (ValueError, TypeError, AttributeError) as exc:
                        raise ApiError(
                            422,
                            "invalid_signature",
                            "candidate evidence has no valid rule signature",
                        ) from exc
                    rid = str(uuid.uuid4())
                    ov.execute(
                        "INSERT INTO identity_rules"
                        " (id,device_id,signature,created_at,created_by,expires_at) VALUES"
                        " (?,?,?,?,?,?)",
                        (
                            rid,
                            target,
                            dump(signature),
                            now,
                            principal.name,
                            iso_utc(_date(now) + 180 * 86400),
                        ),
                    )
                    result["rule_id"] = rid
                    history["remembered_rule_id"] = rid
                    ov.execute(
                        "UPDATE identity_merges SET prior_overrides=? WHERE id=?",
                        (dump(history), merge_id),
                    )
            else:
                if len(ids) != 1:
                    raise ApiError(409, "invalid_suggestion", "action requires one device")
                if kind == "label":
                    changes = {
                        key: value for key, value in payload.items() if key in {"name", "type"}
                    }
                    try:
                        changes = DevicePatch(**changes).model_dump(exclude_unset=True)
                    except ValueError as exc:
                        raise ApiError(422, "invalid_suggestion", "invalid label payload") from exc
                elif kind in {"move_group", "quarantine"}:
                    changes = {
                        "group_id": "quarantine"
                        if kind == "quarantine"
                        else payload.get("group_id")
                    }
                    if changes["group_id"] is None:
                        raise ApiError(422, "invalid_suggestion", "group_id is required")
                else:
                    raise ApiError(409, "invalid_suggestion", "unknown action")
                writes._validate(ov, changes)
                version = writes._current_version(ov, ids[0]) + 1
                writes._apply(ov, ids[0], changes, version, principal.name, now)
                result["versions"] = {ids[0]: version}
        ov.execute(
            "INSERT INTO suggestion_decisions"
            " (suggestion_id,state,decided_by,decided_at,applied) VALUES (?,?,?,?,?)",
            (sid, result["state"], principal.name, now, dump(result)),
        )
        after = {"decision": result, "overrides": _snapshot(ov, ids)}
        if result.get("rule_id"):
            after["remembered_rule"] = dict(
                ov.execute(
                    "SELECT * FROM identity_rules WHERE id=?", (result["rule_id"],)
                ).fetchone()
            )
            after["group_id"] = after["overrides"][target].get("group_id")
        return result, before, after

    with _prepare_merge(
        inv,
        ov,
        sid=sid,
        accept=accept,
        body=body,
        principal=principal.name,
        now=now,
        request_id=request_id,
        config=config,
        limits=limits,
    ) as prepared:
        return atomic(
            ov,
            principal=principal.name,
            action=action,
            target=sid,
            body=body,
            request_id=request_id,
            now=now,
            operation=operation,
        )


def undo(inv, ov, *, merge_id, body, principal, now, request_id):
    principal.require_write()

    def operation():
        merge = ov.execute("SELECT * FROM identity_merges WHERE id=?", (merge_id,)).fetchone()
        if merge is None:
            raise ApiError(404, "not_found", "merge not found")
        if merge["undone_at"] is not None:
            prior = json.loads(merge["prior_overrides"])
            raise Replay(prior["undo_result"])
        source, target = merge["from_device"], merge["into_device"]
        ids = [source, target]
        current = _versions(ov, ids, body)
        prior = json.loads(merge["prior_overrides"])
        link = ov.execute("SELECT * FROM identity_links WHERE from_device=?", (source,)).fetchone()
        if (
            current != prior["versions"]
            or link is None
            or link["merge_id"] != merge_id
            or link["revoked_at"] is not None
            or resolve(link_map(ov), target) != target
        ):
            raise ApiError(409, "merge_changed", "merge or overrides changed after approval")
        for device in prior["flattened_links"]:
            row = ov.execute(
                "SELECT into_device,revoked_at FROM identity_links WHERE from_device=?", (device,)
            ).fetchone()
            if not row or row[0] != target or row[1] is not None:
                raise ApiError(409, "merge_changed", "an alias changed after approval")
        before = _snapshot(ov, ids)
        remembered = prior.get("remembered_rule_id")
        if remembered is not None:
            principal.require_write(rules=True)
            rule = ov.execute("SELECT * FROM identity_rules WHERE id=?", (remembered,)).fetchone()
            if (
                rule is None
                or rule["device_id"] != target
                or rule["created_by"] != merge["decided_by"]
            ):
                raise ApiError(409, "merge_changed", "remembered rule changed after approval")
            ov.execute(
                "UPDATE identity_rules SET revoked_at=COALESCE(revoked_at,?) WHERE id=?",
                (now, remembered),
            )
            before["remembered_rule"] = dict(rule)
        ov.execute(
            "UPDATE identity_links SET revoked_at=? WHERE from_device=? AND merge_id=?",
            (now, source, merge_id),
        )
        for device, into in prior["flattened_links"].items():
            ov.execute(
                "UPDATE identity_links SET into_device=? WHERE from_device=?", (into, device)
            )
        versions = {}
        for device in ids:
            versions[device] = current[device] + 1
            fields = {key: prior["overrides"][device][key] for key in writes.FIELDS}
            writes._apply(ov, device, fields, versions[device], principal.name, now)
        result = {"merge_id": merge_id, "undone": True, "versions": versions}
        prior["undo_result"] = result
        ov.execute(
            "UPDATE identity_merges SET undone_at=?,prior_overrides=? WHERE id=?",
            (now, dump(prior), merge_id),
        )
        return (
            result,
            before,
            {
                "overrides": _snapshot(ov, ids),
                "revoked_link": source,
                "revoked_rule_id": remembered,
            },
        )

    return atomic(
        ov,
        principal=principal.name,
        action="identity.merge.undo",
        target=merge_id,
        body=body,
        request_id=request_id,
        now=now,
        operation=operation,
    )


def create_rule(inv, ov, *, body, principal, now, request_id):
    principal.require_write(rules=True)

    def operation():
        device = body.device_id
        _targets(inv, ov, [device])
        _versions(ov, [device], body)
        if body.expires_at is not None and _date(body.expires_at) <= _date(now):
            raise ApiError(422, "invalid_expiry", "rule expiry must be in the future")
        expires = body.expires_at or iso_utc(_date(now) + 180 * 86400)
        before = _snapshot(ov, [device])
        rid = str(uuid.uuid4())
        ov.execute(
            "INSERT INTO identity_rules"
            " (id,device_id,signature,created_at,created_by,expires_at) VALUES (?,?,?,?,?,?)",
            (rid, device, dump(body.signature), now, principal.name, expires),
        )
        versions = _bump(ov, [device], principal.name, now)
        result = {"id": rid, "device_id": device, "version": versions[device]}
        return (
            result,
            before,
            {"rule": {**result, "signature": body.signature, "expires_at": expires}},
        )

    return atomic(
        ov,
        principal=principal.name,
        action="identity.rule.create",
        target=body.device_id,
        body=body,
        request_id=request_id,
        now=now,
        operation=operation,
    )


def revoke_rule(inv, ov, *, rule_id, body, principal, now, request_id):
    principal.require_write(rules=True)

    def operation():
        row = ov.execute("SELECT * FROM identity_rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise ApiError(404, "not_found", "rule not found")
        device = resolve(link_map(ov), row["device_id"])
        _versions(ov, [device], body)
        if row["revoked_at"] is not None:
            raise ApiError(409, "rule_revoked", "rule already revoked")
        ov.execute("UPDATE identity_rules SET revoked_at=? WHERE id=?", (now, rule_id))
        versions = _bump(ov, [device], principal.name, now)
        result = {
            "id": rule_id,
            "device_id": device,
            "revoked_at": now,
            "version": versions[device],
        }
        return result, dict(row), result

    return atomic(
        ov,
        principal=principal.name,
        action="identity.rule.revoke",
        target=rule_id,
        body=body,
        request_id=request_id,
        now=now,
        operation=operation,
    )


def clear_veto(inv, ov, *, candidate_id, body, principal, now, request_id):
    principal.require_write()

    def operation():
        candidate = inv.execute(
            "SELECT * FROM identity_candidates WHERE id=?", (candidate_id,)
        ).fetchone()
        if candidate is None:
            raise ApiError(404, "not_found", "candidate not found")
        ids = [candidate["device_a"], candidate["device_b"]]
        _targets(inv, ov, ids)
        _versions(ov, ids, body)
        if candidate["state"] != "vetoed":
            raise ApiError(409, "candidate_not_vetoed", "candidate is not vetoed")
        old = ov.execute(
            "SELECT * FROM candidate_decisions WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        decision = str(uuid.uuid4())
        ov.execute(
            "INSERT INTO candidate_decisions"
            " (candidate_id,device_a,device_b,action,decided_by,decided_at,id)"
            " VALUES (?,?,?,'clear_veto',?,?,?) ON CONFLICT(candidate_id) DO UPDATE SET"
            " device_a=excluded.device_a,"
            " device_b=excluded.device_b,action=excluded.action,decided_by=excluded.decided_by,"
            " decided_at=excluded.decided_at,id=excluded.id",
            (candidate_id, *ids, principal.name, now, decision),
        )
        versions = _bump(ov, ids, principal.name, now)
        result = {
            "id": decision,
            "candidate_id": candidate_id,
            "action": "clear_veto",
            "versions": versions,
        }
        return result, dict(old) if old else None, result

    return atomic(
        ov,
        principal=principal.name,
        action="identity.candidate.clear_veto",
        target=candidate_id,
        body=body,
        request_id=request_id,
        now=now,
        operation=operation,
    )


def list_rules(ov, now):
    result = []
    for row in ov.execute("SELECT * FROM identity_rules ORDER BY created_at,id"):
        item = dict(row)
        try:
            item["signature"] = json.loads(row["signature"])
        except (ValueError, TypeError):
            item["signature"] = None
        item["active"] = rule_active(row, _date(now))
        for key in ("created_by", "device_id", "id"):
            item[key] = display_json(item[key])
        result.append(display_json(item))
    nxt = (
        encode_cursor(dump([found[limit - 1]["created_at"], found[limit - 1]["id"]]))
        if len(found) > limit
        else None
    )
    return result, nxt
