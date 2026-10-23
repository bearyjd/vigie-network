"""A read-only snapshot of the overrides.db state stitching needs (rules, groups, versions,
decisions, links). Loaded once per run; the pipeline never writes overrides.db."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property

from vigie_pipeline.logs import log

logger = logging.getLogger("vigie_pipeline")
OPT55_RE = re.compile(r"[0-9]+(,[0-9]+)*")


class OverridesUnreadable(RuntimeError):
    """overrides.db exists but cannot be read: stitching fails closed."""


@dataclass(frozen=True)
class Rule:
    id: str
    device_id: str
    opt55: str
    opt60: str
    hostname: str | None
    mdns_name: str | None
    expires_at: float | None = None  # epoch s; re-checked when the rule is about to be applied


@dataclass(frozen=True)
class Snapshot:
    links: Mapping[str, str]
    rules: tuple[Rule, ...]
    group_auto_inherit: Mapping[str, int]
    overrides: Mapping[str, tuple[int, str | None]]  # device_id -> (version, group_id)
    decisions: Mapping[str, str]  # suggestion_id -> accepted|rejected
    malformed_rules: int = 0  # active-looking identity_rules rows skipped as malformed
    malformed_devices: frozenset[str] = frozenset()  # their targets: these need a human
    unknown_target: bool = False  # a malformed rule whose target is unreadable: every hit needs one

    @cached_property
    def _canon(self) -> dict[str, str]:
        """Canonical device of every linked device, through the COMPLETE chain (any length),
        iteratively with a visited set (cycle-safe) and memoised along the path."""
        memo: dict[str, str] = {}
        for start in self.links:
            if start in memo:
                continue
            path, seen, current = [start], {start}, start
            while True:
                nxt = self.links.get(current)
                if nxt is None or nxt in seen:
                    canon = current
                    break
                if nxt in memo:
                    canon = memo[nxt]
                    break
                path.append(nxt)
                seen.add(nxt)
                current = nxt
            for device in path:
                memo[device] = canon
        return memo

    def canonical(self, device_id: str) -> str:
        return self._canon.get(device_id, device_id)

    def version(self, device_id: str) -> int:
        return self.overrides[device_id][0] if device_id in self.overrides else 0


EMPTY = Snapshot({}, (), {}, {}, {})


def _text(value: object) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


class MalformedRule(ValueError):
    """An identity_rules row whose fields have the wrong type or shape: never used. `device_id`
    is the rule's target when that much was readable (the target then needs a human)."""

    def __init__(self, message: str, device_id: str | None = None) -> None:
        super().__init__(message)
        self.device_id = device_id


def _ident(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MalformedRule(f"{what} is not a non-blank string")
    return value


def _sig_text(value: object, what: str) -> str | None:
    """A signature name field: absent or null means "not required"; anything else SUPPLIED must be
    a non-blank string, otherwise the whole rule is malformed (never silently weakened)."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise MalformedRule(f"signature {what} is supplied but not a non-blank string")
    return value.strip()


def _sig_opt55(value: object) -> str | None:
    """opt55 as a comma list of integers ("1,2,3") or a list of integers; absent or null is
    "missing" (the rule is then incomplete and ignored); any other supplied shape is malformed."""
    if value is None:
        return None
    if isinstance(value, list):
        if not value or not all(isinstance(x, int) and not isinstance(x, bool) for x in value):
            raise MalformedRule("signature opt55 list must hold integers")
        return ",".join(str(x) for x in value)
    text = _sig_text(value, "opt55")
    if text is None or not OPT55_RE.fullmatch(text):
        raise MalformedRule("signature opt55 is not a comma list of integers")
    return text


def parse_rule(row: sqlite3.Row) -> Rule | None:
    """A rule needs opt55 and opt60 plus hostname and/or mdns_name; an incomplete signature is
    ignored (None). Wrong types (non-string ids, a BLOB device_id, a signature that is not a JSON
    object, nesting deep enough to exhaust the parser) raise MalformedRule."""
    device_id = _ident(row["device_id"], "rule device_id")  # first: kept on every later failure
    try:
        rule_id = _ident(row["id"], "rule id")
    except MalformedRule as exc:
        raise MalformedRule(str(exc), device_id) from exc
    try:
        sig = json.loads(row["signature"])
    except (TypeError, ValueError) as exc:
        raise MalformedRule("signature is not valid JSON", device_id) from exc
    except RecursionError as exc:
        raise MalformedRule("signature nesting too deep", device_id) from exc
    if not isinstance(sig, dict):
        raise MalformedRule("signature is not a JSON object", device_id)
    try:
        opt55 = _sig_opt55(sig.get("opt55"))
        opt60, host, mdns = (_sig_text(sig.get(k), k) for k in ("opt60", "hostname", "mdns_name"))
    except MalformedRule as exc:
        raise MalformedRule(str(exc), device_id) from exc
    if not (opt55 and opt60 and (host or mdns)):
        return None
    return Rule(rule_id, device_id, opt55, opt60, host, mdns, _expiry(row["expires_at"]))


def _expiry(value: object) -> float | None:
    """Epoch seconds of an expires_at value, or None for NULL (never expires) / unparseable."""
    expiry = _text(value)
    if not expiry:
        return None
    try:
        expires = datetime.fromisoformat(expiry)
    except ValueError:
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires.timestamp()


def rule_active(row: sqlite3.Row, now: float) -> bool:
    """Active = created by a named principal, never revoked, and not expired. Anything odd fails
    closed: ANY non-NULL revoked_at counts as revoked, a blank/unparseable expires_at as expired."""
    if row["revoked_at"] is not None:
        return False
    if not _text(row["created_by"]):
        return False
    if row["expires_at"] is None:
        return True
    expires = _expiry(row["expires_at"])
    return expires is not None and expires > now


def _rows(conn: sqlite3.Connection, sql: str, *, required: bool = False) -> list[sqlite3.Row]:
    try:
        return conn.execute(sql).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc) and not required:  # the api has not created it yet
            return []
        raise


def _int(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OverridesUnreadable(f"{what} is not an integer")
    return value


def _str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise OverridesUnreadable(f"{what} is not text")
    return value


def _read(conn: sqlite3.Connection, now: float) -> Snapshot:
    links = {
        _str(r["from_device"], "identity_links.from_device"): _str(
            r["into_device"], "identity_links.into_device"
        )
        for r in _rows(conn, "SELECT from_device, into_device FROM identity_links")
    }
    rules, malformed, bad_devices, unknown = [], 0, set(), False
    for row in _rows(
        conn,
        "SELECT id, device_id, signature, created_by, expires_at, revoked_at FROM identity_rules"
        " ORDER BY id",
    ):
        if not rule_active(row, now):
            continue
        try:
            rule = parse_rule(row)
        except MalformedRule as exc:  # fail closed: this row is never used
            malformed += 1
            if exc.device_id:
                bad_devices.add(exc.device_id)
            else:
                unknown = True  # not even the target is readable: every rule hit needs a human
            log(logger, logging.ERROR, "rule_malformed", error=str(exc))
            continue
        if rule:
            rules.append(rule)
    groups = {
        _str(r["id"], "groups.id"): _int(r["auto_inherit"], "groups.auto_inherit")
        for r in _rows(conn, "SELECT id, auto_inherit FROM groups")
    }
    # With a live rule, a missing device_overrides table would read as "unassigned" (= attach).
    overrides = {
        _str(r["device_id"], "device_overrides.device_id"): (
            _int(r["version"], "device_overrides.version"),
            None if r["group_id"] is None else _str(r["group_id"], "device_overrides.group_id"),
        )
        for r in _rows(
            conn,
            "SELECT device_id, version, group_id FROM device_overrides",
            required=bool(rules),
        )
    }
    decisions = {
        _str(r["suggestion_id"], "suggestion_decisions.suggestion_id"): _str(
            r["state"], "suggestion_decisions.state"
        )
        for r in _rows(conn, "SELECT suggestion_id, state FROM suggestion_decisions")
    }
    return Snapshot(
        links,
        tuple(rules),
        groups,
        overrides,
        decisions,
        malformed,
        frozenset(bad_devices),
        unknown,
    )


def load_snapshot(conn: sqlite3.Connection, now: float) -> Snapshot:
    """One consistent read transaction; any surprise (missing column, odd type) fails closed."""
    try:
        conn.execute("BEGIN")
        try:
            return _read(conn, now)
        finally:
            if conn.in_transaction:
                conn.execute("COMMIT")
    except Exception as exc:  # noqa: BLE001 - anything unexpected fails closed
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        log(logger, logging.ERROR, "overrides_snapshot_failed", error=str(exc))
        raise OverridesUnreadable(str(exc)) from exc
