"""A read-only snapshot of the overrides.db state stitching needs (rules, groups, versions,
decisions, links). Loaded once per run; the pipeline never writes overrides.db."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from vigie_pipeline.logs import log

logger = logging.getLogger("vigie_pipeline")
MAX_LINK_DEPTH = 32


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


@dataclass(frozen=True)
class Snapshot:
    links: Mapping[str, str]
    rules: tuple[Rule, ...]
    group_auto_inherit: Mapping[str, int]
    overrides: Mapping[str, tuple[int, str | None]]  # device_id -> (version, group_id)
    decisions: Mapping[str, str]  # suggestion_id -> accepted|rejected

    def canonical(self, device_id: str) -> str:
        seen, current = {device_id}, device_id
        for _ in range(MAX_LINK_DEPTH):
            nxt = self.links.get(current)
            if nxt is None or nxt in seen:
                return current
            current = nxt
            seen.add(current)
        return current

    def version(self, device_id: str) -> int:
        return self.overrides[device_id][0] if device_id in self.overrides else 0


EMPTY = Snapshot({}, (), {}, {}, {})


def _text(value: object) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


def _opt55(value: object) -> str | None:
    if isinstance(value, list) and all(isinstance(x, int) for x in value):
        return ",".join(str(x) for x in value) or None
    return _text(value)


def parse_rule(row: sqlite3.Row) -> Rule | None:
    """A rule needs opt55 and opt60 plus hostname and/or mdns_name; anything else is ignored."""
    try:
        sig = json.loads(row["signature"])
    except (TypeError, ValueError):
        return None
    if not isinstance(sig, dict):
        return None
    opt55, opt60 = _opt55(sig.get("opt55")), _text(sig.get("opt60"))
    host, mdns = _text(sig.get("hostname")), _text(sig.get("mdns_name"))
    if not (opt55 and opt60 and (host or mdns)):
        return None
    return Rule(row["id"], row["device_id"], opt55, opt60, host, mdns)


def _active(row: sqlite3.Row, now: float) -> bool:
    if row["revoked_at"]:
        return False
    if not row["expires_at"]:
        return True
    try:
        expires = datetime.fromisoformat(row["expires_at"])
    except ValueError:
        return False  # unparseable expiry fails closed
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires.timestamp() > now


def _rows(conn: sqlite3.Connection, sql: str) -> list[sqlite3.Row]:
    try:
        return conn.execute(sql).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):  # the api has not created that table yet
            return []
        raise


def load_snapshot(conn: sqlite3.Connection, now: float) -> Snapshot:
    try:
        links = {
            r["from_device"]: r["into_device"] for r in _rows(conn, "SELECT * FROM identity_links")
        }
        rules = []
        for row in _rows(conn, "SELECT * FROM identity_rules ORDER BY id"):
            rule = parse_rule(row) if _active(row, now) else None
            if rule:
                rules.append(rule)
        groups = {
            r["id"]: int(r["auto_inherit"])
            for r in _rows(conn, "SELECT id, auto_inherit FROM groups")
        }
        overrides = {
            r["device_id"]: (int(r["version"]), r["group_id"])
            for r in _rows(conn, "SELECT device_id, version, group_id FROM device_overrides")
        }
        decisions = {
            r["suggestion_id"]: r["state"]
            for r in _rows(conn, "SELECT suggestion_id, state FROM suggestion_decisions")
        }
    except sqlite3.Error as exc:
        log(logger, logging.ERROR, "overrides_snapshot_failed", error=str(exc))
        raise OverridesUnreadable(str(exc)) from exc
    return Snapshot(links, tuple(rules), groups, overrides, decisions)
