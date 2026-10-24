"""Versioned, bounded type hints; never identity or enforcement decisions.

See docs/characterization.md for the rule contract and heuristic-strength semantics.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass

MODEL_VERSION = "services-v1"
DEFAULT_TTL_SECONDS = 86400.0
MAX_OBSERVATIONS = 256
MAX_TEXT_BYTES = 256
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.ASCII)
_TV = ("_googlecast._tcp", "_androidtvremote2._tcp")
_PRINT = ("_printer._tcp", "_ipp._tcp", "_ipps._tcp")


@dataclass(frozen=True)
class Observation:
    mac: str
    observed_at: float
    kind: str
    service: str | None = None
    hostname: str | None = None
    opt55: str | None = None
    opt60: str | None = None
    ua: str | None = None


@dataclass(frozen=True)
class Evidence:
    kind: str
    service: str
    observed_at: float


@dataclass(frozen=True)
class Classification:
    inferred_type: str = "unknown"
    role: str | None = None
    strength: str = "none"
    confidence: None = None
    source: str = "deterministic-services"
    rule_ids: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    model_version: str = MODEL_VERSION
    valid_until: float | None = None
    reason: str = "insufficient_evidence"


def _number(value: object) -> bool:
    try:
        return (
            isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
        )
    except OverflowError:
        return False


def _text(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        return len(value.encode("utf-8")) <= MAX_TEXT_BYTES and all(
            ord(c) >= 32 and not 127 <= ord(c) <= 159 for c in value
        )
    except UnicodeError:
        return False


def _service(value: str) -> str:
    # ASCII case folding, exact suffixes only; never substring/instance matching.
    value = value.lower() if value.isascii() else ""
    if value.endswith("."):
        value = value[:-1]
    if value.endswith(".local"):
        value = value[:-6]
    return value


def classify(
    observations: Iterable[Observation], now: float, *, ttl_seconds: float = DEFAULT_TTL_SECONDS
) -> Classification:
    """Classify one MAC's bounded observations using an explicitly injected clock.

    Unknown is the normal result for incomplete/expired evidence. Invalid/partial inputs
    fail closed, even when an earlier prefix would have matched a rule.
    """
    if not _number(now) or not _number(ttl_seconds) or ttl_seconds <= 0:
        return Classification(reason="invalid_input")
    latest: dict[str, float] = {}
    mac: str | None = None
    expired_support = False
    for index, observation in enumerate(observations):
        if index >= MAX_OBSERVATIONS:
            return Classification(reason="input_limit")
        if not isinstance(observation, Observation):
            return Classification(reason="invalid_input")
        texts = (
            observation.mac,
            observation.kind,
            observation.service,
            observation.hostname,
            observation.opt55,
            observation.opt60,
            observation.ua,
        )
        if not all(_text(v) for v in texts) or not isinstance(observation.mac, str):
            return Classification(reason="invalid_input")
        key = observation.mac.lower()
        if not _MAC.fullmatch(key) or key == "00:00:00:00:00:00" or int(key[:2], 16) & 1:
            return Classification(reason="invalid_input")
        if mac is not None and key != mac:
            return Classification(reason="mixed_macs")
        mac = key
        timestamp = observation.observed_at
        if (
            observation.kind not in ("mdns", "ssdp", "dhcp")
            or not _number(timestamp)
            or timestamp > now
            or not math.isfinite(timestamp + ttl_seconds)
        ):
            return Classification(reason="invalid_input")
        if observation.kind != "mdns" or not observation.service:
            continue
        service = _service(observation.service)
        if service in (*_TV, *_PRINT):
            if timestamp + ttl_seconds <= now:
                expired_support = True
            else:
                latest[service] = max(timestamp, latest.get(service, timestamp))
    matches: list[tuple[str, str, str, tuple[str, ...]]] = []
    if all(service in latest for service in _TV):
        matches.append(("android-tv-services-v1", "tv", "television", _TV))
    if _PRINT[0] in latest:
        alternatives = [s for s in _PRINT[1:] if s in latest]
        if alternatives:
            best = max(alternatives, key=lambda service: (latest[service], service))
            matches.append(("printing-services-v1", "iot", "printing", (_PRINT[0], best)))
    if not matches:
        return Classification(
            reason="expired_evidence" if expired_support else "insufficient_evidence"
        )
    evidence = tuple(
        Evidence("mdns", service, latest[service])
        for service in sorted({service for _, _, _, support in matches for service in support})
    )
    expires = min(e.observed_at for e in evidence) + ttl_seconds
    if len(matches) > 1:
        return Classification(
            rule_ids=tuple(m[0] for m in matches),
            evidence=evidence,
            valid_until=expires,
            reason="conflicting_roles",
        )
    rule, inferred_type, role, _ = matches[0]
    return Classification(
        inferred_type=inferred_type,
        role=role,
        strength="corroborated",
        rule_ids=(rule,),
        evidence=evidence,
        valid_until=expires,
        reason="matched_rule",
    )
