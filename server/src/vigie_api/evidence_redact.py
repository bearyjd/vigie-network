"""Redaction of an evidence pack: Sensitive leaves become level-appropriate plain values.

Pseudonyms are HMAC-SHA256(salt, kind-namespace + value) truncated to 8 hex characters. The
32-byte salt is drawn per export and never stored, so pseudonyms are stable inside one pack and
unlinkable across packs. `search_queries` are built here, only from fields the chosen level
allows and only from fragments that match a strict pattern.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from vigie_api.evidence_types import Pack, Sensitive
from vigie_ingest.db import iso_utc

LEVELS = ("full", "pseudonymized", "minimal")
SALT_BYTES = 32
PSEUDONYM_SCOPE = "this-export"
MAX_QUERIES = 12

OPT55_RE = re.compile(r"[0-9]{1,3}(,[0-9]{1,3}){0,63}")
SERVICE_RE = re.compile(r"_[a-z0-9-]{1,32}\._(tcp|udp)")
OUI_RE = re.compile(r"[0-9a-f]{6}")
VENDOR_RE = re.compile(r"[a-z0-9 .-]{1,64}")

# DHCP option 60 is device-controlled free text. Only these generic vendor classes are kept
# readable (and searched); anything else is replaced by a pseudonym.
_ARCH = "(?:armv[5-8][a-z]*|aarch64|x86_64|i[3-6]86|mips|mipsel|ppc64le|riscv64)"
KNOWN_VENDOR_CLASSES = re.compile(
    r"MSFT [0-9]{1,3}(?:\.[0-9])?"
    r"|android-dhcp-[0-9]{1,2}(?:\.[0-9])?"
    r"|dhcpcd-[0-9]{1,2}(?:\.[0-9]{1,3}){1,2}(?::Linux-[0-9]{1,2}(?:\.[0-9]{1,3}){1,2}:"
    + _ARCH
    + ")?"
    r"|udhcp [0-9]{1,2}(?:\.[0-9]{1,3}){1,2}"
    r"|Linux [0-9]{1,2}(?:\.[0-9]{1,3}){1,2}"
)


def is_known_vendor_class(value: str) -> bool:
    return KNOWN_VENDOR_CLASSES.fullmatch(value) is not None


# kind -> (prefix, hashed namespace); the namespace keeps one string from sharing a pseudonym
# across kinds (a host called "x" and a device called "x" are different things).
_PSEUDONYM = {
    "mac": ("mac", "mac"),
    "hostname": ("host", "host"),
    "mdns": ("host", "host"),
    "name": ("host", "host"),
    "owner": ("host", "host"),
    "device_id": ("dev", "device"),
    "collector_id": ("col", "collector"),
    "incident_id": ("inc", "incident"),
    "lineage": ("lin", "lineage"),
    "baseline_id": ("base", "baseline"),
    "rule_ref": ("rule", "rule"),
    "opt60": ("vc", "opt60"),
}
_INDEXED = {"device_id": "dev", "collector_id": "col", "incident_id": "inc"}
_OMITTED = object()


def _ip_class(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local-v6" if ip.version == 6 else "link-local-v4"
    if ip.version == 6:
        return "ula" if ip in ipaddress.ip_network("fc00::/7") else "global-v6"
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return "shared-v4"
    return "private-v4" if ip.is_private else "global-v4"


def _round_hour(value: Any) -> Any:
    if not isinstance(value, str):
        return _OMITTED
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return _OMITTED
    return iso_utc(parsed.astimezone(UTC).replace(minute=0, second=0, microsecond=0).timestamp())


class _Redactor:
    def __init__(self, level: str, salt: bytes) -> None:
        self.level = level
        self.salt = salt
        self.indexes: dict[str, dict[Any, int]] = {}

    def _pseudonym(self, kind: str, value: Any) -> str:
        prefix, namespace = _PSEUDONYM[kind]
        digest = hmac.new(self.salt, f"{namespace}\0{value}".encode(), hashlib.sha256)
        return f"{prefix}-{digest.hexdigest()[:8]}"

    def _index(self, kind: str, value: Any) -> str:
        seen = self.indexes.setdefault(kind, {})
        return f"{_INDEXED[kind]}-{seen.setdefault(value, len(seen) + 1)}"

    def leaf(self, leaf: Sensitive) -> Any:
        kind, value = leaf.kind, leaf.value
        if kind == "opt55":  # a bare list of option numbers: raw at every level, but only if it is
            return value if OPT55_RE.fullmatch(str(value)) else _OMITTED
        if self.level == "full":
            return value
        if kind == "ts":
            return value if self.level == "pseudonymized" else _round_hour(value)
        if kind == "ip":
            return _ip_class(str(value)) if self.level == "pseudonymized" else _OMITTED
        if kind == "opt60" and self.level == "pseudonymized":
            known = is_known_vendor_class(str(value))
            return value if known else self._pseudonym(kind, value)
        if kind in ("oui", "opt60"):
            return value if self.level == "pseudonymized" else _OMITTED
        if self.level == "minimal":
            return self._index(kind, value) if kind in _INDEXED else _OMITTED
        return self._pseudonym(kind, value) if kind in _PSEUDONYM else _OMITTED

    def walk(self, node: Any) -> Any:
        if isinstance(node, Sensitive):
            return self.leaf(node)
        if isinstance(node, dict):
            out = {k: self.walk(v) for k, v in node.items()}
            return {k: v for k, v in out.items() if v is not _OMITTED}
        if isinstance(node, (list, tuple)):
            return [v for v in map(self.walk, node) if v is not _OMITTED]
        return node


def _items(body: dict[str, Any], section: str) -> list[dict[str, Any]]:
    found = body.get("sections", {}).get(section, {})
    return found.get("items", []) if isinstance(found, dict) else []


def _raw(value: Any) -> str:
    return str(value.value if isinstance(value, Sensitive) else value or "")


def _fragments(body: dict[str, Any], level: str) -> list[tuple[str, str, str]]:
    """(template, fragment, field) triples from the fields this level may disclose."""
    found: list[tuple[str, str, str]] = []
    for item in _items(body, "fingerprints"):
        found.append(("DHCP parameter request list {}", _raw(item.get("opt55")), "opt55"))
        if level != "minimal":
            vendor = _raw(item.get("opt60"))
            known = vendor if is_known_vendor_class(vendor) else ""
            found.append(("DHCP vendor class {}", known.lower(), "opt60"))
    for item in _items(body, "determinations"):
        for signal in item.get("signals", []):
            found.append(("mDNS service {}", _raw(signal.get("ref")), "service_kind"))
    if level != "minimal":
        for item in _items(body, "identity"):
            found.append(("OUI {} vendor", _raw(item.get("oui")), "oui"))
    return found


_PATTERN = {"opt55": OPT55_RE, "opt60": VENDOR_RE, "service_kind": SERVICE_RE, "oui": OUI_RE}


def build_queries(body: dict[str, Any], level: str) -> list[dict[str, Any]]:
    queries: dict[str, str] = {}
    for template, fragment, name in _fragments(body, level):
        if fragment and _PATTERN[name].fullmatch(fragment):
            queries[template.format(fragment)] = name
    return [{"q": q, "built_from": [queries[q]]} for q in sorted(queries)[:MAX_QUERIES]]


def redact(pack: Pack, level: str, salt: bytes) -> Pack:
    if level not in LEVELS:
        raise ValueError(f"unknown redaction level: {level!r}")
    if len(salt) != SALT_BYTES:
        raise ValueError(f"salt must be {SALT_BYTES} bytes")
    body = _Redactor(level, salt).walk(pack.body)
    body["redaction"] = {"level": level, "pseudonym_scope": PSEUDONYM_SCOPE}
    body["search_queries"] = build_queries(pack.body, level)
    return Pack(body, redacted=True)
