"""Strict, bounded parser for the offline M2b-I product-signal inventory document.

See docs/product-signal-inventory.md. Every rejection raises InventoryError with a fixed
message that never echoes input values. Parsed data is immutable.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from vigie_api.effective import MAX_LINK_DEPTH
from vigie_pipeline.characterization import DEFAULT_TTL_SECONDS, MAX_TEXT_BYTES
from vigie_pipeline.sources import normalize_mac

FORMAT = "vigie-product-signal-inventory"
VERSION = 1
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_DEVICES = 10_000
MAX_LINKS = 10_000
MAX_MACS_PER_DEVICE = 64
MAX_OBSERVATIONS = 200_000
MAX_TTL_SECONDS = 366 * 86400.0
STATUSES = ("active", "transient", "retired")
KINDS = ("mdns", "ssdp", "dhcp")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}", re.ASCII)
_MAC_LIKE = re.compile(r"[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}", re.ASCII)
_ENVELOPE = {"format", "version", "now", "ttl_seconds", "devices", "links", "observations"}
_TEXT_FIELDS = ("service", "ua", "opt55", "opt60", "hostname", "manufacturer", "model")
# Fields each kind may carry (mirrors what sources.py fills; manufacturer/model are the
# structured device-description fields a future reader would supply).
_KIND_FIELDS = {
    "mdns": frozenset({"service", "hostname", "manufacturer", "model"}),
    "ssdp": frozenset({"ua", "hostname", "manufacturer", "model"}),
    "dhcp": frozenset({"hostname", "opt55", "opt60"}),
}


def _address_like(value: str) -> bool:
    if _MAC_LIKE.fullmatch(value):
        return True
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class InventoryError(ValueError):
    """Invalid inventory; the message is fixed text, never an input value."""


@dataclass(frozen=True)
class Mac:
    mac: str
    oui_vendor: str | None


@dataclass(frozen=True)
class Device:
    id: str
    status: str
    macs: tuple[Mac, ...]


@dataclass(frozen=True)
class Obs:
    mac: str
    kind: str
    observed_at: float
    service: str | None = None
    ua: str | None = None
    opt55: str | None = None
    opt60: str | None = None
    hostname: str | None = None
    manufacturer: str | None = None
    model: str | None = None


@dataclass(frozen=True)
class Inventory:
    now: float
    ttl_seconds: float
    devices: tuple[Device, ...]
    active_links: MappingProxyType[str, str]
    observations: tuple[Obs, ...]


def _fail(message: str) -> InventoryError:
    return InventoryError(message)


def _reject_constant(_: str) -> Any:
    raise _fail("non-finite number")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _fail("duplicate key")
        out[key] = value
    return out


def load_inventory(data: bytes) -> Inventory:
    """Parse inventory bytes: size-capped, UTF-8, no NaN/Infinity, no duplicate keys."""
    if len(data) > MAX_INPUT_BYTES:
        raise _fail("input too large")
    try:
        text = data.decode("utf-8")
        doc = json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_unique_pairs)
    except InventoryError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _fail("malformed JSON") from None
    return parse_inventory(doc)


def _number(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _text(value: object, what: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value.encode("utf-8", "replace")) > MAX_TEXT_BYTES:
        raise _fail(f"invalid {what}")
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 or unicodedata.category(c) in ("Cf", "Cs")
           for c in value):  # fmt: skip
        raise _fail(f"invalid {what}")
    return value if value.strip() else None  # blank or whitespace-only is absent, not evidence


def _mapping(value: object, keys: set[str], required: set[str], what: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= value.keys() <= keys:
        raise _fail(f"invalid {what}")
    return value


def _list(value: object, cap: int, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise _fail(f"invalid {what}")
    if len(value) > cap:
        raise _fail(f"too many {what}")
    return value


def _mac(value: object) -> str:
    mac = normalize_mac(value) if isinstance(value, str) else None
    if mac is None:
        raise _fail("invalid mac")
    return mac


def _device(value: object) -> Device:
    item = _mapping(value, {"id", "status", "macs"}, {"id", "status", "macs"}, "device")
    if not isinstance(item["id"], str) or not _ID.fullmatch(item["id"]):
        raise _fail("invalid device id")
    if _address_like(item["id"]):
        raise _fail("invalid device id")
    if item["status"] not in STATUSES:
        raise _fail("invalid device status")
    macs = _list(item["macs"], MAX_MACS_PER_DEVICE, "macs")
    if not macs:
        raise _fail("invalid macs")
    parsed = []
    for entry in macs:
        mac = _mapping(entry, {"mac", "oui_vendor"}, {"mac", "oui_vendor"}, "mac entry")
        parsed.append(Mac(_mac(mac["mac"]), _text(mac["oui_vendor"], "oui vendor")))
    return Device(item["id"], item["status"], tuple(sorted(parsed, key=lambda m: m.mac)))


def _observation(value: object, now: float) -> Obs:
    item = _mapping(value, {"mac", "kind", "observed_at", *_TEXT_FIELDS},
                    {"mac", "kind", "observed_at"}, "observation")  # fmt: skip
    if item["kind"] not in KINDS:
        raise _fail("invalid observation kind")
    stamp = item["observed_at"]
    if not _number(stamp) or not 0 <= stamp <= now:
        raise _fail("invalid observation time")
    texts = {field: _text(item.get(field), field) for field in _TEXT_FIELDS}
    if any(v is not None and f not in _KIND_FIELDS[item["kind"]] for f, v in texts.items()):
        raise _fail("invalid observation fields")
    return Obs(_mac(item["mac"]), item["kind"], float(stamp), **texts)


def _links(value: object, ids: set[str]) -> dict[str, str]:
    active: dict[str, str] = {}
    for entry in _list(value, MAX_LINKS, "links"):
        link = _mapping(entry, {"from", "into", "revoked"}, {"from", "into", "revoked"}, "link")
        src, dst, revoked = link["from"], link["into"], link["revoked"]
        if not isinstance(src, str) or not isinstance(dst, str):
            raise _fail("invalid link")
        if src not in ids or dst not in ids or src == dst or not isinstance(revoked, bool):
            raise _fail("invalid link")
        if revoked:
            continue
        if src in active:
            raise _fail("duplicate active link")
        active[src] = dst
    for start in active:
        seen, current = {start}, start
        for _ in range(MAX_LINK_DEPTH + 1):
            current = active.get(current)
            if current is None:
                break
            if current in seen:
                raise _fail("link cycle")
            seen.add(current)
        else:
            raise _fail("link chain too deep")
    return active


def parse_inventory(doc: object) -> Inventory:
    """Validate a decoded document into immutable inventory data, or raise InventoryError."""
    env = _mapping(doc, _ENVELOPE, _ENVELOPE - {"ttl_seconds"}, "document")
    if env["format"] != FORMAT or env["version"] != VERSION or type(env["version"]) is not int:
        raise _fail("unsupported format")
    now = env["now"]
    ttl = env.get("ttl_seconds", DEFAULT_TTL_SECONDS)
    if not _number(now) or now < 0:
        raise _fail("invalid now")
    if not _number(ttl) or not 0 < ttl <= MAX_TTL_SECONDS:
        raise _fail("invalid ttl_seconds")
    devices = tuple(_device(d) for d in _list(env["devices"], MAX_DEVICES, "devices"))
    ids = {d.id for d in devices}
    if len(ids) != len(devices):
        raise _fail("duplicate device id")
    macs = [m.mac for d in devices for m in d.macs]
    if len(set(macs)) != len(macs):
        raise _fail("mac on more than one device")
    observations = tuple(
        _observation(o, now) for o in _list(env["observations"], MAX_OBSERVATIONS, "observations")
    )
    links = MappingProxyType(_links(env["links"], ids))
    return Inventory(float(now), float(ttl), devices, links, observations)
