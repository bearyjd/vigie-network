"""Pure parsers for the offline known-issue datasets (CISA KEV JSON, URLhaus CSV).

No I/O, no network, no clock. Structure is strict: a file that is not the expected shape, has a
wrong column count, an oversized field or a control character anywhere raises ValueError naming
the row, so a staged import is never a silently partial parse. Host problems in single URLhaus
rows (odd scheme, bad port, lookalike characters) skip just that row; skips are counted and too
many reject the file. Every cap is checked before the structure it protects is built. URLhaus
rows are reduced to the lower-cased host and the threat label; the path, query, port and
credentials of a listed URL are dropped here and never reach the database.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import urlsplit

KEV_MAX_INPUT = 16 * 1024 * 1024
KEV_MAX_ENTRIES = 100_000
URLHAUS_MAX_INPUT = 64 * 1024 * 1024
URLHAUS_MAX_ENTRIES = 250_000  # ~2.5 s of inserts inside one write transaction
MAX_FIELD_LEN = 512
SKIP_FLOOR = 100
SKIP_FRACTION = 0.01
_BRACE_SLACK = 16  # braces outside the entry objects: the catalog itself, a stray few

_CVE = re.compile(r"CVE-[0-9]{4}-(?:[1-9][0-9]{4,18}|[0-9]{4})", re.ASCII)
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)
_DNS = re.compile(r"(?:[a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}", re.ASCII)
_IPV4_LIKE = re.compile(r"[0-9.]+", re.ASCII)
_KEV_FIELDS = ("cveID", "vendorProject", "product", "dateAdded")
_URLHAUS_COLUMNS = 9
_URL_COL, _THREAT_COL = 2, 5
_SCHEMES = frozenset({"http", "https"})
_MAX_HOST_LEN = 253


@dataclass(frozen=True)
class Entry:
    key: str
    payload: dict[str, str]


def input_limit(source: str) -> int:
    return {"kev": KEV_MAX_INPUT, "urlhaus": URLHAUS_MAX_INPUT}[source]


def _check_size(data: bytes, limit: int) -> None:
    if len(data) > limit:
        raise ValueError(f"input too large (max {limit} bytes)")


def _field(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where}: field is not a string")
    if len(value) > MAX_FIELD_LEN:
        raise ValueError(f"{where}: field longer than {MAX_FIELD_LEN} characters")
    if not value.isprintable():
        raise ValueError(f"{where}: field has non-printable characters")
    return value


def _too_many(limit: int) -> ValueError:
    return ValueError(f"too many entries (max {limit})")


def _kev_entry(item: Any, index: int) -> Entry:
    where = f"vulnerabilities[{index}]"
    if not isinstance(item, dict):
        raise ValueError(f"{where}: not an object")
    payload = {name: _field(item.get(name), f"{where}.{name}") for name in _KEV_FIELDS}
    if not _CVE.fullmatch(payload["cveID"]):
        raise ValueError(f"{where}: bad cveID")
    try:
        if not _DATE.fullmatch(payload["dateAdded"]):
            raise ValueError
        date.fromisoformat(payload["dateAdded"])
    except ValueError:
        raise ValueError(f"{where}: bad dateAdded") from None
    return Entry(payload["cveID"], payload)


def parse_kev(data: bytes) -> list[Entry]:
    _check_size(data, KEV_MAX_INPUT)
    if data.count(b"{") > KEV_MAX_ENTRIES + _BRACE_SLACK:  # before json builds anything
        raise _too_many(KEV_MAX_ENTRIES)
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError is a ValueError
        raise ValueError(f"KEV JSON is not valid: {exc.__class__.__name__}") from None
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ValueError("KEV JSON has no 'vulnerabilities' list")
    if len(items) > KEV_MAX_ENTRIES:
        raise _too_many(KEV_MAX_ENTRIES)
    entries = [_kev_entry(item, index) for index, item in enumerate(items)]
    keys = [entry.key for entry in entries]
    if len(set(keys)) != len(keys):
        raise ValueError("KEV JSON has a duplicate cveID")
    return entries


def _ip_key(host: str, bracketed: bool) -> str | None:
    try:
        if bracketed:
            return None if "%" in host else str(ipaddress.IPv6Address(host))
        return str(ipaddress.IPv4Address(host)) if _IPV4_LIKE.fullmatch(host) else None
    except ValueError:
        return None


def _urlhaus_host(url: str) -> str | None:
    """The normalised host key of a listed URL, or None when the row is unusable."""
    if "\\" in url:
        return None
    try:
        split = urlsplit(url)
        split.port  # noqa: B018 - reading it validates the port (http://secret:token/)
    except ValueError:
        return None
    # ASCII before lower(): U+212A (Kelvin) would otherwise fold into a plain k
    if split.scheme not in _SCHEMES or not split.netloc.isascii() or not split.hostname:
        return None
    bracketed = "[" in split.netloc
    host = split.hostname.lower()
    if bracketed or _IPV4_LIKE.fullmatch(host):
        return _ip_key(host, bracketed)
    host = host.removesuffix(".")  # evil.com. and evil.com are one host
    ok = len(host) <= _MAX_HOST_LEN and _DNS.fullmatch(host) and not host.startswith("-")
    return host if ok else None


def _urlhaus_row(row: list[str], where: str) -> Entry | None:
    if len(row) != _URLHAUS_COLUMNS:
        raise ValueError(f"{where}: expected {_URLHAUS_COLUMNS} columns, got {len(row)}")
    for column in row:
        _field(column, where)
    host = _urlhaus_host(row[_URL_COL])
    return None if host is None else Entry(host, {"host": host, "threat": row[_THREAT_COL]})


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("URLhaus CSV is not valid UTF-8") from None


def parse_urlhaus(data: bytes) -> tuple[list[Entry], int]:
    """Entries (first row per host wins) and the number of rows skipped for an unusable host."""
    _check_size(data, URLHAUS_MAX_INPUT)
    reader = csv.reader(io.StringIO(_decode(data), newline=""))
    seen: dict[str, Entry] = {}
    rows = skipped = 0
    try:
        for row in reader:
            if not row or row[0].startswith("#"):  # blank and comment rows, after CSV parsing
                continue
            rows += 1
            if rows > URLHAUS_MAX_ENTRIES:  # stop at cap+1, never read the rest
                raise _too_many(URLHAUS_MAX_ENTRIES)
            entry = _urlhaus_row(row, f"line {reader.line_num}")
            if entry is None:
                skipped += 1
            else:
                seen.setdefault(entry.key, entry)
    except csv.Error as exc:
        raise ValueError(f"line {reader.line_num}: URLhaus CSV is not valid: {exc}") from None
    if skipped > max(SKIP_FLOOR, rows * SKIP_FRACTION):
        raise ValueError(f"too many rows skipped for an unusable host ({skipped} of {rows})")
    if not seen:
        raise ValueError("URLhaus CSV has no usable entries")
    return list(seen.values()), skipped
