"""Pure parsers for the offline known-issue datasets (CISA KEV JSON, URLhaus CSV).

No I/O, no network, no clock. Input is strict: anything malformed raises ValueError naming the
row, so a staged import is all-or-nothing and never a partially parsed file. URLhaus rows are
reduced to the lower-cased host and the threat label; the path, query, port and credentials of a
listed URL are dropped here and never reach the database.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 2_000_000
MAX_FIELD_LEN = 512

_CVE = re.compile(r"CVE-\d{4}-\d{4,19}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_HOST = re.compile(r"[a-z0-9][a-z0-9.:-]{0,252}")
_KEV_FIELDS = ("cveID", "vendorProject", "product", "dateAdded")
_URLHAUS_COLUMNS = 9
_URL_COL, _THREAT_COL = 2, 5


@dataclass(frozen=True)
class Entry:
    key: str
    payload: dict[str, str]


def _check_size(data: bytes) -> None:
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"input too large (max {MAX_INPUT_BYTES} bytes)")


def _field(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where}: field is not a string")
    if len(value) > MAX_FIELD_LEN:
        raise ValueError(f"{where}: field longer than {MAX_FIELD_LEN} characters")
    if not value.isprintable():
        raise ValueError(f"{where}: field has non-printable characters")
    return value


def _check_count(count: int) -> None:
    if count > MAX_ENTRIES:
        raise ValueError(f"too many entries (max {MAX_ENTRIES})")


def _kev_entry(item: Any, index: int) -> Entry:
    where = f"vulnerabilities[{index}]"
    if not isinstance(item, dict):
        raise ValueError(f"{where}: not an object")
    payload = {name: _field(item.get(name), f"{where}.{name}") for name in _KEV_FIELDS}
    if not _CVE.fullmatch(payload["cveID"]):
        raise ValueError(f"{where}: bad cveID")
    if not _DATE.fullmatch(payload["dateAdded"]):
        raise ValueError(f"{where}: bad dateAdded")
    return Entry(payload["cveID"], payload)


def parse_kev(data: bytes) -> list[Entry]:
    _check_size(data)
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError is a ValueError
        raise ValueError(f"KEV JSON is not valid: {exc.__class__.__name__}") from None
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ValueError("KEV JSON has no 'vulnerabilities' list")
    _check_count(len(items))
    entries = [_kev_entry(item, index) for index, item in enumerate(items)]
    keys = [entry.key for entry in entries]
    if len(set(keys)) != len(keys):
        raise ValueError("KEV JSON has a duplicate cveID")
    return entries


def _urlhaus_host(url: str, where: str) -> str:
    if "\\" in url:
        raise ValueError(f"{where}: bad host")
    try:
        host = urlsplit(url).hostname  # lower-cased; credentials, port, path and query dropped
    except ValueError:
        host = None
    if not host or not _HOST.fullmatch(host):
        raise ValueError(f"{where}: bad host")
    return host


def _urlhaus_entry(row: list[str], where: str) -> Entry:
    if len(row) != _URLHAUS_COLUMNS:
        raise ValueError(f"{where}: expected {_URLHAUS_COLUMNS} columns, got {len(row)}")
    url = _field(row[_URL_COL], where)
    threat = _field(row[_THREAT_COL], where)
    host = _urlhaus_host(url, where)
    return Entry(host, {"host": host, "threat": threat})


def parse_urlhaus(data: bytes) -> list[Entry]:
    _check_size(data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("URLhaus CSV is not valid UTF-8") from None
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    _check_count(len(lines))
    seen: dict[str, Entry] = {}
    try:
        for number, row in enumerate(csv.reader(lines), start=1):
            entry = _urlhaus_entry(row, f"row {number}")
            seen.setdefault(entry.key, entry)  # duplicate hosts: the first row wins
    except csv.Error as exc:
        raise ValueError(f"URLhaus CSV is not valid: {exc}") from None
    if not seen:
        raise ValueError("URLhaus CSV has no entries")
    return list(seen.values())
