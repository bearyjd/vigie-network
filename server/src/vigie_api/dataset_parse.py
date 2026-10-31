"""Pure parsers for the offline known-issue datasets (CISA KEV JSON, URLhaus CSV).

No I/O, no network, no clock. Structure is strict: a file that is not the expected shape, has a
wrong column count, an oversized or control-character field (any column but the URL) raises
ValueError naming the line. Problems in a single URLhaus row's URL (odd scheme, bad port,
lookalike characters, oversized) skip just that row; skips are counted, and a majority of
skipped rows rejects the file. Caps are enforced before the structure they protect is built:
KEV from raw byte counts, URLhaus by iterating lazily and bounding each physical line. URLhaus
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

KEV_MAX_INPUT = 8 * 1024 * 1024  # the real catalog is ~1.3 MB
KEV_MAX_ENTRIES = 20_000  # ... and ~1.5k entries
URLHAUS_MAX_INPUT = 64 * 1024 * 1024
URLHAUS_MAX_ENTRIES = 250_000  # ~2.5 s of inserts inside one write transaction
MAX_FIELD_LEN = 512
MAX_LINE_LEN = 16 * 1024  # one physical CSV line; real URLhaus rows are a few hundred bytes
SKIP_MAX_FRACTION = 0.5  # more skipped than this means the file is not the expected format
_SCAN_SLACK = 16  # structure outside the entries: the catalog itself, a stray few
_BRACKETS_PER_ENTRY = 3  # real KEV: one object and one cwes array per entry
_COMMAS_PER_ENTRY = 64  # real KEV: ~15

_CVE = re.compile(r"CVE-[0-9]{4}-(?:[1-9][0-9]{4,18}|[0-9]{4})", re.ASCII)
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
# a host whose last label is numeric (or 0x..) is an address; only strict dotted quads are kept
_IPV4_LIKE = re.compile(r"(?:.*\.)?(?:[0-9]+|0x[0-9a-f]*)", re.ASCII)
_KEV_FIELDS = ("cveID", "vendorProject", "product", "dateAdded")
_URLHAUS_COLUMNS = 9
_URL_COL, _THREAT_COL = 2, 5
_SCHEMES = frozenset({"http", "https"})
_MAX_HOST_LEN = 253
_BOM = b"\xef\xbb\xbf"
_EMBEDS_IPV4 = (ipaddress.IPv6Network("::/96"), ipaddress.IPv6Network("64:ff9b::/96"))


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


def _prescan_kev(data: bytes) -> None:
    """Bound the number of items from raw byte counts, so no object is built to count them."""
    structure = data.count(b"{") + data.count(b"[")
    if structure > _BRACKETS_PER_ENTRY * KEV_MAX_ENTRIES + _SCAN_SLACK:
        raise _too_many(KEV_MAX_ENTRIES)
    if data.count(b",") > _COMMAS_PER_ENTRY * KEV_MAX_ENTRIES + _SCAN_SLACK:
        raise _too_many(KEV_MAX_ENTRIES)


def parse_kev(data: bytes) -> list[Entry]:
    _check_size(data, KEV_MAX_INPUT)
    data = data.removeprefix(_BOM)
    _prescan_kev(data)  # before json builds anything
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError is a ValueError
        raise ValueError(f"KEV JSON is not valid: {exc.__class__.__name__}") from None
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ValueError("KEV JSON has no 'vulnerabilities' list")
    if not items:
        raise ValueError("KEV JSON has no vulnerabilities")
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
            if "%" in host:
                return None
            address = ipaddress.IPv6Address(host)
            if address.ipv4_mapped:
                return str(address.ipv4_mapped)
            # IPv4-compatible and NAT64 forms embed an address ambiguously: skipped, not guessed
            if int(address) > 1 and any(address in net for net in _EMBEDS_IPV4):
                return None
            return str(address)
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
    bracketed = "[" in split.netloc.rpartition("@")[2]  # the host part, not the userinfo
    host = split.hostname.lower().removesuffix(".")  # evil.com. and evil.com are one host
    if bracketed or _IPV4_LIKE.fullmatch(host):
        return _ip_key(host, bracketed)
    labels = host.split(".")
    ok = len(host) <= _MAX_HOST_LEN and all(_LABEL.fullmatch(label) for label in labels)
    return host if ok else None


def _urlhaus_row(row: list[str], where: str) -> Entry | None:
    if len(row) != _URLHAUS_COLUMNS:
        raise ValueError(f"{where}: expected {_URLHAUS_COLUMNS} columns, got {len(row)}")
    for index, column in enumerate(row):
        if index != _URL_COL:
            _field(column, where)
    url = row[_URL_COL]  # a bad URL column is a bad host: that row is skipped, not the file
    host = None
    if len(url) <= MAX_FIELD_LEN and url.isprintable():
        host = _urlhaus_host(url)
    return None if host is None else Entry(host, {"host": host, "threat": row[_THREAT_COL]})


class _Lines:
    """Physical lines of the CSV, decoded as a stream and capped before csv.reader sees them.

    It only feeds lines and remembers, for the row csv.reader is currently building, the raw
    first physical line and how many were consumed; quoting is left entirely to csv.reader.
    `number` is the physical line last read.
    """

    def __init__(self, data: bytes) -> None:
        raw = io.BytesIO(data.removeprefix(_BOM))
        self._text = io.TextIOWrapper(raw, encoding="utf-8", errors="strict", newline="")
        self.number = 0
        self.first = ""
        self.count = 0

    def begin_row(self) -> None:
        self.first, self.count = "", 0

    def __iter__(self):
        while line := self._text.readline(MAX_LINE_LEN + 1):  # never reads past the cap
            self.number += 1
            if len(line) > MAX_LINE_LEN:
                raise ValueError(f"line {self.number}: line longer than {MAX_LINE_LEN} characters")
            if self.count == 0:
                self.first = line
            self.count += 1
            yield line


def _data_rows(reader, lines: _Lines):
    """Rows of the CSV without comments.

    A comment is a row of exactly one physical line that starts with `#` in column 0. One that
    starts that way but runs on over several lines would silently swallow rows: rejected.
    """
    while True:
        lines.begin_row()
        try:
            row = next(reader)
        except StopIteration:
            return
        if lines.first.startswith("#"):
            if lines.count > 1:
                raise ValueError(f"line {lines.number}: comment-like line opens a multi-line field")
            continue
        yield row


def parse_urlhaus(data: bytes) -> tuple[list[Entry], int]:
    """Entries (first row per host wins) and the number of rows skipped for an unusable host."""
    _check_size(data, URLHAUS_MAX_INPUT)
    lines = _Lines(data)
    reader = csv.reader(lines, strict=True)
    seen: dict[str, Entry] = {}
    rows = skipped = 0
    try:
        for row in _data_rows(reader, lines):
            if not row:  # blank line
                continue
            rows += 1
            if rows > URLHAUS_MAX_ENTRIES:  # stop at cap+1, never read the rest
                raise _too_many(URLHAUS_MAX_ENTRIES)
            entry = _urlhaus_row(row, f"line {lines.number}")
            if entry is None:
                skipped += 1
            else:
                seen.setdefault(entry.key, entry)
    except csv.Error as exc:
        raise ValueError(f"line {lines.number}: URLhaus CSV is not valid: {exc}") from None
    except UnicodeDecodeError:
        raise ValueError("URLhaus CSV is not valid UTF-8") from None
    if not seen:
        raise ValueError("URLhaus CSV has no usable entries")
    if skipped > rows * SKIP_MAX_FRACTION:
        raise ValueError(f"too many rows skipped for an unusable host ({skipped} of {rows})")
    return list(seen.values()), skipped


def _plain(payload: Any, fields: tuple[str, ...]) -> bool:
    """Exactly `fields`, every value a string `_field` would accept."""
    if not (isinstance(payload, dict) and set(payload) == set(fields)):
        return False
    try:
        return all(_field(value, name) is not None for name, value in payload.items())
    except ValueError:
        return False


def _canonical_host_key(key: str) -> bool:
    """True when the URLhaus parser itself would derive exactly `key` as a host key."""
    url = f"http://[{key}]/" if ":" in key else f"http://{key}/"
    return _urlhaus_host(url) == key


def is_valid_staged(source: str, key: str, payload_text: str) -> bool:
    """True when a staged row has exactly the shape the parser of `source` would have produced."""
    try:
        payload = json.loads(payload_text)
    except ValueError:
        return False
    if source == "kev":
        if not (_plain(payload, _KEV_FIELDS) and payload["cveID"] == key):
            return False
        try:
            return bool(
                _CVE.fullmatch(key)
                and _DATE.fullmatch(payload["dateAdded"])
                and date.fromisoformat(payload["dateAdded"])
            )
        except ValueError:
            return False
    if source == "urlhaus":
        return (
            _plain(payload, ("host", "threat"))
            and payload["host"] == key
            and _canonical_host_key(key)
        )
    return False
