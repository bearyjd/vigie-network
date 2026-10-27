"""Pure dataset parsers: KEV JSON and URLhaus CSV, strict, bounded, host-only for URLhaus."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from vigie_api import dataset_parse
from vigie_api.dataset_parse import Entry, parse_kev, parse_urlhaus

FIX = Path(__file__).parent.parent / "fixtures" / "datasets"


def urlhaus_row(url: str, threat: str = "malware_download") -> bytes:
    cols = ["1", "2024-01-01 00:00:01", url, "online", "2024-01-02", threat, "", "l", "r"]
    return (",".join(f'"{c}"' for c in cols) + "\n").encode()


def test_entry_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        Entry("k", {}).key = "x"  # type: ignore[misc]


def test_kev_keeps_only_the_four_fields():
    entries = parse_kev((FIX / "kev_small.json").read_bytes())
    assert [e.key for e in entries] == ["CVE-2021-0001", "CVE-2022-12345", "CVE-2023-0003"]
    assert entries[0].payload == {
        "cveID": "CVE-2021-0001", "vendorProject": "Example Vendor",
        "product": "Widget", "dateAdded": "2021-11-03",
    }  # fmt: skip
    assert "SECRET-DESC-CANARY" not in json.dumps([e.payload for e in entries])


def test_kev_malformed_entry_fails_the_whole_parse():
    with pytest.raises(ValueError, match="cveID"):
        parse_kev((FIX / "kev_malformed.json").read_bytes())


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"\xff\xfe\x00",
        b"[]",
        b'{"vulnerabilities": "x"}',
        b'{"vulnerabilities": [1]}',
        b'{"vulnerabilities": [{"cveID":"CVE-2021-0001","vendorProject":"A","product":"B"}]}',
        b'{"vulnerabilities": [{"cveID":"CVE-2021-0001","vendorProject":"A\\u0000","product":"B",'
        b'"dateAdded":"2021-01-01"}]}',
        b'{"vulnerabilities": [{"cveID":"CVE-2021-0001","vendorProject":"A","product":"B",'
        b'"dateAdded":"yesterday"}]}',
        b"[" * 100000,
    ],
)
def test_kev_rejects_malformed_input(raw):
    with pytest.raises(ValueError):
        parse_kev(raw)


def test_kev_duplicate_cve_is_malformed():
    row = '{"cveID":"CVE-2021-0001","vendorProject":"A","product":"B","dateAdded":"2021-01-01"}'
    with pytest.raises(ValueError, match="duplicate"):
        parse_kev(f'{{"vulnerabilities": [{row},{row}]}}'.encode())


def test_urlhaus_stores_only_host_and_threat():
    entries = parse_urlhaus((FIX / "urlhaus_small.csv").read_bytes())
    assert [e.key for e in entries] == ["evil.example.com", "creds.example.net", "192.0.2.7"]
    assert entries[0].payload == {"host": "evil.example.com", "threat": "malware_download"}
    blob = json.dumps([[e.key, e.payload] for e in entries])
    for leaked in ("SECRET-QUERY-CANARY", "SECRET-PW-CANARY", "mal.exe", "8080", "user"):
        assert leaked not in blob


def test_urlhaus_dedupes_by_host_first_wins():
    raw = urlhaus_row("http://A.test/x", "one") + urlhaus_row("http://a.test/y", "two")
    (entry,) = parse_urlhaus(raw)
    assert entry == Entry("a.test", {"host": "a.test", "threat": "one"})


def test_urlhaus_unicode_lookalike_host_is_rejected():
    with pytest.raises(ValueError, match="host"):
        parse_urlhaus((FIX / "urlhaus_malformed.csv").read_bytes())


@pytest.mark.parametrize(
    "raw",
    [
        b'"1","d","http://a.test/","online"\n',  # wrong column count
        urlhaus_row("not a url"),
        urlhaus_row("http:///nohost"),
        urlhaus_row("http://a.test\\@b.test/"),
        urlhaus_row("http://a.test/\x07"),
        urlhaus_row("http://a.test/", "bad\x00threat"),
        urlhaus_row("http://" + "a" * 600 + ".test/"),
        urlhaus_row("http://a_b.test/"),
        b"\xff\xfe",
        b"",
    ],
)
def test_urlhaus_rejects_malformed_input(raw):
    with pytest.raises(ValueError):
        parse_urlhaus(raw)


def test_input_size_cap(monkeypatch):
    monkeypatch.setattr(dataset_parse, "MAX_INPUT_BYTES", 10)
    with pytest.raises(ValueError, match="too large"):
        parse_urlhaus(urlhaus_row("http://a.test/"))
    with pytest.raises(ValueError, match="too large"):
        parse_kev(b'{"vulnerabilities": []}')


def test_entry_count_cap(monkeypatch):
    monkeypatch.setattr(dataset_parse, "MAX_ENTRIES", 2)
    raw = b"".join(urlhaus_row(f"http://h{i}.test/") for i in range(3))
    with pytest.raises(ValueError, match="too many"):
        parse_urlhaus(raw)
    with pytest.raises(ValueError, match="too many"):
        parse_kev((FIX / "kev_small.json").read_bytes())


def test_field_length_cap(monkeypatch):
    monkeypatch.setattr(dataset_parse, "MAX_FIELD_LEN", 20)
    parse_urlhaus(urlhaus_row("http://a.test/", "x" * 20))  # at the cap is fine
    with pytest.raises(ValueError, match="field"):
        parse_urlhaus(urlhaus_row("http://a.test/", "x" * 21))
    with pytest.raises(ValueError, match="field"):
        parse_urlhaus(urlhaus_row("http://a.test/" + "p" * 20))
    monkeypatch.setattr(dataset_parse, "MAX_FIELD_LEN", 5)
    with pytest.raises(ValueError, match="field"):
        parse_kev((FIX / "kev_small.json").read_bytes())
