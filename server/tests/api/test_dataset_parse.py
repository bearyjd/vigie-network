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


def keys(entries) -> list[str]:
    return [e.key for e in entries]


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
        b'{"vulnerabilities": [{"cveID":"CVE-2021-0001","vendorProject":"A","product":"B",'
        b'"dateAdded":"2021-13-45"}]}',
        b'{"vulnerabilities": [{"cveID":"CVE-2021-0001","vendorProject":"A","product":"B",'
        b'"dateAdded":"\xd9\xa2\xd9\xa0\xd9\xa2\xd9\xa1-01-01"}]}',
    ],
)
def test_kev_rejects_malformed_input(raw):
    with pytest.raises(ValueError):
        parse_kev(raw)


@pytest.mark.parametrize(
    "cve", ["CVE-2024-00001", "CVE-2024-123", "CVE-\u0662\u0660\u0662\u0664-1234", "cve-2024-1234"]
)
def test_kev_cve_must_be_ascii_without_leading_zero(cve):
    row = {"cveID": cve, "vendorProject": "A", "product": "B", "dateAdded": "2021-01-01"}
    with pytest.raises(ValueError, match="cveID"):
        parse_kev(json.dumps({"vulnerabilities": [row]}).encode())


@pytest.mark.parametrize("cve", ["CVE-2024-0001", "CVE-2024-12345", "CVE-1999-1000000"])
def test_kev_accepts_plain_cve_ids(cve):
    row = {"cveID": cve, "vendorProject": "A", "product": "B", "dateAdded": "2021-01-01"}
    assert parse_kev(json.dumps({"vulnerabilities": [row]}).encode())[0].key == cve


def test_kev_duplicate_cve_is_malformed():
    row = '{"cveID":"CVE-2021-0001","vendorProject":"A","product":"B","dateAdded":"2021-01-01"}'
    with pytest.raises(ValueError, match="duplicate"):
        parse_kev(f'{{"vulnerabilities": [{row},{row}]}}'.encode())


def test_urlhaus_stores_only_host_and_threat():
    entries, skipped = parse_urlhaus((FIX / "urlhaus_small.csv").read_bytes())
    assert keys(entries) == ["evil.example.com", "creds.example.net", "192.0.2.7"]
    assert skipped == 0
    assert entries[0].payload == {"host": "evil.example.com", "threat": "malware_download"}
    blob = json.dumps([[e.key, e.payload] for e in entries])
    for leaked in ("SECRET-QUERY-CANARY", "SECRET-PW-CANARY", "mal.exe", "8080", "user"):
        assert leaked not in blob


def test_urlhaus_dedupes_by_host_first_wins():
    raw = urlhaus_row("http://A.test/x", "one") + urlhaus_row("http://a.test/y", "two")
    (entry,), skipped = parse_urlhaus(raw)
    assert entry == Entry("a.test", {"host": "a.test", "threat": "one"}) and skipped == 0


def test_host_edge_cases_keep_normalised_hosts_and_skip_the_rest():
    entries, skipped = parse_urlhaus((FIX / "urlhaus_hosts.csv").read_bytes())
    assert keys(entries) == [
        "evil.com", "2001:db8::1", "userinfo.example.org", "192.0.2.7",
        "good1.example.org", "good2.example.org", "good3.example.org",
    ]  # fmt: skip
    assert skipped == 7
    assert "pw" not in json.dumps([e.payload for e in entries])


def test_unicode_lookalike_host_is_skipped_not_stored():
    entries, skipped = parse_urlhaus((FIX / "urlhaus_lookalike.csv").read_bytes())
    assert keys(entries) == ["good.example.com"] and skipped == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://\u212aelvin.test/",  # Kelvin sign lower-cases to ASCII k
        "http://caf\u00e9.test/",
        "ftp://a.test/",
        "file:///etc/passwd",
        "http://secret:token/",
        "http://a.test:70000/",
        "http://[fe80::1%25eth0]/",
        "http://[v1.fe]/",
        "http://[::1/",
        "http://a.test\\@b.test/",
        "http://a_b.test/",
        "http://-a.test/",
        "http://a..test/",
        "http://999.1.1.1/",
        "http://0x7f.0.0.1/",  # ambiguous browser forms are skipped on purpose
        "http://127.1/",
        "http://010.0.0.1/",
        "http://2130706433/",
        "http://1.2.3.4.5/",
        "http://a.test/\x07",  # a bad URL column skips the row, it does not reject the file
        "http://a.test/\u00a0x",
        "http://a.test/\n",
        "http://" + "a" * 600 + ".test/",
        "not a url",
        "http:///nohost",
    ],
)
def test_unusable_hosts_are_skipped_and_counted(url):
    ok = urlhaus_row("http://ok.test/")
    entries, skipped = parse_urlhaus(ok + urlhaus_row(url))
    assert keys(entries) == ["ok.test"] and skipped == 1


def test_only_unusable_rows_means_no_import():
    with pytest.raises(ValueError, match="no usable"):
        parse_urlhaus(urlhaus_row("ftp://a.test/"))


def test_trailing_dot_and_ip_normalisation():
    urls = [
        "http://Evil.COM./a", "http://[2001:DB8::0:1]/", "http://1.2.3.4./",
        "http://[::ffff:1.2.3.4]/", "http://[::FFFF:102:304]:80/", "http://[::ffff:5.6.7.8]/",
    ]  # fmt: skip
    entries, _ = parse_urlhaus(b"".join(urlhaus_row(u) for u in urls))
    assert keys(entries) == ["evil.com", "2001:db8::1", "1.2.3.4", "5.6.7.8"]


def test_skip_policy_rejects_only_a_majority_of_skipped_rows():
    good, bad = urlhaus_row("http://ok.test/"), urlhaus_row("ftp://x.test/")
    assert parse_urlhaus(good + bad)[1] == 1  # exactly half is still staged
    assert (
        parse_urlhaus(
            good * 1
            + bad * 1
            + b"".join(urlhaus_row(f"http://h{i}.test/") for i in range(200))
            + bad * 150
        )[1]
        == 151
    )
    with pytest.raises(ValueError, match="skipped"):
        parse_urlhaus(good + bad * 2)


def test_a_few_hundred_crafted_rows_cannot_block_an_update():
    good = b"".join(urlhaus_row(f"http://h{i}.test/") for i in range(1000))
    assert parse_urlhaus(good + urlhaus_row("ftp://x.test/") * 300)[1] == 300


@pytest.mark.parametrize(
    "raw",
    [
        b'"1","d","http://a.test/","online"\n',  # wrong column count
        urlhaus_row("http://a.test/", "bad\x00threat"),
        urlhaus_row("http://a.test/", "x" * 513),
        b'"1","d","http://a.test/","o","l","t","\x07","l","r"\n',  # control char, any column
        b'"1","d","http://a.test/","o","l","t","","l","r\x00"\n',
        b"\xff\xfe",
        b"",
        b"# only comments\n\n",
    ],
)
def test_urlhaus_structural_problems_reject_the_whole_file(raw):
    with pytest.raises(ValueError):
        parse_urlhaus(raw)


def test_embedded_newline_is_not_read_as_a_shorter_host():
    raw = b'"1","d","http://a.\ntest/x","o","l","t","","l","r"\n'
    entries, skipped = parse_urlhaus(urlhaus_row("http://ok.test/") + raw)
    assert keys(entries) == ["ok.test"] and skipped == 1  # skipped, not stored as a.test


def test_comments_and_blank_rows_are_skipped_after_csv_parsing():
    raw = b"# c\n\n" + urlhaus_row("http://ok.test/") + b"\n# more\n"
    assert keys(parse_urlhaus(raw)[0]) == ["ok.test"]


def test_errors_name_the_csv_line():
    raw = b"# c\n" + urlhaus_row("http://ok.test/") + b'"1","d"\n'
    with pytest.raises(ValueError, match="line 3"):
        parse_urlhaus(raw)


class CountingReader:
    """csv.reader stand-in that records how many rows the parser pulled."""

    pulled = 0

    def __init__(self, real):
        self._real = real

    def __iter__(self):
        return self

    def __next__(self):
        row = next(self._real)
        type(self).pulled += 1
        return row

    @property
    def line_num(self):
        return self._real.line_num


def test_urlhaus_entry_cap_stops_iterating_at_cap_plus_one(monkeypatch):
    monkeypatch.setattr(dataset_parse, "URLHAUS_MAX_ENTRIES", 3)
    real = dataset_parse.csv.reader
    CountingReader.pulled = 0
    monkeypatch.setattr(dataset_parse.csv, "reader", lambda f, **kw: CountingReader(real(f, **kw)))
    raw = b"".join(urlhaus_row(f"http://h{i}.test/") for i in range(500))
    with pytest.raises(ValueError, match="too many"):
        parse_urlhaus(raw)
    assert CountingReader.pulled == 4


def test_urlhaus_entry_cap_boundary(monkeypatch):
    monkeypatch.setattr(dataset_parse, "URLHAUS_MAX_ENTRIES", 3)
    rows = [urlhaus_row(f"http://h{i}.test/") for i in range(4)]
    assert len(parse_urlhaus(b"".join(rows[:3]))[0]) == 3
    with pytest.raises(ValueError, match="too many"):
        parse_urlhaus(b"".join(rows))


def test_urlhaus_input_cap_boundary(monkeypatch):
    raw = urlhaus_row("http://a.test/")
    monkeypatch.setattr(dataset_parse, "URLHAUS_MAX_INPUT", len(raw))
    parse_urlhaus(raw)
    with pytest.raises(ValueError, match="too large"):
        parse_urlhaus(raw + b"\n")


def test_kev_limits_are_smaller_than_urlhaus_limits():
    assert dataset_parse.KEV_MAX_INPUT == 8 * 1024 * 1024
    assert dataset_parse.KEV_MAX_ENTRIES == 20_000
    assert dataset_parse.URLHAUS_MAX_INPUT == 64 * 1024 * 1024
    assert dataset_parse.URLHAUS_MAX_ENTRIES == 250_000


def test_kev_input_cap_boundary(monkeypatch):
    raw = (FIX / "kev_small.json").read_bytes()
    monkeypatch.setattr(dataset_parse, "KEV_MAX_INPUT", len(raw))
    assert len(parse_kev(raw)) == 3
    with pytest.raises(ValueError, match="too large"):
        parse_kev(raw + b" ")


def test_kev_entry_cap_boundary(monkeypatch):
    raw = (FIX / "kev_small.json").read_bytes()
    monkeypatch.setattr(dataset_parse, "KEV_MAX_ENTRIES", 3)
    assert len(parse_kev(raw)) == 3
    monkeypatch.setattr(dataset_parse, "KEV_MAX_ENTRIES", 2)
    with pytest.raises(ValueError, match="too many"):
        parse_kev(raw)


def test_kev_prescan_counts_arrays_too(monkeypatch):
    monkeypatch.setattr(dataset_parse, "KEV_MAX_ENTRIES", 2)

    def boom(*_a, **_k):
        raise AssertionError("json.loads must not run")

    monkeypatch.setattr(dataset_parse.json, "loads", boom)
    raw = b'{"vulnerabilities":[' + b"[]," * 40 + b"[]]}"
    with pytest.raises(ValueError, match="too many"):
        parse_kev(raw)


@pytest.mark.parametrize("item", [b"0", b"[]", b"{}", b'"x"', b"null"])
def test_kev_prescan_bounds_every_item_shape(monkeypatch, item):
    monkeypatch.setattr(dataset_parse, "KEV_MAX_ENTRIES", 2)

    def boom(*_a, **_k):
        raise AssertionError("json.loads must not run")

    monkeypatch.setattr(dataset_parse.json, "loads", boom)
    raw = b'{"vulnerabilities":[' + (item + b",") * 400 + item + b"]}"
    with pytest.raises(ValueError, match="too many"):
        parse_kev(raw)


def test_a_realistic_kev_catalog_passes_the_prescan(monkeypatch):
    entry = {"cveID": "CVE-2021-%04d", "vendorProject": "A", "product": "B",
             "dateAdded": "2021-01-01", "cwes": ["CWE-1", "CWE-2"]}  # fmt: skip
    items = [{**entry, "cveID": entry["cveID"] % n} for n in range(1, 51)]
    monkeypatch.setattr(dataset_parse, "KEV_MAX_ENTRIES", 50)
    assert len(parse_kev(json.dumps({"vulnerabilities": items}).encode())) == 50


def test_kev_brace_prescan_rejects_before_json_is_built(monkeypatch):
    monkeypatch.setattr(dataset_parse, "KEV_MAX_ENTRIES", 2)

    def boom(*_a, **_k):
        raise AssertionError("json.loads must not run")

    monkeypatch.setattr(dataset_parse.json, "loads", boom)
    raw = b'{"vulnerabilities":[' + b"{}," * 40 + b"{}]}"
    with pytest.raises(ValueError, match="too many"):
        parse_kev(raw)


def test_field_length_cap(monkeypatch):
    monkeypatch.setattr(dataset_parse, "MAX_FIELD_LEN", 20)
    parse_urlhaus(urlhaus_row("http://a.test/", "x" * 20))  # at the cap is fine
    with pytest.raises(ValueError, match="field"):
        parse_urlhaus(urlhaus_row("http://a.test/", "x" * 21))
    entries, skipped = parse_urlhaus(
        urlhaus_row("http://ok.test/") + urlhaus_row("http://a.te/" + "p" * 20)
    )
    assert keys(entries) == ["ok.test"] and skipped == 1  # the URL column skips, not rejects
    monkeypatch.setattr(dataset_parse, "MAX_FIELD_LEN", 5)
    with pytest.raises(ValueError, match="field"):
        parse_kev((FIX / "kev_small.json").read_bytes())


def test_a_giant_physical_line_is_rejected_before_it_becomes_a_row(monkeypatch):
    real = dataset_parse.csv.reader
    CountingReader.pulled = 0
    monkeypatch.setattr(dataset_parse.csv, "reader", lambda f, **kw: CountingReader(real(f, **kw)))
    raw = urlhaus_row("http://ok.test/") + b"," * 1_000_000 + b"\n"
    with pytest.raises(ValueError, match="line 2: line longer"):
        parse_urlhaus(raw)
    assert CountingReader.pulled == 1  # the comma line never reached the tokenizer


def test_line_cap_boundary_and_legal_long_urls(monkeypatch):
    long_url = "http://ok.test/" + "p" * 400
    assert keys(parse_urlhaus(urlhaus_row(long_url))[0]) == ["ok.test"]
    row = urlhaus_row("http://ok.test/")
    monkeypatch.setattr(dataset_parse, "MAX_LINE_LEN", len(row))
    parse_urlhaus(row)
    with pytest.raises(ValueError, match="line longer"):
        parse_urlhaus(row.replace(b"\n", b" \n"))


def test_quoted_multiline_fields_still_parse_as_one_row():
    raw = b'"1","d","http://ok.test/","o","l","t","line one\nline two","l","r"\n'
    with pytest.raises(ValueError, match="non-printable"):  # structural, but read as ONE row
        parse_urlhaus(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'"1","d","http://a.test/","o","l","t","","l","unterminated\n',
        b'"1","d","http://a.test/","o","l","t","","l","r"x\n',
    ],
)
def test_malformed_quoting_is_rejected_strictly(raw):
    with pytest.raises(ValueError, match="line"):
        parse_urlhaus(raw)
