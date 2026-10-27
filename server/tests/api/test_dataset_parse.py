"""Pure dataset parsers: KEV JSON and URLhaus CSV, strict, bounded, host-only for URLhaus."""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import random
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
    ("raw", "message"),
    [
        (b'"1","d","http://a.test/","online"\n', "expected 9 columns"),
        (urlhaus_row("http://a.test/", "bad\x00threat"), "non-printable"),
        (urlhaus_row("http://a.test/", "x" * 513), "longer than"),
        (b'"1","d","http://a.test/","o","l","t","\x07","l","r"\n', "non-printable"),
        (b'"1","d","http://a.test/","o","l","t","","l","r\x00"\n', "non-printable"),
        (b"\xff\xfe", "UTF-8"),
        (b"", "no usable"),
        (b"# only comments\n\n", "no usable"),
        (b"\n\n  \n", "expected 9 columns"),
    ],
)
def test_urlhaus_structural_problems_reject_the_whole_file(raw, message):
    with pytest.raises(ValueError, match=message):
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


@pytest.mark.parametrize(
    "url",
    [
        "http://a.-b.test/",
        "http://a-.test/",
        "http://a.test-/",
        "http://a-.com/",
        "http://-a.test/",
        "http://" + "a" * 64 + ".test/",
        "http://" + ".".join(["a" * 50] * 6) + "/",  # 305 characters in total
        "http://evil%2ecom/",
        "http://[::1.2.3.4]/",  # IPv4-compatible
        "http://[64:ff9b::1.2.3.4]/",  # NAT64
        "http://[64:ff9b::102:304]/",
    ],
)
def test_odd_dns_labels_and_embedded_ipv4_forms_are_skipped(url):
    entries, skipped = parse_urlhaus(urlhaus_row("http://ok.test/") + urlhaus_row(url))
    assert keys(entries) == ["ok.test"] and skipped == 1


def test_legal_labels_and_loopback_literals_are_kept():
    urls = [
        "http://" + "a" * 63 + ".test/",
        "http://a-b.xn--p1ai/",
        "http://[::1]/",
        "http://9a.t/",
    ]
    entries, skipped = parse_urlhaus(b"".join(urlhaus_row(u) for u in urls))
    assert keys(entries) == ["a" * 63 + ".test", "a-b.xn--p1ai", "::1", "9a.t"] and skipped == 0


def test_a_bracketed_userinfo_url_is_skipped_by_this_pythons_urlsplit():
    raw = urlhaus_row("http://ok.test/") + urlhaus_row("http://[::1]:80@evil.com/")
    assert keys(parse_urlhaus(raw)[0]) == ["ok.test"]  # never stored as ::1 or evil.com


def test_the_host_part_decides_whether_a_netloc_is_bracketed(monkeypatch):
    """Another Python's urlsplit may accept this form; the host must then be evil.com."""
    from types import SimpleNamespace

    fake = SimpleNamespace(
        scheme="http", netloc="[::1]:80@evil.com", hostname="evil.com", port=None
    )
    monkeypatch.setattr(dataset_parse, "urlsplit", lambda _url: fake)
    assert dataset_parse._urlhaus_host("http://[::1]:80@evil.com/") == "evil.com"


def test_a_comment_like_row_cannot_swallow_rows_that_would_otherwise_parse():
    """Without the guard this parses (nine fields) and silently drops the 30 rows it spans."""
    swallowed = b"".join(b"1,d,http://h%d.test/,o,l,t,,l,r\n" % i for i in range(30))
    attack = b'#x,"swallow\n' + swallowed + b'",c,d,e,f,g,h,i\n'
    raw = urlhaus_row("http://before.test/") + attack + urlhaus_row("http://after.test/")
    with pytest.raises(ValueError, match="comment-like line opens a multi-line field"):
        parse_urlhaus(raw)


def test_a_hash_line_inside_an_open_quote_is_data_not_a_comment():
    raw = b'"1","d","http://ok.test/","o","l","t","a\n#b","l","r"\n'
    with pytest.raises(ValueError, match="non-printable"):
        parse_urlhaus(raw)


def test_a_quoted_hash_first_field_is_an_ordinary_row():
    raw = b'"#1","d","http://ok.test/","o","l","t","th","l","r"\n'
    assert keys(parse_urlhaus(b"# header\n" + raw)[0]) == ["ok.test"]


def test_urlhaus_is_streamed_not_copied_into_one_string(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("whole-text copy")

    monkeypatch.setattr(dataset_parse.io, "StringIO", boom)
    assert keys(parse_urlhaus(urlhaus_row("http://ok.test/"))[0]) == ["ok.test"]


def test_a_newline_free_blob_is_cut_at_the_line_cap():
    with pytest.raises(ValueError, match="line 1: line longer"):
        parse_urlhaus(b"a" * (dataset_parse.MAX_LINE_LEN * 4))


def test_invalid_utf8_in_a_later_row_is_a_structural_rejection():
    with pytest.raises(ValueError, match="UTF-8"):
        parse_urlhaus(urlhaus_row("http://ok.test/") + b'"1","d","\xff"\n')


def test_a_utf8_bom_is_ignored_in_both_formats():
    bom = b"\xef\xbb\xbf"
    assert keys(parse_urlhaus(bom + urlhaus_row("http://ok.test/"))[0]) == ["ok.test"]
    assert len(parse_kev(bom + (FIX / "kev_small.json").read_bytes())) == 3
    assert keys(parse_urlhaus(bom + b"# c\n" + urlhaus_row("http://ok.test/"))[0]) == ["ok.test"]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"vulnerabilities":[]}',
        b'{"vulnerabilities" : [ ]}\n',
        b' \n{\n"vulnerabilities":\n[\n]\n}\n',
    ],
)
def test_an_empty_kev_catalog_is_rejected(raw):
    with pytest.raises(ValueError, match="no vulnerabilities"):
        parse_kev(raw)


def test_the_stream_never_asks_for_more_than_one_capped_line(monkeypatch):
    sizes = []

    class Spy(io.TextIOWrapper):
        def readline(self, size=-1):
            sizes.append(size)
            return super().readline(size)

    monkeypatch.setattr(dataset_parse.io, "TextIOWrapper", Spy)
    parse_urlhaus(urlhaus_row("http://ok.test/"))
    assert sizes and set(sizes) == {dataset_parse.MAX_LINE_LEN + 1}


def test_a_comment_after_a_row_ending_in_a_literal_quote_is_still_a_comment():
    row = b'"1","d","http://ok.test/","o","l","t","","l",r"\n'  # odd quote count, valid for csv
    comment = b"#2,d,http://comment.test/,o,l,t,x,l,r\n"
    entries, skipped = parse_urlhaus(row + comment + urlhaus_row("http://next.test/"))
    assert keys(entries) == ["ok.test", "next.test"] and skipped == 0


def test_comments_with_crlf_and_a_final_comment_without_newline():
    raw = b"# header\r\n" + urlhaus_row("http://ok.test/").replace(b"\n", b"\r\n") + b"# last"
    assert keys(parse_urlhaus(raw)[0]) == ["ok.test"]


def reference_rows(text: str):
    """Independent oracle: whole-file csv.reader, comment status from the physical line index."""
    lines = io.StringIO(text, newline="").readlines()
    reader = csv.reader(lines, strict=True)
    start, out = 0, []
    try:
        for row in reader:
            first, span = lines[start], reader.line_num - start
            start = reader.line_num
            if first.startswith("#"):
                if span > 1:
                    return "error"
                continue
            out.append(row)
    except csv.Error:
        return "error"
    return out


def streamed_rows(text: str):
    lines = dataset_parse._Lines(text.encode())
    try:
        return list(dataset_parse._data_rows(csv.reader(lines, strict=True), lines))
    except (csv.Error, ValueError):
        return "error"


FUZZ_LINES = [
    '"1","a","b"', "x,y,z", "# comment", '#x,"open', '"#q",1', 'tail"', 'r"', '"multi', 'end"',
    "", "#", '# a "quoted" word', '"a""b",c', "\x20#not column zero", '"#',
]  # fmt: skip


def test_streamed_comment_logic_matches_the_reference_on_random_files():
    rng = random.Random(20261027)  # noqa: S311 - seeded test data, not security
    for _ in range(600):
        picked = [rng.choice(FUZZ_LINES) for _ in range(rng.randint(1, 8))]
        ends = [rng.choice(["\n", "\r\n"]) for _ in picked]
        if rng.random() < 0.3:
            ends[-1] = ""
        text = "".join(line + end for line, end in zip(picked, ends, strict=True))
        assert streamed_rows(text) == reference_rows(text), repr(text)
