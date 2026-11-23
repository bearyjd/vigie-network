from __future__ import annotations

import io
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from vigie_ingest.db import ensure_shard, iso_utc, open_inventory, shard_name, utc_day
from vigie_ingest.models import Health
from vigie_pipeline import nextdns_cli

START = 1_780_000_000
END = START + 60
PROFILE = "a123bc"
DEVICE = "ROUTER42"
COLLECTOR = "test-router"
KEY = "synthetic-operator-key"
MAC = "02:00:00:00:00:01"
QNAME = "sample.example"
REASON = "threat-intelligence-feeds"


def provider_row(ts=START + 15, *, status="blocked", reason=REASON, device=DEVICE):
    return {
        "timestamp": iso_utc(ts).replace("Z", ".100Z"),
        "domain": "Sample.Example.",
        "device": {"id": device, "name": "synthetic-name"},
        "status": status,
        "reasons": [{"id": reason, "name": "synthetic-reason"}],
    }


def page(rows, cursor=None):
    return {"data": rows, "meta": {"pagination": {"cursor": cursor}}}


class Response(io.BytesIO):
    status = 200
    length = None

    def getheader(self, header):
        return None


class Sources:
    def __init__(self, root):
        self.root = root
        self.inventory = root / "inventory.db"
        self.key = root / "secret"
        self.key.write_text(KEY + "\n")
        self.key.chmod(0o600)
        open_inventory(self.inventory).close()
        self.shard = root / shard_name(utc_day(START))
        ensure_shard(root, utc_day(START))
        self.requests = []
        self.pages = []

    def batch(self, batch_id, rows, *, low=START - 10, high=END + 10, **changes):
        meta = {
            "collector_id": COLLECTOR,
            "batch_id": batch_id,
            "received_at": iso_utc(END + 60),
            "window_start": low,
            "window_end": high,
            "observation_kind": "observation",
            "health": '{"dns_log_quiet":false,"spool_batches":0,"uptime_s":600}',
            "dropped_batches": 0,
            "truncated": "{}",
            "dns_queries": len(rows),
        }
        meta.update(changes)
        with sqlite3.connect(self.inventory) as inv:
            inv.execute(
                "INSERT INTO batches (collector_id,batch_id,received_at,truncated,dropped_batches,"
                "window_start,window_end,observation_kind,health,dns_queries)"
                " VALUES (:collector_id,:batch_id,:received_at,:truncated,:dropped_batches,"
                ":window_start,:window_end,:observation_kind,:health,:dns_queries)",
                meta,
            )
        for row in rows:
            day = utc_day(row[0])
            ensure_shard(self.root, day)
            with sqlite3.connect(self.root / shard_name(day)) as db:
                db.execute(
                    "INSERT INTO raw_dns(collector_id,batch_id,ts,device_mac,qname,qtype)"
                    " VALUES(?,?,?,?,?,?)",
                    (meta["collector_id"], batch_id, *row),
                )

    def https(self, host, *, timeout, context):
        assert host == "api.nextdns.io"
        assert timeout > 0

        class Connection:
            def request(connection, method, resource, *, headers):
                self.requests.append((method, resource, headers))

            def getresponse(connection):
                response = self.pages.pop(0)
                if isinstance(response, Response):
                    return response
                return Response(json.dumps(response).encode())

            def close(connection):
                pass

        return Connection()

    def argv(self):
        return [
            "--raw-dir",
            str(self.root),
            "--inventory",
            str(self.inventory),
            "--profile",
            PROFILE,
            "--device",
            DEVICE,
            "--collector",
            COLLECTOR,
            "--key-file",
            str(self.key),
            "--mac",
            MAC,
            "--confirm-exclusive-binding",
            "--from",
            iso_utc(START),
            "--to",
            iso_utc(END),
        ]

    def run(self, *extra):
        return nextdns_cli.main([*self.argv(), *extra])


@pytest.fixture
def sources(tmp_path, monkeypatch):
    result = Sources(tmp_path)
    monkeypatch.setattr(nextdns_cli, "time", lambda: END + 600)
    monkeypatch.setattr("http.client.HTTPSConnection", result.https)
    return result


def test_read_only_scoped_fixed_paged_request_and_redacted_report(sources, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.batch("other", [(START + 15, "02:00:00:00:00:99", QNAME, "A")], collector_id="other")
    with sqlite3.connect(sources.shard) as db:
        db.execute(
            "INSERT INTO raw_dns(collector_id,batch_id,ts,device_mac,qname,qtype)"
            " VALUES(?,?,?,?,?,?)",
            (COLLECTOR, "unaccepted", START + 15, MAC, QNAME, "A"),
        )
    sources.pages = [
        page([provider_row(START + 11, status="default")], cursor="opaque+/key?"),
        page([provider_row()]),
    ]
    before = [p.read_bytes() for p in (sources.inventory, sources.shard)]
    assert sources.run() == 0
    result = capsys.readouterr()
    assert not result.err
    assert json.loads(result.out) == {
        "source": "nextdns",
        "window": {"from": iso_utc(START), "to": iso_utc(END)},
        "devices": [{"mac": MAC, "threat_intelligence_blocks": 1}],
    }
    assert all(value not in result.out for value in (PROFILE, DEVICE, KEY, QNAME, COLLECTOR))
    assert [p.read_bytes() for p in (sources.inventory, sources.shard)] == before
    assert len(sources.requests) == 2
    for i, (method, resource, headers) in enumerate(sources.requests):
        target = urlsplit(resource)
        assert method == "GET"
        assert not target.scheme and not target.netloc
        assert target.path == f"/profiles/{PROFILE}/logs"
        params = parse_qs(target.query)
        expected = {"from", "to", "sort", "limit", "raw"}
        assert set(params) == (expected | {"cursor"} if i else expected)
        assert params["from"] == [iso_utc(START - 4)]
        assert params["to"] == [iso_utc(END + 4)]
        assert params["raw"] == ["1"]
        assert params.get("cursor") == (["opaque+/key?"] if i else None)
        assert headers["X-Api-Key"] == KEY
        assert "no-store" in headers["Cache-Control"]


@pytest.mark.parametrize(
    ("local", "provider"),
    [
        ([(START + 15, MAC, QNAME, "A"), (START + 15, MAC, QNAME, "AAAA")], [provider_row()]),
        ([(START + 15, MAC, QNAME, "A")] * 2, [provider_row()]),
        ([(START + 15, MAC, QNAME, "A")], [provider_row()] * 2),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(), provider_row(status="future")]),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(), provider_row(device=None)]),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(device=None)]),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(reason="blocklist:oisd")]),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(reason="security:" + REASON)]),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(status="allowed")]),
        ([(START + 15, MAC, "other.sample.example", "A")], [provider_row()]),
        ([(START + 13, MAC, QNAME, "A")], [provider_row()]),
        ([(START - 10, MAC, QNAME, "A"), (START + 15, MAC, QNAME, "A")], [provider_row()]),
        ([(START - 10, MAC, QNAME, "A")], [provider_row()]),
    ],
)
def test_excludes_non_unique_unbound_non_threat_and_imprecise_candidates(
    sources,
    capsys,
    local,
    provider,
):
    sources.batch("a", local)
    sources.pages = [page(provider)]
    assert sources.run() == 0
    assert json.loads(capsys.readouterr().out)["devices"] == []


def test_mutual_uniqueness_includes_both_padded_margins(sources, capsys):
    sources.batch("a", [(START, MAC, QNAME, "A"), (START - 3, MAC, QNAME, "A")])
    sources.pages = [page([provider_row(START - 2)])]
    assert sources.run() == 0
    assert json.loads(capsys.readouterr().out)["devices"] == []


@pytest.mark.parametrize(
    "changes",
    [
        {"dns_queries": 2},
        {"dns_queries": None},
        {"observation_kind": None},
        {"dropped_batches": 1},
        {"truncated": '{"dns_client_throttled":1}'},
        {"truncated": '{"truncated_other":1}'},
        {"health": '{"dns_log_quiet":true,"spool_batches":0,"uptime_s":600}'},
        {"health": None},
        {"health": Health().model_dump_json()},
        {"health": '{"dns_log_quiet":false,"spool_batches":1,"uptime_s":600}'},
        {"health": '{"dns_log_quiet":false,"spool_batches":0,"uptime_s":-1}'},
        {"truncated": '{"tail_open_failed":1}'},
        {"truncated": '{"future_counter":1}'},
        {"truncated": '{"source_flags":16}'},
    ],
)
def test_fails_before_provider_request_with_partial_raw_provenance(sources, capsys, changes):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")], **changes)
    assert sources.run() == 1
    assert not sources.requests
    result = capsys.readouterr()
    assert not result.out and "coverage" in result.err


def test_fails_before_provider_request_with_coverage_gap(sources, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")], high=START + 25)
    sources.batch("b", [], low=START + 26)
    assert sources.run() == 1
    assert not sources.requests
    assert not capsys.readouterr().out


def test_fails_before_provider_request_with_missing_retained_shard(sources, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.shard.unlink()
    assert sources.run() == 1
    assert not sources.requests
    assert not capsys.readouterr().out


@pytest.mark.parametrize(
    "pages",
    [
        [{"data": [provider_row()]}],
        [page([provider_row()], cursor="again"), page([provider_row()], cursor="again")],
        [page([], cursor="unexpected")],
        [page([provider_row(END + 40)])],
        [page([{**provider_row(), "timestamp": KEY}])],
        [page([{**provider_row(), "domain": "..sample.example"}])],
        [{"errors": [{"detail": KEY}], **page([provider_row()])}],
    ],
)
def test_provider_incomplete_or_invalid_is_never_a_partial_report(sources, capsys, pages):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.pages = pages.copy()
    assert sources.run() == 1
    result = capsys.readouterr()
    assert not result.out
    assert "NextDNS" in result.err
    assert all(value not in result.err for value in (PROFILE, DEVICE, KEY, QNAME, COLLECTOR))


def test_provider_redirect_is_never_followed(sources, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    redirect = Response(b"untrusted redirect")
    redirect.status = 302
    sources.pages = [redirect]
    assert sources.run() == 1
    assert len(sources.requests) == 1
    assert not capsys.readouterr().out


@pytest.mark.parametrize("secret_kind", ["symlink", "public", "fifo", "long", "header"])
def test_rejects_unsuitable_secret_file_before_any_request(sources, capsys, secret_kind):
    if secret_kind == "symlink":
        target = sources.root / "real"
        sources.key.rename(target)
        sources.key.symlink_to(target)
    elif secret_kind == "public":
        sources.key.chmod(0o644)
    elif secret_kind == "fifo":
        sources.key.unlink()
        os.mkfifo(sources.key, mode=0o600)
    else:
        sources.key.write_text(KEY * 100 if secret_kind == "long" else KEY + "\nInjected: bad")
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    assert sources.run() == 1
    assert not sources.requests
    result = capsys.readouterr()
    assert not result.out
    assert "key file" in result.err
    assert KEY not in result.err


def test_requires_explicit_binding_confirmation(sources, capsys):
    with pytest.raises(SystemExit) as exc:
        nextdns_cli.main([arg for arg in sources.argv() if arg != "--confirm-exclusive-binding"])
    assert exc.value.code == 2
    assert not sources.requests
    assert not capsys.readouterr().out


def test_exclusive_binding_cannot_report_for_another_local_mac(sources, capsys):
    sources.batch("a", [(START + 15, "02:00:00:00:00:99", QNAME, "A")])
    sources.pages = [page([provider_row()])]
    assert sources.run() == 0
    assert json.loads(capsys.readouterr().out)["devices"] == []


def test_rereads_raw_after_provider_to_include_late_accepted_competitor(
    sources, monkeypatch, capsys
):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.pages = [page([provider_row()])]
    dial = sources.https

    def batch_during_fetch(host, **kwargs):
        sources.batch("later", [(START + 15, MAC, QNAME, "AAAA")])
        return dial(host, **kwargs)

    monkeypatch.setattr("http.client.HTTPSConnection", batch_during_fetch)
    assert sources.run() == 0
    assert json.loads(capsys.readouterr().out)["devices"] == []


@pytest.mark.parametrize("failure", ["body", "pages", "duplicate", "short"])
def test_provider_response_bounds_and_json_framing(sources, monkeypatch, capsys, failure):
    from vigie_pipeline import nextdns

    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    if failure == "body":
        monkeypatch.setattr(nextdns, "MAX_PAGE_BYTES", 3)
        sources.pages = [page([provider_row()])]
    elif failure == "pages":
        monkeypatch.setattr(nextdns, "MAX_PAGES", 1)
        sources.pages = [page([provider_row()], cursor="another")]
    elif failure == "duplicate":
        raw = json.dumps(page([provider_row()]))
        sources.pages = [Response((raw[:-1] + ', "data": []}').encode())]
    else:
        response = Response(json.dumps(page([provider_row()])).encode())
        response.length = 10
        sources.pages = [response]
    assert sources.run() == 1
    result = capsys.readouterr()
    assert not result.out and "NextDNS" in result.err


def test_padding_cannot_cross_raw_retention(sources, monkeypatch, capsys):
    monkeypatch.setattr(nextdns_cli, "time", lambda: START + 7 * 86400 - 100)
    assert sources.run() == 1
    assert "retention" in capsys.readouterr().err
    assert not sources.requests


def test_shard_rollover_reconciles_full_accepted_batch(sources, monkeypatch, capsys):
    midnight = (START // 86400 + 1) * 86400
    argv = sources.argv()
    argv[-3] = iso_utc(midnight - 10)
    argv[-1] = iso_utc(midnight + 10)
    sources.batch(
        "a",
        [(midnight - 5, MAC, QNAME, "A"), (midnight + 5, MAC, QNAME, "AAAA")],
        low=midnight - 20,
        high=midnight + 20,
        truncated='{"ct_unmapped_bytes":42,"source_flags":4}',
    )
    sources.pages = [page([provider_row(midnight - 5), provider_row(midnight + 5)])]
    monkeypatch.setattr(nextdns_cli, "time", lambda: midnight + 600)
    assert nextdns_cli.main(argv) == 0
    assert json.loads(capsys.readouterr().out)["devices"] == [
        {"mac": MAC, "threat_intelligence_blocks": 2},
    ]


@pytest.mark.parametrize("edge", ["before", "after"])
def test_boundary_row_in_adjacent_accepted_batch_vetoes_match(sources, capsys, edge):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    low = START - 40 if edge == "before" else END + 20
    high = low + 20
    boundary = high if edge == "before" else low
    sources.batch("adjacent", [(boundary, "02:00:00:00:00:99", QNAME, "AAAA")], low=low, high=high)
    sources.pages = [page([provider_row()])]
    assert sources.run() == 0
    assert json.loads(capsys.readouterr().out)["devices"] == []


def test_adjacent_batch_cannot_fill_an_inner_coverage_gap(sources, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")], low=START + 1)
    sources.batch("earlier", [], low=START - 40, high=START - 10)
    assert sources.run() == 1
    assert "coverage" in capsys.readouterr().err
    assert not sources.requests


def test_adjacent_batch_with_nonboundary_rows_does_not_veto_match(sources, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.batch("later", [(END + 30, MAC, QNAME, "AAAA")], low=END + 20, high=END + 40)
    sources.pages = [page([provider_row()])]
    assert sources.run() == 0
    assert json.loads(capsys.readouterr().out)["devices"] == [
        {"mac": MAC, "threat_intelligence_blocks": 1},
    ]


def test_degraded_adjacent_batch_prevents_report(sources, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.batch("later", [], low=END + 20, high=END + 40, dropped_batches=1)
    assert sources.run() == 1
    assert "coverage" in capsys.readouterr().err
    assert not sources.requests


@pytest.mark.parametrize("database", ["inventory", "shard"])
def test_foreign_owned_database_is_rejected_before_sqlite_open(
    sources,
    monkeypatch,
    capsys,
    database,
):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    foreign = getattr(sources, database)
    real_stat = Path.stat
    real_connect = sqlite3.connect
    opened = []

    def fake_stat(path, **kwargs):
        result = real_stat(path, **kwargs)
        if path == foreign:
            return SimpleNamespace(st_mode=result.st_mode, st_uid=os.geteuid() + 1)
        return result

    def record_open(path, *args, **kwargs):
        opened.append(path)
        return real_connect(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(sqlite3, "connect", record_open)
    assert sources.run() == 1
    result = capsys.readouterr()
    assert not result.out
    assert "coverage" in result.err
    assert not sources.requests
    assert not any(uri.startswith(foreign.as_uri()) for uri in opened)
