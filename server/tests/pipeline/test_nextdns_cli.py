from __future__ import annotations

import http.client
import io
import json
import os
import signal
import sqlite3
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import KEY as INGEST_KEY
from conftest import encode, make_batch, signed_headers

from vigie_api.monitoring import collector_summary
from vigie_ingest.app import _parse_envelope, process_batch
from vigie_ingest.config import Settings
from vigie_ingest.db import connect, ensure_shard, iso_utc, open_inventory, shard_name, utc_day
from vigie_ingest.models import Health
from vigie_ingest.store import provision_collector
from vigie_pipeline import nextdns, nextdns_cli, nextdns_raw
from vigie_pipeline.essential_absence import configure_recording
from vigie_pipeline.measurements import read_measurements
from vigie_pipeline.schema import open_pipeline_inventory

START = 1_780_000_000
END = START + 60
COVERAGE_LOW = START - 304
COVERAGE_HIGH = END + 304
PROFILE = "a123bc"
DEVICE = "ROUTER42"
COLLECTOR = "test-router"
KEY = "synthetic-operator-key"
MAC = "02:00:00:00:00:01"
QNAME = "sample.example"
REASON = "threat-intelligence-feeds"

pytestmark = pytest.mark.skipif(
    os.name != "posix"
    or not all(hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "setitimer")),
    reason="NextDNS report integration requires POSIX interval timers",
)


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

    def batch(self, batch_id, rows, *, low=COVERAGE_LOW, high=COVERAGE_HIGH, **changes):
        meta = {
            "collector_id": COLLECTOR,
            "batch_id": batch_id,
            "received_at": iso_utc(END + 60),
            "window_start": low,
            "window_end": high,
            "observation_kind": "observation",
            "health": (
                '{"dns_log_quiet":false,"dns_evidence_reported":true,'
                '"spool_batches":0,"uptime_s":600}'
            ),
            "dropped_batches": 0,
            "truncated": "{}",
            "dns_queries": len(rows),
        }
        meta.update(changes)
        with closing(sqlite3.connect(self.inventory)) as inv, inv:
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
            with closing(sqlite3.connect(self.root / shard_name(day))) as db, db:
                db.execute(
                    "INSERT INTO raw_dns(collector_id,batch_id,ts,device_mac,qname,qtype)"
                    " VALUES(?,?,?,?,?,?)",
                    (meta["collector_id"], batch_id, *row),
                )

    def https(self, host, *, timeout, context):
        assert host == "api.nextdns.io"
        assert timeout > 0
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
        assert context.keylog_filename is None

        class Connection:
            def request(connection, method, resource, *, headers):
                self.requests.append((method, resource, headers))

            def getresponse(connection):
                response = self.pages.pop(0)
                if isinstance(response, Response | http.client.HTTPResponse):
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
    monkeypatch.setattr(nextdns_cli, "time", lambda: END + 700)
    monkeypatch.setattr("http.client.HTTPSConnection", result.https)
    return result


def test_read_only_scoped_fixed_paged_request_and_redacted_report(sources, monkeypatch, capsys):
    keylog_path = sources.root / "transport-keylog"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog_path))
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.batch("other", [(START + 15, "02:00:00:00:00:99", QNAME, "A")], collector_id="other")
    with closing(sqlite3.connect(sources.shard)) as db, db:
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
    assert not keylog_path.exists()
    assert json.loads(result.out) == {
        "source": "nextdns",
        "provider_coverage": "unverified",
        "ambiguity_withheld": False,
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
    ("local", "provider", "ambiguity_withheld"),
    [
        ([], [], False),
        ([], [provider_row()], False),
        (
            [(START + 15, MAC, QNAME, "A")],
            [provider_row(device=None), provider_row(device=None)],
            False,
        ),
        ([(START + 15, MAC, QNAME, "A"), (START + 15, MAC, QNAME, "AAAA")], [provider_row()], True),
        ([(START + 15, MAC, QNAME, "A")] * 2, [provider_row()], True),
        ([(START + 15, MAC, QNAME, "A")], [provider_row()] * 2, True),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(), provider_row(status="future")], True),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(), provider_row(device=None)], True),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(device=None)], False),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(reason="blocklist:oisd")], False),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(reason="security:" + REASON)], False),
        ([(START + 15, MAC, QNAME, "A")], [provider_row(status="allowed")], False),
        ([(START + 15, MAC, "other.sample.example", "A")], [provider_row()], False),
        ([(START + 13, MAC, QNAME, "A")], [provider_row()], False),
        ([(COVERAGE_LOW, MAC, QNAME, "A"), (START + 15, MAC, QNAME, "A")], [provider_row()], True),
        ([(COVERAGE_LOW, MAC, QNAME, "A")], [provider_row()], False),
    ],
)
def test_excludes_non_unique_unbound_non_threat_and_imprecise_candidates(
    sources,
    capsys,
    local,
    provider,
    ambiguity_withheld,
):
    sources.batch("a", local)
    sources.pages = [page(provider)]
    assert sources.run() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["devices"] == []
    assert result["ambiguity_withheld"] is ambiguity_withheld


def test_mutual_uniqueness_includes_both_padded_margins(sources, capsys):
    sources.batch("a", [(START + 1, MAC, QNAME, "A"), (START - 1, MAC, QNAME, "A")])
    sources.pages = [page([provider_row(START)])]
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
        {"health": '{"dns_log_quiet":false,"spool_batches":0,"uptime_s":600}'},
        {
            "health": '{"dns_log_quiet":false,"dns_evidence_reported":1,'
            '"spool_batches":0,"uptime_s":600}'
        },
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


@pytest.mark.parametrize("failure", ["body", "duplicate", "short"])
def test_provider_response_bounds_and_json_framing(sources, monkeypatch, capsys, failure):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    if failure == "body":
        monkeypatch.setattr(nextdns, "MAX_PAGE_BYTES", 3)
        sources.pages = [page([provider_row()])]
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
        low=midnight - 320,
        high=midnight + 320,
        truncated='{"ct_unmapped_bytes":42,"source_flags":4}',
    )
    sources.pages = [page([provider_row(midnight - 5), provider_row(midnight + 5)])]
    monkeypatch.setattr(nextdns_cli, "time", lambda: midnight + 710)
    assert nextdns_cli.main(argv) == 0
    assert json.loads(capsys.readouterr().out)["devices"] == [
        {"mac": MAC, "threat_intelligence_blocks": 2},
    ]


@pytest.mark.parametrize("edge", ["before", "after"])
def test_boundary_row_in_adjacent_accepted_batch_vetoes_match(sources, capsys, edge):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")], low=START - 10, high=END + 10)
    before = [(START - 10, "02:00:00:00:00:99", QNAME, "AAAA")] if edge == "before" else []
    after = [(END + 10, "02:00:00:00:00:99", QNAME, "AAAA")] if edge == "after" else []
    sources.batch("early", before, low=COVERAGE_LOW, high=START - 10)
    sources.batch("late", after, low=END + 10, high=COVERAGE_HIGH)
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


@pytest.mark.parametrize("omitted", [None, "dns_log_quiet", "dns", "truncated", "dropped_batches"])
def test_signed_ingest_retains_dns_evidence_provenance(sources, capsys, omitted):
    ingest_key_id = "router-test-key"
    secrets = sources.root / "ingest-secrets"
    secrets.mkdir()
    (secrets / f"collector_key_{ingest_key_id}").write_text(INGEST_KEY.hex())
    settings = Settings(data_dir=sources.root, secrets_dir=secrets)
    with closing(open_pipeline_inventory(sources.inventory)) as inv:
        provision_collector(inv, COLLECTOR, ingest_key_id)
        configure_recording(inv, enabled=True, now=COVERAGE_LOW - 7200)
    sent = COVERAGE_HIGH
    health = {"spool_batches": 0, "uptime_s": 600, "rss_kb": 256}
    if omitted != "dns_log_quiet":
        health["dns_log_quiet"] = False
    batch = make_batch(
        collector_id=COLLECTOR,
        key_id=ingest_key_id,
        observation_kind="observation",
        window_start=COVERAGE_LOW,
        window_end=sent,
        sent_ts=sent,
        health=health,
        dns=[{"ts": START + 15, "mac": MAC, "qname": QNAME, "qtype": "A"}],
    )
    if omitted in ("dns", "truncated", "dropped_batches"):
        del batch[omitted]
    body = encode(batch)
    headers = signed_headers(body, batch)
    envelope = _parse_envelope({key.lower(): value for key, value in headers.items()})
    assert envelope is not None
    assert process_batch(settings, envelope, body, sent + 1) == (200, {"duplicate": False})
    with closing(connect(sources.inventory)) as db:
        accepted = json.loads(db.execute("SELECT health FROM batches").fetchone()[0])
        summary = collector_summary(db, COLLECTOR)
        measurements = read_measurements(db, sources.root, COLLECTOR, batch["batch_id"])
        essential_seconds = db.execute(
            "SELECT qualified_seconds FROM essential_observation_hours WHERE collector_id=?",
            (COLLECTOR,),
        ).fetchone()[0]
    assert accepted["dns_log_quiet"] is False
    assert accepted["dns_evidence_reported"] is (omitted is None)
    assert summary["dns_log_quiet"] is False
    assert summary["agent_uptime_s"] == 600
    assert summary["agent_rss_kb"] == 256
    assert "dns_evidence_reported" not in summary
    assert measurements.reasons == ()
    assert measurements.counters.get(MAC, (0, 0, 0, 0))[3] == int(omitted != "dns")
    assert essential_seconds == (COVERAGE_HIGH - COVERAGE_LOW if omitted is None else 0)

    sources.pages = [page([provider_row()])]
    result = sources.run()
    output = capsys.readouterr()
    if omitted is None:
        assert result == 0 and len(sources.requests) == 1
        assert json.loads(output.out)["devices"] == [
            {"mac": MAC, "threat_intelligence_blocks": 1},
        ]
    else:
        assert result == 1 and not sources.requests
        assert "coverage" in output.err and not output.out


@pytest.mark.parametrize(
    ("local_ts", "provider_ts", "expected"),
    [
        (START, START - 1, False),
        (START, START, True),
        (END - 1, END - 1, True),
        (END - 1, END, False),
    ],
)
def test_positive_provider_timestamp_must_be_inside_requested_window(
    sources,
    capsys,
    local_ts,
    provider_ts,
    expected,
):
    sources.batch("a", [(local_ts, MAC, QNAME, "A")])
    # Exact whole-second provider timestamp exercises the end-exclusive boundary.
    sources.pages = [page([{**provider_row(), "timestamp": iso_utc(provider_ts)}])]
    assert sources.run() == 0
    result = json.loads(capsys.readouterr().out)
    assert bool(result["devices"]) is expected
    assert result["ambiguity_withheld"] is False


def test_outside_provider_event_remains_an_ambiguity_competitor(sources, capsys):
    sources.batch("a", [(START, MAC, QNAME, "A")])
    sources.pages = [page([provider_row(START - 1, status="default"), provider_row(START)])]
    assert sources.run() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["devices"] == []
    assert result["ambiguity_withheld"] is True


def test_dns_root_can_coexist_with_a_match_without_becoming_a_verdict(sources, capsys):
    sources.batch("a", [(START + 5, MAC, ".", "DNSKEY"), (START + 15, MAC, QNAME, "A")])
    sources.pages = [page([{**provider_row(START + 5), "domain": "."}, provider_row()])]
    assert sources.run() == 0
    assert json.loads(capsys.readouterr().out)["devices"] == [
        {"mac": MAC, "threat_intelligence_blocks": 1},
    ]


@pytest.mark.parametrize(("low", "high"), [(START - 20, COVERAGE_HIGH), (COVERAGE_LOW, END + 20)])
def test_missing_outer_local_coverage_prevents_report(sources, capsys, low, high):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")], low=low, high=high)
    sources.pages = [page([provider_row()])]
    assert sources.run() == 1
    result = capsys.readouterr()
    assert not result.out and "coverage" in result.err
    assert not sources.requests


def test_outer_local_coverage_must_be_settled(sources, monkeypatch, capsys):
    monkeypatch.setattr(nextdns_cli, "time", lambda: END + 500)
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.pages = [page([provider_row()])]
    assert sources.run() == 1
    assert "settled" in capsys.readouterr().err
    assert not sources.requests


@pytest.mark.parametrize("kind", ["probe", "unknown-window"])
def test_non_observation_cannot_establish_coverage(sources, capsys, kind):
    if kind == "probe":
        sources.batch("probe", [], observation_kind="probe")
    else:
        sources.batch("unknown", [], window_start=None)
        sources.batch("observation", [])
    assert sources.run() == 1
    assert "coverage" in capsys.readouterr().err
    assert not sources.requests


def test_unattributable_local_mac_still_competes(sources, capsys):
    sources.batch(
        "a", [(START + 15, MAC, QNAME, "A"), (START + 15, "00:00:00:00:00:00", QNAME, "AAAA")]
    )
    sources.pages = [page([provider_row()])]
    assert sources.run() == 0
    assert json.loads(capsys.readouterr().out)["devices"] == []


def test_incomplete_chunked_provider_response_never_emits_report(sources, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    body = json.dumps(page([provider_row()])).encode()
    raw = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + f"{len(body):x}\r\n".encode()
        + body
        + b"\r\n"
    )
    response = http.client.HTTPResponse(SimpleNamespace(makefile=lambda _mode: io.BytesIO(raw)))
    response.begin()
    sources.pages = [response]
    assert sources.run() == 1
    result = capsys.readouterr()
    assert not result.out and "NextDNS" in result.err


def test_stalled_provider_reaches_total_deadline(sources, monkeypatch, capsys):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])

    class StalledPage(Response):
        def read(self, *_args):
            time.sleep(5)
            raise AssertionError("deadline did not interrupt this read")

    sources.pages = [StalledPage()]
    monkeypatch.setattr(nextdns_cli, "RUN_TIMEOUT_S", 1)
    assert sources.run() == 1
    result = capsys.readouterr()
    assert not result.out and "report time limit exceeded" in result.err
    assert len(sources.requests) == 1


@pytest.mark.parametrize("invalid_key", [False, True])
def test_alarm_delivered_while_cancelling_stays_sanitized_and_restores_handler(
    sources,
    monkeypatch,
    capsys,
    invalid_key,
):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.pages = [page([provider_row()])]
    if invalid_key:
        sources.key.chmod(0o644)

    previous = signal.getsignal(signal.SIGALRM)
    original_setitimer = signal.setitimer
    late_alarm_fired = False

    def deliver_during_cancel(which, seconds, interval=0):
        nonlocal late_alarm_fired
        timer = original_setitimer(which, seconds, interval)
        if seconds == 0 and not late_alarm_fired:
            late_alarm_fired = True
            signal.raise_signal(signal.SIGALRM)
        return timer

    monkeypatch.setattr(signal, "setitimer", deliver_during_cancel)
    try:
        assert sources.run() == 1
        assert signal.getsignal(signal.SIGALRM) == previous
    finally:
        # On a regression, keep the leaked handler from affecting the remainder of pytest.
        signal.signal(signal.SIGALRM, previous)
    assert late_alarm_fired
    result = capsys.readouterr()
    assert not result.out
    assert result.err == "vigie-nextdns: report time limit exceeded\n"


def test_selected_mac_boundary_inside_interval_withholds_attribution(sources, capsys):
    sources.batch("a", [])
    sources.batch("clamped", [(START + 15, MAC, QNAME, "A")], low=START + 15)
    sources.pages = [page([provider_row()])]
    assert sources.run() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["devices"] == []
    assert result["ambiguity_withheld"] is True


@pytest.mark.parametrize("legacy_collector", [COLLECTOR, "another-collector"])
def test_old_unknown_window_blocks_only_the_selected_collector(
    sources,
    capsys,
    legacy_collector,
):
    old_received = iso_utc(START - 6 * 86400)
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.batch(
        "synthetic-legacy-row",
        [],
        collector_id=legacy_collector,
        received_at=old_received,
        window_start=None,
        window_end=None,
    )
    sources.pages = [page([provider_row()])]
    code = sources.run()
    result = capsys.readouterr()
    if legacy_collector == COLLECTOR:
        assert code == 1 and not sources.requests and not result.out
        assert "legacy batches without observation timestamps" in result.err
        assert "age out" in result.err
        assert all(secret not in result.err for secret in (legacy_collector, old_received, KEY))
    else:
        assert code == 0 and not result.err
        assert json.loads(result.out)["devices"] == [
            {"mac": MAC, "threat_intelligence_blocks": 1},
        ]


@pytest.mark.parametrize("cursor", [None, "next-page"])
def test_provider_page_limit_abstains_only_if_pagination_is_unfinished(
    sources,
    monkeypatch,
    capsys,
    cursor,
):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    monkeypatch.setattr(nextdns, "MAX_PAGES", 1)
    sources.pages = [page([provider_row()], cursor=cursor)]
    status = sources.run()
    result = capsys.readouterr()
    assert len(sources.requests) == 1
    if cursor is None:
        assert status == 0 and not result.err
        assert json.loads(result.out)["devices"] == [
            {"mac": MAC, "threat_intelligence_blocks": 1},
        ]
    else:
        assert status == 1
        assert not result.out
        assert result.err == (
            "vigie-nextdns: window exceeds report read limits. Choose a shorter interval\n"
        )


@pytest.mark.parametrize("limit", ["MAX_BATCHES", "MAX_RAW_DNS"])
def test_local_read_limit_fails_before_provider_request(sources, monkeypatch, capsys, limit):
    sources.batch("a", [(START + 15, MAC, QNAME, "A")])
    sources.batch("b", [(START + 30, MAC, QNAME, "A")])
    monkeypatch.setattr(nextdns_raw, limit, 1)
    assert sources.run() == 1
    assert not sources.requests
    result = capsys.readouterr()
    assert not result.out
    assert result.err == (
        "vigie-nextdns: window exceeds report read limits. Choose a shorter interval\n"
    )


@pytest.mark.parametrize("failure", ["missing-timer", "worker-thread"])
def test_unsupported_runtime_fails_before_reading_key(sources, monkeypatch, capsys, failure):
    sources.key.unlink()
    if failure == "missing-timer":
        with monkeypatch.context() as patch:
            patch.delattr(signal, "ITIMER_REAL")
            status = sources.run()
    else:
        with ThreadPoolExecutor(max_workers=1) as workers:
            status = workers.submit(sources.run).result()
    assert status == 1
    assert not sources.requests
    result = capsys.readouterr()
    assert not result.out
    assert result.err == (
        "vigie-nextdns: report requires POSIX interval timers and the main thread\n"
    )
