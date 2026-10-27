"""dataset_writes.stage: parse, hash, insert import + entries + ONE audit row, atomically."""

from __future__ import annotations

import hashlib
import itertools
import json
import sqlite3
from pathlib import Path

import pytest

from vigie_api import dataset_writes
from vigie_api.errors import ApiError
from vigie_api.schema import open_overrides

FIX = Path(__file__).parent.parent / "fixtures" / "datasets"
KEV = (FIX / "kev_small.json").read_bytes()
URLHAUS = (FIX / "urlhaus_small.csv").read_bytes()
NOW = "2026-10-27T10:00:00Z"
COUNTER = itertools.count(1)


@pytest.fixture
def ov(tmp_path):
    global COUNTER
    COUNTER = itertools.count(1)  # ids restart per test so "imp-1" is predictable
    conn = open_overrides(tmp_path / "overrides.db")
    yield conn
    conn.close()


def stage(ov, source="kev", data=KEV, *, version="2099.01.01", licence="CC0", ids=None):
    return dataset_writes.stage(
        ov, source, data, version, licence, "cli:local", NOW,
        ids or (lambda: f"imp-{next(COUNTER)}"),
    )  # fmt: skip


def count(ov, table):
    return ov.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608


def test_stage_records_import_entries_and_one_audit_row(ov):
    assert stage(ov) == "imp-1"
    row = dict(ov.execute("SELECT * FROM dataset_imports").fetchone())
    assert row == {
        "id": "imp-1", "source": "kev", "version": "2099.01.01", "licence": "CC0",
        "sha256": hashlib.sha256(KEV).hexdigest(), "entry_count": 3, "status": "staged",
        "created_at": NOW, "created_by": "cli:local",
    }  # fmt: skip
    keys = [r[0] for r in ov.execute("SELECT key FROM dataset_entries_staging ORDER BY key")]
    assert keys == ["CVE-2021-0001", "CVE-2022-12345", "CVE-2023-0003"]
    (audit,) = ov.execute("SELECT * FROM audit_log WHERE action LIKE 'dataset.%'").fetchall()
    assert (audit["principal"], audit["action"], audit["ts"]) == ("cli:local", "dataset.stage", NOW)
    assert json.loads(audit["detail"]) == {
        "source": "kev", "version": "2099.01.01", "entry_count": 3,
        "sha256": hashlib.sha256(KEV).hexdigest(),
    }  # fmt: skip
    assert "CVE-2021" not in audit["detail"] and "Widget" not in audit["detail"]


def test_urlhaus_entries_hold_only_host_and_threat(ov):
    stage(ov, "urlhaus", URLHAUS)
    rows = ov.execute("SELECT key, payload FROM dataset_entries_staging")
    stored = " ".join(r[0] + r[1] for r in rows)
    assert "evil.example.com" in stored and "malware_download" in stored
    for leaked in ("SECRET-QUERY-CANARY", "SECRET-PW-CANARY", "mal.exe", "8080"):
        assert leaked not in stored
    dump = "\n".join(ov.iterdump())
    assert "SECRET-QUERY-CANARY" not in dump and "SECRET-PW-CANARY" not in dump


def audit_count(ov):
    return ov.execute("SELECT COUNT(*) FROM audit_log WHERE action='dataset.stage'").fetchone()[0]


def test_same_source_and_bytes_twice_is_refused_and_writes_nothing(ov):
    stage(ov)
    with pytest.raises(ApiError) as caught:
        stage(ov)
    assert (caught.value.status, caught.value.code) == (409, "dataset_already_staged")
    assert count(ov, "dataset_imports") == 1 and audit_count(ov) == 1
    assert count(ov, "dataset_entries_staging") == 3
    assert not ov.in_transaction


def test_a_new_version_of_different_bytes_is_a_second_staged_import(ov):
    stage(ov)
    stage(ov, data=KEV.replace(b"Widget", b"Gadget"), version="2099.01.02")
    assert count(ov, "dataset_imports") == 2


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"data": b"not json"}, "dataset_invalid"),
        ({"source": "other"}, "dataset_invalid"),
        ({"version": ""}, "dataset_invalid"),
        ({"licence": "  "}, "dataset_invalid"),
        ({"licence": "a\nb"}, "dataset_invalid"),
        ({"version": "v" * 513}, "dataset_invalid"),
    ],
)
def test_invalid_input_is_422_and_writes_nothing(ov, kwargs, code):
    with pytest.raises(ApiError) as caught:
        stage(ov, **kwargs)
    assert (caught.value.status, caught.value.code) == (422, code)
    assert count(ov, "dataset_imports") == 0 and count(ov, "audit_log") == 0


def test_audit_failure_rolls_back_the_import_and_entries(ov):
    ov.execute(
        "CREATE TRIGGER no_audit BEFORE INSERT ON audit_log"
        " BEGIN SELECT RAISE(ABORT,'audit down'); END"
    )
    with pytest.raises(sqlite3.DatabaseError, match="audit down"):
        stage(ov)
    assert count(ov, "dataset_imports") == 0 and count(ov, "dataset_entries_staging") == 0
    assert not ov.in_transaction
