"""dataset_writes.accept/reject: one transaction, one audit row, guarded transitions."""

from __future__ import annotations

import itertools
import json
import sqlite3

import pytest

from vigie_api import dataset_writes
from vigie_api.errors import ApiError
from vigie_api.schema import open_overrides

NOW = "2026-10-30T10:00:00Z"
LATER = "2026-10-31T10:00:00Z"
COUNTER = itertools.count(1)


def kev(n: int, tag: str = "") -> bytes:
    items = [
        {"cveID": f"CVE-2024-{1000 + i}", "vendorProject": f"V{tag}", "product": "P",
         "dateAdded": "2024-01-01"}
        for i in range(n)
    ]  # fmt: skip
    return json.dumps({"catalogVersion": "x", "vulnerabilities": items}).encode()


@pytest.fixture
def ov(tmp_path):
    global COUNTER
    COUNTER = itertools.count(1)
    conn = open_overrides(tmp_path / "overrides.db")
    yield conn
    conn.close()


def stage(ov, n=3, tag="", *, version="2026.10.01", source="kev", data=None):
    data = data or kev(n, tag)
    return dataset_writes.stage(
        ov, source, data, version, "CC0", "cli:local", NOW, lambda: f"imp-{next(COUNTER)}"
    )


def accept(ov, import_id, *, force=False, by="cli:local", now=LATER):
    return dataset_writes.accept(ov, import_id, "cli:local", by, now, force=force)


def reject(ov, import_id, reason=None, by="cli:local"):
    return dataset_writes.reject(ov, import_id, "cli:local", by, LATER, reason)


def status(ov, import_id):
    return ov.execute("SELECT status FROM dataset_imports WHERE id=?", (import_id,)).fetchone()[0]


def audits(ov, action):
    return ov.execute("SELECT * FROM audit_log WHERE action=?", (action,)).fetchall()


def code(exc_info):
    return exc_info.value.code


def test_accept_flips_status_only_and_audits_once(ov):
    imp = stage(ov)
    accept(ov, imp, by="alice")
    row = ov.execute("SELECT * FROM dataset_imports WHERE id=?", (imp,)).fetchone()
    assert (row["status"], row["accepted_by"], row["accepted_at"]) == ("accepted", "alice", LATER)
    assert ov.execute("SELECT COUNT(*) FROM dataset_entries_staging").fetchone()[0] == 3
    (a,) = audits(ov, "dataset.accept")
    assert (a["principal"], a["target"], a["ts"]) == ("cli:local", imp, LATER)
    detail = json.loads(a["detail"])
    assert detail == {
        "source": "kev", "version": "2026.10.01", "sha256": row["sha256"], "entry_count": 3,
        "skipped_count": 0, "by": "alice", "force": False, "superseded": None,
    }  # fmt: skip
    assert "CVE-2024" not in a["detail"]


def test_reject_records_provenance_and_audits_without_contents(ov):
    imp = stage(ov)
    reject(ov, imp, "licence unclear", by="bob")
    row = ov.execute("SELECT * FROM dataset_imports WHERE id=?", (imp,)).fetchone()
    assert (row["status"], row["rejected_by"], row["rejected_at"], row["reject_reason"]) == (
        "rejected", "bob", LATER, "licence unclear",
    )  # fmt: skip
    assert row["accepted_by"] is None
    (a,) = audits(ov, "dataset.reject")
    detail = json.loads(a["detail"])
    assert detail["reason"] == "licence unclear" and detail["by"] == "bob"
    assert detail["entry_count"] == 3 and detail["source"] == "kev"
    assert "CVE-2024" not in a["detail"]


def test_reject_without_reason_is_allowed(ov):
    imp = stage(ov)
    reject(ov, imp)
    assert status(ov, imp) == "rejected"
    assert json.loads(audits(ov, "dataset.reject")[0]["detail"])["reason"] is None


@pytest.mark.parametrize("reason", ["x" * 201, "bad\x00reason", "   ", "line\nbreak"])
def test_reject_reason_is_length_limited_and_printable(ov, reason):
    imp = stage(ov)
    with pytest.raises(ApiError) as exc:
        reject(ov, imp, reason)
    assert exc.value.status == 422 and status(ov, imp) == "staged"
    assert audits(ov, "dataset.reject") == []


def test_reject_reason_at_the_limit_is_stored(ov):
    imp = stage(ov)
    reject(ov, imp, "x" * 200)
    assert len(ov.execute("SELECT reject_reason FROM dataset_imports").fetchone()[0]) == 200


@pytest.mark.parametrize("by", ["", "x" * 129, "a\nb"])
def test_operator_identity_is_sanitized(ov, by):
    imp = stage(ov)
    with pytest.raises(ApiError) as exc:
        accept(ov, imp, by=by)
    assert exc.value.status == 422 and status(ov, imp) == "staged"


@pytest.mark.parametrize("first", ["accept", "reject"])
@pytest.mark.parametrize("second", ["accept", "reject"])
def test_only_staged_imports_transition(ov, first, second):
    imp = stage(ov)
    do = {"accept": accept, "reject": reject}
    do[first](ov, imp)
    before = [tuple(r) for r in ov.execute("SELECT * FROM dataset_imports")]
    n_audit = ov.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    with pytest.raises(ApiError) as exc:
        do[second](ov, imp)
    assert (exc.value.status, code(exc)) == (409, "dataset_not_staged")
    assert before == [tuple(r) for r in ov.execute("SELECT * FROM dataset_imports")]
    assert ov.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == n_audit


def test_unknown_import_is_not_found(ov):
    for fn in (accept, reject):
        with pytest.raises(ApiError) as exc:
            fn(ov, "nope")
        assert (exc.value.status, code(exc)) == (404, "dataset_import_not_found")


def test_rejected_is_terminal_and_restaging_the_same_bytes_stays_blocked(ov):
    imp = stage(ov)
    reject(ov, imp)
    with pytest.raises(ApiError) as exc:
        stage(ov)
    assert code(exc) == "dataset_already_staged"


def test_staging_slots_free_up_after_accept_and_reject(ov):
    ids = [stage(ov, n=3, tag=str(i), version=f"2026.10.0{i + 1}") for i in range(5)]
    with pytest.raises(ApiError) as exc:
        stage(ov, tag="6", version="2026.10.09")
    assert code(exc) == "dataset_staging_full"
    reject(ov, ids[0])
    stage(ov, tag="6", version="2026.10.09")  # 6th fits after a reject
    with pytest.raises(ApiError):
        stage(ov, tag="7", version="2026.10.10")
    accept(ov, ids[1])
    stage(ov, tag="7", version="2026.10.10")  # and after an accept


def test_accept_supersedes_the_earlier_accepted_import(ov):
    a, b = stage(ov, tag="a", version="2026.10.01"), stage(ov, tag="b", version="2026.10.02")
    assert dataset_writes.latest_accepted(ov, "kev") is None
    accept(ov, a)
    assert dataset_writes.latest_accepted(ov, "kev")["id"] == a
    accept(ov, b, now="2026-11-01T00:00:00Z")
    assert dataset_writes.latest_accepted(ov, "kev")["id"] == b
    old = ov.execute("SELECT * FROM dataset_imports WHERE id=?", (a,)).fetchone()
    assert (old["status"], old["superseded_by"], old["superseded_at"]) == (
        "accepted", b, "2026-11-01T00:00:00Z",
    )  # fmt: skip
    detail = json.loads(audits(ov, "dataset.accept")[-1]["detail"])
    assert detail["superseded"] == a
    assert len(audits(ov, "dataset.accept")) == 2


def test_latest_accepted_is_per_source(ov):
    a = stage(ov)
    accept(ov, a)
    assert dataset_writes.latest_accepted(ov, "urlhaus") is None


def test_only_one_unsuperseded_accepted_import_per_source(ov):
    a = stage(ov, tag="a")
    accept(ov, a)
    b = stage(ov, tag="b", version="2026.10.02")
    with pytest.raises(sqlite3.IntegrityError):  # the DB itself refuses a second live accept
        ov.execute(
            "UPDATE dataset_imports SET status='accepted', accepted_by='x', accepted_at='t'"
            " WHERE id=?",
            (b,),
        )


def test_older_version_than_the_accepted_one_is_refused(ov):
    a, b = stage(ov, tag="a", version="2026.10.05"), stage(ov, tag="b", version="2026.10.04")
    accept(ov, a)
    with pytest.raises(ApiError) as exc:
        accept(ov, b, force=True)  # --force does not bypass the version rule
    assert (exc.value.status, code(exc)) == (409, "dataset_version_older")
    assert status(ov, b) == "staged" and dataset_writes.latest_accepted(ov, "kev")["id"] == a


def test_same_version_different_bytes_is_not_older(ov):
    a, b = stage(ov, tag="a"), stage(ov, tag="b")
    accept(ov, a)
    accept(ov, b)
    assert dataset_writes.latest_accepted(ov, "kev")["id"] == b


@pytest.mark.parametrize(
    ("old", "new"),
    [("2026.10.05", "weekly-42"), ("v1", "2026.10.06"), ("2026-13-45", "2026-10-06")],
)
def test_incomparable_versions_fail_closed(ov, old, new):
    a, b = stage(ov, tag="a", version=old), stage(ov, tag="b", version=new)
    accept(ov, a)
    with pytest.raises(ApiError) as exc:
        accept(ov, b)
    assert (exc.value.status, code(exc)) == (409, "dataset_version_incomparable")
    assert status(ov, b) == "staged"


def test_dash_and_dot_date_styles_compare_equal_by_date(ov):
    a, b = stage(ov, tag="a", version="2026.10.05"), stage(ov, tag="b", version="2026-10-06")
    accept(ov, a)
    accept(ov, b)
    assert dataset_writes.latest_accepted(ov, "kev")["id"] == b


def test_first_accept_has_no_churn_or_version_check(ov):
    accept(ov, stage(ov, n=1, version="weekly-42"))


@pytest.mark.parametrize(("new", "ok"), [(15, True), (5, True), (16, False), (4, False)])
def test_churn_beyond_half_is_refused_unless_forced(ov, new, ok):
    a = stage(ov, n=10, tag="a")
    accept(ov, a)
    b = stage(ov, n=new, tag="b", version="2026.10.02")
    if ok:
        accept(ov, b)
        return
    with pytest.raises(ApiError) as exc:
        accept(ov, b)
    assert (exc.value.status, code(exc)) == (409, "dataset_churn_exceeded")
    assert status(ov, b) == "staged" and audits(ov, "dataset.accept")[-1]["target"] == a
    accept(ov, b, force=True)
    detail = json.loads(audits(ov, "dataset.accept")[-1]["detail"])
    assert detail["force"] is True and detail["superseded"] == a


def test_churn_from_an_empty_accepted_import_needs_force(ov):
    a = stage(ov, n=1, tag="a")
    accept(ov, a)
    ov.execute("UPDATE dataset_imports SET entry_count=0 WHERE id=?", (a,))  # parsers refuse empty
    b = stage(ov, n=1, tag="b", version="2026.10.02")
    with pytest.raises(ApiError) as exc:
        accept(ov, b)
    assert code(exc) == "dataset_churn_exceeded"


def test_staged_payload_is_revalidated_on_accept(ov):
    imp = stage(ov)
    ov.execute(
        "UPDATE dataset_entries_staging SET payload='{\"cveID\":\"x\"}' WHERE key LIKE '%1000'"
    )
    with pytest.raises(ApiError) as exc:
        accept(ov, imp)
    assert (exc.value.status, code(exc)) == (409, "dataset_staged_invalid")
    assert status(ov, imp) == "staged" and audits(ov, "dataset.accept") == []


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM dataset_entries_staging WHERE key LIKE '%1000'",
        "UPDATE dataset_entries_staging SET key='CVE-2024-9999' WHERE key LIKE '%1000'",
        "UPDATE dataset_entries_staging SET payload='not json' WHERE key LIKE '%1000'",
        "UPDATE dataset_entries_staging SET payload='[]' WHERE key LIKE '%1000'",
    ],
)
def test_count_key_and_shape_mismatches_refuse_accept(ov, sql):
    imp = stage(ov)
    ov.execute(sql)
    with pytest.raises(ApiError) as exc:
        accept(ov, imp)
    assert code(exc) == "dataset_staged_invalid" and status(ov, imp) == "staged"


def test_urlhaus_staged_payload_is_revalidated(ov):
    data = (
        b'"1","2024-01-01 00:00:01","http://evil.example.com/a","online","d","malware_download",'
        b'"t","l","r"\n'
    )
    imp = stage(ov, source="urlhaus", data=data)
    ov.execute('UPDATE dataset_entries_staging SET payload=\'{"host":"other","threat":"t"}\'')
    with pytest.raises(ApiError) as exc:
        accept(ov, imp)
    assert code(exc) == "dataset_staged_invalid"
    ov.execute(
        'UPDATE dataset_entries_staging SET payload=\'{"host":"evil.example.com",'
        '"threat":"malware_download"}\''
    )
    accept(ov, imp)
    assert status(ov, imp) == "accepted"


@pytest.mark.parametrize("fn", ["accept", "reject"])
def test_failure_rolls_back_everything(ov, fn):
    imp = stage(ov)
    ov.execute(
        "CREATE TRIGGER boom BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'boom'); END"
    )
    with pytest.raises(sqlite3.DatabaseError):
        (accept if fn == "accept" else reject)(ov, imp)
    assert status(ov, imp) == "staged" and not ov.in_transaction
    assert (
        ov.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'dataset.a%'").fetchone()[0]
        == 0
    )


def test_supersede_is_rolled_back_with_a_failed_accept(ov):
    a = stage(ov, tag="a")
    accept(ov, a)
    b = stage(ov, tag="b", version="2026.10.02")
    ov.execute(
        "CREATE TRIGGER boom BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'boom'); END"
    )
    with pytest.raises(sqlite3.DatabaseError):
        accept(ov, b)
    assert dataset_writes.latest_accepted(ov, "kev")["id"] == a
    assert status(ov, b) == "staged"


def test_keyboard_interrupt_rolls_back(ov, monkeypatch):
    imp = stage(ov)

    def boom(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(dataset_writes, "_revalidate", boom)
    with pytest.raises(KeyboardInterrupt):
        accept(ov, imp)
    assert not ov.in_transaction and status(ov, imp) == "staged"
