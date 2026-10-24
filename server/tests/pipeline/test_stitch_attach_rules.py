"""Standing rules (T1/T2): attach only under an active rule into an explicit auto_inherit group,
re-read under the lock; rule parsing and malformed rows; identity_state gating; orphan cleanup;
overrides.db is never written."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import UTC, datetime

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401
from stitch_helpers import (
    MDNS,
    NOW,
    NOW_ABS,
    OLD,
    RULE,
    RULE_SNAP,
    Inv,
    Overrides,
    appear,
    candidates,
    device_of,
    dump,
    inv,  # noqa: F401
    kinds,
    mac,
    run,
    run_at,
    seeded,
    seeded_d,
    sig,
    source_of,
    suggestions,
)

from vigie_ingest.db import iso_utc
from vigie_pipeline import processor
from vigie_pipeline import stitch_apply as apply_mod
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import canonical_device, open_overrides_ro
from vigie_pipeline.processor import run_once
from vigie_pipeline.snapshot import EMPTY, OverridesUnreadable, Rule, Snapshot, load_snapshot
from vigie_pipeline.stitch import stitch
from vigie_pipeline.stitch_apply import apply_plan
from vigie_pipeline.stitch_compute import compute_plan
from vigie_pipeline.stitch_db import withdraw_orphan_suggestions
from vigie_pipeline.stitch_types import Attach


def link_of(data: Data, mac_addr: str):
    return data.q(
        "SELECT device_id, link_source, link_rule_id, link_score FROM observations WHERE mac=?",
        mac_addr,
    )[0]


def digest(ov: Overrides) -> str:
    return hashlib.sha256(ov.path.read_bytes()).hexdigest()


# ---- the attach --------------------------------------------------------------------------------


def test_rule_attaches_auto_inherit_device_and_retires_the_orphan(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 400, 1100)
    run(data)
    row = link_of(data, b)
    assert tuple(row)[:3] == (dev, "rule", RULE) and row[3] == 0.8  # opt55+opt60+hostname
    assert [r[0] for r in data.q("SELECT status FROM devices WHERE id<>?", dev)] == ["retired"]
    assert data.q("SELECT COUNT(*) FROM devices")[0][0] == 2  # never deleted
    (ev,) = kinds(data, "mac_attached")
    assert ev["device_id"] == dev and b not in ev["summary"]
    assert suggestions(data) == []
    ov.close()


def test_attach_is_idempotent_and_overrides_stay_byte_identical(data):
    ov, dev = seeded(data)
    appear(data, 2, 400, 1100)
    ov.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = digest(ov)
    run(data)
    snap = dump(data, "events", "observations", "devices", "rule_attachments")
    run(data)
    run(data)
    assert snap == dump(data, "events", "observations", "devices", "rule_attachments")
    assert digest(ov) == before
    assert ov.conn.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 1
    ov.close()


def test_auto_inherit_off_group_makes_a_confirm_suggestion_and_does_not_attach(data):
    ov, dev = seeded(data, group="trusted")
    b = appear(data, 2, 400, 1100)
    run(data)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    (s,) = suggestions(data)
    assert s["reason_code"] == "rule_hit_needs_confirm" and s["action"] == "merge_identity"
    assert s["reason_text"] is None
    assert json.loads(s["device_ids"]) == [device_of(data, b), dev]
    assert json.loads(s["basis"])[dev] == 3
    assert kinds(data, "mac_attached") == []
    ov.close()


@pytest.mark.parametrize("group", [None, "null-row", "ghost-group"])
def test_unassigned_or_unknown_group_needs_confirmation_not_attach(data, group):
    ov, dev = seeded(data, group=None)  # no device_overrides row at all
    if group == "null-row":
        ov.override(dev, None, version=2)
    elif group == "ghost-group":
        ov.conn.execute("PRAGMA foreign_keys=OFF")  # a dangling group reference
        ov.override(dev, "ghost-group")
    b = appear(data, 2, 400, 1200)
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    assert [s["reason_code"] for s in suggestions(data)] == ["rule_hit_needs_confirm"]
    ov.close()


@pytest.mark.parametrize(
    "kw",
    [{"revoked_at": "2026-10-02T00:00:00Z"}, {"expires_at": "2026-10-02T00:00:00Z"},
     {"expires_at": "not-a-date"}],
)  # fmt: skip
def test_revoked_or_expired_rules_do_not_attach(data, kw):
    ov, _ = seeded(data, rule_kw=kw)
    b = appear(data, 2, 400, 1100)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    ov.close()


def test_rule_with_future_expiry_is_active(data):
    ov, _ = seeded(data, rule_kw={"expires_at": "2099-01-01T00:00:00Z"})
    b = appear(data, 2, 400, 1100)
    run(data)
    assert link_of(data, b)["link_source"] == "rule"
    ov.close()


def test_invalid_or_incomplete_rule_signatures_are_ignored(data):
    ov, dev = seeded(data)
    ov.conn.execute("DELETE FROM identity_rules")
    ov.rule("r-noname", dev, {"opt55": "1,121,3,6,15,119,252", "opt60": "android-dhcp-14"})
    ov.rule("r-no60", dev, {"opt55": "1,121,3,6,15,119,252", "hostname": "Daves-Phone"})
    ov.conn.execute(
        "INSERT INTO identity_rules VALUES ('r-bad', ?, '{nope', 't', 'o', NULL, NULL)", (dev,)
    )
    b = appear(data, 2, 400, 1100)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    ov.close()


def test_signature_matching_two_rule_devices_attaches_nothing(data):
    ov, dev = seeded(data)
    other = appear(data, 5, 0, 300, opt55="[9]")  # a second device with another fingerprint
    run(data)
    ov.rule("22222222-rule", device_of(data, other), sig())  # same signature, other device
    b = appear(data, 2, 400, 1100)
    run(data)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    assert kinds(data, "mac_attached") == []
    assert len(kinds(data, "identity_candidate_ambiguous")) == 1
    assert not [s for s in suggestions(data) if device_of(data, b) in s["device_ids"]]
    ov.close()


def test_two_rules_for_the_same_device_still_attach(data):
    ov, dev = seeded(data)
    ov.rule("33333333-rule", dev, sig())
    b = appear(data, 2, 400, 1100)
    run(data)
    assert link_of(data, b)["device_id"] == dev
    ov.close()


@pytest.mark.parametrize(
    ("rule_sig", "kw"),
    [
        (sig(mdns_name="Daves Phone"), {"mdns": "Other Name"}),  # both names required
        (sig(opt60="some-other-dhcp-client"), {}),
        (sig(), {"host": "Someone-Elses-Phone"}),
        (sig(hostname=None, mdns_name=MDNS), {"mdns": "Other Name"}),
    ],
)
def test_rule_requires_every_named_field_to_match(data, rule_sig, kw):
    ov, dev = seeded(data, rule_sig=rule_sig)
    b = appear(data, 2, 400, 1200, **kw)
    run(data)
    assert link_of(data, b)["link_source"] == "self" and kinds(data, "mac_attached") == []
    ov.close()


def test_attach_follows_identity_links_to_the_canonical_device(data):
    ov, dev = seeded(data)
    z = appear(data, 6, 0, 100, opt55="[9]")
    run(data)
    ov.link(dev, device_of(data, z))
    ov.override(device_of(data, z), "iot", version=1)  # the canonical device decides the gate
    b = appear(data, 2, 400, 1100)
    run(data)
    assert link_of(data, b)["device_id"] == device_of(data, z)
    ov.close()


def test_revoking_a_rule_never_detaches_existing_attachments(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 400, 1100)
    run(data)
    ov.conn.execute("UPDATE identity_rules SET revoked_at='2026-10-03T00:00:00Z'")
    run(data)
    assert link_of(data, b)["link_source"] == "rule"
    assert kinds(data, "mac_detached") == []
    ov.close()


def test_without_any_rule_nothing_is_ever_attached(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 1100)
    appear(data, 3, 800, 900)
    run(data)
    assert {r[0] for r in data.q("SELECT link_source FROM observations")} == {"self"}
    assert data.q("SELECT COUNT(*) FROM devices WHERE status='retired'")[0][0] == 0
    assert candidates(data)  # candidates exist, but they grant nothing


def test_chain_of_rolled_macs_all_attach_to_the_rule_device_in_one_pass(data):
    ov, dev = seeded(data)
    macs = [appear(data, n, 400 + 800 * (n - 2), 1100 + 800 * (n - 2)) for n in (2, 3, 4)]
    run(data)
    assert {link_of(data, m)["device_id"] for m in macs} == {dev}
    assert len(kinds(data, "mac_attached")) == 3
    ov.close()


def test_pipeline_connection_to_overrides_is_read_only(data):
    ov, _ = seeded(data)
    conn = open_overrides_ro(ov.path)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("UPDATE groups SET auto_inherit=1")
    ov.close()


def test_rule_pointing_at_a_missing_device_attaches_nothing(data, caplog):
    appear(data, 1, 0, 300)
    run(data)
    ov = Overrides(data.root)
    ov.rule(RULE, "no-such-device", sig())
    b = appear(data, 2, 400, 1200)
    with caplog.at_level(logging.WARNING):
        run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    assert "rule_device_missing" in caplog.text
    ov.close()


def test_young_mac_is_deferred_without_events_then_attaches(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 400, 400)  # a single stamp: observed span below the grace window
    run(data)
    run(data)
    assert source_of(data, b) == "self"
    for kind in ("identity_overlap_veto", "identity_candidate_ambiguous", "mac_attached",
                 "stitch_deferred"):  # fmt: skip
        assert kinds(data, kind) == []
    appear(data, 2, 400, 1200)  # now observed for longer than the grace window, no overlap
    run(data)
    assert device_of(data, b) == dev and source_of(data, b) == "rule"
    ov.close()


# ---- identity_state gating ---------------------------------------------------------------------


@pytest.mark.parametrize("state", ["conflict", "pending_confirm"])
def test_target_identity_state_not_ok_needs_confirmation(data, state):
    ov, dev = seeded(data)
    data.inv.execute("UPDATE devices SET identity_state=? WHERE id=?", (state, dev))
    b = appear(data, 2, 400, 1200)
    run(data)
    assert source_of(data, b) == "self"
    (s,) = suggestions(data)
    assert s["reason_code"] == "rule_hit_needs_confirm"
    ov.close()


def test_candidates_own_identity_state_must_be_ok_for_a_rule_attach(data):
    a = appear(data, 1, 0, 900)
    b = appear(data, 2, 2000, 3000)
    run(data)  # no rule yet: a fingerprint suggestion only
    ov = Overrides(data.root)
    ov.rule(RULE, device_of(data, a), sig())
    ov.override(device_of(data, a), "iot", version=1)
    data.inv.execute(
        "UPDATE devices SET identity_state='conflict' WHERE id=?", (device_of(data, b),)
    )
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    assert len(suggestions(data)) == 1  # the earlier fingerprint_match one is kept, for a human
    ov.close()


# ---- the rule clock ----------------------------------------------------------------------------


def expiring_world(data: Data, expires: int):
    a = appear(data, 1, 0, 300)
    run_at(data, T0 + 301)
    ov = Overrides(data.root)
    dev = device_of(data, a)
    ov.rule(RULE, dev, sig(), expires_at=iso_utc(T0 + expires))
    ov.override(dev, "iot", version=3)
    ov.conn.commit()
    return ov


def slow_clock(monkeypatch, start: float, elapsed: float):
    state = {"t": start}
    monkeypatch.setattr(
        processor, "time", type("T", (), {"time": staticmethod(lambda: state["t"])})
    )
    real = processor._process_batches

    def slow(*a, **kw):
        out = real(*a, **kw)
        state["t"] += elapsed  # the batch backlog took this long
        return out

    monkeypatch.setattr(processor, "_process_batches", slow)


@pytest.mark.parametrize(("elapsed", "expect"), [(0, "rule"), (120, "self")])
def test_rule_expiry_is_judged_at_stitch_time_not_at_run_start(data, monkeypatch, elapsed, expect):
    n = 20000
    ov = expiring_world(data, n + 700)
    b = appear(data, 2, n - 1000, n)
    slow_clock(monkeypatch, T0 + n + 610, elapsed)
    run_once(PipelineConfig(data_dir=data.root))  # a live clock
    assert source_of(data, b) == expect
    ov.close()


def test_injected_now_pins_the_clock(data):
    n = 20000
    ov = expiring_world(data, n + 700)
    b = appear(data, 2, n - 1000, n)
    run_at(data, T0 + n + 610)
    assert source_of(data, b) == "rule"
    ov.close()


def expiring_inv(inv: Inv, expires: float):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    b = inv.mac("B", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    rule = Rule("r1", "D", "1,2,3", "x", "victim", None, expires)
    return b, Snapshot({}, (rule,), {"iot": 1}, {"D": (1, "iot")}, {})


def test_expiry_is_rechecked_with_the_clock_read_after_the_lock_is_held(inv):
    b, snap = expiring_inv(inv, NOW_ABS + 10)
    reads: list[bool] = []

    def clock():
        reads.append(inv.db.in_transaction)
        return NOW_ABS if len(reads) == 1 else NOW_ABS + 20  # expired once the lock is ours

    st = inv.stitch(snap, NOW_ABS, clock)
    assert reads[0] is False and reads[1] is True  # compute stamp, then the under-lock read
    assert st.attached == 0 and inv.link_of(b) == ("B", "self")


def test_expiry_boundary_is_exclusive(inv):
    b, snap = expiring_inv(inv, NOW_ABS + 10)
    assert inv.stitch(snap, NOW_ABS, lambda: NOW_ABS + 10).attached == 0  # == expiry: expired
    assert inv.stitch(snap, NOW_ABS, lambda: NOW_ABS + 9).attached == 1, b


# ---- the fresh overrides snapshot under the lock -----------------------------------------------


def ro(path) -> sqlite3.Connection:
    conn = open_overrides_ro(path)
    assert conn is not None
    return conn


def authorised_world(data):
    ov, dev = seeded_d(data, 300)
    ov.conn.commit()
    b = appear(data, 2, 4000, 4700)
    run_at(data, T0 + 4800)  # B is recorded but not yet mature
    return ov, dev, b


def late_stitch(data, ov_conn, snap):
    return stitch(data.inv, snap, PipelineConfig(data_dir=data.root), T0 + 6000, None, ov_conn)


@pytest.mark.parametrize(
    ("change", "attached"),
    [
        (None, 1),
        ("UPDATE identity_rules SET revoked_at='2026-10-02T00:00:00Z'", 0),
        ("UPDATE groups SET auto_inherit=0 WHERE id='iot'", 0),
        ("UPDATE device_overrides SET group_id=NULL", 0),
        ("UPDATE device_overrides SET group_id='guest'", 0),
    ],
)
def test_the_attach_rereads_the_rule_and_group_under_the_lock(data, change, attached):
    ov, dev, b = authorised_world(data)
    conn = ro(data.root / "overrides.db")
    snap = load_snapshot(conn, T0 + 6000)
    assert len(snap.rules) == 1 and snap.group_auto_inherit["iot"] == 1
    if change:
        ov.conn.execute(change)
        ov.conn.commit()
    assert late_stitch(data, conn, snap).attached == attached
    assert source_of(data, b) == ("rule" if attached else "self")
    ov.close()


def test_an_unreadable_overrides_db_at_attach_time_aborts_the_attach(data):
    ov, dev, b = authorised_world(data)
    conn = ro(data.root / "overrides.db")
    snap = load_snapshot(conn, T0 + 6000)
    ov.conn.execute("ALTER TABLE groups RENAME COLUMN auto_inherit TO auto_inherit_x")
    ov.conn.commit()
    assert late_stitch(data, conn, snap).attached == 0
    ov.close()


def test_run_once_hands_its_overrides_connection_to_the_attach_recheck(data, monkeypatch):
    ov, dev, b = authorised_world(data)
    real = processor.stitch

    def revoke_then_stitch(*args, **kwargs):
        ov.conn.execute("UPDATE identity_rules SET revoked_at='2026-10-02T00:00:00Z'")
        ov.conn.commit()  # revoked after the snapshot was read, before the attach
        return real(*args, **kwargs)

    monkeypatch.setattr(processor, "stitch", revoke_then_stitch)
    stats = run_at(data, T0 + 6000)
    assert stats.attached == 0 and source_of(data, b) == "self"
    ov.close()


def test_a_mac_moved_between_compute_and_apply_is_not_attached_twice(inv, monkeypatch):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], newdev=False)
    inv.mac("E", "victim", None, "self", OLD, [(NOW_ABS - 70000, NOW_ABS - 60000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    real = apply_mod.Applier._still_self

    def moved(self, m, dev):  # a human merged A away in the meantime
        inv.db.execute(
            "UPDATE observations SET device_id='E', link_source='human' WHERE mac=?", (a,)
        )
        return real(self, m, dev)

    monkeypatch.setattr(apply_mod.Applier, "_still_self", moved)
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.link_of(a) == ("E", "human")


# ---- T2 and fail-closed reading ----------------------------------------------------------------


def test_overrides_db_bytes_unchanged_across_an_attaching_run(data):
    ov, dev = seeded(data)
    ov.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = digest(ov)
    b = appear(data, 2, 400, 1200)
    run(data)
    assert device_of(data, b) == dev
    assert digest(ov) == before
    ov.close()


def seeded_snapshot(tmp_path, **rule_kw):
    ov = Overrides(tmp_path)
    ov.rule("r1", "dev-1", sig(), **{k: v for k, v in rule_kw.items() if k != "created_by"})
    if "created_by" in rule_kw:
        ov.conn.execute("UPDATE identity_rules SET created_by=?", (rule_kw["created_by"],))
    ov.close()
    return ro(tmp_path / "overrides.db")


@pytest.mark.parametrize("who", ["", "   "])
def test_rule_without_a_creator_is_ignored(tmp_path, who):
    assert load_snapshot(seeded_snapshot(tmp_path, created_by=who), NOW).rules == ()


def test_rule_with_a_creator_is_active(tmp_path):
    assert len(load_snapshot(seeded_snapshot(tmp_path), NOW).rules) == 1


@pytest.mark.parametrize("revoked", ["", " ", "2026-10-02T00:00:00Z", "garbage"])
def test_any_non_null_revoked_at_is_revoked(tmp_path, revoked):
    assert load_snapshot(seeded_snapshot(tmp_path, revoked_at=revoked), NOW).rules == ()


@pytest.mark.parametrize("expires", ["", "   "])
def test_blank_expires_at_ignores_the_rule(tmp_path, expires):
    assert load_snapshot(seeded_snapshot(tmp_path, expires_at=expires), NOW).rules == ()


def test_snapshot_expiry_boundary_is_exclusive(tmp_path):
    at = datetime(2026, 12, 1, tzinfo=UTC)
    conn = seeded_snapshot(tmp_path, expires_at=at.isoformat())
    assert len(load_snapshot(conn, at.timestamp() - 1).rules) == 1
    assert load_snapshot(conn, at.timestamp()).rules == ()


def raw_overrides(tmp_path, ddl: str, *inserts):
    path = tmp_path / "overrides.db"
    conn = sqlite3.connect(path)
    conn.executescript(ddl)
    for stmt in inserts:
        conn.execute(*((stmt,) if isinstance(stmt, str) else (stmt[0], (stmt[1],))))
    conn.commit()
    conn.close()
    return open_overrides_ro(path)


RULES_DDL = (
    "CREATE TABLE identity_rules (id TEXT, device_id TEXT, signature TEXT, created_at TEXT,"
    " created_by TEXT, expires_at TEXT, revoked_at TEXT);"
)


@pytest.mark.parametrize(
    ("ddl", "inserts"),
    [
        ("CREATE TABLE groups (id, auto_inherit);", ("INSERT INTO groups VALUES ('iot', 'yes')",)),
        ("CREATE TABLE identity_rules (id TEXT, device_id TEXT);", ()),
        (RULES_DDL, (("INSERT INTO identity_rules VALUES ('r', 'd', ?, 't', 'o', NULL, NULL)",
                      json.dumps(sig())),)),  # rules without a device_overrides table
        ("CREATE TABLE identity_rules (id TEXT);", ()),
    ],
)  # fmt: skip
def test_odd_overrides_shapes_fail_closed_and_leave_no_open_transaction(tmp_path, ddl, inserts):
    conn = raw_overrides(tmp_path, ddl, *inserts)
    with pytest.raises(OverridesUnreadable):
        load_snapshot(conn, NOW)
    assert not conn.in_transaction


def test_missing_device_overrides_in_a_live_run_skips_stitching(data, caplog):
    ov, _ = seeded(data)
    ov.conn.execute("DROP TABLE device_overrides")
    b = appear(data, 2, 400, 1200)
    with caplog.at_level(logging.ERROR):
        run(data)
    assert source_of(data, b) == "self"
    assert "stitching_skipped" in caplog.text
    ov.close()


def broken_overrides(root) -> None:
    conn = sqlite3.connect(root / "overrides.db")
    conn.execute("CREATE TABLE identity_links (from_device TEXT PRIMARY KEY)")  # no into_device
    conn.commit()
    conn.close()


def test_malformed_overrides_skips_stitching_but_keeps_cursor_progress(data, caplog):
    broken_overrides(data.root)
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    with caplog.at_level(logging.ERROR):
        stats = run_at(data, T0 + 7000)
    assert stats.batches == 2 and stats.suggestions == 0 and stats.attached == 0
    assert data.q("SELECT COUNT(*) FROM observations")[0][0] == 2
    assert data.q("SELECT COUNT(*) FROM pipeline_cursor")[0][0] == 1
    assert candidates(data) == [] and caplog.text.count("stitching_skipped") == 1
    assert run_at(data, T0 + 7100).batches == 0  # nothing reprocessed


def test_canonical_lookup_with_a_malformed_or_missing_table_returns_the_device(tmp_path, caplog):
    broken_overrides(tmp_path)
    conn = sqlite3.connect(tmp_path / "overrides.db")
    conn.row_factory = sqlite3.Row
    with caplog.at_level(logging.ERROR):
        assert canonical_device(conn, "dev") == "dev"
    assert "overrides_unreadable" in caplog.text
    caplog.clear()
    empty = sqlite3.connect(tmp_path / "empty.db")
    empty.row_factory = sqlite3.Row
    with caplog.at_level(logging.ERROR):
        assert canonical_device(empty, "dev") == "dev"
    assert caplog.text == ""


def break_groups(root) -> None:
    conn = sqlite3.connect(root / "overrides.db")
    conn.execute("ALTER TABLE groups RENAME COLUMN auto_inherit TO auto_inherit_x")
    conn.commit()
    conn.close()


def fix_groups(root) -> None:
    conn = sqlite3.connect(root / "overrides.db")
    conn.execute("ALTER TABLE groups RENAME COLUMN auto_inherit_x TO auto_inherit")
    conn.commit()
    conn.close()


def test_unreadable_overrides_writes_one_event_per_day_naming_the_error_class(data):
    appear(data, 1, 0, 300)
    Overrides(data.root).close()
    run_at(data, T0 + 400)
    assert kinds(data, "stitching_skipped") == []  # readable: no skip event
    break_groups(data.root)
    run_at(data, T0 + 500)
    run_at(data, T0 + 600)
    (event,) = kinds(data, "stitching_skipped")
    assert "OperationalError" in event["summary"] and event["severity"] == "warn"
    run_at(data, T0 + 500 + 86400)
    assert len(kinds(data, "stitching_skipped")) == 2


def test_merged_device_ranges_catch_up_after_an_unreadable_period(data):
    a = appear(data, 1, 0, 300)
    b = appear(data, 2, 400, 700, host="other", mdns="Other")
    run_at(data, T0 + 800)
    dev_a, dev_b = device_of(data, a), device_of(data, b)
    ov = Overrides(data.root)
    ov.link(dev_a, dev_b)
    ov.conn.commit()
    ov.close()
    break_groups(data.root)
    appear(data, 1, 900, 1000)
    run_at(data, T0 + 1100)
    last = "SELECT last_seen FROM devices WHERE id=?"
    assert data.q(last, dev_b)[0][0] < data.q(last, dev_a)[0][0]  # not widened while unreadable
    fix_groups(data.root)
    run_at(data, T0 + 1200)
    assert data.q(last, dev_b)[0][0] == data.q(last, dev_a)[0][0]


def test_snapshot_reads_run_inside_one_transaction(tmp_path):
    conn = seeded_snapshot(tmp_path)
    seen: list[str] = []
    conn.set_trace_callback(seen.append)
    load_snapshot(conn, NOW)
    conn.set_trace_callback(None)
    assert seen[0].upper().startswith("BEGIN") and seen[-1].upper() == "COMMIT"
    assert sum(s.upper().startswith("SELECT") for s in seen) >= 5
    assert not conn.in_transaction


def test_load_snapshot_maps_any_unexpected_exception_to_unreadable(tmp_path, monkeypatch):
    Overrides(tmp_path).close()
    monkeypatch.setattr("vigie_pipeline.snapshot._read", lambda *a: 1 / 0)
    with pytest.raises(OverridesUnreadable):
        load_snapshot(ro(tmp_path / "overrides.db"), NOW)


# ---- malformed rule rows -----------------------------------------------------------------------


def snapshot_with(tmp_path, signature) -> Snapshot:
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('r','D',?,'t','owner')", (json.dumps(signature),),
    )  # fmt: skip
    ov.conn.commit()
    return load_snapshot(ro(tmp_path / "overrides.db"), NOW)


BASE = {"opt55": "1,121,3", "opt60": "android", "hostname": "victim"}


@pytest.mark.parametrize(
    "extra",
    [
        {"mdns_name": {"required": "Different Name"}},
        {"mdns_name": 5}, {"mdns_name": []}, {"mdns_name": True}, {"mdns_name": "   "},
        {"mdns_name": ""}, {"hostname": 5}, {"hostname": ["a"]}, {"hostname": " "},
        {"opt60": 7}, {"opt60": {}}, {"opt60": ""}, {"opt55": "abc"}, {"opt55": "1,,2"},
        {"opt55": "1, 2"}, {"opt55": [1, "x"]}, {"opt55": [True]}, {"opt55": {}}, {"opt55": []},
        {"opt55": 5}, {"opt55": ""},
    ],
)  # fmt: skip
def test_a_supplied_field_of_the_wrong_type_rejects_the_whole_rule(tmp_path, extra):
    snap = snapshot_with(tmp_path, {**BASE, **extra})
    assert snap.rules == () and snap.malformed_rules == 1 and snap.malformed_devices == {"D"}


@pytest.mark.parametrize(
    "sigdict",
    [BASE, {**BASE, "mdns_name": None},
     {"opt55": [1, 121, 3], "opt60": "android", "mdns_name": "Dave"},
     {**BASE, "extra_ignored": {"any": "thing"}}],
)  # fmt: skip
def test_absent_or_null_fields_and_valid_values_are_fine(tmp_path, sigdict):
    snap = snapshot_with(tmp_path, sigdict)
    assert len(snap.rules) == 1 and snap.malformed_rules == 0


def test_an_incomplete_signature_is_ignored_not_malformed(tmp_path):
    snap = snapshot_with(tmp_path, {"opt55": "1,2", "opt60": "x"})  # no name at all
    assert snap.rules == () and snap.malformed_rules == 0


@pytest.mark.parametrize("raw", ["not json", '"a string"', "[1, 2]", "42", "null", ""])
def test_a_signature_that_is_not_a_json_object_is_malformed_and_names_its_target(tmp_path, raw):
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('r','D',?,'t','owner')", (raw,),
    )  # fmt: skip
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert snap.rules == () and snap.malformed_rules == 1 and snap.malformed_devices == {"D"}


def test_a_deeply_nested_signature_is_skipped_not_fatal(tmp_path):
    ov = Overrides(tmp_path)
    ov.rule("good", "D", sig())
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('deep','D',?,'t','owner')", ("[" * 200_000 + "]" * 200_000,),
    )  # fmt: skip
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert [r.id for r in snap.rules] == ["good"] and snap.malformed_rules == 1


@pytest.mark.parametrize("device_id", [b"\x00\x01", "", "   "])
def test_a_rule_with_a_non_string_or_blank_device_id_is_skipped(tmp_path, device_id):
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('bad',?,?,'t','owner')", (device_id, json.dumps(sig())),
    )  # fmt: skip
    ov.rule("good", "D", sig())
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert [r.id for r in snap.rules] == ["good"] and snap.malformed_rules == 1


def test_a_rule_with_a_blob_id_is_skipped(tmp_path):
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES (?, 'D', ?, 't', 'owner')", (b"\xff", json.dumps(sig())),
    )  # fmt: skip
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert snap.rules == () and snap.malformed_rules == 1


def test_a_link_with_a_blob_endpoint_fails_the_whole_snapshot_closed(tmp_path):
    ov = Overrides(tmp_path)
    ov.conn.execute("PRAGMA ignore_check_constraints=ON")
    ov.conn.execute(
        "INSERT INTO identity_links (from_device, into_device, merge_id, created_at, created_by)"
        " VALUES (?, 'E', 'm', 't', 'owner')", (b"\x01",),
    )  # fmt: skip
    ov.conn.commit()
    with pytest.raises(OverridesUnreadable):
        load_snapshot(ro(tmp_path / "overrides.db"), NOW)


def test_a_weakened_rule_cannot_attach_a_different_mdns_name(data):
    ov, dev = seeded_d(data, 300)
    ov.conn.execute("DELETE FROM identity_rules")
    ov.rule("weak", dev, {**sig(), "mdns_name": {"required": "Different Name"}})
    ov.conn.commit()
    b = appear(data, 2, 4000, 4700, mdns="Another Name")
    run_at(data, T0 + 6000)
    assert source_of(data, b) == "self" and len(kinds(data, "rule_malformed")) == 1
    ov.close()


def test_a_rule_with_a_blob_device_does_not_abort_the_run_and_makes_hits_suggestions(data):
    ov, dev = seeded_d(data, 300)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('blob',?,?,'t','owner')", (b"\x00", json.dumps(sig())),
    )  # fmt: skip
    ov.conn.commit()
    b = appear(data, 2, 4000, 4700)
    run_at(data, T0 + 6000)  # must not raise; the unreadable target makes every hit a suggestion
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    (s,) = suggestions(data)
    assert (s["reason_code"], s["reason_text"]) == ("rule_hit_needs_confirm", "malformed_target")
    assert len(kinds(data, "rule_malformed")) == 1
    run_at(data, T0 + 6100)
    assert len(kinds(data, "rule_malformed")) == 1  # once per day
    run_at(data, T0 + 6000 + 86400)
    assert len(kinds(data, "rule_malformed")) == 2
    ov.close()


def test_a_malformed_rule_on_a_target_turns_a_valid_attach_into_a_suggestion(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    snap = Snapshot({}, RULE_SNAP.rules, {"iot": 1}, {"D": (1, "iot")}, {}, 1, frozenset({"D"}))
    st = inv.stitch(snap)
    assert st.attached == 0 and inv.link_of(a) == ("A", "self") and st.suggestions == 1
    row = inv.db.execute("SELECT reason_code, reason_text FROM suggestions").fetchone()
    assert tuple(row) == ("rule_hit_needs_confirm", "malformed_target")
    assert inv.count("stitch_deferred") == 1


def test_a_malformed_target_is_matched_through_merges(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.mac("E", "elsewhere", None, "self", OLD, [], rand=0)
    snap = Snapshot(
        {"E": "D"}, RULE_SNAP.rules, {"iot": 1}, {"D": (1, "iot")}, {}, 1, frozenset({"E"})
    )  # the malformed rule sits on E, which is merged into D
    assert inv.stitch(snap).attached == 0 and inv.link_of(a) == ("A", "self")


# ---- the attach record and the orphan cleanup --------------------------------------------------


def two_rule_snap() -> Snapshot:
    rules = (
        Rule("r1", "D", "1,2,3", "x", "victim", None),
        Rule("r2", "D", "1,2,3", "x", None, "Dave"),
    )
    return Snapshot({}, rules, {"iot": 1}, {"D": (1, "iot")}, {})


def test_the_attach_records_every_matched_rules_fields_values_and_fingerprints(inv):
    inv.mac("D", "previous", "old", "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", "Dave", "self", "2026-01-02T00:00:00Z",
                [(NOW_ABS - 60000, NOW_ABS - 4000)])  # fmt: skip
    assert inv.stitch(two_rule_snap(), NOW_ABS - 3000).attached == 1
    row = inv.db.execute(
        "SELECT rule_id, target, hostname, mdns_name, opt55, opt60, views FROM rule_attachments"
        " WHERE mac=?", (a,),
    ).fetchone()  # fmt: skip
    assert tuple(row)[:6] == ("r1", "D", "victim", "Dave", "1,2,3", "x")
    assert json.loads(row["views"]) == [[False, True], [True, False]]


def test_the_attach_stores_the_hostname_of_a_matching_rule_that_is_not_the_lowest_id(inv):
    rules = (
        Rule("r1", "D", "1,2,3", "x", None, "Dave"),
        Rule("r2", "D", "1,2,3", "x", "victim", None),
    )
    snap = Snapshot({}, rules, {"iot": 1}, {"D": (1, "iot")}, {})
    inv.mac("D", "previous", "old", "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", "Dave", "self", "2026-01-02T00:00:00Z",
                [(NOW_ABS - 60000, NOW_ABS - 4000)])  # fmt: skip
    assert inv.stitch(snap, NOW_ABS - 3000).attached == 1
    row = inv.db.execute(
        "SELECT rule_id, hostname, mdns_name FROM rule_attachments WHERE mac=?", (a,)
    )
    assert tuple(row.fetchone()) == ("r1", "victim", "Dave")


def attach_unit(inv: Inv) -> str:
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    return a


def suggestion(inv: Inv, sid: str, pair: list[str], expires: int) -> None:
    inv.db.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES (?,'merge_identity',?,'{}','x','{}','t',?)",
        (sid, json.dumps(pair), iso_utc(expires)),
    )


def test_the_attach_expires_the_orphans_suggestions_in_both_directions_under_the_row_cap(
    inv, monkeypatch
):
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 10)
    a = attach_unit(inv)
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','X','A',0.9,'{}','suggested','t')"
    )
    suggestion(inv, "from", ["A", "D"], NOW_ABS + 10**6)
    suggestion(inv, "from2", ["A", "Q"], NOW_ABS + 10**6)
    suggestion(inv, "into", ["X", "A"], NOW_ABS + 10**6)
    suggestion(inv, "other", ["X", "Q"], NOW_ABS + 10**6)  # unrelated: untouched
    suggestion(inv, "gone", ["A", "R"], NOW_ABS - 10)  # already expired
    inv.commit()
    assert inv.stitch(RULE_SNAP).attached == 1 and inv.link_of(a) == ("D", "rule")
    rows = dict(inv.db.execute("SELECT id, expires_at FROM suggestions").fetchall())
    assert rows["from"] < iso_utc(NOW_ABS) and rows["from2"] < iso_utc(NOW_ABS)
    assert rows["into"] < iso_utc(NOW_ABS)
    assert rows["other"] == iso_utc(NOW_ABS + 10**6) and rows["gone"] == iso_utc(NOW_ABS - 10)
    assert (
        inv.db.execute("SELECT COUNT(*) FROM stitch_state WHERE key LIKE 'settle:%'").fetchone()[0]
        == 0
    )


def test_a_decided_suggestion_is_never_withdrawn_by_the_orphan_cleanup(inv):
    attach_unit(inv)
    suggestion(inv, "s1", ["A", "X"], NOW_ABS + 10**6)
    suggestion(inv, "into", ["X", "A"], NOW_ABS + 10**6)
    inv.commit()
    snap = Snapshot({}, (), {}, {}, {"s1": "accepted", "into": "rejected"})
    written, more, _cursor = withdraw_orphan_suggestions(inv.db, snap, "A", NOW_ABS, 100, {})
    assert (written, more) == (0, False)


def test_an_attach_to_a_retired_target_still_moves_the_mac(inv):
    a = attach_unit(inv)
    inv.db.execute("UPDATE devices SET status='retired' WHERE id='D'")
    inv.commit()
    assert inv.stitch(RULE_SNAP).attached == 1 and inv.link_of(a) == ("D", "rule")


def test_attaches_per_pass_are_capped_and_the_rest_follow(inv, monkeypatch):
    monkeypatch.setattr(apply_mod, "MAX_ATTACHES_PER_PASS", 2)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(5):
        inv.mac(f"A{k}", "victim", None, "self", f"2026-01-0{k + 2}T00:00:00Z",
                [(NOW_ABS - 70000 + k * 10000, NOW_ABS - 65000 + k * 10000)])  # fmt: skip
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 2 and st.capped >= 3
    inv.stitch(RULE_SNAP, NOW_ABS + 1)
    inv.stitch(RULE_SNAP, NOW_ABS + 2)
    assert inv.count("mac_attached") == 5


def test_a_mac_without_an_anchor_is_never_attached_by_a_rule(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    b = inv.mac("B", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.db.execute("DELETE FROM mac_first_received WHERE mac=?", (b,))
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.link_of(b) == ("B", "self")
    inv.db.execute(
        "INSERT INTO mac_first_received (mac, received) VALUES (?, ?)", (b, NOW_ABS - 10**6)
    )
    assert inv.stitch(RULE_SNAP).attached == 1


def test_veto_peers_cover_every_matched_rule(data):
    a = appear(data, 1, 0, 300)
    run(data)
    ov = Overrides(data.root)
    dev = device_of(data, a)
    ov.rule("a-rule", dev, sig())  # hostname rule
    ov.rule("b-rule", dev, sig(hostname=None, mdns_name=MDNS))  # mDNS rule
    d = appear(data, 3, 0, 1500, host="Other-Host")  # matches only b-rule, long-lived
    b = appear(data, 2, 100, 1500)  # matches both; overlaps d for 1400 s
    run(data)
    assert source_of(data, b) == "self" and source_of(data, d) == "self"
    assert kinds(data, "mac_attached") == []
    ov.close()


def test_mdns_rule_attaches_a_matching_mac_that_overlaps_nothing(data):
    ov, _ = seeded(data, rule_sig=sig(hostname=None, mdns_name=MDNS))
    c = appear(data, 3, 1500, 2300)
    run(data)
    assert source_of(data, c) == "rule"
    ov.close()


def test_empty_unmigrated_overrides_behaves_like_no_rules(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    data.make_overrides()  # only identity_links exists
    run(data)
    assert len(suggestions(data)) == 1


def test_stats_name_the_attach(data):
    ov, _ = seeded(data)
    appear(data, 2, 400, 1100)
    assert run(data).attached == 1
    assert EMPTY.rules == () and mac(2).startswith("ae:")
    ov.close()


# ---- fix round 1 -------------------------------------------------------------------------------


def test_a_malformed_rule_with_a_blob_id_still_names_its_target(tmp_path):
    ov = Overrides(tmp_path)
    ov.rule("good", "D", sig())
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES (?, 'D', ?, 't', 'owner')", (b"\xff", json.dumps(sig())),
    )  # fmt: skip
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert [r.id for r in snap.rules] == ["good"] and snap.malformed_rules == 1
    assert snap.malformed_devices == {"D"} and snap.unknown_target is False


def test_a_malformed_rule_whose_target_cannot_be_read_makes_every_rule_hit_a_suggestion(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    snap = Snapshot({}, RULE_SNAP.rules, {"iot": 1}, {"D": (1, "iot")}, {}, 1, frozenset(), True)
    st = inv.stitch(snap)
    assert st.attached == 0 and st.suggestions == 1 and inv.link_of(a) == ("A", "self")
    assert inv.db.execute("SELECT reason_text FROM suggestions").fetchone()[0] == "malformed_target"


@pytest.mark.parametrize("device_id", [b"\x00\x01", "", "   "])
def test_an_unreadable_target_is_reported_on_the_snapshot(tmp_path, device_id):
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('bad',?,?,'t','owner')", (device_id, json.dumps(sig())),
    )  # fmt: skip
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert snap.malformed_rules == 1 and snap.unknown_target is True


def test_a_dismissal_between_compute_and_apply_cancels_the_attach(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','A','D',0.8,'{}','open','t')"
    )
    inv.commit()
    plan = compute_plan(inv.db, RULE_SNAP, inv.cfg, NOW_ABS)
    assert any(isinstance(d, Attach) for d in plan.decisions)
    inv.db.execute("UPDATE identity_candidates SET state='dismissed' WHERE id='c1'")  # a human
    st = apply_plan(inv.db, RULE_SNAP, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert st.attached == 0 and st.stale == 1 and inv.link_of(a) == ("A", "self")
    assert inv.stitch(RULE_SNAP).attached == 1  # recomputed against the new state


def test_the_cleanup_of_an_orphans_candidate_rows_is_budgeted_and_finishes_later(inv, monkeypatch):
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 200)
    a = attach_unit(inv)
    inv.db.executemany(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES (?, 'A', ?, 0.8, '{}', 'open', 't')",
        ((f"c{i}", f"X{i}") for i in range(1000)),
    )
    for i in range(3):
        suggestion(inv, f"s{i}", ["A", f"X{i}"], NOW_ABS + 10**6)
    inv.commit()
    open_q = "SELECT COUNT(*) FROM identity_candidates WHERE state='open'"
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 1 and inv.link_of(a) == ("D", "rule")
    assert 900 <= inv.db.execute(open_q).fetchone()[0] < 1000  # at most half the cap per pass
    rows = inv.db.execute(
        "SELECT COUNT(*) FROM suggestions WHERE expires_at >= ?", (iso_utc(NOW_ABS),)
    )
    assert rows.fetchone()[0] == 0  # the suggestions are unactionable at once
    assert (
        inv.db.execute("SELECT COUNT(*) FROM stitch_state WHERE key LIKE 'settle:%'").fetchone()[0]
        == 1
    )
    for i in range(12):
        inv.stitch(RULE_SNAP, NOW_ABS + i + 1)
    assert inv.db.execute(open_q).fetchone()[0] == 0
    assert (
        inv.db.execute("SELECT COUNT(*) FROM stitch_state WHERE key LIKE 'settle:%'").fetchone()[0]
        == 0
    )


def test_the_lock_time_revalidation_does_not_depend_on_the_size_of_overrides(data):
    ov, dev, b = authorised_world(data)
    conn = ro(data.root / "overrides.db")
    snap = load_snapshot(conn, T0 + 6000)
    cfg = PipelineConfig(data_dir=data.root)

    def measure() -> int:
        steps = [0]
        conn.set_progress_handler(lambda: steps.__setitem__(0, steps[0] + 1) or 0, 1)
        plan = compute_plan(data.inv, snap, cfg, T0 + 6000)
        steps[0] = 0  # only the APPLY phase is measured
        apply_plan(data.inv, snap, cfg, T0 + 6000, lambda: T0 + 6000, conn, plan)
        conn.set_progress_handler(None, 0)
        return steps[0]

    small = measure()
    data.inv.execute(
        "UPDATE observations SET device_id=?, link_source='self' WHERE mac=?",
        (device_of(data, b), b),
    )
    assert source_of(data, b) == "self"
    ov.conn.execute("BEGIN")
    ov.conn.executemany(
        "INSERT INTO device_overrides (device_id, group_id, version, updated_at, updated_by)"
        " VALUES (?, 'guest', 1, 't', 'owner')", ((f"u{i}",) for i in range(10_000)),
    )  # fmt: skip
    ov.conn.executemany(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES (?, ?, ?, 't', 'owner')",
        ((f"r{i}", f"u{i}", json.dumps(sig(hostname=f"h{i}"))) for i in range(2_000)),
    )  # fmt: skip
    ov.conn.execute("COMMIT")
    snap = load_snapshot(conn, T0 + 6000)
    big = measure()
    assert small > 0 and big <= small * 2 + 2_000, (small, big)
    ov.close()


# ---- fix round 1, opus addendum: any write to overrides.db since the snapshot drops attaches


def snapshot_world(tmp_path):
    """A real overrides.db (rule r1 on D in iot) read through the pipeline's ro connection."""
    ov = Overrides(tmp_path)
    ov.rule("r1", "D", {"opt55": "1,2,3", "opt60": "x", "hostname": "victim"})
    ov.override("D", "iot", version=1)
    ov.conn.commit()
    conn = ro(tmp_path / "overrides.db")
    return ov, conn


def test_the_snapshot_records_the_overrides_identity_version(tmp_path):
    ov, conn = snapshot_world(tmp_path)
    snap = load_snapshot(conn, NOW)
    assert isinstance(snap.identity_version, int)
    assert snap.data_version is None
    assert load_snapshot(conn, NOW).identity_version == snap.identity_version  # nothing changed
    ov.override("Z", "guest", version=1)
    ov.conn.commit()
    assert load_snapshot(conn, NOW).identity_version != snap.identity_version
    ov.close()


def test_a_merge_between_compute_and_apply_cannot_launder_a_veto(inv, tmp_path):
    """Opus M2: a veto (B, X) exists; a human merges X into D after the plan was computed."""
    ov, conn = snapshot_world(tmp_path)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("X", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    b = inv.mac("B", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('v','B','X',0.8,'{}','vetoed','t')"
    )
    inv.commit()
    snap = load_snapshot(conn, NOW_ABS)
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    assert any(isinstance(d, Attach) for d in plan.decisions)
    ov.link("X", "D")  # the human merge lands between COMPUTE and APPLY
    ov.conn.commit()
    st = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, conn, plan)
    assert st.attached == 0 and st.stale == 1 and inv.link_of(b) == ("B", "self")
    fresh = load_snapshot(conn, NOW_ABS)  # the next pass sees the merge: the veto now covers D
    assert stitch(inv.db, fresh, inv.cfg, NOW_ABS + 1, None, conn).attached == 0
    assert inv.link_of(b) == ("B", "self")
    ov.close()


@pytest.mark.parametrize("change", [
    "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
    " VALUES ('r2','E','{\"opt55\":\"1,2,3\",\"opt60\":\"x\",\"hostname\":\"victim\"}','t','o')",
    "INSERT INTO identity_links (from_device,into_device,merge_id,created_at,created_by)"
    " VALUES ('D','E','m','t','o')",
    "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
    " VALUES ('bad','D','not json','t','o')",
    "UPDATE device_overrides SET group_id='trusted' WHERE device_id='D'",
])  # fmt: skip
def test_any_overrides_change_between_compute_and_apply_drops_the_attach(inv, tmp_path, change):
    """A second matching rule, a merge of the target, a malformed rule on it, a regroup: each
    appears after the snapshot and must not be applied against the old one (opus L4, A03)."""
    ov, conn = snapshot_world(tmp_path)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("E", "elsewhere", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    snap = load_snapshot(conn, NOW_ABS)
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    ov.conn.execute(change)
    ov.conn.commit()
    st = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, conn, plan)
    assert st.attached == 0 and st.stale == 1 and inv.link_of(a) == ("A", "self")
    ov.close()


@pytest.mark.parametrize("device", ["D", "A"])
def test_an_identity_state_change_between_compute_and_apply_drops_the_attach(inv, device):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    plan = compute_plan(inv.db, RULE_SNAP, inv.cfg, NOW_ABS)
    inv.db.execute("UPDATE devices SET identity_state='conflict' WHERE id=?", (device,))
    st = apply_plan(inv.db, RULE_SNAP, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert st.attached == 0 and inv.link_of(a) == ("A", "self")


def test_a_veto_row_written_between_compute_and_apply_drops_the_attach(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    plan = compute_plan(inv.db, RULE_SNAP, inv.cfg, NOW_ABS)
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('v','A','D',0.8,'{}','vetoed','t')"
    )
    st = apply_plan(inv.db, RULE_SNAP, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert st.attached == 0 and st.stale == 1 and inv.link_of(a) == ("A", "self")


def test_an_unrelated_overrides_write_allows_the_attach_in_the_same_pass(inv, tmp_path):
    """Audit activity cannot delay an attach authorized by unchanged identity inputs."""
    ov, conn = snapshot_world(tmp_path)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    snap = load_snapshot(conn, NOW_ABS)
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    ov.conn.execute(
        "INSERT INTO audit_log (id, ts, principal, action, target) VALUES ('x','t','o','a','t')"
    )
    ov.conn.commit()
    st = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, conn, plan)
    assert st.attached == 1 and st.stale == 0
    assert inv.link_of(a) == ("D", "rule")
    ov.close()


# ---- fix round 2 (Codex) -------------------------------------------------------------------------


def test_identity_version_is_re_read_immediately_before_every_attach(inv, tmp_path, monkeypatch):
    """Two attaches in one pass; the API commits between them: the second is dropped, the pass
    ends for attaches."""
    ov, conn = snapshot_world(tmp_path)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a1 = inv.mac(
        "A1", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 60000, NOW_ABS - 59000)]
    )
    a2 = inv.mac("A2", "victim", None, "self", "2026-01-04T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    snap = load_snapshot(conn, NOW_ABS)
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    assert sum(isinstance(d, Attach) for d in plan.decisions) == 2
    real = apply_mod.save_attachment

    def commit_in_between(*args, **kwargs):  # right after the first attach's write
        real(*args, **kwargs)
        ov.conn.execute("UPDATE identity_rules SET revoked_at='t'")
        ov.conn.commit()

    monkeypatch.setattr(apply_mod, "save_attachment", commit_in_between)
    st = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, conn, plan)
    assert st.attached == 1 and st.stale == 1
    assert inv.link_of(a1) == ("D", "rule") and inv.link_of(a2) == ("A2", "self")
    ov.close()


@pytest.mark.parametrize("change", [
    "UPDATE identity_rules SET revoked_at='t'",
    "UPDATE identity_rules SET expires_at='2000-01-01T00:00:00Z'",
    "UPDATE groups SET auto_inherit=0 WHERE id='iot'",
    "UPDATE device_overrides SET group_id='trusted' WHERE device_id='D'",
])  # fmt: skip
def test_an_attachment_whose_rule_or_group_no_longer_authorises_it_is_flagged_next_pass(
    inv, tmp_path, change
):
    """The check-to-write window between overrides.db and inventory.db cannot be closed; an attach
    made in it is surfaced by the next pass (event only, never a detach)."""
    ov, conn = snapshot_world(tmp_path)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    assert stitch(inv.db, load_snapshot(conn, NOW_ABS), inv.cfg, NOW_ABS, None, conn).attached == 1
    assert inv.stitch(load_snapshot(conn, NOW_ABS), NOW_ABS + 1).suspect == 0  # still authorised
    ov.conn.execute(change)
    ov.conn.commit()
    st = stitch(inv.db, load_snapshot(conn, NOW_ABS + 2), inv.cfg, NOW_ABS + 2, None, conn)
    assert st.suspect == 1 and inv.link_of(a) == ("D", "rule")  # flagged, not detached
    row = inv.db.execute("SELECT summary FROM events WHERE kind='rule_attach_suspect'").fetchone()
    assert "no longer authorises" in row[0]
    assert (
        stitch(inv.db, load_snapshot(conn, NOW_ABS + 3), inv.cfg, NOW_ABS + 3, None, conn).suspect
        == 0
    )
    ov.close()


def test_orphan_suggestion_expiry_is_bounded_per_pass_and_finishes_later(inv, monkeypatch):
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 200)
    a = attach_unit(inv)
    inv.db.execute("BEGIN")
    for i in range(1000):
        suggestion(inv, f"s{i}", ["A", f"X{i}"], NOW_ABS + 10**6)
    for i in range(5):
        suggestion(inv, f"in{i}", [f"Y{i}", "A"], NOW_ABS + 10**6)
    inv.commit()
    live = "SELECT COUNT(*) FROM suggestions WHERE expires_at >= ?"
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 1 and inv.link_of(a) == ("D", "rule")
    left = inv.db.execute(live, (iso_utc(NOW_ABS + 100),)).fetchone()[0]
    assert 905 <= left <= 1005  # at most half the row cap of one pass was spent
    assert (
        inv.db.execute("SELECT COUNT(*) FROM stitch_state WHERE key LIKE 'settle:%'").fetchone()[0]
        == 1
    )
    for i in range(12):
        inv.stitch(RULE_SNAP, NOW_ABS + i + 1)
    assert inv.db.execute(live, (iso_utc(NOW_ABS + 100),)).fetchone()[0] == 0
    assert (
        inv.db.execute("SELECT COUNT(*) FROM stitch_state WHERE key LIKE 'settle:%'").fetchone()[0]
        == 0
    )


# ---- fix round 2 (opus) -------------------------------------------------------------------------


def test_an_unreadable_data_version_fails_closed(inv, tmp_path):
    ov, conn = snapshot_world(tmp_path)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    snap = load_snapshot(conn, NOW_ABS)
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    conn.close()  # the PRAGMA cannot be read any more
    st = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, conn, plan)
    assert st.attached == 0 and st.stale == 1 and inv.link_of(a) == ("A", "self")
    ov.close()


def test_any_malformed_rule_makes_every_rule_hit_a_suggestion(inv):
    """A malformed rule on ANOTHER device could have named this signature too: conservative."""
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    snap = Snapshot({}, RULE_SNAP.rules, {"iot": 1}, {"D": (1, "iot")}, {}, 1, frozenset({"Z"}))
    st = inv.stitch(snap)
    assert st.attached == 0 and st.suggestions == 1 and inv.link_of(a) == ("A", "self")
    assert inv.db.execute("SELECT reason_text FROM suggestions").fetchone()[0] == "malformed_target"


def test_the_orphan_cleanup_keeps_half_the_row_cap_for_decisions(inv, monkeypatch):
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 20)
    a = attach_unit(inv)
    inv.db.execute("BEGIN")
    inv.db.executemany(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES (?, 'A', ?, 0.8, '{}', 'open', 't')",
        ((f"c{i}", f"X{i}") for i in range(100)),
    )
    inv.db.executemany(  # rows where the orphan is the TARGET are settled too
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES (?, ?, 'A', 0.8, '{}', 'suggested', 't')",
        ((f"b{i}", f"Y{i}") for i in range(5)),
    )
    for i in range(6):  # six fresh pairs that need their own rows this pass
        inv.mac(f"O{i}", f"h{i}", None, "self", OLD, [(NOW_ABS - 90000 + i,) * 2])
        inv.mac(
            f"P{i}",
            f"h{i}",
            None,
            "self",
            f"2026-02-01T00:00:{i:02d}Z",
            [(NOW_ABS - 5000 + i,) * 2],
        )
    inv.commit()
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 1 and inv.link_of(a) == ("D", "rule")
    dismissed = inv.db.execute(
        "SELECT COUNT(*) FROM identity_candidates WHERE state='dismissed'"
    ).fetchone()[0]
    assert dismissed <= 10  # the cleanup took at most half the cap ...
    assert st.candidates >= 5  # ... and the fresh decisions still got rows
    for i in range(14):
        inv.stitch(RULE_SNAP, NOW_ABS + i + 1)
    open_rows = inv.db.execute(
        "SELECT COUNT(*) FROM identity_candidates WHERE (device_a='A' OR device_b='A')"
        " AND state IN ('open','suggested')"
    ).fetchone()[0]
    assert open_rows == 0


# ---- round 3 -----------------------------------------------------------------------------------


def test_decided_suggestions_inside_the_scan_window_do_not_hide_undecided_ones(inv):
    """Opus/Codex L1: 102 decided rows filled the LIMITed window, `more` came back False and the
    undecided ones stayed open with the settle key dropped."""
    attach_unit(inv)
    inv.db.execute("BEGIN")
    for i in range(102):
        suggestion(inv, f"d{i:03d}", ["A", f"X{i}"], NOW_ABS + 10**6)
    for i in range(5):
        suggestion(inv, f"u{i}", ["A", f"Y{i}"], NOW_ABS + 10**6)
    inv.commit()
    snap = Snapshot({}, (), {}, {}, {f"d{i:03d}": "rejected" for i in range(102)})
    written, more, cursor = withdraw_orphan_suggestions(inv.db, snap, "A", NOW_ABS, 100, {})
    assert (written, more) == (0, True)  # the window was all decided rows: the cursor moved on
    written, more, cursor = withdraw_orphan_suggestions(inv.db, snap, "A", NOW_ABS, 100, cursor)
    assert (written, more) == (5, False)
    live = inv.db.execute(
        "SELECT id FROM suggestions WHERE expires_at >= ? ORDER BY id", (iso_utc(NOW_ABS),)
    )
    assert [r[0] for r in live] == [f"d{i:03d}" for i in range(102)]  # decided rows untouched


def test_rule_expiry_is_read_again_before_each_attach_write(inv, tmp_path):
    """Codex L2: expiry does not change data_version, so the clock must be read per attach."""
    ov, conn = snapshot_world(tmp_path)
    ov.conn.execute("UPDATE identity_rules SET expires_at=?", (iso_utc(NOW_ABS + 1),))
    ov.conn.commit()
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a1 = inv.mac(
        "A1", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 60000, NOW_ABS - 59000)]
    )
    a2 = inv.mac("A2", "victim", None, "self", "2026-01-04T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    snap = load_snapshot(conn, NOW_ABS)
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    assert sum(isinstance(d, Attach) for d in plan.decisions) == 2
    reads = iter([NOW_ABS, NOW_ABS, NOW_ABS + 2])  # lock, first attach, second attach

    st = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: next(reads), conn, plan)
    assert (
        st.attached == 1 and inv.link_of(a1) == ("D", "rule") and inv.link_of(a2) == ("A2", "self")
    )
    ov.close()


# ---- round 4 -----------------------------------------------------------------------------------


def test_orphan_cleanup_cost_does_not_depend_on_the_number_of_decisions(inv):
    """Opus/Codex M1: the decided-id set used to be serialised into every cleanup statement."""
    attach_unit(inv)
    inv.db.execute("BEGIN")
    for i in range(300):
        suggestion(inv, f"s{i:04d}", ["A", f"X{i}"], NOW_ABS + 10**6)
    inv.commit()

    def steps(decisions: dict) -> int:
        count = [0]
        inv.db.set_progress_handler(lambda: count.__setitem__(0, count[0] + 1) or 0, 1)
        snap = Snapshot({}, (), {}, {}, decisions)
        inv.db.execute("BEGIN")
        written, more, cursor = withdraw_orphan_suggestions(inv.db, snap, "A", NOW_ABS, 50, {})
        inv.db.execute("ROLLBACK")
        inv.db.set_progress_handler(None, 0)
        assert (written, more) == (50, True)
        return count[0]

    small = steps({"other": "rejected"})
    big = steps({f"z{i}": "rejected" for i in range(200_000)})
    assert big <= small * 2 + 100, (small, big)


def test_the_orphan_cleanup_cursor_advances_past_decided_rows(inv):
    attach_unit(inv)
    inv.db.execute("BEGIN")
    for i in range(102):
        suggestion(inv, f"d{i:03d}", ["A", f"X{i}"], NOW_ABS + 10**6)
    for i in range(5):
        suggestion(inv, f"u{i}", ["A", f"Y{i}"], NOW_ABS + 10**6)
    inv.commit()
    snap = Snapshot({}, (), {}, {}, {f"d{i:03d}": "rejected" for i in range(102)})
    written, more, cursor = withdraw_orphan_suggestions(inv.db, snap, "A", NOW_ABS, 50, {})
    assert written == 0 and more is True and cursor  # fifty decided rows examined, cursor moved
    total = written
    for _ in range(5):
        written, more, cursor = withdraw_orphan_suggestions(inv.db, snap, "A", NOW_ABS, 50, cursor)
        total += written
        if not more:
            break
    assert total == 5 and more is False
    live = inv.db.execute(
        "SELECT id FROM suggestions WHERE expires_at >= ? ORDER BY id", (iso_utc(NOW_ABS),)
    )
    assert [r[0] for r in live] == [f"d{i:03d}" for i in range(102)]
