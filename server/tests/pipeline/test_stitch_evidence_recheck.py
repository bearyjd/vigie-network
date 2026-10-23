"""The post-attach re-check: attach-time evidence (names, fingerprints, per-rule views) is
immutable, the re-check flags (never detaches), incomplete evidence is itself flagged."""

from __future__ import annotations

import json

import pytest
from pipeline_helpers import data  # noqa: F401
from stitch_helpers import (
    NOW_ABS,
    OLD,
    RULE,
    RULE_SNAP,
    Inv,
    Overrides,
    appear,
    device_of,
    inv,  # noqa: F401
    kinds,
    run,
    sig,
    source_of,
)

from vigie_pipeline import stitch_hood
from vigie_pipeline.snapshot import EMPTY, Rule, Snapshot


def seed(data, victim_end: int = 2880, step: int = 120):
    a = appear(data, 1, 0, victim_end, step=step)
    run(data)
    dev = device_of(data, a)
    ov = Overrides(data.root)
    ov.rule(RULE, dev, sig())
    ov.override(dev, "iot", version=1)
    return ov, dev


def test_attached_mac_later_found_overlapping_is_flagged_never_detached(data):
    ov, dev = seed(data, victim_end=300, step=60)
    b = appear(data, 2, 1000, 2000, step=30)
    run(data)
    assert device_of(data, b) == dev and source_of(data, b) == "rule"
    appear(data, 3, 1200, 4000, step=60)  # the real victim's new MAC, concurrent with b
    before = (data.root / "overrides.db").read_bytes()
    run(data)
    suspects = kinds(data, "rule_attach_suspect")
    assert len(suspects) == 1 and suspects[0]["device_id"] == dev
    assert device_of(data, b) == dev and source_of(data, b) == "rule"  # trust is not rewritten
    run(data)
    assert len(kinds(data, "rule_attach_suspect")) == 1  # once per MAC
    assert kinds(data, "mac_detached") == []
    assert (data.root / "overrides.db").read_bytes() == before
    ov.close()


def test_clean_rule_attach_chain_raises_no_suspect(data):
    ov, dev = seed(data, victim_end=700, step=60)
    appear(data, 2, 760, 1800, step=60)
    run(data)
    assert len(kinds(data, "mac_attached")) == 1 and kinds(data, "rule_attach_suspect") == []
    ov.close()


# ---- the evidence is frozen at attach time ------------------------------------------------------


def attach_then_rename(inv: Inv, rename: str | None) -> str:
    inv.mac("D", "previous-name", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac(
        "A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 60000, NOW_ABS - 4000)]
    )
    assert inv.stitch(RULE_SNAP, NOW_ABS - 3000).attached == 1
    if rename:
        inv.db.execute("UPDATE observations SET hostname=? WHERE mac=?", (rename, a))
    inv.act(a, [(NOW_ABS - 3999, NOW_ABS)])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 4000, NOW_ABS)])
    return a


@pytest.mark.parametrize("rename", [None, "renamed-copy"])
def test_renaming_an_attached_copy_cannot_hide_a_later_overlap(inv, rename):
    attach_then_rename(inv, rename)
    st = inv.stitch(RULE_SNAP, NOW_ABS)
    assert st.suspect == 1 and inv.count("rule_attach_suspect") == 1


def test_the_evidence_survives_the_rule_being_revoked(inv):
    attach_then_rename(inv, "renamed-copy")
    revoked = Snapshot({}, (), {"iot": 1}, {"D": (1, "iot")}, {})
    assert inv.stitch(revoked, NOW_ABS).suspect == 1


def two_rule_snap() -> Snapshot:
    rules = (
        Rule("r1", "D", "1,2,3", "x", "victim", None),
        Rule("r2", "D", "1,2,3", "x", None, "Dave"),
    )
    return Snapshot({}, rules, {"iot": 1}, {"D": (1, "iot")}, {})


def attach_with_two_rules(inv: Inv) -> str:
    inv.mac("D", "previous", "old", "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac(
        "A", "victim", "Dave", "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 60000, NOW_ABS - 4000)]
    )
    assert inv.stitch(two_rule_snap(), NOW_ABS - 3000).attached == 1
    return a


def test_the_recheck_uses_both_rules_fields_after_a_rename(inv):
    a = attach_with_two_rules(inv)
    inv.db.execute("UPDATE observations SET hostname='x1', mdns_name='x2' WHERE mac=?", (a,))
    inv.act(a, [(NOW_ABS - 3999, NOW_ABS)])
    inv.mac(
        "V", None, "Dave", "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 4000, NOW_ABS)]
    )  # mdns only
    assert inv.stitch(two_rule_snap(), NOW_ABS).suspect == 1


def test_the_recheck_searches_the_attach_time_fingerprint_bucket(inv):
    a = attach_with_two_rules(inv)
    inv.db.execute("UPDATE observations SET dhcp_fingerprint='9,9' WHERE mac=?", (a,))
    inv.act(a, [(NOW_ABS - 3999, NOW_ABS)])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 4000, NOW_ABS)])
    assert inv.stitch(two_rule_snap(), NOW_ABS).suspect == 1


def test_each_matched_rules_view_is_stored_and_checked_separately(inv):
    a = attach_with_two_rules(inv)
    views = inv.db.execute("SELECT views FROM rule_attachments WHERE mac=?", (a,)).fetchone()[0]
    assert json.loads(views) == [[False, True], [True, False]]
    inv.act(a, [(NOW_ABS - 3999, NOW_ABS)])
    # no hostname, an mDNS name that contradicts the UNION but not the hostname-only view,
    # first seen within a gap of the attached MAC
    inv.mac("V", None, "Elsewhere", "self", "2026-01-02T00:01:00Z", [(NOW_ABS - 4000, NOW_ABS)])
    assert inv.stitch(two_rule_snap(), NOW_ABS).suspect == 1


def attached_world(inv: Inv, rule_id: str) -> str:
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("D", "victim", "Dave", "rule", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)],
                newdev=False)  # fmt: skip
    inv.db.execute("UPDATE observations SET link_rule_id=? WHERE mac=?", (rule_id, a))
    inv.attachment(a, rule_id, "D", "victim", None, [[True, False]])  # hostname-only rule
    inv.mac("V", None, "Elsewhere", "self", "2026-01-03T00:01:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    return a


def test_recheck_with_its_rule_uses_the_rule_names_only(inv):
    attached_world(inv, "r1")  # hostname-only rule: V (mDNS only, other name) is a peer
    assert inv.stitch(RULE_SNAP).suspect == 1


def test_an_extra_applicant_name_cannot_hide_a_suspect_from_the_recheck(inv):
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW_ABS - 10000, NOW_ABS - 5000)], rand=0)
    inv.mac("V", None, "Dave", "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 4000, NOW_ABS)])
    a = inv.mac("D", "victim", "Other", "rule", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)],
                newdev=False)  # fmt: skip
    inv.attachment(a, "r1", "D", "victim", None, [[True, False]])
    st = inv.stitch(RULE_SNAP)
    assert st.suspect == 1 and inv.count("rule_attach_suspect") == 1


def test_a_revoked_rules_attach_is_rechecked_against_the_persisted_evidence(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)],
                newdev=False)  # fmt: skip
    inv.db.execute(
        "UPDATE observations SET link_rule_id='gone', hostname='renamed' WHERE mac=?", (a,)
    )
    inv.attachment(a, "gone", "D", "victim", None, [[True, False]])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    assert inv.stitch(EMPTY).suspect == 1  # found via the stored hostname


def test_attachments_without_stored_fingerprints_use_the_current_ones(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)],
                newdev=False)  # fmt: skip
    inv.db.execute(
        "INSERT INTO rule_attachments (mac, rule_id, target, hostname, mdns_name, views,"
        " attached_at) VALUES (?, 'gone', 'D', 'victim', NULL, '[[true,false]]', 't')", (a,),
    )  # fmt: skip
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    assert inv.stitch(EMPTY).suspect == 1


def test_a_missing_attach_record_is_itself_flagged(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)],
                newdev=False)  # fmt: skip
    st = inv.stitch(EMPTY)
    assert st.suspect == 1
    row = inv.db.execute("SELECT summary FROM events WHERE kind='rule_attach_suspect'").fetchone()
    assert "evidence missing" in row[0] and inv.link_of(a) == ("D", "rule")


def test_a_recheck_subject_without_activity_in_retention_is_skipped(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [], newdev=False)
    assert inv.stitch(EMPTY).examined == 0 and inv.count("rule_attach_suspect") == 0


# ---- each peer source matters to the re-check --------------------------------------------------


def attached(inv: Inv, host="victim", mdns=None) -> str:
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac(
        "D", host, mdns, "rule", "2026-01-02T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)], newdev=False
    )
    inv.attachment(a, "r1", "D", host, mdns, [[True, False]])
    return a


def test_recheck_flags_overlap_with_a_compatible_mdns_only_peer(inv):
    attached(inv)
    inv.mac("V", None, "Dave", "self", "2026-01-02T00:01:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    assert inv.stitch(RULE_SNAP).suspect == 1  # only compatible_peers can see V (first seen
    # within a gap of the attached MAC)


def test_recheck_flags_overlap_with_a_same_name_rule_attached_mac_of_another_device(inv):
    attached(inv)
    inv.mac("E", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    e = inv.mac("E", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)],
                newdev=False)  # fmt: skip
    inv.attachment(e, "r1", "E", "victim", None, [[True, False]])
    # not a live self MAC (so not compatible) and another canonical device: only name_peers
    assert inv.stitch(RULE_SNAP).suspect == 2  # each of the two flags the other


def test_recheck_stays_quiet_for_a_clean_attach(inv):
    attached(inv)
    assert inv.stitch(RULE_SNAP).suspect == 0


def test_a_copy_attached_before_the_victim_is_flagged_when_the_victim_arrives(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 200000, NOW_ABS - 190000)], rand=0)
    copy = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z",
                   [(NOW_ABS - 100000 + i * 400,) * 2 for i in range(70)])  # fmt: skip
    st = inv.stitch(RULE_SNAP, NOW_ABS - 60000)
    assert st.attached == 1 and inv.link_of(copy) == ("D", "rule")
    inv.act(copy, [(NOW_ABS - 5000 + i * 400,) * 2 for i in range(13)])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    st = inv.stitch(RULE_SNAP, NOW_ABS)
    assert st.suspect == 1 and inv.count("rule_attach_suspect") == 1


def test_a_recheck_that_cannot_gather_complete_evidence_flags_the_attachment(inv, monkeypatch):
    """A spray of look-alikes around a rule-attached MAC pushes the victim out of the bounded
    lookup: the re-check cannot conclude, so it flags instead of staying silent."""
    monkeypatch.setattr(stitch_hood, "BUCKET_ROWS", 10)
    a = attached(inv)
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)],
            last_seen="2026-01-03T00:00:00Z")  # fmt: skip
    for i in range(12):  # newer last_seen than the victim: they fill the bounded lookup
        inv.mac(
            f"S{i}",
            "victim",
            None,
            "self",
            "2026-06-01T00:00:00Z",
            [],
            last_seen="2026-09-01T00:00:00Z",
        )
    st = inv.stitch(RULE_SNAP)
    assert st.suspect == 1 and inv.link_of(a) == ("D", "rule")
    row = inv.db.execute("SELECT summary FROM events WHERE kind='rule_attach_suspect'").fetchone()
    assert "evidence incomplete" in row[0]
