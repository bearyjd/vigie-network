"""Standing identity rules: attach, auto_inherit gating, ambiguity, veto, read-only overrides."""

from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest
from pipeline_helpers import Data, data  # noqa: F401
from stitch_helpers import (
    Overrides,
    appear,
    candidates,
    device_of,
    dump,
    kinds,
    run,
    sig,
    suggestions,
)

from vigie_pipeline.overrides import open_overrides_ro

RULE = "11111111-rule"


def seeded(data: Data, *, group: str | None = None, rule_kw: dict | None = None, a_end: int = 300):
    """Device A exists (mac 1), a human rule says its signature is A, optionally in `group`."""
    a = appear(data, 1, 0, a_end)
    run(data)
    ov = Overrides(data.root)
    dev = device_of(data, a)
    ov.rule(RULE, dev, sig(), **(rule_kw or {}))
    if group is not None:
        ov.override(dev, group, version=3)
    return ov, dev


def link_of(data: Data, mac_addr: str):
    return data.q(
        "SELECT device_id, link_source, link_rule_id, link_score FROM observations WHERE mac=?",
        mac_addr,
    )[0]


def digest(ov: Overrides) -> str:
    return hashlib.sha256(ov.path.read_bytes()).hexdigest()


def test_rule_attaches_unassigned_device_and_retires_the_orphan(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 400, 700)
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
    appear(data, 2, 400, 700)
    ov.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = digest(ov)
    run(data)
    snap = dump(data, "events", "observations", "devices")
    run(data)
    run(data)
    assert snap == dump(data, "events", "observations", "devices")
    assert digest(ov) == before
    groups = ov.conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
    assert (
        groups == 5 and ov.conn.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 0
    )
    ov.close()


def test_auto_inherit_group_attaches(data):
    ov, dev = seeded(data, group="iot")
    b = appear(data, 2, 400, 700)
    run(data)
    assert link_of(data, b)["link_source"] == "rule"
    ov.close()


def test_auto_inherit_off_group_makes_a_confirm_suggestion_and_does_not_attach(data):
    ov, dev = seeded(data, group="trusted")
    b = appear(data, 2, 400, 700)
    run(data)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    (s,) = suggestions(data)
    assert s["reason_code"] == "rule_hit_needs_confirm" and s["action"] == "merge_identity"
    assert json.loads(s["device_ids"]) == [device_of(data, b), dev]
    assert json.loads(s["basis"])[dev] == 3
    assert kinds(data, "mac_attached") == []
    ov.close()


@pytest.mark.parametrize(
    "kw",
    [
        {"revoked_at": "2026-10-02T00:00:00Z"},
        {"expires_at": "2026-10-02T00:00:00Z"},
        {"expires_at": "not-a-date"},
    ],
)
def test_revoked_or_expired_rules_do_not_attach(data, kw):
    ov, _ = seeded(data, rule_kw=kw)
    b = appear(data, 2, 400, 700)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    ov.close()


def test_rule_with_future_expiry_is_active(data):
    ov, _ = seeded(data, rule_kw={"expires_at": "2099-01-01T00:00:00Z"})
    b = appear(data, 2, 400, 700)
    run(data)
    assert link_of(data, b)["link_source"] == "rule"
    ov.close()


def test_invalid_rule_signatures_are_ignored(data):
    ov, dev = seeded(data)
    ov.conn.execute("DELETE FROM identity_rules")
    ov.rule("r-noname", dev, {"opt55": "1,121,3,6,15,119,252", "opt60": "android-dhcp-14"})
    ov.rule("r-no60", dev, {"opt55": "1,121,3,6,15,119,252", "hostname": "Daves-Phone"})
    ov.conn.execute(
        "INSERT INTO identity_rules VALUES ('r-bad', ?, '{nope', 't', 'o', NULL, NULL)", (dev,)
    )
    b = appear(data, 2, 400, 700)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    ov.close()


def test_signature_matching_two_rule_devices_attaches_nothing(data):
    ov, dev = seeded(data)
    other = appear(data, 5, 0, 300, opt55="[9]")  # a second device with another fingerprint
    run(data)
    ov.rule("22222222-rule", device_of(data, other), sig())  # same signature, other device
    b = appear(data, 2, 400, 700)
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
    b = appear(data, 2, 400, 700)
    run(data)
    assert link_of(data, b)["device_id"] == dev
    ov.close()


def test_rule_requires_every_named_field_to_match(data):
    ov, dev = seeded(data)
    ov.conn.execute("DELETE FROM identity_rules")
    ov.rule(RULE, dev, sig(mdns_name="Daves Phone"))  # hostname AND mdns_name both required
    b = appear(data, 2, 400, 700, mdns="Other Name")
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    ov.close()


def test_sustained_overlap_with_the_rule_device_blocks_attach(data):
    ov, dev = seeded(data, a_end=1500)
    b = appear(data, 2, 100, 1500)  # 1400 s concurrent with A: a second device, not a roll
    run(data)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    assert kinds(data, "mac_attached") == []
    assert len(kinds(data, "identity_overlap_veto")) == 1
    assert suggestions(data) == []
    ov.close()


def test_overlap_veto_uses_the_whole_device(data):
    ov, dev = seeded(data)
    a_second = appear(data, 4, 0, 1500, opt55="[9]")  # same device by human link, long activity
    run(data)
    ov.link(device_of(data, a_second), dev)
    b = appear(data, 2, 100, 1400)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    assert len(kinds(data, "identity_overlap_veto")) == 1
    ov.close()


def test_short_overlap_with_the_rule_device_attaches(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 150, 700)  # 150 s concurrent with A (0..300)
    run(data)
    assert link_of(data, b)["link_source"] == "rule"
    ov.close()


def test_attach_follows_identity_links_to_the_canonical_device(data):
    ov, dev = seeded(data)
    z = appear(data, 6, 0, 100, opt55="[9]")
    run(data)
    ov.link(dev, device_of(data, z))
    b = appear(data, 2, 400, 700)
    run(data)
    assert link_of(data, b)["device_id"] == device_of(data, z)
    ov.close()


def test_revoking_a_rule_never_detaches_existing_attachments(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 400, 700)
    run(data)
    ov.conn.execute("UPDATE identity_rules SET revoked_at='2026-10-03T00:00:00Z'")
    run(data)
    assert link_of(data, b)["link_source"] == "rule"
    ov.close()


def test_without_any_rule_nothing_is_ever_attached(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    appear(data, 3, 800, 900)
    run(data)
    assert {r[0] for r in data.q("SELECT link_source FROM observations")} == {"self"}
    assert data.q("SELECT COUNT(*) FROM devices WHERE status='retired'")[0][0] == 0
    assert candidates(data)  # candidates exist, but they grant nothing


def test_chain_of_rolled_macs_all_attach_to_the_rule_device(data):
    ov, dev = seeded(data)
    macs = [appear(data, n, 400 * (n - 1), 400 * (n - 1) + 300) for n in (2, 3, 4)]
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


def test_group_row_that_cannot_be_found_fails_closed(data):
    ov, dev = seeded(data)
    ov.conn.execute("PRAGMA foreign_keys=OFF")  # a dangling group reference
    ov.override(dev, "ghost-group")
    b = appear(data, 2, 400, 700)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    (s,) = suggestions(data)
    assert s["reason_code"] == "rule_hit_needs_confirm"
    ov.close()


def test_rule_with_a_different_opt60_does_not_match(data):
    ov, dev = seeded(data)
    ov.conn.execute("DELETE FROM identity_rules")
    ov.rule(RULE, dev, sig(opt60="some-other-dhcp-client"))
    b = appear(data, 2, 400, 700)
    run(data)
    assert link_of(data, b)["link_source"] == "self"
    ov.close()
