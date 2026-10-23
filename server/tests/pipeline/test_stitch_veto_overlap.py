"""Fingerprint candidates, ambiguity, the overlap veto (union, tail, lead), sticky vetoes through
merges, safety peers derived from the rule and the target, and immutable suggestions."""

from __future__ import annotations

import json

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401
from stitch_helpers import (
    HOST,
    MDNS,
    NOW,
    NOW_ABS,
    OLD,
    OPT55,
    RULE,
    RULE_SNAP,
    Inv,
    Overrides,
    appear,
    candidates,
    device_of,
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
from vigie_pipeline.activity import merge_intervals, overlap_seconds
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.snapshot import EMPTY, Rule, Snapshot
from vigie_pipeline.stitch_db import upsert_candidate, vetoed_between
from vigie_pipeline.stitch_hood import load_obs
from vigie_pipeline.stitch_types import components

TABLES = ("suggestions", "identity_candidates", "events")


# ---- candidates and suggestions ----------------------------------------------------------------


def test_interval_math():
    assert merge_intervals([(5, 6), (0, 1), (2, 3)], 1) == [(0, 3), (5, 6)]
    assert overlap_seconds([(0, 10), (20, 30)], [(5, 25)]) == 10


def test_sequential_rolling_makes_one_suggestion_into_the_older_device(data):
    a = appear(data, 1, 0, 300)
    b = appear(data, 2, 400, 700)
    stats = run(data)
    (s,) = suggestions(data)
    da, db = device_of(data, a), device_of(data, b)
    assert s["action"] == "merge_identity" and s["reason_code"] == "fingerprint_match"
    assert s["reason_text"] is None
    assert json.loads(s["device_ids"]) == [db, da]
    payload = json.loads(s["payload"])
    assert payload["from_device"] == db and payload["into_device"] == da
    assert payload["score"] == 1.0
    assert json.loads(s["basis"]) == {da: 0, db: 0}  # overrides.db absent entirely => 0
    assert s["expires_at"] > s["created_at"]
    (c,) = candidates(data)
    assert (c["device_a"], c["device_b"], c["state"]) == (db, da, "suggested")
    assert json.loads(c["evidence"])["opt55"] == "1,121,3,6,15,119,252"
    assert len(kinds(data, "identity_candidate")) == 1
    assert stats.suggestions == 1
    assert all(r["link_source"] == "self" for r in data.q("SELECT link_source FROM observations"))


def test_rerun_is_idempotent(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    snap = [data.q(f"SELECT * FROM {t}") for t in TABLES]  # noqa: S608
    run(data)
    run(data)
    assert snap == [data.q(f"SELECT * FROM {t}") for t in TABLES]  # noqa: S608
    assert [c["state"] for c in candidates(data)] == ["suggested"]  # only newer -> older


@pytest.mark.parametrize(
    "kw",
    [
        {"opt60": "something-else"}, {"opt60": None}, {"opt55": "[1,3,6]"}, {"opt55": None},
        {"host": "other", "mdns": "Other"},  # fingerprint equal, names differ
        {"host": None, "mdns": None},
    ],
)  # fmt: skip
def test_weaker_than_full_signature_is_not_a_candidate(data, kw):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700, **kw)
    run(data)
    assert candidates(data) == [] and suggestions(data) == []


def test_hostname_alone_never_becomes_a_candidate(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700, opt55="[1,3,6]", opt60="other", mdns="Other")  # hostname equal
    appear(data, 3, 800, 900, opt55="[9]", opt60=None, host=HOST, mdns=MDNS)  # both names equal
    run(data)
    assert candidates(data) == [] and suggestions(data) == []


def test_mdns_only_name_match_is_a_candidate_and_the_threshold_gates_the_suggestion(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700, host="renamed")  # opt55+opt60+mdns = 0.8
    run(data, suggest_threshold=0.9)
    assert [c["state"] for c in candidates(data)] == ["open"] and suggestions(data) == []
    assert kinds(data, "identity_candidate") == []
    run(data, suggest_threshold=0.8)
    assert [c["state"] for c in candidates(data)] == ["suggested"] and len(suggestions(data)) == 1


def test_non_randomized_mac_is_never_the_candidate(data):
    appear(data, 1, 0, 300)
    static = "00:11:22:33:44:55"
    data.add_batch(
        T0 + 400,
        leases=[(static, HOST, OPT55, "android-dhcp-14")],
        sightings=[(static, "mdns", MDNS)],
        dns=[(static, T0 + 400)],
    )
    run(data)
    assert candidates(data) == [] and suggestions(data) == []


def test_an_older_device_with_no_retained_activity_still_gets_a_fingerprint_suggestion(inv):
    inv.mac("O", "VICTIM", "Dave", "self", OLD, [], rand=0)  # activity long purged, other case
    inv.mac("Z", "unrelated", None, "self", OLD, [])
    inv.mac("Y", "victim", "Dave", "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 500, NOW_ABS)])
    stats = inv.stitch()
    assert stats.suggestions == 1 and inv.state("Y") == [("O", "suggested")]


def test_two_concurrent_matching_devices_make_the_newcomer_ambiguous(data):
    appear(data, 1, 0, 1500)
    appear(data, 2, 0, 1500)  # identical twin, concurrent
    appear(data, 3, 2000, 2200)
    run(data)
    run(data)
    c3 = [c for c in candidates(data) if c["device_a"] == device_of(data, mac(3))]
    assert len(c3) == 2 and {c["state"] for c in c3} == {"ambiguous"}
    assert len(kinds(data, "identity_candidate_ambiguous")) == 1
    newcomer = device_of(data, mac(3))
    assert not [s for s in suggestions(data) if newcomer in s["device_ids"]]


# ---- the overlap veto --------------------------------------------------------------------------


def test_sustained_overlap_is_vetoed_once_with_no_suggestion(data):
    a = appear(data, 1, 0, 1500)
    b = appear(data, 2, 100, 1500)  # 1400 s concurrent > 600
    run(data)
    run(data)
    assert suggestions(data) == []
    assert [c["state"] for c in candidates(data)] == ["vetoed"]
    assert len(kinds(data, "identity_overlap_veto")) == 1
    assert kinds(data, "identity_overlap_veto")[0]["device_id"] in {
        device_of(data, a),
        device_of(data, b),
    }


def test_short_overlap_is_tolerated_and_the_grace_is_configurable(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 120, 600)  # 180 s overlap < 600 grace
    run(data)
    assert [c["state"] for c in candidates(data)] == ["suggested"]
    assert kinds(data, "identity_overlap_veto") == []
    run(data, overlap_grace_s=100)
    assert [c["state"] for c in candidates(data)] == ["vetoed"]
    assert all(s["expires_at"] < iso_utc(NOW) for s in suggestions(data))


def test_overlap_exactly_at_grace_is_tolerated(data):
    appear(data, 1, 0, 600)
    appear(data, 2, 0, 1260, mdns=MDNS)  # overlap 600; covered 1260, so below the half-covered rule
    run(data, overlap_grace_s=600)
    assert [c["state"] for c in candidates(data)] == ["suggested"]  # vetoed only when > grace


def test_veto_considers_all_macs_of_the_target_device(data):
    a = appear(data, 1, 0, 300)
    a2 = appear(data, 9, 0, 1500, opt55="[7]", opt60="x")  # other signature, same device via link
    b = appear(data, 2, 400, 1500)
    run(data)
    ov = Overrides(data.root)
    ov.link(device_of(data, a2), device_of(data, a))
    ov.close()
    data.inv.execute("DELETE FROM identity_candidates")
    data.inv.execute("DELETE FROM suggestions")
    run(data)
    assert [c["state"] for c in candidates(data)] == ["vetoed"]
    assert device_of(data, b) == candidates(data)[0]["device_a"]


def test_mature_candidate_wholly_inside_another_device_is_vetoed(data):
    appear(data, 1, 0, 3000)
    appear(data, 2, 1000, 2000)  # 1000 s covered (mature), wholly inside the peer
    run(data)
    assert suggestions(data) == [] and [c["state"] for c in candidates(data)] == ["vetoed"]


def test_candidate_almost_inside_another_device_is_not_vetoed(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 160, 160)  # widened to [10, 310]: overlap 290 < covered 300
    run(data)
    assert [c["state"] for c in candidates(data)] == ["suggested"]


def test_zero_overlap_is_never_vetoed_even_with_zero_covered_time(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 400)
    run(data, activity_gap_s=0)  # no widening: the stamp covers 0 s and overlaps 0 s
    assert [c["state"] for c in candidates(data)] == ["suggested"]


def test_loop_mode_passes_30s_apart_never_attach_a_fingerprint_copy(data):
    ov, _ = seeded(data, a_end=2400)
    for end in range(30, 1800, 30):  # the pipeline runs every 30 s while the copy stays online
        b = appear(data, 2, end - 30, end, step=10)
        run(data)
        assert source_of(data, b) == "self", f"attached at pass ending {end}"
    assert kinds(data, "mac_attached") == []
    assert len(kinds(data, "identity_overlap_veto")) == 1
    ov.close()


def test_sparse_attacker_at_301s_is_vetoed_not_attached(data):
    ov, _ = seeded(data, a_end=3100)
    b = appear(data, 2, 0, 3010, step=301)  # one stamp per interval: zero-length intervals
    run(data)
    assert source_of(data, b) == "self"
    assert kinds(data, "mac_attached") == []
    assert len(kinds(data, "identity_overlap_veto")) == 1
    ov.close()


def test_short_pulses_cannot_hide_below_the_gap(data):
    ov, _ = seeded(data, a_end=3100)
    b = appear(data, 2, 0, 10, step=5)
    for start in (301, 602, 903):
        b = appear(data, 2, start, start + 10, step=5)
    run(data)
    assert source_of(data, b) == "self"
    ov.close()


def test_sustained_overlap_with_the_rule_device_blocks_attach(data):
    ov, dev = seeded(data, a_end=1500)
    b = appear(data, 2, 100, 1500)  # 1400 s concurrent with A: a second device, not a roll
    run(data)
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    assert len(kinds(data, "identity_overlap_veto")) == 1 and suggestions(data) == []
    ov.close()


def test_overlap_veto_uses_the_whole_device(data):
    ov, dev = seeded(data)
    a_second = appear(data, 4, 0, 1500, opt55="[9]")  # same device by human link, long activity
    run(data)
    ov.link(device_of(data, a_second), dev)
    b = appear(data, 2, 100, 1400)
    run(data)
    assert source_of(data, b) == "self" and len(kinds(data, "identity_overlap_veto")) == 1
    ov.close()


def test_short_overlap_with_the_rule_device_attaches(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 150, 1100)  # 150 s concurrent with A (0..300)
    run(data)
    assert source_of(data, b) == "rule"
    ov.close()


# ---- tail and lead ----------------------------------------------------------------------------


def seed(data: Data, victim_end: int = 2880, step: int = 120):
    a = appear(data, 1, 0, victim_end, step=step)
    run(data)
    dev = device_of(data, a)
    ov = Overrides(data.root)
    ov.rule(RULE, dev, sig())
    ov.override(dev, "iot", version=1)
    return ov, dev


def test_tail_lead_attacker_is_vetoed_not_attached_and_the_victim_is_not_locked_out(data):
    ov, dev = seed(data)  # victim stamps every 120 s over [0, 2880]
    b = appear(data, 2, 2280, 2890, step=10)  # 610 s dense, 10 s lead past the victim's last stamp
    run(data)
    assert device_of(data, b) != dev and source_of(data, b) == "self"
    assert [r["state"] for r in candidates(data)] == ["vetoed"]
    assert len(kinds(data, "identity_overlap_veto")) == 1
    v = appear(data, 3, 2900, 6000, step=60)  # the victim's next MAC, after it truly left
    run(data)
    assert device_of(data, v) == dev  # nothing was attached to squat on the victim's device
    ov.close()


def _vs_victim_ending_at_1000(data: Data, attacker_start: int, attacker_end: int):
    a = appear(data, 1, 0, 1000, step=60)
    run(data)
    dev = device_of(data, a)
    ov = Overrides(data.root)
    ov.rule(RULE, dev, sig())
    ov.override(dev, "iot", version=1)
    c = appear(data, 2, attacker_start, attacker_end, step=30)
    run(data)
    ov.close()
    return dev, c


def test_small_own_time_lead_below_the_grace_overlap_is_vetoed(data):
    # covered 630 > grace, overlap 560 <= grace, but only 70 s of its own time: a tail lead
    dev, c = _vs_victim_ending_at_1000(data, 400, 1030)
    assert device_of(data, c) != dev and source_of(data, c) == "self"


def test_same_overlap_with_a_real_lead_still_attaches(data):
    dev, c = _vs_victim_ending_at_1000(data, 400, 1230)  # lead 270 s of its own time
    assert device_of(data, c) == dev and source_of(data, c) == "rule"


def test_established_peer_is_presumed_present_one_gap_past_its_last_stamp(data):
    ov, dev = seed(data)  # victim present [0, 2880]: established (longer than 2 x grace)
    b = appear(data, 2, 2280, 3200, step=30)  # 320 s past the last stamp, inside last stamp + gap
    run(data)
    assert device_of(data, b) != dev and source_of(data, b) == "self"
    c = appear(data, 3, 3300, 5000, step=30)  # entirely after last stamp + gap (3180)
    run(data)
    assert source_of(data, c) == "rule" and device_of(data, c) == dev
    ov.close()


@pytest.mark.parametrize(
    ("gap", "lead", "expect"),
    [(301, 150, True), (300, 150, False), (302, 150, True), (299, 150, False),
     (300, 149, True), (300, 100, True), (300, 151, False)],
)  # fmt: skip
def test_half_gap_lead_boundary_is_exact(inv, gap, lead, expect):
    inv.cfg = PipelineConfig(data_dir=inv.cfg.data_dir, activity_gap_s=gap)
    cand = inv.mac("C", "h", None, "self", OLD, [(NOW_ABS, NOW_ABS + 601)])
    peer = inv.mac("P", "h", None, "self", OLD, [(NOW_ABS - 100, NOW_ABS + 601 - lead)])
    cp, hood, _ = inv.hood(cand)  # covered 601 > grace 600, own lead as given
    assert cp.sustained(hood, cand, [peer]) is expect


# ---- safety peers: the rule and the target, never the applicant's extras -----------------------


def test_victims_new_mdns_only_mac_is_a_peer_even_without_a_hostname(data):
    ov, dev = seed(data, victim_end=300, step=60)
    v = appear(data, 3, 400, 4000, host=None, step=60)  # opt55/opt60 + mDNS only
    b = appear(data, 2, 1000, 2000, mdns=None, step=30)  # copies only the hostname
    run(data)
    assert device_of(data, b) != dev and source_of(data, b) == "self"
    assert device_of(data, v) != dev
    ov.close()


def test_unrelated_same_os_device_with_another_name_is_not_a_peer(data):
    ov, dev = seed(data, victim_end=300, step=60)
    appear(data, 3, 400, 4000, host="Someone-Elses-Phone", mdns="Other", step=60)
    b = appear(data, 2, 1000, 2000, step=30)
    run(data)
    assert device_of(data, b) == dev and source_of(data, b) == "rule"
    ov.close()


def test_victims_partial_match_mac_is_a_veto_peer(data):
    ov, _ = seeded(data, rule_sig=sig(mdns_name=MDNS))
    v2 = appear(data, 3, 400, 3000, mdns=None)  # victim's new MAC, mDNS not seen yet
    b = appear(data, 2, 400, 3000)  # a full-signature copy beside it
    run(data)  # a single pass must already veto
    assert source_of(data, b) == "self" and source_of(data, v2) == "self"
    assert kinds(data, "mac_attached") == []
    assert device_of(data, b) in {e["device_id"] for e in kinds(data, "identity_overlap_veto")}
    ov.close()


def extra_name_world(inv: Inv) -> str:
    """Hostname-only rule for D. D's old MAC: victim/Dave. V (the real device's current MAC):
    no hostname, mDNS Dave. A (the applicant): victim, and an extra mDNS 'Other' the rule never
    asked for."""
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW_ABS - 10000, NOW_ABS - 5000)], rand=0)
    inv.mac("V", None, "Dave", "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 4000, NOW_ABS)])
    return inv.mac(
        "A", "victim", "Other", "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)]
    )


def test_an_extra_applicant_name_cannot_exclude_the_real_device_from_the_veto(inv):
    a = extra_name_world(inv)
    st = inv.stitch(RULE_SNAP)
    assert inv.link_of(a) == ("A", "self") and st.attached == 0
    assert ("D", "vetoed") in inv.state("A") and inv.count("identity_overlap_veto") == 1


def test_a_legitimate_roll_with_the_rule_names_only_still_attaches(inv):
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", "Other", "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    assert inv.stitch(RULE_SNAP).attached == 1 and inv.link_of(a) == ("D", "rule")


def peer_world(inv: Inv, v_host, v_mdns, v_src="self", v_first="2026-01-03T00:01:00Z") -> str:
    """Hostname-only rule for D (old MAC victim/Dave); V overlaps the applicant A (victim/Other)."""
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("V", v_host, v_mdns, v_src, v_first, [(NOW_ABS - 3000, NOW_ABS)])
    return inv.mac(
        "A", "victim", "Other", "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)]
    )


@pytest.mark.parametrize(
    ("v_host", "v_mdns", "v_src"),
    [(None, "Elsewhere", "self"),  # only the hostname-only rule view does not contradict V
     ("renamed", "Dave", "self"),  # shares only D's mDNS name (the target's signature)
     ("victim", None, "rule")],  # not self-linked: only the view's name peers see it
)  # fmt: skip
def test_each_peer_source_alone_vetoes(inv, v_host, v_mdns, v_src):
    a = peer_world(inv, v_host, v_mdns, v_src)
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.link_of(a) == ("A", "self")


def test_view_name_peers_catch_a_peer_when_the_target_no_longer_has_the_rule_name(inv):
    inv.mac("D", "oldname", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("P", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    a = inv.mac("A", "victim", None, "self", "2026-03-01T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.link_of(a) == ("A", "self")


def test_a_rule_on_the_start_of_a_41_link_chain_still_vetoes_an_overlap_with_its_far_end(inv):
    links = {f"d{i}": f"d{i + 1}" for i in range(41)}
    inv.mac("d0", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("d40", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.mac("d41", "other", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    rule = Rule("r", "d0", "1,2,3", "x", "victim", None)
    snap = Snapshot(links, (rule,), {"iot": 1}, {"d41": (1, "iot")}, {})
    st = inv.stitch(snap)
    assert st.attached == 0 and inv.link_of(a) == ("A", "self")
    assert ("d41", "vetoed") in inv.state("A")  # decided against the COMPLETE chain's end


# ---- compatible peers need a reason ------------------------------------------------------------


def test_compatible_peer_selection(inv):
    c = inv.mac(
        "C", "victim", "Dave", "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS - 4000)]
    )
    same = inv.mac(
        "P1", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)]
    )
    mdns_only = inv.mac(
        "P2", None, "Dave", "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)]
    )
    other_host = inv.mac(
        "P3", "other", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)]
    )
    other_mdns = inv.mac("P5", "victim", "Elsewhere", "self", "2026-01-03T00:00:00Z",
                         [(NOW_ABS - 5000, NOW_ABS)])  # fmt: skip
    nameless_far = inv.mac(
        "P6", None, None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)]
    )
    nameless_near = inv.mac(
        "P7", None, None, "self", "2026-01-03T00:00:01Z", [(NOW_ABS - 5000, NOW_ABS)]
    )
    silent = inv.mac("P8", "victim", None, "self", "2026-01-03T00:00:00Z",
                     [(NOW_ABS - 20 * 86400, NOW_ABS - 19 * 86400)])  # fmt: skip
    ruled = inv.mac("C", "victim", None, "rule", "2026-01-03T00:00:00Z",
                    [(NOW_ABS - 5000, NOW_ABS)], newdev=False)  # fmt: skip
    got = inv.compatible(c)
    assert same in got and mdns_only in got and nameless_near in got
    assert other_host not in got and other_mdns not in got  # a contradicting name excludes
    assert nameless_far not in got  # no name, not first seen with the candidate
    assert silent not in got and ruled not in got  # not live self MACs


@pytest.mark.parametrize(
    ("offset", "expect"), [(300, True), (301, False), (-300, True), (-301, False)]
)
def test_a_nameless_mac_is_a_peer_only_within_a_gap_of_the_candidate(inv, offset, expect):
    c = inv.mac("C", "victim", None, "self", "2026-01-03T00:10:00Z", [(NOW_ABS - 500, NOW_ABS)])
    t = 600 + offset
    z = inv.mac("Z", None, None, "self", f"2026-01-03T00:{t // 60:02d}:{t % 60:02d}Z",
                [(NOW_ABS - 500, NOW_ABS)])  # fmt: skip
    assert (z in inv.compatible(c)) is expect


@pytest.mark.parametrize(("offset", "expect"), [(300, True), (301, False)])
def test_a_junk_named_mac_is_a_peer_only_within_a_gap_too(inv, offset, expect):
    c = inv.mac("C", "victim", None, "self", "2026-01-03T00:10:00Z", [(NOW_ABS - 500, NOW_ABS)])
    t = 600 + offset
    z = inv.mac("Z", None, "junk", "self", f"2026-01-03T00:{t // 60:02d}:{t % 60:02d}Z",
                [(NOW_ABS - 500, NOW_ABS)])  # fmt: skip
    assert (z in inv.compatible(c)) is expect


def test_a_mac_with_a_name_the_target_already_used_is_a_peer_at_any_time(inv):
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    c = inv.mac("C", "victim", None, "self", "2026-03-01T00:00:00Z", [(NOW_ABS - 500, NOW_ABS)])
    v = inv.mac("V", None, "dave", "self", "2026-09-01T00:00:00Z", [(NOW_ABS - 500, NOW_ABS)])
    j = inv.mac("J", None, "junk", "self", "2026-09-01T00:00:00Z", [(NOW_ABS - 500, NOW_ABS)])
    cp, hood, obs = inv.hood(c)
    cp._gather_peers(hood, "D", [obs])
    got = cp._compatible(hood, obs, hood.names_of("D"))
    assert v in got and j not in got


def test_a_mac_sharing_the_candidates_own_name_is_a_peer_at_any_time(inv):
    c = inv.mac("C", "victim", None, "self", "2026-03-01T00:00:00Z", [(NOW_ABS - 500, NOW_ABS)])
    v = inv.mac("V", "Victim", "x", "self", "2026-09-01T00:00:00Z", [(NOW_ABS - 500, NOW_ABS)])
    assert v in inv.compatible(c)


def test_a_distant_nameless_mac_is_no_peer_so_the_legit_roll_attaches(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z",
            [(NOW_ABS - 79000, NOW_ABS - 60000)], newdev=False)  # fmt: skip
    v2 = inv.mac(
        "V2", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 59000, NOW_ABS - 1000)]
    )
    inv.mac("Z", None, None, "self", OLD, [(NOW_ABS - 80000, NOW_ABS)])
    assert inv.stitch(RULE_SNAP).attached == 1 and inv.link_of(v2) == ("D", "rule")


def test_a_nameless_mac_first_seen_within_a_gap_of_the_candidate_is_a_peer(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    v2 = inv.mac(
        "V2", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 59000, NOW_ABS - 1000)]
    )
    inv.mac("Z", None, None, "self", "2026-01-03T00:04:00Z", [(NOW_ABS - 80000, NOW_ABS)])
    inv.stitch(RULE_SNAP)
    assert inv.state("V2") == [("D", "vetoed")] and inv.link_of(v2) == ("V2", "self")


def test_a_retired_peers_intervals_still_veto_by_name_and_by_pool(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    rn = inv.mac(
        "RN", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS - 100)]
    )
    rp = inv.mac(
        "RP", None, "other", "self", "2026-02-01T00:00:30Z", [(NOW_ABS - 3000, NOW_ABS - 100)]
    )
    inv.db.execute("UPDATE devices SET status='retired' WHERE id IN ('RN', 'RP')")
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.link_of(b) == ("B", "self")
    cp, hood, obs = inv.hood(b)
    cp._gather_peers(hood, "D", [obs])
    peers, _ = cp._safety_peers(hood, "D", [obs])
    assert {rn, rp} <= peers


# ---- vetoes are sticky and follow merges --------------------------------------------------------


def test_vetoed_pair_is_not_re_evaluated_and_fresh_stamps_never_launder_it(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 100000, NOW_ABS - 80000)], rand=0)
    a = inv.mac(
        "A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 90000, NOW_ABS - 85000)]
    )
    inv.stitch(RULE_SNAP, NOW_ABS - 84000)
    assert inv.state("A") == [("D", "vetoed")]
    inv.act(a, [(NOW_ABS - 75000 + i * 400,) * 2 for i in range(64)])  # alone for hours since
    inv.stitch(RULE_SNAP, NOW_ABS - 49000)
    assert inv.state("A") == [("D", "vetoed")] and inv.link_of(a) == ("A", "self")
    assert inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 0


def test_fingerprint_candidate_veto_is_sticky_too(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 100000, NOW_ABS - 80000)], rand=0)
    a = inv.mac(
        "A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 90000, NOW_ABS - 85000)]
    )
    inv.stitch(EMPTY, NOW_ABS - 84000)
    assert inv.state("A") == [("D", "vetoed")]
    inv.act(a, [(NOW_ABS - 75000 + i * 400,) * 2 for i in range(64)])
    inv.stitch(EMPTY, NOW_ABS - 49000)
    assert inv.state("A") == [("D", "vetoed")]
    assert inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 0


def test_upsert_never_rewrites_a_vetoed_row_but_a_human_dismissal_wins(inv):
    cid, _ = upsert_candidate(inv.db, "A", "D", 0.9, {}, "vetoed", NOW_ABS)
    assert upsert_candidate(inv.db, "A", "D", 0.9, {}, "suggested", NOW_ABS) == (cid, False)
    assert inv.state("A") == [("D", "vetoed")]
    inv.db.execute("UPDATE identity_candidates SET state='dismissed'")
    assert upsert_candidate(inv.db, "A", "D", 0.9, {}, "vetoed", NOW_ABS) == (cid, False)
    assert inv.state("A") == [("D", "dismissed")]


def test_a_mature_overlap_is_a_permanent_veto_that_only_a_human_dismissal_clears(data):
    ov, dev = seeded_d(data, 3000)
    b = appear(data, 2, 1000, 2000)  # 1000 s covered, wholly inside the device's presence
    run_at(data, T0 + 4000)
    assert [c["state"] for c in candidates(data)] == ["vetoed"] and source_of(data, b) == "self"
    run_at(data, T0 + 4100)
    assert [c["state"] for c in candidates(data)] == ["vetoed"]
    data.inv.execute("UPDATE identity_candidates SET state='dismissed'")  # the API's "clear"
    run_at(data, T0 + 4200)
    assert [c["state"] for c in candidates(data)] == ["dismissed"]
    assert source_of(data, b) == "self"  # the overlap is real: dismissal does not invent a clear
    ov.close()


def test_a_stale_veto_dismissed_by_a_human_lets_the_next_pass_attach(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','A','D',0.8,'{}','vetoed','t')"
    )
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.link_of(a) == ("A", "self")
    inv.db.execute("UPDATE identity_candidates SET state='dismissed' WHERE id='c1'")
    assert inv.stitch(RULE_SNAP).attached == 1 and inv.link_of(a) == ("D", "rule")


def test_dismissed_candidate_stays_dismissed(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700, host="renamed")  # score 0.8
    run(data)
    (s,) = suggestions(data)
    ov = Overrides(data.root)
    ov.decide(s["id"], "rejected")
    ov.close()
    run(data)
    assert [c["state"] for c in candidates(data)] == ["dismissed"]
    run(data, suggest_threshold=0.9)  # would otherwise fall back to 'open'
    assert [c["state"] for c in candidates(data)] == ["dismissed"]


def merged_veto_world(inv: Inv) -> str:
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 100000, NOW_ABS - 80000)], rand=0)
    inv.mac("E", "elsewhere", None, "self", OLD, [(NOW_ABS - 100000, NOW_ABS - 99000)], rand=0)
    a = inv.mac(
        "A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 50000, NOW_ABS - 40000)]
    )
    inv.db.execute(  # the historical veto (A, D): its overlap has long since left the window
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','A','D',0.8,'{}','vetoed','t')"
    )
    return a


def merged_snap(links: dict[str, str]) -> Snapshot:
    rule = Rule("r1", "E", "1,2,3", "x", "victim", None)
    return Snapshot(links, (rule,), {"iot": 1}, {"E": (1, "iot")}, {})


def test_a_permanent_veto_survives_its_target_being_merged(inv):
    a = merged_veto_world(inv)
    assert inv.stitch(merged_snap({"D": "E"})).attached == 0 and inv.link_of(a) == ("A", "self")


def test_without_the_merge_the_other_target_is_not_blocked_by_the_veto(inv):
    a = merged_veto_world(inv)
    assert inv.stitch(merged_snap({})).attached == 1 and inv.link_of(a) == ("E", "rule")


def test_a_veto_on_a_merged_candidate_device_also_blocks(inv):
    a = merged_veto_world(inv)
    inv.db.execute("UPDATE identity_candidates SET device_a='Aold'")
    inv.db.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('Aold','t','t')")
    inv.db.execute("UPDATE devices SET status='retired' WHERE id='Aold'")
    assert inv.stitch(merged_snap({"D": "E", "Aold": "A"})).attached == 0, a


def test_components_follow_chains_of_any_length_and_cycles():
    links = {f"d{i}": f"d{i + 1}" for i in range(100)} | {"x": "y", "y": "x", "q": "d0"}
    comp = components(links)
    assert comp["d100"] == comp["d0"] == comp["q"] and len(comp["d0"]) == 102
    assert comp["d100"] is comp["d0"]  # one shared set per component
    assert comp["x"] == frozenset({"x", "y"}) and "free" not in comp


def test_canonical_follows_the_complete_chain_of_any_length_and_survives_cycles():
    chain = {f"d{i}": f"d{i + 1}" for i in range(200)}
    snap = Snapshot(chain | {"x": "y", "y": "z", "z": "x", "w": "x"}, (), {}, {}, {})
    assert snap.canonical("d0") == snap.canonical("d150") == "d200"
    assert snap.canonical("d200") == "d200" and snap.canonical("free") == "free"
    assert snap.canonical("x") == snap.canonical("y") == snap.canonical("z")
    assert snap.canonical("w") == snap.canonical("x")


def test_a_veto_survives_a_merge_chain_longer_than_the_link_depth(inv):
    inv.mac("A", "victim", None, "self", OLD, [(NOW_ABS - 100, NOW_ABS)])
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('Ad0','A','d0',0.8,'{}','vetoed','t')"
    )
    links = {f"d{i}": f"d{i + 1}" for i in range(60)}
    cp = inv.compute(Snapshot(links, (), {}, {}, {}))
    hood = cp._hood()
    assert cp._veto_state(hood, "A", "d60") == "vetoed"
    assert cp._veto_state(hood, "A", "unrelated") is None


def test_vetoed_between_is_chunked_and_looked_up_from_the_smaller_side(inv):
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('v','a-39999','b-39999',0.8,'{}','vetoed','t')"
    )
    inv.commit()
    a = {f"a-{i}" for i in range(40_000)}
    b = {f"b-{i}" for i in range(40_000)}
    assert vetoed_between(inv.db, a, b) is True
    assert vetoed_between(inv.db, a - {"a-39999"}, b) is False
    assert vetoed_between(inv.db, set(), b) is False
    seen: list[str] = []
    inv.db.set_trace_callback(seen.append)
    vetoed_between(inv.db, frozenset({"A"}), b)
    vetoed_between(inv.db, b, frozenset({"A"}))
    inv.db.set_trace_callback(None)
    assert "device_a IN" in seen[0] and "device_b IN" in seen[1]
    plan = " ".join(
        r[3] for r in inv.db.execute(
            "EXPLAIN QUERY PLAN SELECT device_a FROM identity_candidates"
            " WHERE state='vetoed' AND device_b IN (?, ?)", ("x", "y"),
        )
    )  # fmt: skip
    assert "idx_candidates_b" in plan and "SCAN" not in plan


# ---- suggestions: basis, decisions, links, withdrawal --------------------------------------------


def test_basis_carries_current_override_versions(data):
    a = appear(data, 1, 0, 300)
    b = appear(data, 2, 400, 700)
    run(data)  # creates the devices
    data.inv.execute("DELETE FROM suggestions")
    data.inv.execute("DELETE FROM identity_candidates")
    ov = Overrides(data.root)
    ov.override(device_of(data, a), "trusted", version=4)
    ov.close()
    run(data)
    (s,) = suggestions(data)
    assert json.loads(s["basis"]) == {device_of(data, a): 4, device_of(data, b): 0}


def test_decided_pair_gets_no_new_suggestion(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    (s,) = suggestions(data)
    ov = Overrides(data.root)
    ov.decide(s["id"], "rejected")
    ov.close()
    data.inv.execute("UPDATE suggestions SET expires_at='2000-01-01T00:00:00Z'")
    run(data)
    assert len(suggestions(data)) == 1
    assert [c["state"] for c in candidates(data)] == ["dismissed"]


def test_open_suggestion_not_duplicated_but_expired_one_is_renewed(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    run(data)
    assert len(suggestions(data)) == 1
    data.inv.execute("UPDATE suggestions SET expires_at='2000-01-01T00:00:00Z'")
    run(data)
    assert len(suggestions(data)) == 2
    assert len(kinds(data, "identity_candidate")) == 1  # event once per pair


def test_existing_identity_link_means_no_suggestion(data):
    a = appear(data, 1, 0, 300)
    b = appear(data, 2, 400, 700)
    run(data)
    data.inv.execute("DELETE FROM suggestions")
    data.inv.execute("DELETE FROM identity_candidates")
    ov = Overrides(data.root)
    ov.link(device_of(data, b), device_of(data, a))
    ov.close()
    run(data)
    assert suggestions(data) == [] and candidates(data) == []


def test_vetoed_pair_withdraws_the_open_suggestion_but_a_decided_one_is_kept(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    (s,) = suggestions(data)
    assert s["expires_at"] > iso_utc(NOW)
    appear(data, 1, 300, 1700)  # now they are provably concurrent for 1300 s
    appear(data, 2, 700, 1700)
    run(data)
    (s,) = suggestions(data)
    assert s["expires_at"] < iso_utc(NOW) and candidates(data)[0]["state"] == "vetoed"
    run(data)
    assert len(suggestions(data)) == 1  # nothing new was created


def test_decided_suggestion_is_not_withdrawn(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    (s,) = suggestions(data)
    ov = Overrides(data.root)
    ov.decide(s["id"], "accepted")
    appear(data, 1, 300, 1700)
    appear(data, 2, 700, 1700)
    run(data)
    assert suggestions(data)[0]["expires_at"] == s["expires_at"]
    ov.close()


def test_ambiguous_pair_withdraws_the_open_suggestion(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    assert len(suggestions(data)) == 1
    appear(data, 3, 0, 300)  # a second old device with the same signature, concurrent with 1
    appear(data, 1, 300, 1700)
    appear(data, 3, 300, 1700)
    run(data)
    assert all(s["expires_at"] < iso_utc(NOW) for s in suggestions(data))
    assert len(kinds(data, "identity_candidate_ambiguous")) >= 1


def test_hostile_names_never_reach_logs_events_or_suggestion_payloads(data, caplog):
    hostile = 'evil"}\\u202e;DROP TABLE devices;--'
    appear(data, 1, 0, 300, host=hostile, mdns="mdns<script>alert(1)</script>")
    appear(data, 2, 400, 700, host=hostile, mdns="mdns<script>alert(1)</script>")
    with caplog.at_level("DEBUG"):
        run(data)
    blob = caplog.text + json.dumps([dict(r) for r in data.q("SELECT * FROM events")])
    blob += "".join(s["payload"] + s["reason_code"] for s in suggestions(data))
    assert "DROP TABLE" not in blob and "<script>" not in blob and "evil" not in blob
    (c,) = candidates(data)
    assert "DROP TABLE" in c["evidence"]  # full values live only in the evidence column


def test_unreadable_overrides_fails_closed_without_stopping_the_run(data, caplog):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    (data.root / "overrides.db").write_bytes(b"this is not a database" * 100)
    with caplog.at_level("ERROR"):
        stats = run(data)
    assert stats.batches == 2
    assert suggestions(data) == [] and candidates(data) == []
    assert "stitching_skipped" in caplog.text


def test_obs_view_of_a_mac(inv):
    m = inv.mac("D", "Host", "Name", "self", OLD, [(NOW_ABS - 100, NOW_ABS)])
    inv.commit()
    o = load_obs(inv.db, EMPTY, m)
    assert o is not None and (o.hostname, o.mdns, o.canon, o.retired) == (
        "Host",
        "Name",
        "D",
        False,
    )
    assert load_obs(inv.db, EMPTY, "no:such:mac") is None


# ---- fix round 2 (opus): one Unicode fold everywhere --------------------------------------------

NAMES = [
    ("Éloïse-iPhone", "éloïse-iphone"),
    ("Straße-PC", "STRASSE-PC"),
    ("Ødegaard", "ødegaard"),
    ("Σίσυφος", "ΣΊΣΥΦΟΣ"),  # final sigma folds like the others
    ("Yılmaz", "YıLMAZ"),  # dotless i is its own letter under Unicode casefold (not an I)
    ("Café", "Café"),  # NFC vs NFD
    ("Ｄaves-Phone", "daves-phone"),  # full-width D (NFKC)
]


@pytest.mark.parametrize(("stored", "seen"), NAMES)
def test_non_ascii_names_match_exactly_like_ascii_ones(data, stored, seen):
    appear(data, 1, 0, 300, host=stored, mdns=None)
    appear(data, 2, 400, 700, host=seen, mdns=None)
    run(data)
    assert [c["state"] for c in candidates(data)] == ["suggested"], (stored, seen)


@pytest.mark.parametrize(("stored", "seen"), NAMES)
def test_a_present_non_ascii_victim_still_vetoes_the_copy(data, stored, seen):
    appear(data, 1, 0, 1500, host=stored, mdns=None)
    appear(data, 2, 100, 1500, host=seen, mdns=None)  # 1400 s concurrent > grace
    run(data)
    assert [c["state"] for c in candidates(data)] == ["vetoed"], (stored, seen)


def test_a_fresh_non_ascii_roll_of_the_victim_vetoes_a_copy_under_a_rule(data):
    """Opus H1 e2e: the copy attached beside the present victim because every name-bucket lookup
    missed the Unicode name; the ASCII control was vetoed."""
    host = "Éloïse-iPhone"
    ov, dev = seeded(data, a_end=300, rule_sig=sig(hostname=host))
    data.inv.execute("UPDATE observations SET hostname=?", (host,))  # the seeded device too
    v = appear(data, 3, 1000, 4000, host=host, mdns=None)  # the victim's fresh roll
    b = appear(data, 2, 1400, 2400, host=host.lower(), mdns=None)  # the copy, beside it
    run(data)
    assert source_of(data, b) == "self" and device_of(data, b) != dev
    assert ("vetoed" in {c["state"] for c in candidates(data)}) or kinds(
        data, "rule_attach_suspect"
    )
    assert source_of(data, v) in ("self", "rule")
    ov.close()


def test_fold_is_one_function_for_python_and_sql(inv):
    from vigie_pipeline.stitch_types import fold

    for stored, seen in NAMES:
        assert fold(stored) == fold(seen), (stored, seen)
    m = inv.mac("D", "Éloïse-iPhone", "Straße", "self", OLD, [(NOW_ABS - 100, NOW_ABS)])
    inv.commit()
    row = inv.db.execute(
        "SELECT hostname_fold, mdns_fold FROM observations WHERE mac=?", (m,)
    ).fetchone()
    assert tuple(row) == (fold("Éloïse-iPhone"), fold("Straße"))
    sql = (
        "EXPLAIN QUERY PLAN SELECT mac FROM observations WHERE dhcp_fingerprint=?"
        " AND vendor_class=? AND hostname_fold=? ORDER BY last_seen DESC"
    )
    plan = " ".join(r[3] for r in inv.db.execute(sql, ("a", "b", "c")))
    assert "idx_obs_fp_host" in plan and "SCAN" not in plan
    assert "NOCASE" not in open("src/vigie_pipeline/stitch_hood.py").read()
