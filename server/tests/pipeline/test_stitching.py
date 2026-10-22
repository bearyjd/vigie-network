"""Identity stitching: activity, candidates, ambiguity, veto, suggestions (PRP section 8)."""

from __future__ import annotations

import json

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401
from stitch_helpers import (
    HOST,
    MDNS,
    OPT55,
    Overrides,
    appear,
    candidates,
    device_of,
    dump,
    kinds,
    run,
    suggestions,
)

from vigie_pipeline.activity import merge_intervals, overlap_seconds

TABLES = ("suggestions", "identity_candidates", "events")


def intervals(data, mac_addr):
    return [tuple(r) for r in data.q('SELECT start, "end" FROM mac_activity WHERE mac=?', mac_addr)]


# ---- activity intervals ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("gap", "expected"),
    [(300, [(0, 120), (1000, 1060)]), (2000, [(0, 1060)]), (879, [(0, 120), (1000, 1060)]),
     (880, [(0, 1060)])],  # a gap of exactly the threshold does not split
)  # fmt: skip
def test_activity_splits_on_gap_and_is_configurable(data, gap, expected):
    m = appear(data, 1, 0, 120, step=60)
    data.add_batch(T0 + 1000, dns=[(m, T0 + 1000), (m, T0 + 1060)])
    run(data, activity_gap_s=gap)
    assert intervals(data, m) == [(T0 + s, T0 + e) for s, e in expected]


def test_activity_idempotent_out_of_order_and_retention(data):
    m = appear(data, 1, 600, 720)
    run(data)
    before = intervals(data, m)
    data.add_batch(T0, dns=[(m, T0), (m, T0 + 60)])  # older batch arrives later
    run(data)
    assert intervals(data, m) == [(T0, T0 + 60), *before]
    data.add_batch(T0 + 300, dns=[(m, T0 + 300)])  # bridges the gap (<=5 min each side)
    run(data)
    assert intervals(data, m) == [(T0, T0 + 720)]
    run(data)
    assert intervals(data, m) == [(T0, T0 + 720)]
    # retention: 7 days after the interval end
    from vigie_pipeline.config import PipelineConfig
    from vigie_pipeline.processor import run_once

    run_once(PipelineConfig(data_dir=data.root), now=T0 + 720 + 7 * 86400 + 1)
    assert intervals(data, m) == []


def test_interval_math():
    assert merge_intervals([(5, 6), (0, 1), (2, 3)], 1) == [(0, 3), (5, 6)]
    assert overlap_seconds([(0, 10), (20, 30)], [(5, 25)]) == 10


# ---- candidates and suggestions ----------------------------------------------------------------


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
    snap = dump(data, *TABLES)
    run(data)
    run(data)
    assert snap == dump(data, *TABLES)


def test_older_mac_is_never_a_candidate_for_a_newer_one(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    assert [c["state"] for c in candidates(data)] == ["suggested"]  # only newer -> older


@pytest.mark.parametrize(
    "kw",
    [
        {"opt60": "something-else"},
        {"opt60": None},
        {"opt55": "[1,3,6]"},
        {"opt55": None},
        {"host": "other", "mdns": "Other"},  # fingerprint equal, names differ
        {"host": None, "mdns": None},
    ],
)
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


def test_mdns_only_name_match_is_a_candidate(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700, host="renamed")
    run(data)
    assert [c["state"] for c in candidates(data)] == ["suggested"]


def test_threshold_gates_the_suggestion_but_not_the_candidate(data):
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


# ---- ambiguity -------------------------------------------------------------------------------


def test_two_concurrent_matching_devices_make_the_newcomer_ambiguous(data):
    appear(data, 1, 0, 1500)
    appear(data, 2, 0, 1500)  # identical twin, concurrent
    appear(data, 3, 2000, 2200)
    run(data)
    run(data)
    c3 = [c for c in candidates(data) if c["device_a"] == device_of(data, "ae:00:00:00:00:03")]
    assert c3 and {c["state"] for c in c3} == {"ambiguous"}
    assert len(kinds(data, "identity_candidate_ambiguous")) == 1
    newcomer = device_of(data, "ae:00:00:00:00:03")
    assert not [s for s in suggestions(data) if newcomer in s["device_ids"]]


# ---- overlap veto ----------------------------------------------------------------------------


def test_sustained_overlap_is_vetoed_once_with_no_suggestion(data):
    a = appear(data, 1, 0, 1500)
    b = appear(data, 2, 100, 1500)  # 1400 s concurrent > 600
    run(data)
    run(data)
    assert suggestions(data) == []
    assert [c["state"] for c in candidates(data)] == ["vetoed"]
    assert len(kinds(data, "identity_overlap_veto")) == 1
    assert {device_of(data, a), device_of(data, b)} >= {
        kinds(data, "identity_overlap_veto")[0]["device_id"]
    }


def test_short_overlap_is_tolerated(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 120, 600)  # 180 s overlap < 600 grace
    run(data)
    assert [c["state"] for c in candidates(data)] == ["suggested"]
    assert kinds(data, "identity_overlap_veto") == []


def test_overlap_grace_is_configurable(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 120, 600)
    run(data, overlap_grace_s=100)
    assert [c["state"] for c in candidates(data)] == ["vetoed"] and suggestions(data) == []


def test_overlap_exactly_at_grace_is_tolerated(data):
    appear(data, 1, 0, 600)
    appear(data, 2, 0, 1260, mdns=MDNS)  # overlap 600; covered 1260, so below the half-covered rule
    run(data, overlap_grace_s=600)
    assert [c["state"] for c in candidates(data)] == ["suggested"]  # vetoed only when > grace


def test_veto_considers_all_macs_of_the_target_device(data):
    # target device owns a second MAC (human link); the candidate overlaps that one
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


# ---- suggestions: basis, decisions, links --------------------------------------------------------


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


# ---- overrides availability --------------------------------------------------------------------


def test_unreadable_overrides_fails_closed_without_stopping_the_run(data, caplog):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    (data.root / "overrides.db").write_bytes(b"this is not a database" * 100)
    with caplog.at_level("ERROR"):
        stats = run(data)
    assert stats.batches == 2
    assert suggestions(data) == [] and candidates(data) == []
    assert "stitching_skipped" in caplog.text


def test_empty_unmigrated_overrides_behaves_like_no_rules(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    data.make_overrides()  # only identity_links exists
    run(data)
    assert len(suggestions(data)) == 1


# ---- sanitising ----


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
