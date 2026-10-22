"""Fix-round 4 tests: budget starvation, nameless peers, sticky veto, interval cap."""

from __future__ import annotations

import pytest

from vigie_ingest.db import open_inventory
from vigie_pipeline import stitch as stitch_mod
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.schema import apply_pipeline_migrations
from vigie_pipeline.snapshot import EMPTY, Rule, Snapshot
from vigie_pipeline.stitch import Stitcher, stitch
from vigie_pipeline.stitch_db import upsert_candidate

NOW = 1_800_000_000
RULE_SNAP = Snapshot({}, (Rule("r1", "D", "1,2,3", "x", "victim", None),), {"iot": 1},
                     {"D": (1, "iot")}, {})  # fmt: skip


class Inv:
    """A bare inventory.db with hand-placed MACs and activity."""

    def __init__(self, tmp_path):
        self.cfg = PipelineConfig(data_dir=tmp_path)
        self.db = open_inventory(tmp_path / "inventory.db")
        apply_pipeline_migrations(self.db)
        self.n = 0
        self.db.execute("BEGIN")

    def mac(self, dev, host, mdns, src, fs, ivs, *, rand=1, newdev=True, fp="1,2,3") -> str:
        m = f"ae:{self.n >> 16 & 255:02x}:{self.n >> 8 & 255:02x}:{self.n & 255:02x}:00:01"
        self.n += 1
        if newdev:
            self.db.execute(
                "INSERT INTO devices (id, first_seen, last_seen) VALUES (?,?,?)", (dev, fs, fs)
            )
        self.db.execute(
            "INSERT INTO observations (mac, device_id, is_randomized, dhcp_fingerprint,"
            " vendor_class, hostname, mdns_name, link_source, first_seen, last_seen)"
            " VALUES (?,?,?,?,'x',?,?,?,?,?)",
            (m, dev, rand, fp, host, mdns, src, fs, fs),
        )
        self.act(m, ivs)
        return m

    def act(self, m, ivs) -> None:
        self.db.executemany(
            'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
            [(m, s, e) for s, e in ivs],
        )

    def stitch(self, snap=EMPTY, now=NOW):
        if self.db.in_transaction:
            self.db.execute("COMMIT")
        return stitch(self.db, snap, self.cfg, now)

    def count(self, kind: str) -> int:
        return self.db.execute("SELECT COUNT(*) FROM events WHERE kind=?", (kind,)).fetchone()[0]

    def state(self, dev: str):
        return [
            tuple(r)
            for r in self.db.execute(
                "SELECT device_b, state FROM identity_candidates WHERE device_a=?", (dev,)
            )
        ]

    def stitcher(self) -> Stitcher:
        if self.db.in_transaction:
            self.db.execute("COMMIT")
        return Stitcher(self.db, EMPTY, self.cfg, NOW)


@pytest.fixture
def inv(tmp_path):
    return Inv(tmp_path)


def peer_macs(st: Stitcher, mac_addr: str) -> set[str]:
    return st.compatible_peers(next(o for o in st.obs if o.mac == mac_addr))


# ---- HIGH-1: reviewer's rule-phase starvation recipe, scaled down ----


def build_starve(inv: Inv, burners: int = 12, pool: int = 40):
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 86400, NOW - 80000)],
            rand=0)  # fmt: skip
    x = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 10800, NOW)],
                newdev=False)  # fmt: skip
    inv.mac("V1", "victim", None, "self", "2026-12-01T00:00:00Z", [(NOW - 10800, NOW)])
    for k in range(burners):  # rule-matching, mature, older than V1: each costs rule-phase budget
        inv.mac(f"B{k}", "victim", None, "self", f"2026-02-01T00:00:{k:02d}Z",
                [(NOW - 7000, NOW - 6000)])  # fmt: skip
    for k in range(pool):  # same opt55/opt60, own mDNS name, 64 isolated intervals each
        inv.mac(f"P{k}", None, f"p{k}", "self", "2026-03-01T00:00:00Z",
                [(NOW - 500000 + i * 1000 + k % 7,) * 2 for i in range(64)])  # fmt: skip
    inv.mac("L0", "legit", None, "self", "2026-04-01T00:00:00Z", [(NOW - 90000, NOW - 89000)])
    inv.mac("L1", "legit", None, "self", "2026-04-02T00:00:00Z", [(NOW - 50000, NOW - 49000)])
    return x


def test_rule_phase_budget_burn_starves_neither_suspect_nor_candidates(inv, monkeypatch):
    build_starve(inv)
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 90)
    st = inv.stitch(RULE_SNAP)
    assert inv.count("stitch_budget_exhausted") == 1  # the rule loop did run out
    assert st.suspect == 1 and inv.count("rule_attach_suspect") == 1
    assert inv.state("L1") == [("L0", "suggested")]  # the legit candidate still got processed


def test_budget_event_is_deduplicated_per_day_across_phases_and_passes(inv, monkeypatch):
    build_starve(inv)
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 20)  # every phase runs out
    inv.stitch(RULE_SNAP)
    inv.stitch(RULE_SNAP, NOW + 60)
    assert inv.count("stitch_budget_exhausted") == 1
    inv.stitch(RULE_SNAP, NOW + 86400)  # next UTC day: one more
    assert inv.count("stitch_budget_exhausted") == 2


def test_recheck_has_its_own_budget_even_when_other_phases_would_spend_it_all(inv, monkeypatch):
    x = build_starve(inv, burners=0, pool=0)
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 8)
    st = inv.stitch(RULE_SNAP)
    assert st.suspect == 1, x


def test_rule_loop_processes_undecided_macs_first(inv, monkeypatch):
    snap = Snapshot({}, RULE_SNAP.rules, {"iot": 0}, {"D": (1, "iot")}, {})  # human confirms
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 90000, NOW - 80000)],
            rand=0)  # fmt: skip
    inv.mac("A", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 70000, NOW - 69000)])
    inv.stitch(snap)
    assert inv.state("A") == [("D", "suggested")]
    b_mac = inv.mac("B", "victim", None, "self", "2026-03-01T00:00:00Z",
                    [(NOW - 50000, NOW - 49000)])  # fmt: skip
    calls = []
    real = Stitcher.sustained

    def spy(self, mac_addr, others):
        calls.append(mac_addr)
        return real(self, mac_addr, others)

    monkeypatch.setattr(Stitcher, "sustained", spy)
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 5)  # room for one decision only
    inv.stitch(snap, NOW + 60)
    assert inv.state("B") == [("D", "suggested")]  # the new MAC, not the already decided one
    assert calls[0] == b_mac


def test_pool_larger_than_a_signature_bucket_is_flooded_for_rule_attach(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_SIGNATURE_BUCKET", 3)
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 90000, NOW - 80000)],
            rand=0)  # fmt: skip
    for k in range(5):  # five live MACs with the victim's opt55/opt60 and their own names
        inv.mac(f"P{k}", None, f"p{k}", "self", "2026-03-01T00:00:00Z",
                [(NOW - 3600 * (k + 1),) * 2])  # fmt: skip
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 70000, NOW - 69000)])
    st = inv.stitch(RULE_SNAP)
    row = inv.db.execute("SELECT link_source FROM observations WHERE mac=?", (b,)).fetchone()
    assert row[0] == "self" and st.attached == 0 and st.suggestions == 0
    assert inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 0
    assert inv.count("signature_flood") == 1 and st.flooded >= 1


def test_vetoed_pair_is_not_re_evaluated_and_stays_vetoed(inv, monkeypatch):
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 100000, NOW - 80000)],
            rand=0)  # fmt: skip
    inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 90000, NOW - 85000)])
    inv.stitch(RULE_SNAP, NOW - 84000)
    assert inv.state("A") == [("D", "vetoed")]
    calls = []
    real = Stitcher.sustained
    monkeypatch.setattr(Stitcher, "sustained", lambda s, m, o: (calls.append(m), real(s, m, o))[1])
    inv.stitch(RULE_SNAP, NOW - 83000)
    assert calls == []  # skipped, no peer set / overlap work
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 1)
    inv.stitch(RULE_SNAP, NOW - 82000)
    assert inv.count("stitch_budget_exhausted") == 0  # a vetoed pair costs nothing


def test_interval_cap_keeps_the_newest_intervals(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_INTERVALS_PER_MAC", 4)
    m = inv.mac("A", "h", None, "self", "2026-01-01T00:00:00Z",
                [(1000 * i, 1000 * i) for i in range(10)])  # fmt: skip
    st = inv.stitcher()
    assert len(st.act[m]) == 4
    assert [s for s, _ in st.act[m]] == [6000 - 150 + 0, 7000 - 150, 8000 - 150, 9000 - 150]


def test_cap_cannot_launder_a_veto_by_pushing_the_overlap_out_of_the_window(inv, monkeypatch):
    """Reviewer's poc_cap_unveto: 64 fresh lone stamps used to un-veto a co-present copy."""
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 100000, NOW - 80000)],
            rand=0)  # fmt: skip
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z",
                [(NOW - 90000, NOW - 85000)])  # fmt: skip
    inv.stitch(RULE_SNAP, NOW - 84000)
    assert inv.state("A") == [("D", "vetoed")]
    inv.act(a, [(NOW - 75000 + i * 400, NOW - 75000 + i * 400) for i in range(64)])
    inv.stitch(RULE_SNAP, NOW - 49000)
    assert inv.state("A") == [("D", "vetoed")]
    link = inv.db.execute("SELECT link_source FROM observations WHERE mac=?", (a,)).fetchone()[0]
    assert link == "self"


def test_fingerprint_candidate_veto_is_sticky_too(inv):
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 100000, NOW - 80000)],
            rand=0)  # fmt: skip
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z",
                [(NOW - 90000, NOW - 85000)])  # fmt: skip
    inv.stitch(EMPTY, NOW - 84000)
    assert inv.state("A") == [("D", "vetoed")]
    inv.act(a, [(NOW - 75000 + i * 400,) * 2 for i in range(64)])
    inv.stitch(EMPTY, NOW - 49000)
    assert inv.state("A") == [("D", "vetoed")]
    assert inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 0


def test_upsert_never_rewrites_a_vetoed_row_but_a_human_dismissal_wins(inv):
    cid, _ = upsert_candidate(inv.db, "A", "D", 0.9, {}, "vetoed", NOW)
    assert upsert_candidate(inv.db, "A", "D", 0.9, {}, "suggested", NOW) == (cid, False)
    assert inv.state("A") == [("D", "vetoed")]


def test_compatible_set_of_exactly_the_bucket_size_is_not_a_flood(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_SIGNATURE_BUCKET", 6)  # D + five mDNS-only peers
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 90000, NOW - 80000)],
            rand=0)  # fmt: skip
    for k in range(5):
        inv.mac(
            f"P{k}", None, f"p{k}", "self", "2026-03-01T00:00:00Z", [(NOW - 3600 * (k + 1),) * 2]
        )
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 70000, NOW - 69000)])
    st = inv.stitch(RULE_SNAP)
    assert inv.count("signature_flood") == 0 and st.attached == 1, b


# ---- MEDIUM-1: nameless MACs are not compatible peers ----


def nameless_world(inv: Inv, nameless_first_seen: str):
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 90000, NOW - 80000)],
            rand=0)  # fmt: skip
    inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 79000, NOW - 60000)],
            newdev=False)  # fmt: skip
    v2 = inv.mac("V2", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 59000, NOW - 1000)])
    inv.mac("Z", None, None, "self", nameless_first_seen, [(NOW - 80000, NOW)])
    return v2


def test_a_distant_nameless_mac_is_no_peer_so_the_legit_roll_attaches(inv):
    v2 = nameless_world(inv, "2026-01-01T00:00:00Z")
    st = inv.stitch(RULE_SNAP)
    link = inv.db.execute("SELECT device_id, link_source FROM observations WHERE mac=?", (v2,))
    assert tuple(link.fetchone()) == ("D", "rule")
    assert st.suspect == 0 and inv.count("rule_attach_suspect") == 0


def test_a_nameless_mac_first_seen_within_a_gap_of_the_candidate_is_a_peer(inv):
    v2 = nameless_world(inv, "2026-01-03T00:04:00Z")  # 240 s after the candidate's first sighting
    inv.stitch(RULE_SNAP)
    assert inv.state("V2") == [("D", "vetoed")]
    assert (
        inv.db.execute("SELECT link_source FROM observations WHERE mac=?", (v2,)).fetchone()[0]
        == "self"
    )


def test_compatible_peer_selection(inv):
    c = inv.mac("C", "victim", "Dave", "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW - 4000)])
    same = inv.mac("P1", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW)])
    mdns_only = inv.mac("P2", None, "Dave", "self", "2026-02-01T00:00:00Z", [(NOW - 5000, NOW)])
    other_host = inv.mac("P3", "other", None, "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW)])
    inv.mac("P4", "victim", "Dave", "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW)])
    other_mdns = inv.mac("P5", "victim", "Elsewhere", "self", "2026-01-03T00:00:00Z",
                         [(NOW - 5000, NOW)])  # fmt: skip
    nameless_far = inv.mac("P6", None, None, "self", "2026-02-01T00:00:00Z", [(NOW - 5000, NOW)])
    nameless_near = inv.mac("P7", None, None, "self", "2026-01-03T00:00:01Z", [(NOW - 5000, NOW)])
    silent = inv.mac("P8", "victim", None, "self", "2026-01-03T00:00:00Z",
                     [(NOW - 20 * 86400, NOW - 19 * 86400)])  # fmt: skip
    ruled = inv.mac("C", "victim", None, "rule", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW)],
                    newdev=False)  # fmt: skip
    st = inv.stitcher()
    got = peer_macs(st, c)
    assert same in got and mdns_only in got and nameless_near in got
    assert other_host not in got  # contradicting hostname
    assert other_mdns not in got  # contradicting mDNS name (hostname agrees)
    assert nameless_far not in got  # no name, not first seen with the candidate
    assert silent not in got and ruled not in got  # not live self MACs


def test_contradicting_hostname_alone_excludes_and_so_does_mdns_alone(inv):
    c = inv.mac("C", "victim", "Dave", "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW - 4000)])
    h = inv.mac("H", "other", "Dave", "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW)])
    m = inv.mac("M", "victim", "Else", "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW)])
    got = peer_macs(inv.stitcher(), c)
    assert h not in got and m not in got


# ---- recheck: each peer source matters ----


def attached(inv: Inv, host="victim", mdns=None, dev="D", src="rule"):
    inv.mac("D", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 90000, NOW - 80000)],
            rand=0)  # fmt: skip
    return inv.mac(dev, host, mdns, src, "2026-01-02T00:00:00Z", [(NOW - 5000, NOW)],
                   newdev=False)  # fmt: skip


def test_recheck_flags_overlap_with_a_compatible_mdns_only_peer(inv):
    attached(inv)
    inv.mac("V", None, "Dave", "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW)])
    assert inv.stitch(RULE_SNAP).suspect == 1  # only compatible_peers can see V


def test_recheck_flags_overlap_with_a_same_name_rule_attached_mac_of_another_device(inv):
    attached(inv)
    inv.mac("E", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 90000, NOW - 80000)],
            rand=0)  # fmt: skip
    inv.mac("E", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 5000, NOW)],
            newdev=False)  # fmt: skip
    # not a live self MAC (so not compatible) and another canonical device: only name_peers
    assert inv.stitch(RULE_SNAP).suspect >= 1


def test_recheck_stays_quiet_for_a_clean_attach(inv):
    attached(inv)
    assert inv.stitch(RULE_SNAP).suspect == 0
