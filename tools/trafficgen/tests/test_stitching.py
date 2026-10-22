"""Identity stitching ground truth: committed fixtures -> real ingest -> real `run_once`.

The committed iOS archetype sends no DHCP option 60 (as on real iOS), but a candidate REQUIRES
opt55 AND opt60 (PRP section 8). So the as-committed fixtures can never stitch (asserted below),
and the behavioural assertions run on the same fixtures with a fixed opt60 injected into every
iPhone lease before it is posted (`inject=True`): nothing else about the traffic changes.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from conftest import FIXTURES
from vigie_api.schema import open_overrides
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

from trafficgen.generator import load_emissions

IOS_OPT55 = [1, 121, 3, 6, 15, 119, 252]
INJECTED_OPT60 = "ios-sim-dhcp"
FIXTURE_NAMES = sorted(p.stem for p in FIXTURES.glob("*.jsonl"))


class World:
    """One fixture pushed through ingest and the pipeline, with convenient lookups."""

    def __init__(self, ingest, name: str, *, inject: bool = True, **cfg) -> None:
        self.data_dir: Path = ingest.data_dir
        self.cfg = cfg
        ems = load_emissions(FIXTURES / f"{name}.jsonl")
        if inject:
            for em in ems:
                for lease in em.batch["leases"]:
                    if lease["opt55"] == IOS_OPT55 and lease["opt60"] is None:
                        lease["opt60"] = INJECTED_OPT60
        assert all(r.ok for r in ingest.replay(ems))
        self.now = float(ems[-1].arrival_ts)
        manifest = json.loads((FIXTURES / f"{name}.manifest.json").read_text())
        self.macs = {d["device_id"]: [m["mac"] for m in d["macs"]] for d in manifest["devices"]}
        self.run()

    def run(self) -> None:
        run_once(PipelineConfig(data_dir=self.data_dir, **self.cfg), now=self.now)

    def q(self, sql: str, *args: object) -> list[sqlite3.Row]:
        conn = sqlite3.connect(self.data_dir / "inventory.db")
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def device(self, mac: str) -> str:
        return self.q("SELECT device_id FROM observations WHERE mac=?", mac)[0][0]

    def first_mac(self, device_id: str) -> str:
        """A device's first MAC; a retired orphan (its MAC attached elsewhere) has none."""
        rows = self.q(
            "SELECT mac FROM observations WHERE device_id=? ORDER BY first_seen, mac", device_id
        )
        return rows[0][0] if rows else f"orphan:{device_id[:8]}"

    def edges(self) -> dict[tuple[str, str], str]:
        """(from_mac, into_mac) -> candidate state, naming each device by its first MAC."""
        return {
            (self.first_mac(r["device_a"]), self.first_mac(r["device_b"])): r["state"]
            for r in self.q("SELECT * FROM identity_candidates")
        }

    def suggested(self) -> set[tuple[str, str]]:
        out = set()
        for r in self.q("SELECT device_ids, reason_code FROM suggestions"):
            a, b = json.loads(r["device_ids"])
            out.add((self.first_mac(a), self.first_mac(b), r["reason_code"]))
        return out

    def count(self, kind: str) -> int:
        return self.q("SELECT COUNT(*) FROM events WHERE kind=?", kind)[0][0]

    def link_source(self, mac: str) -> str:
        return self.q("SELECT link_source FROM observations WHERE mac=?", mac)[0][0]

    def seed_rule(self, mac: str, sig: dict, group: str | None) -> None:
        """A human approves a rule for the device owning `mac` (and optionally files it)."""
        dev = self.device(mac)
        conn = open_overrides(self.data_dir / "overrides.db")
        conn.execute(
            "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
            " VALUES ('rule-1', ?, ?, '2026-10-01T00:00:00Z', 'owner')",
            (dev, json.dumps(sig)),
        )
        if group:
            conn.execute(
                "INSERT INTO device_overrides (device_id, group_id, version, updated_at,"
                " updated_by) VALUES (?,?,1,'2026-10-01T00:00:00Z','owner')",
                (dev, group),
            )
        conn.close()
        self.run()


# A MAC must be observed for longer than the grace window before a rule may attach it (so an
# overlapping copy cannot dodge the veto by timing). The fixture rollers live 3-5 min, hence a
# grace below the 5 min minimum interval width; the default 10 min would defer every roll.
RULE_GRACE_S = 200

ROLLER_SIG = {
    "opt55": ",".join(map(str, IOS_OPT55)),
    "opt60": INJECTED_OPT60,
    "hostname": "Daves-iPhone-roller",
}


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_as_committed_fixtures_never_stitch_because_ios_sends_no_opt60(ingest, name):
    w = World(ingest, name, inject=False)
    assert w.q("SELECT COUNT(*) FROM identity_candidates")[0][0] == 0
    assert w.q("SELECT COUNT(*) FROM suggestions")[0][0] == 0


def test_rolling_mac_later_macs_suggest_the_first_device(ingest):
    w = World(ingest, "rolling_mac")
    first, *later = w.macs["dev-08"]
    assert w.edges() == {(m, first): "suggested" for m in later}
    assert w.suggested() == {(m, first, "fingerprint_match") for m in later}
    assert {w.link_source(m) for m in w.macs["dev-08"]} == {"self"}  # nothing attaches
    assert w.count("identity_candidate") == 3
    assert w.q("SELECT COUNT(*) FROM mac_activity")[0][0] >= 11


def test_overlap_veto_fixture_short_overlap_stitches_and_sustained_overlap_is_vetoed(ingest):
    w = World(ingest, "rolling_overlap_veto")
    first, *later = w.macs["dev-08"]
    bob_old, bob_new = w.macs["dev-09"][0], w.macs["dev-10"][0]
    expected = {(m, first): "suggested" for m in later} | {(bob_new, bob_old): "vetoed"}
    assert w.edges() == expected
    assert {s[:2] for s in w.suggested()} == {(m, first) for m in later}
    assert w.count("identity_overlap_veto") == 1


def test_fingerprint_copy_victim_present_is_vetoed_and_a_short_roll_stays_provisional(ingest):
    w = World(ingest, "rolling_fingerprint_copy_present")
    first, r1, r2, r3, r4 = w.macs["dev-08"]
    attacker = w.macs["dev-09"][0]
    # exact outcomes: the copy is mature and vetoed. Roll r3 lived wholly inside the copy's
    # presence (indistinguishable from it, a human decides) but under the 10 min grace: too
    # little trusted history, so its overlap is provisional ('open', no veto event, no
    # suggestion), never a permanent veto. The other rolls are suggested.
    assert w.edges() == {
        (r1, first): "suggested", (r2, first): "suggested", (r3, first): "open",
        (r4, first): "suggested", (attacker, first): "vetoed",
    }  # fmt: skip
    assert w.suggested() == {(m, first, "fingerprint_match") for m in (r1, r2, r4)}
    assert w.count("identity_overlap_veto") == 1


def test_fingerprint_copy_victim_away_yields_a_suggestion_the_human_decides(ingest):
    """Documented accepted risk: no overlap exists, so the copy looks like the next roll."""
    w = World(ingest, "rolling_fingerprint_copy_away")
    first = w.macs["dev-08"][0]
    attacker = w.macs["dev-09"][0]
    assert w.edges()[(attacker, first)] == "suggested"
    assert (attacker, first, "fingerprint_match") in w.suggested()
    assert w.link_source(attacker) == "self"  # without a human rule it is only a suggestion


def test_fingerprint_copy_away_attaches_under_an_auto_inherit_rule_residual_risk(ingest):
    """ACCEPTED RESIDUAL RISK (PRP section 8): with a human-approved rule in an auto_inherit
    group, a fingerprint copy arriving after the victim left is attached. Only behavioural
    demotion (a later stage, not built) or the human can catch it."""
    w = World(ingest, "rolling_fingerprint_copy_away", overlap_grace_s=RULE_GRACE_S)
    first = w.macs["dev-08"][0]
    attacker = w.macs["dev-09"][0]
    w.seed_rule(first, ROLLER_SIG, group="iot")  # iot: auto_inherit=1
    target = w.device(first)
    assert w.link_source(attacker) == "rule" and w.device(attacker) == target
    assert {w.device(m) for m in w.macs["dev-08"]} == {target}
    assert w.count("mac_attached") == 3  # two rolls and the attacker
    w.run()
    assert w.count("mac_attached") == 3  # idempotent


def test_copy_away_into_a_confirm_group_attaches_nothing(ingest):
    w = World(ingest, "rolling_fingerprint_copy_away")
    first = w.macs["dev-08"][0]
    w.seed_rule(first, ROLLER_SIG, group="trusted")  # auto_inherit=0
    assert w.count("mac_attached") == 0
    assert {w.link_source(m) for m in [*w.macs["dev-08"], *w.macs["dev-09"]]} == {"self"}
    # every later MAC (rolls and the copy) is waiting for a human, none is trusted
    assert {s[0] for s in w.suggested()} == {*w.macs["dev-08"][1:], *w.macs["dev-09"]}


def test_victim_present_rule_never_attaches_the_overlapping_copy(ingest):
    """With a low grace the fast rollers overlap the copy too: only one short roll (r1, which
    overlaps nothing beyond the grace) attaches; every other roll and the copy are vetoed or
    ambiguous. The copy must never attach."""
    w = World(ingest, "rolling_fingerprint_copy_present", overlap_grace_s=RULE_GRACE_S)
    first, r1, r2, r3, r4 = w.macs["dev-08"]
    attacker = w.macs["dev-09"][0]
    w.seed_rule(first, ROLLER_SIG, group="iot")
    rule_attached = {m for m in [*w.macs["dev-08"], attacker] if w.link_source(m) == "rule"}
    assert rule_attached == {r1}
    assert w.link_source(attacker) == "self" and w.device(attacker) != w.device(first)
    into_first = {a for (a, b), st in w.edges().items() if b == first and st == "vetoed"}
    assert into_first == {r2, r3, attacker}
    # r4 first reached the server within the grace of this run: too little trusted history for a
    # rule attach or a permanent veto, so the candidate pass only marks it ambiguous ...
    assert w.edges()[(r4, first)] == "ambiguous"
    # ... and once the server has known it for longer than the grace, the overlap is a veto
    w.now += RULE_GRACE_S + 1
    w.run()
    assert w.edges()[(r4, first)] == "vetoed"
    assert w.link_source(attacker) == "self" and w.link_source(r4) == "self"


def test_victim_present_with_default_grace_defers_every_short_lived_roll(ingest):
    """Rollers that live under the grace window are not attached until they have been observed
    for longer than it (no event noise while they are deferred); the copy never attaches."""
    w = World(ingest, "rolling_fingerprint_copy_present")
    first, *later = w.macs["dev-08"]
    w.seed_rule(first, ROLLER_SIG, group="iot")
    assert {w.link_source(m) for m in [*later, w.macs["dev-09"][0]]} == {"self"}
    assert w.count("mac_attached") == 0


def test_hostname_only_spoof_is_never_a_candidate(ingest):
    w = World(ingest, "hostname_spoof")
    assert w.edges() == {} and w.suggested() == set()


def test_full_fingerprint_spoof_inside_grace_is_provisional_then_vetoed_once_mature(ingest):
    """The fixture runs 6 min: concurrent for 300 s, inside the default 10 min grace, and the copy
    is wholly inside the victim's presence. It has too little trusted history (under the grace) to
    be vetoed permanently: provisional 'open', no suggestion. With a grace below its covered time
    and after the server has known it for longer than that, the same overlap is a veto."""
    w = World(ingest, "hostname_spoof_full_fingerprint")
    assert len(w.edges()) == 1 and set(w.edges().values()) == {"open"}
    assert w.count("identity_overlap_veto") == 0
    assert w.suggested() == set()
    w.cfg["overlap_grace_s"] = RULE_GRACE_S
    w.now += RULE_GRACE_S + 1
    w.run()
    assert set(w.edges().values()) == {"vetoed"}
    assert w.count("identity_overlap_veto") == 1
    assert w.suggested() == set()


@pytest.mark.parametrize("name", ["baseline", "mac_clone", "mac_clone_same_fingerprint"])
def test_baseline_and_clone_fixtures_keep_their_behaviour(ingest, name):
    w = World(ingest, name)
    assert w.edges() == {} and w.suggested() == set()
    assert w.count("identity_conflict") == {"baseline": 0, "mac_clone": 2}.get(name, 0)
    assert w.count("mac_attached") == 0
