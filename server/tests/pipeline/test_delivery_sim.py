from __future__ import annotations

import pytest
from delivery_sim import EDGE, TIGHT, Tx, World

from vigie_pipeline import delivery_plan as plan_module
from vigie_pipeline.delivery_plan import Reschedule

CONFIGS = {"default": None, "tight": TIGHT, "edge": EDGE}


@pytest.mark.parametrize("name", CONFIGS)
@pytest.mark.parametrize("seed", range(250))
def test_invariants_hold_over_a_random_world(name, seed):
    World(seed + 1000 * list(CONFIGS).index(name), CONFIGS[name]).run()


def test_the_simulation_exercises_every_action_and_crashes():
    seen, crashed = set(), 0
    for seed in range(300):
        world = World(seed, [None, TIGHT, EDGE][seed % 3])
        world.run()
        seen |= world.seen
        crashed += sum(world.crashes.values()) + sum(world.violations.values())
    # Fail is a defensive revival path: a consistent sender already fails rows at the budget
    every = {
        "Enqueue",
        "Suppress",
        "Requeue",
        "Reschedule",
        "Expire",
        "Forget",
        "Withdraw",
        "Revive",
    }
    assert seen >= every
    assert crashed > 5  # senders crash or violate their deadline; the planner reclaims the leases


def test_a_normal_overlap_after_a_violation_still_fails_the_oracle():
    world = World(0)
    world.now = 1_000
    key = ("i1", "open")
    hung = Tx(end=5_000)
    hung.hung = True
    world.sends[key] = [hung]
    world.check_overlap(key)  # overlapping only the hung send is the allowed violation
    world.sends[key].append(Tx(end=1_020))  # a second, ordinary send in progress
    with pytest.raises(AssertionError, match="overlap"):
        world.check_overlap(key)
    hung.end = 900  # once the hung send has finished its exemption is gone
    world.sends[key] = [hung, Tx(end=1_020)]
    with pytest.raises(AssertionError, match="overlap"):
        world.check_overlap(key)
    world.sends[key] = [hung]
    world.check_overlap(key)


def _without_pull_in(monkeypatch, only_retried):
    """Planner mutant: a loud pending row is never pulled in to its backoff-based deadline."""
    original = plan_module._retarget

    def broken(d, target, snoozed, now, config):
        action = original(d, target, snoozed, now, config)
        skip = (
            isinstance(action, Reschedule) and not snoozed and (d.attempts > 0 or not only_retried)
        )
        return None if skip else action

    monkeypatch.setattr(plan_module, "_retarget", broken)


def _first_failure(match):
    for seed in range(300):
        try:
            World(seed, [None, TIGHT, EDGE][seed % 3]).run()
        except AssertionError as error:
            assert match in str(error), error
            return seed
    raise AssertionError("the simulator never noticed the planner bug")


def test_the_oracle_notices_a_pull_in_that_ignores_cleared_reviews(monkeypatch):
    _without_pull_in(monkeypatch, only_retried=False)  # a cleared decision has no review at all
    _first_failure("held back by a cleared snooze")


def test_the_quiescence_check_alone_notices_a_moved_row_left_mis_timed(monkeypatch):
    _without_pull_in(monkeypatch, only_retried=True)
    original = World._check_pending_rows

    def only_at_quiescence(self, skip=()):
        if not isinstance(skip, set):  # drop the in-pass calls (they exempt moved rows)
            original(self, skip)

    monkeypatch.setattr(World, "_check_pending_rows", only_at_quiescence)
    _first_failure("held back by a cleared snooze")
