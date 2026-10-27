from __future__ import annotations

import pytest
from delivery_sim import EDGE, TIGHT, Tx, World

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
