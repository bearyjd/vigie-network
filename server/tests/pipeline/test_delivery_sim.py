from __future__ import annotations

import pytest
from delivery_sim import EDGE, TIGHT, World

CONFIGS = {"default": None, "tight": TIGHT, "edge": EDGE}


@pytest.mark.parametrize("name", CONFIGS)
@pytest.mark.parametrize("seed", range(250))
def test_invariants_hold_over_a_random_world(name, seed):
    World(seed + 1000 * list(CONFIGS).index(name), CONFIGS[name]).run()


def test_the_simulation_exercises_every_action_and_stale_plans():
    seen, skips, dropped = set(), 0, 0
    for seed in range(300):
        world = World(seed, [None, TIGHT, EDGE][seed % 3])
        world.run()
        seen |= world.seen
        skips += world.skips
        dropped += world.dropped
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
    assert dropped > 10  # asynchronous completions that lost to a planner change
    assert skips > 20
