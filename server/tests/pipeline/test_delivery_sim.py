from __future__ import annotations

import pytest
from delivery_sim import World

from vigie_pipeline.delivery_plan import DeliveryConfig


@pytest.mark.parametrize("seed", range(300))
def test_invariants_hold_over_a_random_world(seed):
    World(seed).run()


@pytest.mark.parametrize("seed", range(60))
def test_invariants_hold_with_a_tight_budget(seed):
    cfg = DeliveryConfig(max_attempts=2, pending_ttl_seconds=900, retention_seconds=2000)
    World(10_000 + seed, cfg).run()


def test_the_simulation_exercises_every_action_and_stale_plans():
    seen, skips = set(), 0
    tight = DeliveryConfig(max_attempts=2, pending_ttl_seconds=900, retention_seconds=2000)
    for seed in range(300):
        world = World(seed, tight if seed % 5 == 0 else None)
        world.run()
        seen |= world.seen
        skips += world.skips
    # Fail is a defensive revival path: a consistent sender already fails rows at the budget
    assert seen == {"Enqueue", "Suppress", "Requeue", "Reschedule", "Expire", "Forget", "Withdraw"}
    assert skips > 20
