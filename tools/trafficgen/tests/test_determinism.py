"""Same seed => byte-identical output, independent of PYTHONHASHSEED, for every profile/variant."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

SCRIPT = """
import hashlib, json
from trafficgen import PROFILES, generate
from trafficgen.generator import emissions_to_jsonl
from trafficgen.roster import VARIANTS
out = {}
for p in PROFILES:
    for v in (VARIANTS.get(p) or (None,)):
        sc = generate(p, seed=7, windows=26, variant=v)
        blob = emissions_to_jsonl(sc.emissions) + json.dumps(sc.manifest, sort_keys=True)
        out[f"{p}:{v}"] = hashlib.sha256(blob.encode()).hexdigest()
print(json.dumps(out))
"""


def _digests(hashseed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": hashseed}
    done = subprocess.run(
        [sys.executable, "-c", SCRIPT], env=env, capture_output=True, text=True, check=True
    )
    return done.stdout


@pytest.mark.parametrize("other", ["1", "12345", "random"])
def test_output_independent_of_hash_seed(other):
    assert _digests("0") == _digests(other)


def test_different_seed_changes_output():
    from trafficgen import generate

    assert generate("baseline", seed=1).emissions != generate("baseline", seed=2).emissions
