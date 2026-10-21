from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from conftest import make_batch, uuid7
from pydantic import ValidationError

from vigie_ingest.models import Batch
from vigie_ingest.schema_export import render


def validate(data: dict) -> Batch:
    return Batch.model_validate_json(json.dumps(data))


def test_valid_batch_parses() -> None:
    batch = validate(make_batch())
    assert batch.seq == 1
    assert batch.leases[0].opt55 == [1, 3, 6]


def test_minimal_batch_defaults_to_empty_payloads() -> None:
    data = make_batch()
    for key in ("leases", "neigh", "dns", "conntrack", "sightings", "health", "truncated"):
        data.pop(key)
    batch = validate(data)
    assert batch.dns == [] and batch.health is None and batch.truncated == {}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(extra_field=1),
        lambda d: d["leases"][0].update(mac="AA:BB:CC:00:00:01"),
        lambda d: d["leases"][0].update(mac="aa:bb:cc:00:00"),
        lambda d: d["leases"][0].update(ip="999.1.1.1"),
        lambda d: d["leases"][0].update(hostname="h" * 254),
        lambda d: d["leases"][0].update(opt55=[256]),
        lambda d: d["leases"][0].update(opt55=[1] * 65),
        lambda d: d["dns"][0].update(qname="q" * 254),
        lambda d: d["dns"][0].update(qtype="a"),
        lambda d: d["dns"][0].update(ts=d["window_start"] - 10_000),
        lambda d: d["conntrack"][0].update(dst_port=70000),
        lambda d: d["conntrack"][0].update(bytes_up=-1),
        lambda d: d["conntrack"][0].update(proto="sctp"),
        lambda d: d["sightings"][0].update(kind="upnp"),
        lambda d: d["sightings"][0].update(ua="u" * 256),
        lambda d: d.update(batch_id=str(__import__("uuid").uuid4())),
        lambda d: d.update(batch_id=uuid7().upper()),
        lambda d: d.update(batch_id="not-a-uuid"),
        lambda d: d.update(seq="1"),  # strict: no coercion
        lambda d: d.update(seq=-1),
        lambda d: d.update(collector_id="a|b"),
        lambda d: d.update(window_end=d["window_start"] - 1),
        lambda d: d.update(window_start=d["window_end"] - 90_000),
        lambda d: d.update(window_end=d["sent_ts"] + 3600, window_start=d["sent_ts"]),
        lambda d: d.update(truncated={"BAD KEY": 1}),
        lambda d: d.update(truncated={f"k{i}".replace("1", "a"): 1 for i in range(17)}),
        lambda d: d.update(dropped_batches=-1),
        lambda d: d["health"].update(unknown=True),
        lambda d: d.update(leases=d["leases"] * 1001),
        lambda d: d.update(neigh=d["neigh"] * 2001),
    ],
)
def test_invalid_batches_are_rejected(mutate) -> None:
    data = copy.deepcopy(make_batch())
    mutate(data)
    with pytest.raises(ValidationError):
        validate(data)


def test_other_bucket_conntrack_allows_null_destination() -> None:
    data = make_batch()
    data["conntrack"] = [
        {"mac": "aa:bb:cc:00:00:01", "dst_ip": None, "dst_port": None, "proto": "other",
         "bytes_up": 1, "bytes_down": 2, "flows": 3}
    ]  # fmt: skip
    assert validate(data).conntrack[0].dst_ip is None


def test_committed_json_schema_matches_models() -> None:
    committed = Path(__file__).resolve().parents[2] / "api" / "batch.schema.json"
    assert committed.read_text(encoding="utf-8") == render(), (
        "run: uv run python -m vigie_ingest.schema_export"
    )
