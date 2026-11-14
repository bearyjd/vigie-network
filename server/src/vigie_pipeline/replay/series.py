"""Hourly measurement fixture:
{"version":1,"devices":[{"device","samples":[{"hour","bytes_up","qualified_seconds","degraded"?}]}]}.

`qualified_seconds` is the collector coverage of the hour (the engine needs 3420 or more and no
degradation reason). An hour with no sample row is absent, never zero.
"""

from __future__ import annotations

from dataclasses import dataclass

from vigie_pipeline.replay import _json
from vigie_pipeline.replay.errors import ReplayInputError

MAX_DEVICES = 20  # the engine analyses at most MAX_ENTITIES devices per pass
MAX_SAMPLES_PER_DEVICE = 2160  # the engine's hourly sample bound
MAX_BYTES_UP = 2**50
WHAT = "series"


@dataclass(frozen=True)
class SampleRow:
    hour: int
    bytes_up: int
    qualified_seconds: int
    degraded: bool = False


@dataclass(frozen=True)
class DeviceSeries:
    device: str
    samples: tuple[SampleRow, ...]


def _sample(raw) -> SampleRow:
    _json.exact_keys(raw, {"hour", "bytes_up", "qualified_seconds"}, WHAT, frozenset({"degraded"}))
    degraded = raw.get("degraded", False)
    if type(degraded) is not bool:
        raise ReplayInputError("series: degraded must be a boolean")
    return SampleRow(
        _json.hour_value(raw["hour"], WHAT),
        _json.int_in(raw["bytes_up"], 0, MAX_BYTES_UP, WHAT),
        _json.int_in(raw["qualified_seconds"], 0, 3600, WHAT),
        degraded,
    )


def _device(raw) -> DeviceSeries:
    _json.exact_keys(raw, {"device", "samples"}, WHAT)
    rows = raw["samples"]
    if not isinstance(rows, list) or len(rows) > MAX_SAMPLES_PER_DEVICE:
        raise ReplayInputError("series: too many samples or not a list")
    samples = tuple(sorted((_sample(r) for r in rows), key=lambda s: s.hour))
    if len({s.hour for s in samples}) != len(samples):
        raise ReplayInputError("series: duplicate hour for a device")
    return DeviceSeries(_json.device_id(raw["device"], WHAT), samples)


def load_series(raw: bytes) -> tuple[DeviceSeries, ...]:
    "Validate strictly and return devices sorted by id, samples sorted by hour."
    doc = _json.parse(raw, WHAT)
    _json.check_version(doc, WHAT)
    _json.exact_keys(doc, {"version", "devices"}, WHAT)
    rows = doc["devices"]
    if not isinstance(rows, list) or len(rows) > MAX_DEVICES:
        raise ReplayInputError("series: too many devices or not a list")
    devices = tuple(sorted((_device(r) for r in rows), key=lambda d: d.device))
    if len({d.device for d in devices}) != len(devices):
        raise ReplayInputError("series: duplicate device")
    return devices
