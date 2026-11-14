"""Owner label file: {"version":1,"labels":[{"device","hour","verdict","note"?}]}.

Device ids are opaque placeholders. An hour is the UTC hour start (epoch seconds, multiple of
3600). Verdicts: normal, anomalous, ignore (excluded from every denominator, tallied only).
"""

from __future__ import annotations

from dataclasses import dataclass

from vigie_pipeline.replay import _json
from vigie_pipeline.replay.errors import ReplayInputError

MAX_LABELS = 20_000
MAX_NOTE = 200
VERDICTS = ("normal", "anomalous", "ignore")
WHAT = "labels"


@dataclass(frozen=True)
class Label:
    device: str
    hour: int
    verdict: str
    note: str = ""


def _note(value) -> str:
    if not isinstance(value, str) or len(value) > MAX_NOTE or not value.isprintable():
        raise ReplayInputError("labels: invalid note")
    return value


def _label(raw) -> Label:
    _json.exact_keys(raw, {"device", "hour", "verdict"}, WHAT, frozenset({"note"}))
    if raw["verdict"] not in VERDICTS:
        raise ReplayInputError("labels: unknown verdict")
    return Label(
        _json.device_id(raw["device"], WHAT),
        _json.hour_value(raw["hour"], WHAT),
        raw["verdict"],
        _note(raw["note"]) if "note" in raw else "",
    )


def load_labels(raw: bytes) -> tuple[Label, ...]:
    "Validate strictly and return labels sorted by (device, hour), whatever the input order."
    doc = _json.parse(raw, WHAT)
    _json.check_version(doc, WHAT)
    _json.exact_keys(doc, {"version", "labels"}, WHAT)
    rows = doc["labels"]
    if not isinstance(rows, list) or len(rows) > MAX_LABELS:
        raise ReplayInputError("labels: too many labels or not a list")
    labels = sorted((_label(r) for r in rows), key=lambda x: (x.device, x.hour))
    keys = {(x.device, x.hour) for x in labels}
    if len(keys) != len(labels):
        raise ReplayInputError("labels: duplicate device and hour")
    return tuple(labels)
