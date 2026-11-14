"""Strict, bounded JSON parsing shared by the replay input loaders."""

from __future__ import annotations

import json
import re

from vigie_pipeline.replay.errors import ReplayInputError

MAX_BYTES = 4 << 20
DEVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,63}$")
MAX_HOUR = 2**32


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_constants(_name):
    raise ValueError("non-finite number")


def parse(raw: bytes, what: str) -> dict:
    "Parse a size-capped JSON object; every failure becomes one fixed message."
    if not isinstance(raw, bytes | bytearray) or len(raw) > MAX_BYTES:
        raise ReplayInputError(f"{what}: input too large or unreadable")
    try:
        doc = json.loads(
            bytes(raw).decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_no_constants,
        )
    except (ValueError, RecursionError) as exc:
        raise ReplayInputError(f"{what}: not valid JSON") from exc
    if not isinstance(doc, dict):
        raise ReplayInputError(f"{what}: top level must be an object")
    return doc


def exact_keys(obj, required: set, what: str, optional: frozenset = frozenset()) -> None:
    if not isinstance(obj, dict) or not required <= obj.keys() <= required | optional:
        raise ReplayInputError(f"{what}: unexpected or missing fields")


def int_in(value, lo: int, hi: int, what: str) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ReplayInputError(f"{what}: number out of range")
    return value


def hour_value(value, what: str) -> int:
    if int_in(value, 0, MAX_HOUR, what) % 3600:
        raise ReplayInputError(f"{what}: hour is not on an hour boundary")
    return value


def device_id(value, what: str) -> str:
    if not isinstance(value, str) or not DEVICE_RE.fullmatch(value):
        raise ReplayInputError(f"{what}: invalid device id")
    return value


def check_version(doc: dict, what: str) -> None:
    if doc.get("version") != 1 or type(doc.get("version")) is not int:
        raise ReplayInputError(f"{what}: unsupported version")
