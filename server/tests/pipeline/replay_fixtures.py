"""Synthetic scenario for the replay harness. Placeholders only: no real device or address."""

import json

from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.replay.labels import Label
from vigie_pipeline.replay.series import DeviceSeries, SampleRow

MIB = 1024 * 1024
MONDAY = 20304  # epoch day of a UTC Monday
DAY0 = MONDAY * 86400
DAYS = 7
POLICY = BaselineConfig(minimum_hours=6, minimum_days=3, minimum_bytes=50 * MIB)
BASE = 10 * MIB
GIB = 1024 * MIB


def hr(day, hour):
    return DAY0 + day * 86400 + hour * 3600


def sample(day, hour, value=BASE, secs=3600, degraded=False):
    return SampleRow(hr(day, hour), value, secs, degraded)


def steady(skip=(), override=None, secs=None):
    "Every hour of DAYS days at BASE bytes, minus `skip`, with `override` {(day,hour): value}."
    over = override or {}
    out = []
    for day in range(DAYS):
        for hour in range(24):
            if (day, hour) in skip:
                continue
            out.append(
                sample(day, hour, over.get((day, hour), BASE), (secs or {}).get((day, hour), 3600))
            )
    return tuple(out)


def scenario():
    "name -> DeviceSeries. Each device exercises one situation from the M2 exit criteria."
    sleeping = tuple(s for s in steady() if 8 <= (s.hour // 3600) % 24 < 20)  # night: no rows
    return {
        # a two-hour backup at day 5 hours 2-3: sustained, so upload_deviation fires on hour 3
        "dev-backup": DeviceSeries(
            "dev-backup", steady(override={(5, 2): 300 * MIB, (5, 3): 300 * MIB})
        ),
        # a two-hour update the owner calls normal: a false alert
        "dev-update": DeviceSeries(
            "dev-update", steady(override={(5, 10): 200 * MIB, (5, 11): 200 * MIB})
        ),
        # a single hour over the fixed ceiling during learning: large_upload, no baseline needed
        "dev-big": DeviceSeries("dev-big", steady(override={(1, 5): 2 * GIB})),
        "dev-sleep": DeviceSeries("dev-sleep", sleeping),
        # restart: one hour of low coverage with a zero counter
        "dev-restart": DeviceSeries(
            "dev-restart", steady(override={(4, 6): 0}, secs={(4, 6): 1800})
        ),
        # five consecutive missing hours
        "dev-gap": DeviceSeries("dev-gap", steady(skip={(4, h) for h in range(3, 8)})),
        "2001:db8::1": DeviceSeries("2001:db8::1", steady()),
    }


def labels():
    def lab(dev, day, hour, verdict, note=""):
        return Label(dev, hr(day, hour), verdict, note)

    return (
        lab("dev-backup", 5, 2, "anomalous", "backup first hour"),
        lab("dev-backup", 5, 3, "anomalous", "backup second hour"),
        lab("dev-backup", 5, 4, "normal"),
        lab("dev-update", 5, 10, "normal", "update"),
        lab("dev-update", 5, 11, "normal", "update"),
        lab("dev-big", 1, 5, "anomalous"),
        lab("dev-sleep", 5, 2, "normal"),  # no row: abstains
        lab("dev-sleep", 5, 12, "normal"),
        lab("dev-restart", 4, 6, "ignore", "restart"),
        lab("dev-gap", 4, 5, "normal"),  # in the gap: abstains
        lab("2001:db8::1", 5, 12, "normal"),
    )


def series_json(devices):
    return json.dumps(
        {
            "version": 1,
            "devices": [
                {
                    "device": d.device,
                    "samples": [
                        {
                            "hour": s.hour,
                            "bytes_up": s.bytes_up,
                            "qualified_seconds": s.qualified_seconds,
                            "degraded": s.degraded,
                        }
                        for s in d.samples
                    ],
                }
                for d in devices
            ],
        }
    ).encode()


def labels_json(items):
    return json.dumps(
        {
            "version": 1,
            "labels": [
                {"device": x.device, "hour": x.hour, "verdict": x.verdict, "note": x.note}
                for x in items
            ],
        }
    ).encode()
