"""Probe events (device_id NULL) are served by /events and never shown on device pages."""

from __future__ import annotations

from api_helpers import Env, env  # noqa: F401


def test_null_device_probe_events_list_filter_and_stay_off_device_pages(env: Env) -> None:
    env.device("d1")
    env.event("d1", -300, "new_device")
    env.event(None, -200, "probe_outage", "warn")
    env.event(None, -100, "probe_recovered", "info")
    everything = env.get("/events")
    assert everything.status_code == 200, everything.text
    assert [e["kind"] for e in everything.json()["data"]] == [
        "new_device",
        "probe_outage",
        "probe_recovered",
    ]
    probe = [e for e in everything.json()["data"] if e["kind"].startswith("probe_")]
    assert all(e["device_id"] is None for e in probe)
    only = env.get("/events", kind="probe_outage")
    assert [(e["kind"], e["device_id"]) for e in only.json()["data"]] == [("probe_outage", None)]
    device = env.get("/devices/d1")
    assert device.status_code == 200
    assert "probe_" not in device.text
