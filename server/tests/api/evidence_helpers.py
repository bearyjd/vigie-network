"""Shared builders for the evidence pack tests."""

from __future__ import annotations

from vigie_api.evidence_types import Pack, Sensitive

SALT_A = bytes(range(32))
SALT_B = bytes(range(1, 33))
MAC = "aa:bb:cc:00:11:22"


def section(items, status="present"):
    return {"status": status, "reason": None, "omitted_count": 0, "items": items}


def sample() -> Pack:
    body = {
        "schema": "vigie.evidence-pack",
        "schema_version": 1,
        "generated_at": Sensitive("ts", "2026-10-26T10:34:56Z"),
        "redaction": {},
        "provenance": {
            "vigie_version": "0.1.0",
            "pipeline_schema": 9,
            "api_schema": 8,
            "characterization_model": "services-v1",
            "inventory_newest_batch": Sensitive("ts", "2026-10-26T10:30:00Z"),
        },
        "datasets": [],
        "subject": {
            "type": "tv",
            "status": "active",
            "identity_state": "ok",
            "device_ref": Sensitive("device_id", "d1"),
            "requested_ref": Sensitive("device_id", "d1-alias"),
            "name": Sensitive("name", "Alice's TV"),
            "owner": Sensitive("owner", "Alice"),
            "last_ip": Sensitive("ip", "192.168.1.20"),
            "last_ip6": Sensitive("ip", "2001:db8::1"),
        },
        "sections": {
            "identity": section(
                [
                    {
                        "mac": Sensitive("mac", MAC),
                        "oui": Sensitive("oui", "aabbcc"),
                        "randomized": False,
                        "first_seen": Sensitive("ts", "2026-10-25T08:59:59Z"),
                    },
                    {"mac": Sensitive("mac", "02:00:00:00:00:01"), "randomized": True},
                ]
            ),
            "fingerprints": section(
                [
                    {
                        "mac": Sensitive("mac", MAC),
                        "opt55": Sensitive("opt55", "1,3,6,15"),
                        "opt60": Sensitive("opt60", "android-dhcp-13"),
                        "hostname": Sensitive("hostname", "alices-tv"),
                        "mdns_name": Sensitive("mdns", "Alices TV._airplay._tcp.local"),
                    }
                ]
            ),
            "determinations": section(
                [
                    {
                        "id": "device_type",
                        "reason_text": Sensitive("prose", "hostname looks like alices-tv"),
                        "signals": [{"kind": "mdns", "ref": "_airplay._tcp"}],
                    }
                ]
            ),
            "incidents": section(
                [{"id": Sensitive("incident_id", "inc-1"), "lineage": Sensitive("lineage", "ln")}]
            ),
            "coverage_gaps": section(
                [{"collector_id": Sensitive("collector_id", "rtr-1")}],
            ),
        },
        "unknowns": ["randomized_mac", "no_firmware_version"],
        "search_queries": [],
    }
    return Pack(body)
