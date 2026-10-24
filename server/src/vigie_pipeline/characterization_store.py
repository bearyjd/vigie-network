"""Bounded service-only hints. Raw names, DHCP identifiers and UA are never retained here."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from urllib.parse import quote

from vigie_ingest.db import immediate, iso_utc, shard_name, utc_day
from vigie_pipeline.characterization import Classification, Observation, classify
from vigie_pipeline.monitoring_identity import LineageUnavailable, lineage
from vigie_pipeline.sources import ShardReadError, normalize_mac

TTL = 86400


def read_services(root, measured):
    if measured.end is None:
        return []
    path = root / shard_name(utc_day(measured.end))
    if not path.exists():
        return []
    db = None
    try:
        db = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=2)
        rows = db.execute(
            "SELECT mac,kind,service,ts FROM raw_sighting "
            "WHERE collector_id=? AND batch_id=? LIMIT 1001",
            (measured.collector, measured.batch_id),
        ).fetchall()
        if len(rows) > 1000:
            raise ShardReadError("characterization batch bound")
        return rows
    except sqlite3.Error as exc:
        raise ShardReadError("characterization shard unavailable") from exc
    finally:
        if db is not None:
            db.close()


def save_services(inv, rows, now):
    for raw_mac, kind, service, stamp in rows:
        mac = normalize_mac(raw_mac)
        if mac is None or service is None or stamp > now or stamp <= now - TTL:
            continue
        inv.execute(
            "DELETE FROM characterization_evidence WHERE mac=? AND observed_at<=?", (mac, now - TTL)
        )
        inv.execute(
            "INSERT OR IGNORE INTO characterization_dirty SELECT device_id "
            "FROM observations WHERE mac=?",
            (mac,),
        )
        count = inv.execute(
            "SELECT COUNT(*) FROM characterization_evidence WHERE mac=?", (mac,)
        ).fetchone()[0]
        exists = inv.execute(
            "SELECT 1 FROM characterization_evidence WHERE mac=? AND kind=? AND service=?",
            (mac, kind, service),
        ).fetchone()
        if count >= 256 and not exists:
            inv.execute(
                "INSERT INTO characterization_overflow VALUES (?,?) "
                "ON CONFLICT(mac) DO UPDATE SET until=MAX(until,excluded.until)",
                (mac, stamp + TTL),
            )
            continue
        inv.execute(
            "INSERT INTO characterization_evidence VALUES (?,?,?,?) "
            "ON CONFLICT(mac,kind,service) DO UPDATE SET "
            "observed_at=MAX(observed_at,excluded.observed_at)",
            (mac, kind, service, stamp),
        )


def refresh_characterization(inv, ov, now):
    after = inv.execute(
        "SELECT value FROM pipeline_meta WHERE key='characterization_cursor'"
    ).fetchone()
    devices = inv.execute(
        "SELECT id FROM devices WHERE id>? ORDER BY id LIMIT 20", (after[0] if after else "",)
    ).fetchall()
    priority = inv.execute(
        "SELECT device_id FROM characterization_dirty ORDER BY device_id LIMIT 20"
    ).fetchall()
    expired = inv.execute(
        "SELECT id FROM devices WHERE inferred_valid_until<=? "
        "ORDER BY inferred_valid_until LIMIT 20",
        (now,),
    ).fetchall()
    devices = [(d,) for d in dict.fromkeys(r[0] for r in [*priority, *expired, *devices])][:20]
    with immediate(inv):
        inv.execute(
            "DELETE FROM characterization_evidence WHERE rowid IN "
            "(SELECT rowid FROM characterization_evidence WHERE observed_at<=? "
            "ORDER BY observed_at LIMIT 1000)",
            (now - TTL,),
        )
        inv.execute("DELETE FROM characterization_overflow WHERE until<=?", (now,))
    seen = set()
    for (requested,) in devices:
        device = requested
        try:
            identity = lineage(inv, ov, device)
        except LineageUnavailable:
            continue
        device = identity.device_id
        if device in seen:
            continue
        seen.add(device)
        candidates = []
        incomplete = False
        conflicting = False
        has_evidence = False
        for mac in identity.macs:
            overflow = inv.execute(
                "SELECT 1 FROM characterization_overflow WHERE mac=? AND until>?", (mac, now)
            ).fetchone()
            rows = inv.execute(
                "SELECT kind,service,observed_at FROM characterization_evidence "
                "WHERE mac=? ORDER BY kind,service LIMIT 257",
                (mac,),
            ).fetchall()
            has_evidence |= bool(rows) or bool(overflow)
            result = (
                Classification(reason="input_limit")
                if overflow
                else classify(
                    (Observation(mac, stamp, kind, service) for kind, service, stamp in rows), now
                )
            )
            conflicting |= result.reason == "conflicting_roles"
            incomplete |= result.reason in {"input_limit", "invalid_input", "mixed_macs"}
            if result.inferred_type != "unknown":
                candidates.append(result)
        kinds = {(r.inferred_type, r.role) for r in candidates}
        if conflicting:
            result = Classification(reason="conflicting_roles")
        elif incomplete:
            result = Classification(reason="input_limit")
        elif len(kinds) == 1:
            result = min(candidates, key=lambda r: r.valid_until)
        else:
            result = Classification(
                reason="conflicting_roles" if candidates else "insufficient_evidence"
            )
        with immediate(inv):
            try:
                fresh = lineage(inv, ov, device)
            except LineageUnavailable:
                continue
            if fresh.key != identity.key:
                continue
            inv.execute("DELETE FROM characterization_dirty WHERE device_id=?", (requested,))
            cached = inv.execute(
                "SELECT result FROM characterization_results WHERE device_id=?", (device,)
            ).fetchone()
            payload = json.dumps(
                {"lineage": identity.key, "classification": asdict(result)}, sort_keys=True
            )
            if (cached is None and not has_evidence) or (
                cached is not None and cached[0] == payload
            ):
                continue
            inv.execute(
                "INSERT INTO characterization_results VALUES (?,?) "
                "ON CONFLICT(device_id) DO UPDATE SET result=excluded.result",
                (
                    device,
                    payload,
                ),
            )
            inv.execute(
                "UPDATE devices SET inferred_type=?,inferred_confidence=NULL,"
                "inferred_source=?,inferred_reason_code=?,inferred_reason_text=NULL,"
                "inferred_model_version=?,inferred_updated_at=?,inferred_valid_until=? WHERE id=?",
                (
                    result.inferred_type,
                    result.source,
                    result.reason,
                    result.model_version,
                    iso_utc(now),
                    result.valid_until,
                    device,
                ),
            )
    with immediate(inv):
        inv.execute(
            "INSERT INTO pipeline_meta VALUES ('characterization_cursor',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (devices[-1][0] if devices else "",),
        )
