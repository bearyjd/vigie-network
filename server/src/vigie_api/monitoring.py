"""Read-only, collector-scoped monitoring views. No raw shard mount or human-intent writes."""

from __future__ import annotations

import json

from vigie_api.effective import decode_cursor, encode_cursor
from vigie_api.errors import ApiError
from vigie_api.incident_decisions import attention, review_view, reviews_for
from vigie_pipeline.monitoring_identity import LineageUnavailable, lineage

MAX_MACS = 64
MAX_ALIASES = 256


def required(inv):
    tables = {row[0] for row in inv.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if (
        not {
            "coverage_hourly",
            "measurement_batches",
            "measurements_hourly",
            "monitoring_profiles",
            "monitoring_baselines",
            "monitoring_incidents",
            "monitoring_unavailable",
        }
        <= tables
    ):
        raise ApiError(503, "monitoring_unavailable", "monitoring migrations have not run")


def page(scope, collector, device, start, end, limit, cursor, now):
    finish = int(now) // 3600 * 3600 + 3600 if end is None else end
    begin = finish - 86400 if start is None else start
    if (
        begin < 0
        or begin % 3600
        or finish % 3600
        or not 0 < finish - begin <= 90 * 86400
        or finish > int(now) // 3600 * 3600 + 3600
    ):
        raise ApiError(
            400, "invalid_range", "use UTC hour boundaries within a maximum 90-day range"
        )
    after = begin
    if cursor:
        try:
            value = json.loads(decode_cursor(cursor))
            if (
                not isinstance(value, list)
                or len(value) != 6
                or value[:5] != [scope, collector, device, begin, finish]
            ):
                raise ValueError
            after = value[5]
            if type(after) is not int or not begin <= after < finish or after % 3600:
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise ApiError(
                400, "invalid_cursor", "cursor does not match this monitoring range/scope"
            ) from exc
    stop = min(finish, after + limit * 3600)
    token = (
        encode_cursor(
            json.dumps([scope, collector, device, begin, finish, stop], separators=(",", ":"))
        )
        if stop < finish
        else None
    )
    return after, stop, token


def collector_summary(inv, collector):
    owner = inv.execute(
        "SELECT boot_id,last_seq FROM collectors WHERE id=?", (collector,)
    ).fetchone()
    if owner is None:
        raise ApiError(404, "collector_not_found", "collector not found")
    rows = inv.execute(
        "SELECT received_at,window_start,window_end,observation_kind,health,truncated,"
        "dropped_batches,dns_queries "
        "FROM batches WHERE collector_id=? ORDER BY received_at DESC,batch_id DESC LIMIT 10001",
        (collector,),
    ).fetchall()
    capped = len(rows) > 10000
    rows = rows[:10000]
    observed = next((row for row in rows if row["observation_kind"] == "observation"), None)
    dns_observed = next(
        (
            row
            for row in rows
            if row["observation_kind"] != "probe"
            and row["window_end"] is not None
            and (row["dns_queries"] or 0) > 0
        ),
        None,
    )
    latest = observed or (rows[0] if rows else None)
    health = json.loads(latest["health"] or "{}") if latest else {}
    flags = json.loads(latest["truncated"] or "{}") if latest else {}
    pending = inv.execute(
        "SELECT b.received_at FROM batches b WHERE b.collector_id=? AND NOT EXISTS "
        "(SELECT 1 FROM measurement_batches m WHERE m.collector_id=b.collector_id "
        "AND m.batch_id=b.batch_id) ORDER BY b.received_at,b.batch_id LIMIT 10001",
        (collector,),
    ).fetchall()
    truncated = [json.loads(row["truncated"] or "{}") for row in rows]
    unavailable = [
        dict(row)
        for row in inv.execute(
            "SELECT device_id,reason,retry_at FROM monitoring_unavailable WHERE collector_id=? "
            "ORDER BY device_id LIMIT 21",
            (collector,),
        )
    ]
    return {
        "collector_id": collector,
        "monitoring_unavailable": unavailable[:20],
        "monitoring_unavailable_capped": len(unavailable) > 20,
        "last_received_at": rows[0]["received_at"] if rows else None,
        "latest_observation_received_at": observed["received_at"] if observed else None,
        "latest_window_end": observed["window_end"] if observed else None,
        "latest_dns_observation_window_end": dns_observed["window_end"] if dns_observed else None,
        "latest_dns_observation_received_at": dns_observed["received_at"] if dns_observed else None,
        "boot_id": owner["boot_id"],
        "last_seq": owner["last_seq"],
        "backlog_batches": min(len(pending), 10000),
        "backlog_capped": len(pending) > 10000,
        "oldest_pending_received_at": pending[0]["received_at"] if pending else None,
        "retained_detail_since": rows[-1]["received_at"] if rows else None,
        "summary_capped": capped,
        "dropped_batches_in_retained_detail": sum(row["dropped_batches"] for row in rows),
        "ct_unmapped_bytes_in_retained_detail": sum(
            t.get("ct_unmapped_bytes", 0) for t in truncated
        ),
        "ct_unmapped_flows_in_retained_detail": sum(
            t.get("ct_unmapped_flows", 0) for t in truncated
        ),
        "source_flags_latest": flags.get("source_flags", 0) if latest and health else None,
        "agent_rss_kb": health.get("rss_kb"),
        "agent_uptime_s": health.get("uptime_s"),
        "dns_log_quiet": health.get("dns_log_quiet"),
    }


def coverage(inv, collector, start, stop, now):
    found = {
        row["hour"]: row
        for row in inv.execute(
            "SELECT * FROM coverage_hourly "
            "WHERE collector_id=? AND hour>=? AND hour<? ORDER BY hour",
            (collector, start, stop),
        )
    }
    hours = []
    for hour in range(start, stop, 3600):
        row = found.get(hour)
        reasons = json.loads(row["reasons"]) if row else ["missing"]
        state = (
            "missing"
            if row is None
            else "eligible"
            if row["qualified_seconds"] >= 3420 and not reasons
            else "partial"
        )
        if hour + 3600 > now:
            state = "open"
        hours.append(
            {
                "hour": hour,
                "state": state,
                "observed_seconds": row["observed_seconds"] if row else None,
                "qualified_seconds": row["qualified_seconds"] if row else None,
                "reasons": reasons,
            }
        )
    return hours


def device_macs(inv, ov, device):
    if inv.execute("SELECT 1 FROM devices WHERE id=?", (device,)).fetchone() is None:
        raise ApiError(404, "device_not_found", "device not found")
    try:
        found = lineage(inv, ov, device)
    except LineageUnavailable as exc:
        raise ApiError(409, "monitoring_lineage_unavailable", str(exc)) from exc
    return found.device_id, list(found.macs), found.key


def activity(inv, ov, device, collector, start, stop, hours):
    canonical, macs, lineage = device_macs(inv, ov, device)
    totals = {}
    if macs:
        marks = ",".join("?" for _ in macs)
        rows = inv.execute(
            f"SELECT hour,SUM(bytes_up) AS bytes_up,SUM(bytes_down) AS bytes_down,"  # noqa: S608
            f"SUM(flows) AS flows,SUM(dns_queries) AS dns_queries FROM measurements_hourly "
            f"WHERE collector_id=? AND mac IN ({marks}) AND hour>=? AND hour<? "
            "GROUP BY hour ORDER BY hour",
            (collector, *macs, start, stop),
        ).fetchall()  # noqa: S608
        totals = {row["hour"]: row for row in rows}
    out = []
    for hour in hours:
        row = totals.get(hour["hour"])
        out.append(
            {
                **hour,
                **{
                    key: row[key] if row and "raw_missing" not in hour["reasons"] else None
                    for key in ("bytes_up", "bytes_down", "flows", "dns_queries")
                },
            }
        )
    return {
        "device_id": canonical,
        "collector_id": collector,
        "lineage": lineage,
        "hours": out,
        "baseline": baseline_view(inv, collector, canonical, lineage),
    }


def baseline_view(inv, collector, device, key):
    from vigie_pipeline.baselines import ALGORITHM

    row = inv.execute(
        "SELECT * FROM monitoring_profiles WHERE collector_id=? AND device_id=?",
        (collector, device),
    ).fetchone()
    state = "learning" if row is None else row["state"] if row["lineage"] == key else "rebuilding"
    model = None
    if row is not None and row["baseline_id"] and state == "mature":
        model = inv.execute(
            "SELECT * FROM monitoring_baselines WHERE id=?", (row["baseline_id"],)
        ).fetchone()
        if model is None:
            state = "rebuilding"
        elif inv.execute(
            "SELECT 1 FROM coverage_hourly WHERE collector_id=? AND hour IN "
            "(SELECT value FROM json_each(?)) AND (qualified_seconds<3420 OR reasons<>'[]') "
            "LIMIT 1",
            (collector, model["training_hours"]),
        ).fetchone():
            state = "rebuilding_quality"
            model = None
    return {
        "state": state,
        "baseline_id": model["id"] if model else None,
        "algorithm": ALGORITHM,
        "config_version": row["config_version"] if row else None,
        "sample_hours": row["sample_hours"] if row else 0,
        "distinct_days": row["distinct_days"] if row else 0,
        "training_since": row["training_since"] if row else None,
        "trained_until": model["trained_until"] if model else None,
        "median_upload_bytes": model["median_twice"] / 2 if model else None,
    }


def incident_row(inv, ov, row, review, now):
    try:
        current = device_macs(inv, ov, row["device_id"])[2] == row["lineage"]
    except ApiError:
        current = False
    return {
        "id": row["id"],
        "collector_id": row["collector_id"],
        "device_id": row["device_id"],
        "lineage": row["lineage"],
        "current_lineage": current,
        "detector": row["detector"],
        "state": row["state"],
        "episode_start": row["episode_start"],
        "last_hour": row["last_hour"],
        "detected_at": row["detected_at"],
        "observed_bytes": row["observed_bytes"],
        "threshold_bytes": row["threshold_bytes"],
        "baseline_id": row["baseline_id"],
        "evidence": json.loads(row["evidence"]),
        "review": review_view(review),
        "decision_version": review["version"] if review else 0,
        "attention": attention(row["state"], review, now),
    }


def incident_list(inv, ov, collector, device, cursor, limit, state, now):
    after = 0
    if cursor:
        try:
            value = json.loads(decode_cursor(cursor))
            if (
                not isinstance(value, list)
                or len(value) != 5
                or value[:4] != ["incidents", collector, device, state]
            ):
                raise ValueError
            after = value[4]
            if type(after) is not int or not 0 <= after < 2**63:
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise ApiError(400, "invalid_cursor", "invalid incident cursor") from exc
    if device is None:
        rows = inv.execute(
            "SELECT * FROM monitoring_incidents WHERE collector_id=? AND seq>? AND (? IS NULL"
            " OR state=?) ORDER BY seq LIMIT ?",
            (collector, after, state, state, limit + 1),
        ).fetchall()
    else:
        canonical = device_macs(inv, ov, device)[0]
        rows = inv.execute(
            "SELECT * FROM monitoring_incidents WHERE collector_id=? AND device_id=? A"
            "ND seq>? AND (? IS NULL OR state=?) ORDER BY seq LIMIT ?",
            (collector, canonical, after, state, state, limit + 1),
        ).fetchall()
    page = rows[:limit]
    reviews = reviews_for(ov, [row["id"] for row in page])
    items = [incident_row(inv, ov, row, reviews.get(row["id"]), now) for row in page]
    nxt = (
        encode_cursor(json.dumps(["incidents", collector, device, state, rows[limit - 1]["seq"]]))
        if len(rows) > limit
        else None
    )
    return items, nxt
