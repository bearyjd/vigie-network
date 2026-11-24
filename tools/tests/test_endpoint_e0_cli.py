"""E0 feasibility tool: read-only sqlite loading and the 48 h single-device report. Synthetic."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from e0_synth import (
    COLLECTOR,
    DAY,
    HEALTH,
    MAC,
    MAC_B,
    T0,
    TOOLS,
    WINDOW,
    e0,
    event,
    scope,
    scope_dict,
    write_inventory,
    write_shard,
)

router = e0.router
inputs = e0.inputs
CLI = TOOLS / "endpoint_feasibility.py"
DESTS = ("192.0.2.10", "198.51.100.20", "2001:db8::30", "203.0.113.40")


def ok_row(bid: str, start: int, **over) -> tuple:
    return (
        over.get("collector", COLLECTOR),
        bid,
        start,
        start + WINDOW,
        over.get("kind", "observation"),
        over.get("health", HEALTH),
        over.get("truncated"),
        over.get("dropped", 0),
    )


@pytest.mark.parametrize(
    ("over", "start", "want"),
    [
        ({}, T0, ()),
        ({"kind": "probe"}, T0, ("probe",)),
        ({"kind": None}, T0, ("legacy_kind",)),
        ({"health": None}, T0, ("health_missing",)),
        ({"truncated": '{"ct_dropped_keys": 3}'}, T0, ("flow_degraded",)),
        ({"truncated": '{"truncated_other": 1}'}, T0, ("flow_degraded",)),
        ({"truncated": '{"source_flags": 8, "ct_unmapped_bytes": 9}'}, T0, ()),
        ({"dropped": 2}, T0, ("flow_degraded",)),
        ({}, T0 + 3570, ("cross_hour",)),
    ],
)
def test_batch_reasons_mirror_pipeline_acceptance(over: dict, start: int, want: tuple) -> None:
    row = ok_row("b", start, **over)
    keys = ("collector_id", "batch_id", "window_start", "window_end", "observation_kind")
    record = dict(zip(keys, row[:5], strict=True))
    record.update(health=row[5], truncated=row[6], dropped_batches=row[7])
    assert router.batch_reasons(record) == want


def test_batch_reasons_legacy_and_empty_windows() -> None:
    base = {"observation_kind": "observation", "health": HEALTH, "truncated": None}
    legacy = {**base, "window_start": None, "window_end": None, "dropped_batches": 0}
    assert router.batch_reasons(legacy) == ("legacy_window",)
    empty = {**base, "window_start": T0, "window_end": T0, "dropped_batches": 0}
    assert router.batch_reasons(empty) == ("empty_window",)


def build_48h(tmp_path: Path, wal: bool = False) -> dict[str, Path]:
    raw = tmp_path / "raw"
    raw.mkdir()
    batches, shards, events = [], {}, []
    for i in range(2 * DAY // WINDOW):
        start = T0 + i * WINDOW
        bid = f"b{i:05d}"
        batches.append(ok_row(bid, start))
        day = "202311" + str(15 + (start + WINDOW) // DAY - T0 // DAY)
        dst = DESTS[i % 4]
        end = start + WINDOW
        shards.setdefault(day, []).extend(
            [
                (COLLECTOR, end, MAC, dst, 443, "tcp", 400, 1500, 2, bid),
                (COLLECTOR, end, MAC, None, None, "other", 10, 20, 1, bid),
                (COLLECTOR, end, MAC, "192.168.8.1", 53, "udp", 5, 5, 1, bid),
            ]
        )
        if i % 50:
            events.append(event(start + 5, dst=dst.upper()))
    batches.append((COLLECTOR, "legacy", None, None, None, None, None, 0))
    batches.append(ok_row("hurt", T0 + DAY + 30, truncated='{"ct_errors": 1}'))
    shards["20231116"] += [
        (COLLECTOR, T0 + DAY + 90, MAC, "192.0.2.99", 443, "tcp", 1, 1, 1, "hurt"),
        (COLLECTOR, T0 + DAY + 90, MAC, "192.0.2.98", 443, "tcp", 1, 1, 1, "legacy"),
        (COLLECTOR, T0 + DAY + 90, MAC, "192.0.2.97", 443, "tcp", 1, 1, 1, "ghost"),
    ]
    write_inventory(tmp_path / "inventory.db", batches, wal=wal)
    for day, rows in shards.items():
        write_shard(raw, day, rows, wal=wal)
    paths = {"inventory": tmp_path / "inventory.db", "raw": raw}
    paths["events"] = tmp_path / "events.jsonl"
    paths["events"].write_text("\n".join(json.dumps(e) for e in events + [events[3]]) + "\n")
    paths["scope"] = tmp_path / "scope.json"
    paths["scope"].write_text(json.dumps(scope_dict(export_start=T0)))
    return paths


def run_cli(paths: dict[str, Path], *extra: str) -> subprocess.CompletedProcess:
    args = ["--scope", paths["scope"], "--events", paths["events"]]
    args += ["--inventory", paths["inventory"], "--raw-dir", paths["raw"], *extra]
    cmd = [sys.executable, "-I", str(CLI), *map(str, args)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)


def test_48h_single_device_report_end_to_end(tmp_path: Path) -> None:
    paths = build_48h(tmp_path)
    before = {p: p.read_bytes() for p in paths["raw"].iterdir()}
    proc = run_cli(paths)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["gate"]["verdict"] == "go"
    share = out["other_share"]
    assert share["mapped_bytes"] == 2880 * (1900 + 30 + 10) + 3 * 2  # hurt, legacy, ghost orphan
    assert share["orphan_bytes"] == 2
    assert share["other_bytes"] == 2880 * 30
    m = out["match"]
    assert m["eligible_keys"] == 2880
    assert m["excluded_keys"]["flow_degraded"] == 1 and m["excluded_keys"]["legacy_window"] == 1
    gated, warm = m["gated"], m["warm_up"]
    assert gated["direct"]["denominator"] + warm["direct"]["denominator"] == 2880
    assert gated["direct"]["matched"] == gated["direct"]["denominator"] - 29
    assert gated["combined"]["matched"] == gated["combined"]["denominator"]
    assert out["events"]["duplicates"] == 1
    assert out["flows"]["orphan_rows"] == 1
    assert {p: p.read_bytes() for p in paths["raw"].iterdir()} == before


def test_report_is_byte_identical_across_runs(tmp_path: Path) -> None:
    paths = build_48h(tmp_path)
    first, second = run_cli(paths), run_cli(paths)
    assert first.stdout == second.stdout and first.returncode == 0


def test_no_go_exits_one_and_input_errors_exit_two(tmp_path: Path) -> None:
    paths = build_48h(tmp_path)
    paths["events"].write_text("")
    assert run_cli(paths).returncode == 1
    paths["scope"].write_text('{"host_id": 1}')
    proc = run_cli(paths)
    assert proc.returncode == 2 and "error" in proc.stderr


def test_loader_caps_batches_and_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = build_48h(tmp_path)
    sc = scope()
    monkeypatch.setattr(router, "MAX_BATCHES", 100)
    with pytest.raises(inputs.InputError, match="batch"):
        router.load_router(paths["inventory"], paths["raw"], sc)
    monkeypatch.setattr(router, "MAX_BATCHES", 10_000)
    monkeypatch.setattr(router, "MAX_FLOW_ROWS", 100)
    with pytest.raises(inputs.InputError, match="row"):
        router.load_router(paths["inventory"], paths["raw"], sc)


def test_loader_rejects_bad_counters_and_reports_missing_shards(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    write_inventory(tmp_path / "inv.db", [ok_row("b1", T0)])
    write_shard(
        raw, "20231115", [(COLLECTOR, T0 + 60, MAC, "192.0.2.1", 443, "tcp", 1, 1, 1, "b1")]
    )
    data = router.load_router(tmp_path / "inv.db", raw, scope())
    assert data.missing_shards == ("raw-20231116.db", "raw-20231117.db")
    write_shard(raw, "20231116", [(COLLECTOR, T0 + DAY, MAC, None, None, "other", -5, 1, 1, "b1")])
    with pytest.raises(inputs.InputError, match="counter"):
        router.load_router(tmp_path / "inv.db", raw, scope())


def test_loader_errors_on_missing_inventory(tmp_path: Path) -> None:
    with pytest.raises(inputs.InputError):
        router.load_router(tmp_path / "absent.db", tmp_path, scope())


def test_loader_reads_only_scoped_macs_so_foreign_rows_do_not_trip_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    write_inventory(tmp_path / "inv.db", [ok_row("b1", T0)])
    foreign = [(COLLECTOR, T0 + 60, "02:00:00:00:0f:01", "192.0.2.1", 443, "tcp", 1, 1, 1, "b1")]
    mine = [(COLLECTOR, T0 + 60, MAC, "192.0.2.1", 443, "tcp", 1, 1, 1, "b1")]
    write_shard(raw, "20231115", foreign * 50 + mine)
    monkeypatch.setattr(router, "MAX_FLOW_ROWS", 10)
    data = router.load_router(tmp_path / "inv.db", raw, scope())
    assert [f.mac for f in data.flows] == [MAC]


def test_loader_fetches_only_batches_referenced_by_loaded_rows(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    legacy = [(COLLECTOR, f"old{i}", None, None, None, None, None, 0) for i in range(30)]
    write_inventory(tmp_path / "inv.db", [ok_row("b1", T0), ok_row("b2", T0 + 60), *legacy])
    write_shard(
        raw, "20231115", [(COLLECTOR, T0 + 60, MAC, "192.0.2.1", 443, "tcp", 1, 1, 1, "b1")]
    )
    data = router.load_router(tmp_path / "inv.db", raw, scope())
    assert set(data.batches) == {(COLLECTOR, "b1")}


def test_loader_reads_every_scoped_mac_and_normalizes_ip_and_proto(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    write_inventory(tmp_path / "inv.db", [ok_row("b1", T0)])
    rows = [
        (COLLECTOR, T0 + 60, MAC, "192.0.2.1", 443, "tcp", 1, 1, 1, "b1"),
        (COLLECTOR, T0 + 60, MAC_B, "2001:DB8:0:0::30", 443, "tcp6", 1, 1, 1, "b1"),
        (COLLECTOR, T0 + 60, "02:00:00:00:0f:01", "192.0.2.2", 443, "tcp", 1, 1, 1, "b1"),
    ]
    write_shard(raw, "20231115", rows)
    sc = scope(macs=[{"mac": MAC}, {"mac": MAC_B.upper()}])
    data = router.load_router(tmp_path / "inv.db", raw, sc)
    got = sorted((f.mac, f.dst_ip, f.proto) for f in data.flows)
    assert got == [(MAC, "192.0.2.1", "tcp"), (MAC_B, "2001:db8::30", "tcp")]


def test_loader_counter_cap_is_inclusive(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    write_inventory(tmp_path / "inv.db", [ok_row("b1", T0)])
    cap = router.MAX_COUNTER
    write_shard(raw, "20231115", [(COLLECTOR, T0 + 60, MAC, None, None, "other", cap, 1, 1, "b1")])
    assert router.load_router(tmp_path / "inv.db", raw, scope()).flows[0].bytes_up == cap
    write_shard(
        raw, "20231115", [(COLLECTOR, T0 + 60, MAC, None, None, "other", cap + 1, 1, 1, "b1")]
    )
    with pytest.raises(inputs.InputError, match="counter"):
        router.load_router(tmp_path / "inv.db", raw, scope())


def test_sqlite_connections_are_read_only_twice_over(tmp_path: Path) -> None:
    write_inventory(tmp_path / "inv.db", [])
    db = router._open_ro(tmp_path / "inv.db")
    try:
        assert db.execute("PRAGMA query_only").fetchone()[0] == 1
        db.execute("PRAGMA query_only=OFF")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("CREATE TABLE t (a)")
    finally:
        db.close()


@pytest.mark.parametrize("day", ["20231115", "20231116"])
def test_missing_in_period_shard_gives_no_result(tmp_path: Path, day: str) -> None:
    paths = build_48h(tmp_path)
    (paths["raw"] / f"raw-{day}.db").unlink()
    proc = run_cli(paths)
    assert proc.returncode == 1, proc.stderr
    gate = json.loads(proc.stdout)["gate"]
    assert gate["verdict"] == "no_result"
    assert "raw_shard_missing_in_period" in gate["reasons"]


def test_absent_boundary_shard_after_midnight_end_still_goes(tmp_path: Path) -> None:
    paths = build_48h(tmp_path)
    (paths["raw"] / "raw-20231117.db").unlink()  # the day after a midnight-aligned period_end
    proc = run_cli(paths)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["gate"] == {**out["gate"], "verdict": "go", "reasons": []}
    assert out["flows"]["missing_shards"] == ["raw-20231117.db"]


def test_nonexistent_raw_dir_is_an_input_error(tmp_path: Path) -> None:
    paths = build_48h(tmp_path)
    paths["raw"] = tmp_path / "absent"
    proc = run_cli(paths)
    assert proc.returncode == 2 and "raw" in proc.stderr


def test_wal_mode_inputs_leave_the_directories_unchanged(tmp_path: Path) -> None:
    paths = build_48h(tmp_path, wal=True)
    before = sorted(os.listdir(paths["raw"])), sorted(os.listdir(tmp_path))
    proc = run_cli(paths)
    assert proc.returncode == 0, proc.stderr
    assert (sorted(os.listdir(paths["raw"])), sorted(os.listdir(tmp_path))) == before


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_wal_mode_inputs_in_read_only_directories(tmp_path: Path) -> None:
    paths = build_48h(tmp_path, wal=True)
    dirs = (paths["raw"], tmp_path)
    try:
        for d in dirs:
            d.chmod(0o555)
        proc = run_cli(paths)
    finally:
        for d in dirs:
            d.chmod(0o755)
    assert proc.returncode == 0, proc.stderr


def test_uncheckpointed_wal_is_an_input_error_not_a_silent_short_read(tmp_path: Path) -> None:
    paths = build_48h(tmp_path, wal=True)
    live = sqlite3.connect(paths["raw"] / "raw-20231116.db")
    try:
        live.execute("PRAGMA wal_autocheckpoint=0")
        live.execute("DELETE FROM raw_flow WHERE rowid > 100")
        live.commit()
        assert (paths["raw"] / "raw-20231116.db-wal").stat().st_size > 0
        before = sorted(os.listdir(paths["raw"]))
        proc = run_cli(paths)
        assert sorted(os.listdir(paths["raw"])) == before
    finally:
        live.close()
    assert proc.returncode == 2 and "copy" in proc.stderr


def test_hot_rollback_journal_is_an_input_error(tmp_path: Path) -> None:
    write_inventory(tmp_path / "inv.db", [ok_row("b1", T0)])
    (tmp_path / "inv.db-journal").write_bytes(b"hot")
    with pytest.raises(inputs.InputError, match="copy"):
        router.load_router(tmp_path / "inv.db", tmp_path, scope())


def test_symlinked_shard_with_a_hot_wal_beside_its_target_is_refused(tmp_path: Path) -> None:
    """Review repro: the WAL sits beside the link target, where immutable=1 never looks."""
    paths = build_48h(tmp_path, wal=True)
    target = tmp_path / "elsewhere"
    target.mkdir()
    shard = paths["raw"] / "raw-20231116.db"
    shard.rename(target / shard.name)
    shard.symlink_to(target / shard.name)
    live = sqlite3.connect(target / shard.name)
    try:
        live.execute("PRAGMA wal_autocheckpoint=0")
        row = (COLLECTOR, T0 + DAY + 60, MAC, None, None, "other", 2 * 10**9, 0, 1, "b01440")
        live.execute("INSERT INTO raw_flow VALUES (?,?,?,?,?,?,?,?,?,?)", row)
        live.commit()
        assert (target / f"{shard.name}-wal").stat().st_size > 0
        proc = run_cli(paths)
    finally:
        live.close()
    assert proc.returncode == 2 and "link" in proc.stderr, proc.stdout[:200]


def test_symlinked_inventory_is_refused(tmp_path: Path) -> None:
    paths = build_48h(tmp_path)
    link = tmp_path / "inv-link.db"
    link.symlink_to(paths["inventory"])
    paths["inventory"] = link
    proc = run_cli(paths)
    assert proc.returncode == 2 and "link" in proc.stderr


def _touch_mtime(path: Path) -> None:
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))


def _add_wal(path: Path) -> None:
    path.with_name(path.name + "-wal").write_bytes(b"")


@pytest.mark.parametrize("change", [_touch_mtime, _add_wal])
def test_database_changed_while_being_read_is_an_input_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change
) -> None:
    paths = build_48h(tmp_path)
    real = router._open_ro

    def racing(path: Path):
        db = real(path)
        change(path)
        return db

    monkeypatch.setattr(router, "_open_ro", racing)
    with pytest.raises(inputs.InputError, match="changed while being read"):
        router.load_router(paths["inventory"], paths["raw"], scope())
