"""Probe fold: untrusted state file -> pipeline_meta['probe_status'] + probe_* events."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest
from probe_helpers import NOW, pr, state_doc, target_state, write_probe_file

from vigie_pipeline import probes
from vigie_pipeline.config import PipelineConfig, ProbeSettings
from vigie_pipeline.probe_file import MAX_FILE_BYTES, ProbeFileInvalid, parse_probe_doc
from vigie_pipeline.schema import open_pipeline_inventory

DAY = "2027-01-15"


@pytest.fixture
def inv(tmp_path):
    probes._reset_log_memory()  # the once-per-change log memory is module state
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    yield conn
    conn.close()


@pytest.fixture
def settings(tmp_path):
    return ProbeSettings(file=tmp_path / "probe-state.json")


def fold(inv, settings, now=NOW + 5):
    probes.fold_probes(inv, settings, lambda: now)


def status(inv):
    row = inv.execute("SELECT value FROM pipeline_meta WHERE key='probe_status'").fetchone()
    return json.loads(row[0]) if row else None


def events(inv):
    return [
        tuple(r)
        for r in inv.execute(
            "SELECT kind, severity, summary, dedup, device_id FROM events"
            " WHERE kind LIKE 'probe_%' ORDER BY seq"
        )
    ]


def kinds(inv):
    return [e[0] for e in events(inv)]


# ---------------------------------------------------------------- settings
def test_settings_default_disabled_and_from_env():
    assert not PipelineConfig(data_dir=Path("/x")).probes.enabled
    assert not ProbeSettings.from_env({}).enabled
    on = ProbeSettings.from_env({"VIGIE_PROBE_FILE": "/probe/probe-state.json"})
    assert on.enabled and on.stale_s == 300
    assert (
        ProbeSettings.from_env(
            {"VIGIE_PROBE_FILE": "/probe/probe-state.json", "VIGIE_PROBE_STALE_S": "180"}
        ).stale_s
        == 180
    )
    for bad in ("179", "86401", "abc"):
        with pytest.raises(ValueError):
            ProbeSettings.from_env(
                {"VIGIE_PROBE_FILE": "/probe/probe-state.json", "VIGIE_PROBE_STALE_S": bad}
            )


# ---------------------------------------------------------------- untrusted input
def _big():
    return b" " * (MAX_FILE_BYTES + 1) + json.dumps(state_doc(target_state())).encode()


HOSTILE = {
    "oversize": _big(),
    "not_json": b"{nope",
    "not_utf8": b"\xff\xfe",
    "nan": b'{"v":1,"written_at":NaN,"targets":[]}',
    "infinity_in_target": json.dumps(state_doc(target_state()))
    .encode()
    .replace(b'"last_ok_at": %s' % str(NOW).encode(), b'"last_ok_at": Infinity'),
    "list_top": b"[]",
    "unknown_top_key": json.dumps(state_doc(target_state(), extra=1)).encode(),
    "wrong_version": json.dumps(state_doc(target_state(), v=2)).encode(),
    "bool_version": json.dumps(state_doc(target_state(), v=True)).encode(),
    "unknown_target_key": json.dumps(state_doc(target_state(extra=1))).encode(),
    "missing_target_key": json.dumps(
        state_doc({k: v for k, v in target_state().items() if k != "ring"})
    ).encode(),
    "bad_id_upper": json.dumps(state_doc(target_state("Router"))).encode(),
    "bad_id_long": json.dumps(state_doc(target_state("a" * 33))).encode(),
    "bad_id_type": json.dumps(state_doc(target_state(7))).encode(),
    "bad_state": json.dumps(state_doc(target_state(state="down"))).encode(),
    "bad_error_class": json.dumps(state_doc(target_state(last_error_class="boom"))).encode(),
    "latency_high": json.dumps(state_doc(target_state(last_latency_ms=5001))).encode(),
    "latency_negative": json.dumps(state_doc(target_state(last_latency_ms=-1))).encode(),
    "count_high": json.dumps(state_doc(target_state(consecutive_fail=1001))).encode(),
    "bool_as_int": json.dumps(state_doc(target_state(consecutive_ok=True))).encode(),
    "epoch_high": json.dumps(state_doc(target_state(last_ok_at=2e11))).encode(),
    "written_negative": json.dumps(state_doc(target_state(), written_at=-1)).encode(),
    "ring_too_long": json.dumps(state_doc(target_state(ring=[[1, True, 1, None]] * 61))).encode(),
    "ring_latency_high": json.dumps(state_doc(target_state(ring=[[1, True, 5001, None]]))).encode(),
    "ring_bad_entry": json.dumps(state_doc(target_state(ring=[[1, True, 1]]))).encode(),
    "ring_bad_class": json.dumps(state_doc(target_state(ring=[[1, False, None, "x"]]))).encode(),
    "bad_day": json.dumps(state_doc(target_state(episodes_day="today"))).encode(),
    "bad_note": json.dumps(state_doc(target_state(note="hi"))).encode(),
    "eleven_targets": json.dumps(state_doc(*[target_state(f"t{i}") for i in range(11)])).encode(),
    "duplicate_ids": json.dumps(state_doc(target_state("a"), target_state("a"))).encode(),
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_files_are_stale_never_an_outage(inv, settings, name, caplog):
    write_probe_file(settings.file, HOSTILE[name])
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        fold(inv, settings)
    snap = status(inv)
    assert snap["stale"] is True and snap["reason"] == "invalid" and snap["targets"] == []
    assert kinds(inv) == ["probe_stale"]
    assert [r.getMessage() for r in caplog.records].count("probe_file_invalid") == 1
    with pytest.raises(ProbeFileInvalid):
        parse_probe_doc(HOSTILE[name])


def test_a_valid_document_parses():
    doc = parse_probe_doc(json.dumps(state_doc(target_state(), target_state("b"))).encode())
    assert [t.id for t in doc.targets] == ["router-dns", "b"]


def test_missing_stale_and_future_files_are_unavailable(inv, settings):
    fold(inv, settings)  # no file
    assert status(inv)["reason"] == "missing"
    write_probe_file(settings.file, state_doc(target_state(), written_at=NOW))
    fold(inv, settings, now=NOW + 301)
    assert (status(inv)["stale"], status(inv)["reason"]) == (True, "stale")
    fold(inv, settings, now=NOW + 300)  # exactly at the limit is still fresh
    assert status(inv)["stale"] is False
    write_probe_file(settings.file, state_doc(target_state(), written_at=NOW + 16))
    fold(inv, settings)
    assert (status(inv)["stale"], status(inv)["reason"]) == (True, "future")
    write_probe_file(settings.file, state_doc(target_state(), written_at=NOW + 15))
    fold(inv, settings)  # inside the skew allowance
    assert status(inv)["stale"] is False
    assert set(kinds(inv)) == {"probe_stale"}  # never an outage


def test_stale_data_with_an_outage_inside_never_opens_one(inv, settings):
    bad = target_state(state="outage", consecutive_fail=3, episode_start=int(NOW) - 200)
    write_probe_file(settings.file, state_doc(bad))
    fold(inv, settings, now=NOW + 1000)
    assert kinds(inv) == ["probe_stale"] and status(inv)["targets"] == []


def test_stale_event_is_once_per_utc_day(inv, settings):
    for tick in range(5):
        fold(inv, settings, now=NOW + tick * 30)
    assert kinds(inv) == ["probe_stale"]
    fold(inv, settings, now=NOW + 86400)
    assert kinds(inv) == ["probe_stale", "probe_stale"]


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_non_regular_files_are_invalid_not_a_hang(inv, settings, tmp_path, kind):
    if kind == "symlink":
        real = write_probe_file(tmp_path / "real.json", state_doc(target_state()))
        os.symlink(real, settings.file)
    elif kind == "fifo":
        os.mkfifo(settings.file)
    else:
        settings.file.mkdir()
    fold(inv, settings)
    assert (status(inv)["stale"], status(inv)["reason"]) == (True, "invalid")


# ---------------------------------------------------------------- status document
def test_status_carries_only_validated_fields(inv, settings):
    t = target_state(last_latency_ms=9, ring=[[5, True, 9, None], [6, False, None, "timeout"]])
    write_probe_file(settings.file, state_doc(t))
    fold(inv, settings)
    snap = status(inv)
    assert snap["stale"] is False and snap["reason"] is None and snap["written_at"] == NOW
    assert snap["v"] == 1 and snap["folded_at"] == int(NOW + 5)
    [row] = snap["targets"]
    assert row["id"] == "router-dns" and row["last_latency_ms"] == 9
    assert row["ring"] == [[5, True, 9, None], [6, False, None, "timeout"]]
    assert set(row) == {"id", "state", "consecutive_fail", "consecutive_ok", "last_ok_at",
                        "last_error_class", "last_latency_ms", "episode_start", "flapping",
                        "suppressed", "ring"}  # fmt: skip
    assert events(inv) == []


def test_status_size_is_bounded_before_the_write(inv, settings, monkeypatch, caplog):
    monkeypatch.setattr(probes, "MAX_STATUS_BYTES", 100)
    write_probe_file(settings.file, state_doc(target_state()))
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        fold(inv, settings)
    assert status(inv) is None
    assert "probe_stage_failed" in caplog.text


def test_max_status_fits_the_cap_with_ten_full_rings(inv, settings):
    full = [[i, False, None, "unreachable"] for i in range(60)]
    ts = [target_state(f"t{i}", ring=full, state="outage", episode_start=1, consecutive_fail=9,
                       last_error_class="unreachable") for i in range(10)]  # fmt: skip
    write_probe_file(settings.file, state_doc(*ts))
    fold(inv, settings)
    assert status(inv)["stale"] is False


# ---------------------------------------------------------------- events
START = int(NOW) - 200


def outage(**over):
    base = {"state": "outage", "consecutive_fail": 3, "consecutive_ok": 0,
            "episode_start": START, "last_error_class": "timeout"}  # fmt: skip
    return target_state(**{**base, **over})


def recovered(**over):
    return target_state(**{"state": "ok", "consecutive_ok": 3, "episode_start": START, **over})


def test_outage_then_recovery_is_one_event_each_even_replayed(inv, settings):
    write_probe_file(settings.file, state_doc(outage()))
    for _ in range(3):
        fold(inv, settings)
    write_probe_file(settings.file, state_doc(recovered()))
    for _ in range(3):
        fold(inv, settings)
    token = f"router-dns:{START}"
    assert events(inv) == [
        ("probe_outage", "warn", "probe router-dns failing (timeout)", token, None),
        ("probe_recovered", "info", "probe router-dns recovered", token, None),
    ]


def test_events_carry_no_address_or_qname_and_a_null_device(inv, settings):
    write_probe_file(settings.file, state_doc(outage()))
    fold(inv, settings)
    for _, _, summary, dedup, device in events(inv):
        assert device is None
        assert set(summary.replace("-", " ").replace("(", " ").replace(")", " ").split()) <= {
            "probe",
            "router",
            "dns",
            "failing",
            "timeout",
        }  # id + error class only
        assert "." not in summary and "." not in dedup


def test_an_episode_first_seen_already_recovered_is_announced_as_open_then_recovered(inv, settings):
    # Reversed from "never announced": an episode that opened and closed between two folds (or
    # while the pipeline was down) would otherwise leave no trace at all. Old episodes stay silent
    # (EMIT_MAX_AGE_S) and so do suppressed ones; see test_probes_final.py.
    write_probe_file(settings.file, state_doc(recovered()))
    fold(inv, settings)
    assert kinds(inv) == ["probe_outage", "probe_recovered"]


def test_first_ever_ok_and_unknown_emit_nothing(inv, settings):
    write_probe_file(settings.file, state_doc(target_state(), target_state("b", state="unknown")))
    fold(inv, settings)
    assert events(inv) == []


def test_suppressed_episode_emits_neither_open_nor_recover(inv, settings):
    write_probe_file(settings.file, state_doc(outage(suppressed=True, flapping=True)))
    fold(inv, settings)
    write_probe_file(settings.file, state_doc(recovered(suppressed=True, flapping=True)))
    fold(inv, settings)
    assert kinds(inv) == ["probe_flapping"]  # exactly one, and no open/recover


def test_flapping_event_once_per_target_day(inv, settings):
    flapping = outage(suppressed=True, flapping=True, episodes_day=DAY)
    write_probe_file(settings.file, state_doc(flapping))
    for _ in range(3):
        fold(inv, settings)
    assert events(inv) == [
        ("probe_flapping", "warn", "probe router-dns: repeated outages today, further episodes "
         "are not reported", f"router-dns:{DAY}", None)
    ]  # fmt: skip
    tomorrow = outage(suppressed=True, flapping=True, episodes_day="2027-01-16")
    write_probe_file(settings.file, state_doc(tomorrow, written_at=NOW + 86400))
    fold(inv, settings, now=NOW + 86405)
    assert kinds(inv) == ["probe_flapping", "probe_flapping"]


def test_new_episode_after_a_suppressed_one_is_reported_again(inv, settings):
    write_probe_file(settings.file, state_doc(outage(suppressed=True, flapping=True)))
    fold(inv, settings)
    later = START + 5000
    fresh = target_state(state="outage", consecutive_fail=3, episode_start=later,
                         last_error_class="refused")  # fmt: skip
    write_probe_file(settings.file, state_doc(fresh, written_at=NOW + 6000))
    fold(inv, settings, now=NOW + 6005)
    assert kinds(inv).count("probe_outage") == 1
    assert events(inv)[-1][3] == f"router-dns:{later}"


def test_two_targets_are_independent(inv, settings):
    write_probe_file(settings.file, state_doc(outage(), target_state("lan-web")))
    fold(inv, settings)
    assert [e[3] for e in events(inv)] == [f"router-dns:{START}"]


# ---------------------------------------------------------------- containment
def test_a_failing_fold_never_raises_and_rolls_back(inv, settings, monkeypatch, caplog):
    write_probe_file(settings.file, state_doc(outage()))

    def boom(*a, **k):
        raise RuntimeError("10.0.0.7 secret")

    monkeypatch.setattr(probes, "emit_once", boom)
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        fold(inv, settings)
    assert status(inv) is None and events(inv) == []  # both folds failed: nothing half-written
    assert [r.getMessage() for r in caplog.records] == [
        "probe_stage_failed",
        "probe_status_unmarked",
    ]
    assert all(r.fields == {"error": "RuntimeError"} for r in caplog.records)
    assert "10.0.0.7" not in caplog.text
    assert not inv.in_transaction


# ---------------------------------------------------------------- M1 exit test
def test_runner_outage_sequence_is_visible_within_two_ticks_of_the_third_failure(inv, settings):
    run_cfg = pr.parse_config(
        {"enabled": True, "state_file": str(settings.file),
         "targets": [{"id": "lan-web", "kind": "tcp_lan", "address": "10.0.0.9", "port": 8080}]}
    )  # fmt: skip
    clock = [NOW]
    state = pr.empty_state()

    def refuse(host, port, timeout):
        raise ConnectionRefusedError

    visible_after = None
    for minute in range(6):
        clock[0] = NOW + minute * 60
        state = pr.run_pass(run_cfg, state, now=lambda: clock[0], dns=None, connect=refuse)
        write_probe_file(settings.file, pr.serialize_state(state))
        if minute < 2:  # F, F: no outage yet
            for tick in (0, 30):
                fold(inv, settings, now=clock[0] + tick)
            assert "probe_outage" not in kinds(inv)
        else:
            for tick in (0, 30):  # two 30 s pipeline ticks after the third failure
                fold(inv, settings, now=clock[0] + tick)
                if "probe_outage" in kinds(inv) and visible_after is None:
                    visible_after = tick
        if minute == 2:
            break
    assert visible_after == 0
    [(kind, _, summary, token, _)] = events(inv)
    assert kind == "probe_outage" and summary == "probe lan-web failing (refused)"
    assert token == f"lan-web:{int(NOW + 120)}"
