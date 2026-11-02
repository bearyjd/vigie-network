from __future__ import annotations

import json
import logging

import pytest
from pipeline_helpers import T0, data  # noqa: F401

from vigie_pipeline import cli
from vigie_pipeline.logs import JsonFormatter

NIC = "00:11:22:33:44:55"


def test_run_once_processes_and_exits_zero(data, capsys):
    data.add_batch(neigh=[NIC])
    assert cli.main(["run", "--once", "--data-dir", str(data.root)]) == 0
    assert len(data.q("SELECT * FROM observations")) == 1


def test_data_dir_from_env(data, monkeypatch):
    data.add_batch(neigh=[NIC])
    monkeypatch.setenv("VIGIE_DATA_DIR", str(data.root))
    assert cli.main(["run", "--once"]) == 0
    assert len(data.q("SELECT * FROM observations")) == 1


def test_once_and_loop_are_mutually_exclusive(data):
    with pytest.raises(SystemExit):
        cli.main(["run", "--once", "--loop", "5", "--data-dir", str(data.root)])
    with pytest.raises(SystemExit):
        cli.main(["run", "--data-dir", str(data.root)])


def test_loop_repeats_waits_and_survives_db_errors(data, handlers, monkeypatch):
    import threading

    calls: list[int] = []
    waits: list[float] = []

    class FakeEvent(threading.Event):
        def wait(self, timeout=None):
            waits.append(timeout)
            if len(waits) == 3:
                handlers[cli.signal.SIGTERM](15, None)
            return self.is_set()

    def fake_run(config):
        calls.append(1)
        if len(calls) == 1:
            import sqlite3

            raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(cli, "run_once", fake_run)
    monkeypatch.setattr(cli.threading, "Event", FakeEvent)
    assert cli.main(["run", "--loop", "7", "--data-dir", str(data.root)]) == 0
    assert len(calls) == 3 and waits == [7, 7, 7]


def test_loop_interval_must_be_positive(data):
    with pytest.raises(SystemExit):
        cli.main(["run", "--loop", "0", "--data-dir", str(data.root)])


def test_json_formatter_emits_structured_fields():
    rec = logging.LogRecord("vigie_pipeline", logging.INFO, "f", 1, "run_complete", None, None)
    rec.fields = {"batches": 3}
    out = json.loads(JsonFormatter().format(rec))
    assert out["event"] == "run_complete" and out["batches"] == 3 and out["level"] == "info"


def test_cli_logs_have_no_qnames(data, capsys):
    data.add_batch(neigh=[NIC], dns=[(NIC, T0)])
    cli.main(["run", "--once", "--data-dir", str(data.root)])
    assert "secret-qname" not in capsys.readouterr().err


# --- graceful stop: SIGTERM/SIGINT drain the current pass, then exit 0 -------------------------


@pytest.fixture
def handlers(monkeypatch):
    """Record the handlers cli.main installs instead of touching the real process signals."""
    installed: dict[int, object] = {}
    monkeypatch.setattr(cli.signal, "signal", lambda sig, fn: installed.setdefault(sig, fn))
    return installed


def test_signal_during_idle_wait_exits_at_once_with_zero(data, handlers, monkeypatch):
    import threading
    import time

    monkeypatch.setattr(cli, "run_once", lambda config: None)
    threading.Timer(0.2, lambda: handlers[cli.signal.SIGTERM](cli.signal.SIGTERM, None)).start()
    started = time.monotonic()
    assert cli.main(["run", "--loop", "3600", "--data-dir", str(data.root)]) == 0
    assert time.monotonic() - started < 5


def test_no_new_pass_starts_after_the_first_signal(data, handlers, monkeypatch):
    calls: list[int] = []

    def run(config):
        calls.append(1)
        handlers[cli.signal.SIGINT](cli.signal.SIGINT, None)  # arrives mid-pass

    monkeypatch.setattr(cli, "run_once", run)
    assert cli.main(["run", "--loop", "1", "--data-dir", str(data.root)]) == 0
    assert calls == [1]


def test_second_signal_forces_exit(data, handlers, monkeypatch):
    def run(config):
        handler = handlers[cli.signal.SIGTERM]
        handler(cli.signal.SIGTERM, None)
        handler(cli.signal.SIGTERM, None)  # operator insists

    monkeypatch.setattr(cli, "run_once", run)
    with pytest.raises(SystemExit) as raised:
        cli.main(["run", "--loop", "1", "--data-dir", str(data.root)])
    assert raised.value.code != 0


def test_signal_mid_publish_lets_the_delivery_finish_as_sent(tmp_path, handlers, monkeypatch):
    import threading

    from delivery_runner_helpers import T0, Clock, World

    from vigie_pipeline.config import DeliverySettings, PipelineConfig
    from vigie_pipeline.delivery_publish import FakePublisher
    from vigie_pipeline.delivery_wiring import run_delivery_stage

    world = World(tmp_path)
    try:
        world.incident(at=T0 + 2)
        pub = FakePublisher([threading.Event()])  # the publisher blocks until released
        release = pub._script[0]
        c = PipelineConfig(
            data_dir=tmp_path, delivery=DeliverySettings(enabled=True, file=tmp_path / "out.jsonl")
        )
        run_delivery_stage(world.inv, world.ro, c, Clock(T0 + 2.7), publisher=pub)  # watermark
        passes: list[int] = []

        def run(config):
            passes.append(1)
            timer = threading.Timer(
                0.2, lambda: (handlers[cli.signal.SIGTERM](15, None), release.set())
            )
            timer.start()
            run_delivery_stage(world.inv, world.ro, c, Clock(T0 + 4), publisher=pub)

        monkeypatch.setattr(cli, "run_once", run)
        assert cli.main(["run", "--loop", "1", "--data-dir", str(tmp_path)]) == 0
        assert passes == [1]
        assert list(world.states().values()) == ["sent"]
    finally:
        world.close()
