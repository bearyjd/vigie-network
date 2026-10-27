"""Message privacy, FakePublisher and FilePublisher (no network publisher exists)."""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path

import pytest

from vigie_pipeline.delivery_publish import (
    FakePublisher,
    FilePublisher,
    Message,
    PublishError,
    build_message,
)

HOSTILE = (
    "cam\x00era\x1b[31m\n\r 192.168.1.20 aa:bb:cc:dd:ee:ff evil.example.com "
    "fe80::1 51 MiB 123456789 " + "x" * 5000
)


def test_message_is_frozen():
    msg = Message("d" * 32, "open", "t", "b", "/ui/#incident=i1")
    with pytest.raises(AttributeError):
        msg.title = "x"  # type: ignore[misc]


def test_message_carries_label_and_link_only():
    msg = build_message("d" * 32, "open", "inc-1", "Kitchen cam")
    assert "Kitchen cam" in msg.body
    assert msg.link == "/ui/#incident=inc-1"
    assert "://" not in msg.link


def test_recover_differs_from_open():
    a = build_message("d" * 32, "open", "inc-1", "Cam")
    b = build_message("e" * 32, "recover", "inc-1", "Cam")
    assert a.title != b.title and b.kind == "recover"


def test_hostile_label_is_scrubbed_and_bounded():
    msg = build_message("d" * 32, "open", "inc-1", HOSTILE)
    text = " ".join([msg.title, msg.body, msg.link])
    for needle in ("192.168.1.20", "aa:bb:cc:dd:ee:ff", "evil.example.com", "fe80::1", "MiB"):
        assert needle not in text
    assert "123456789" not in text
    assert not any(ord(c) < 32 or ord(c) == 127 for c in text)
    assert len(msg.title) <= 100 and len(msg.body) <= 300


def test_hostile_incident_id_cannot_escape_link():
    msg = build_message("d" * 32, "open", "a/../b?x=1#\n\x00" + "y" * 5000, "Cam")
    assert msg.link.startswith("/ui/#incident=") and len(msg.link) <= 200
    assert not any(c in msg.link for c in " \n\x00?")
    assert msg.link.count("#") == 1


def test_fake_publisher_records_and_scripts_failures():
    fake = FakePublisher(script=[PublishError("down"), None])
    msg = Message("d" * 32, "open", "t", "b", "/l")
    with pytest.raises(PublishError):
        fake.publish(msg, timeout_seconds=1)
    fake.publish(msg, timeout_seconds=1)
    fake.publish(msg, timeout_seconds=1)  # exhausted script: success
    assert len(fake.attempted) == 3 and fake.sent == [msg, msg]


def test_fake_publisher_hang_blocks_until_released():
    gate = threading.Event()
    fake = FakePublisher(script=[gate])
    msg = Message("d" * 32, "open", "t", "b", "/l")
    t = threading.Thread(target=lambda: fake.publish(msg, timeout_seconds=1), daemon=True)
    t.start()
    t.join(0.2)
    assert t.is_alive()
    gate.set()
    t.join(5)
    assert not t.is_alive()


def _msg(i=0):
    return Message(f"{i:032d}", "open", "title", "body é", f"/ui/#incident={i}")


def test_file_publisher_appends_one_json_line_per_message(tmp_path):
    path = tmp_path / "out.jsonl"
    pub = FilePublisher(path)
    pub.publish(_msg(1), timeout_seconds=1)
    pub.publish(_msg(2), timeout_seconds=1)
    lines = path.read_bytes().split(b"\n")
    assert lines[-1] == b"" and len(lines) == 3
    rows = [json.loads(line) for line in lines[:-1]]
    assert rows[0] == {
        "delivery_id": f"{1:032d}", "kind": "open", "title": "title",
        "body": "body é", "link": "/ui/#incident=1",
    }  # fmt: skip
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_file_publisher_tightens_existing_mode(tmp_path):
    path = tmp_path / "out.jsonl"
    path.write_text("")
    path.chmod(0o644)
    FilePublisher(path).publish(_msg(), timeout_seconds=1)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_file_publisher_refuses_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(PublishError):
        FilePublisher(link).publish(_msg(), timeout_seconds=1)
    assert target.read_text() == ""


def test_file_publisher_refuses_non_regular(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(PublishError):
        FilePublisher(fifo).publish(_msg(), timeout_seconds=1)
    with pytest.raises(PublishError):
        FilePublisher(tmp_path).publish(_msg(), timeout_seconds=1)


def test_file_publisher_is_bounded(tmp_path):
    path = tmp_path / "out.jsonl"
    pub = FilePublisher(path, max_bytes=600)
    with pytest.raises(PublishError, match="full"):
        for i in range(100):
            pub.publish(_msg(i), timeout_seconds=1)
    size = path.stat().st_size
    assert 0 < size <= 600
    assert path.read_bytes().endswith(b"\n")
    assert all(json.loads(line) for line in path.read_bytes().splitlines())


def test_file_publisher_concurrent_appends_stay_whole_lines(tmp_path):
    path = tmp_path / "out.jsonl"
    errors: list[BaseException] = []

    def work(base):
        pub = FilePublisher(path)
        try:
            for i in range(25):
                pub.publish(_msg(base * 100 + i), timeout_seconds=1)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors
    rows = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert len(rows) == 150 and len({r["delivery_id"] for r in rows}) == 150


def test_file_publisher_refuses_a_device_node(tmp_path):
    with pytest.raises(PublishError, match="regular"):
        FilePublisher(Path("/dev/null")).publish(_msg(), timeout_seconds=1)


def test_file_publisher_fsyncs_every_message(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    FilePublisher(tmp_path / "out.jsonl").publish(_msg(), timeout_seconds=1)
    assert len(calls) == 1


def _flaky_write(real, fail_after_bytes, exc):
    """os.write that writes `fail_after_bytes` of the first line, then raises `exc` once."""
    state = {"left": fail_after_bytes, "armed": True}

    def write(fd, data):
        if state["armed"]:
            if state["left"] > 0:
                n = real(fd, bytes(data[: state["left"]]))
                state["left"] -= n
                return n
            state["armed"] = False
            raise exc
        return real(fd, data)

    return write


def _all_lines_parse(path):
    data = path.read_bytes()
    assert data == b"" or data.endswith(b"\n")
    return [json.loads(line) for line in data.splitlines()]


def test_partial_write_then_error_leaves_no_fragment_and_retry_works(tmp_path, monkeypatch):
    path = tmp_path / "out.jsonl"
    FilePublisher(path).publish(_msg(0), timeout_seconds=1)
    before = path.read_bytes()
    monkeypatch.setattr(os, "write", _flaky_write(os.write, 5, OSError(5, "EIO")))
    with pytest.raises(PublishError):
        FilePublisher(path).publish(_msg(1), timeout_seconds=1)
    assert path.read_bytes() == before
    FilePublisher(path).publish(_msg(1), timeout_seconds=1)
    assert [r["delivery_id"] for r in _all_lines_parse(path)] == [f"{0:032d}", f"{1:032d}"]


def test_crash_after_partial_write_leaves_a_valid_file(tmp_path, monkeypatch):
    path = tmp_path / "out.jsonl"
    monkeypatch.setattr(os, "write", _flaky_write(os.write, 7, RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        FilePublisher(path).publish(_msg(1), timeout_seconds=1)
    assert _all_lines_parse(path) == []


def test_short_writes_are_completed(tmp_path, monkeypatch):
    path = tmp_path / "out.jsonl"
    real = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: real(fd, bytes(data[:5])))
    FilePublisher(path).publish(_msg(3), timeout_seconds=1)
    assert [r["delivery_id"] for r in _all_lines_parse(path)] == [f"{3:032d}"]


def _fixed(i):
    """Records of identical size whatever `i` is (0..9999)."""
    return Message(f"{i:032d}", "open", "title", "body", f"/ui/#incident={i:04d}")


def _fixed_len(tmp_path):
    probe = tmp_path / "probe.jsonl"
    FilePublisher(probe).publish(_fixed(0), timeout_seconds=1)
    return probe.stat().st_size


def _line_len():
    return len(json.dumps({"delivery_id": f"{0:032d}", "kind": "open", "title": "title",
        "body": "body é", "link": "/ui/#incident=0"}, separators=(",", ":"))) + 1  # fmt: skip


ROOM = 5  # records the limit admits


def _attempt(path, limit, i):
    try:
        FilePublisher(Path(path), max_bytes=limit).publish(_fixed(i), timeout_seconds=1)
        return True
    except PublishError as exc:
        assert "full" in str(exc)
        return False


def test_concurrent_publishers_cannot_exceed_the_limit(tmp_path):
    path = tmp_path / "out.jsonl"
    limit = _fixed_len(tmp_path) * ROOM
    results = []
    threads = [
        threading.Thread(target=lambda i=i: results.append(_attempt(path, limit, i)))
        for i in range(ROOM + 3)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert results.count(True) == ROOM and results.count(False) == 3
    assert path.stat().st_size == limit
    assert len(_all_lines_parse(path)) == ROOM


def _proc_work(path, limit, i, queue):
    queue.put(_attempt(path, limit, i))


def test_separate_processes_serialize_on_the_file(tmp_path):
    import multiprocessing

    ctx = multiprocessing.get_context("fork")
    path = tmp_path / "out.jsonl"
    limit = _fixed_len(tmp_path) * ROOM
    queue = ctx.Queue()
    procs = [
        ctx.Process(target=_proc_work, args=(str(path), limit, i, queue)) for i in range(ROOM + 3)
    ]
    for p in procs:
        p.start()
    results = [queue.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(30)
    assert results.count(True) == ROOM and results.count(False) == 3
    assert path.stat().st_size == limit
    assert len(_all_lines_parse(path)) == ROOM


def test_check_and_write_are_one_critical_section(tmp_path, monkeypatch):
    """Widen the window between fstat and write: without the lock both appends fit."""
    import time

    real = os.fstat

    def slow_fstat(fd):
        info = real(fd)
        time.sleep(0.1)
        return info

    monkeypatch.setattr(os, "fstat", slow_fstat)
    path = tmp_path / "out.jsonl"
    limit = _line_len() + 5  # room for exactly one line
    results = []

    def work(i):
        try:
            FilePublisher(path, max_bytes=limit).publish(_msg(i), timeout_seconds=1)
            results.append(True)
        except PublishError:
            results.append(False)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(results) == [False, True] and path.stat().st_size <= limit


@pytest.mark.parametrize(
    "hostile",
    [
        "aabbccddeeff",
        "AA BB CC DD EE FF",
        "aa-bb-cc-dd-ee-ff",
        "192\u30021\u300268\u30021\u30021",  # ideographic full stops
        "192\uff0e168\uff0e1\uff0e1",  # fullwidth full stops
        "\uff11\uff19\uff12.168.1.1",  # fullwidth digits
        "evil\u3002example\u3002com",
        "2001:db8::1",
    ],
)
def test_scrub_gaps_are_closed(hostile):
    out = build_message("d" * 32, "open", "i", f"TV {hostile} x").body
    for needle in ("aabbccddeeff", "AA BB", "aa-bb", "168", "192", "evil", "example", "db8"):
        assert needle not in out.split(": unusual")[0]


def test_normal_labels_survive():
    for label in ("Living room TV", "Anna's laptop", "Kitchen cam 2"):
        assert label in build_message("d" * 32, "open", "i", label).body


def test_regexes_never_see_more_than_256_characters(monkeypatch):
    import vigie_pipeline.delivery_publish as dp

    seen = []

    class Spy:
        def __init__(self, inner):
            self.inner = inner

        def sub(self, repl, text):
            seen.append(len(text))
            return self.inner.sub(repl, text)

    monkeypatch.setattr(dp, "_SENSITIVE", Spy(dp._SENSITIVE))
    monkeypatch.setattr(dp, "_CONTROL", Spy(dp._CONTROL))
    dp.scrub_label("a" * 1_000_000)
    dp.scrub_label("\ufdfa" * 100_000)  # NFKC expands this character to 18
    assert seen and max(seen) <= 256


def test_every_line_carries_the_delivery_id(tmp_path):
    path = tmp_path / "o.jsonl"
    FilePublisher(path).publish(_msg(7), timeout_seconds=1)
    assert json.loads(path.read_text())["delivery_id"] == f"{7:032d}"
