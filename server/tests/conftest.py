from __future__ import annotations

import builtins
import io
import json
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from vigie_ingest import auth, store
from vigie_ingest.app import create_app
from vigie_ingest.config import Settings
from vigie_ingest.db import open_inventory

NOW = 1_792_000_000.0  # fixed "server now" (2026-10-14T..Z)
KEY = bytes(range(32))
COLLECTOR = "rtr-1"
KEY_ID = "k1"
BOOT = "boot-a"


def uuid7(offset: int = 0) -> str:
    raw = bytearray(uuid.uuid4().bytes)
    ms = int(NOW * 1000) + offset
    raw[0:6] = ms.to_bytes(6, "big")
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def make_batch(seq: int = 1, **overrides: Any) -> dict[str, Any]:
    now = int(NOW)
    batch: dict[str, Any] = {
        "collector_id": COLLECTOR,
        "key_id": KEY_ID,
        "boot_id": BOOT,
        "seq": seq,
        "batch_id": uuid7(seq),
        "window_start": now - 60,
        "window_end": now,
        "sent_ts": now,
        "truncated": {},
        "dropped_batches": 0,
        "leases": [
            {
                "mac": "aa:bb:cc:00:00:01",
                "ip": "192.168.8.10",
                "hostname": "phone",
                "opt55": [1, 3, 6],
                "opt60": "android-dhcp-14",
            }
        ],
        "neigh": [{"ip": "fe80::1", "mac": "aa:bb:cc:00:00:01", "family": "inet6"}],
        "dns": [
            {
                "ts": now - 5,
                "mac": "aa:bb:cc:00:00:01",
                "qname": "example.com",
                "qtype": "A",
                "answer_ip": "93.184.216.34",
            }
        ],
        "conntrack": [
            {
                "mac": "aa:bb:cc:00:00:01",
                "dst_ip": "93.184.216.34",
                "dst_port": 443,
                "proto": "tcp",
                "bytes_up": 100,
                "bytes_down": 2000,
                "flows": 2,
            }
        ],
        "sightings": [
            {"mac": "aa:bb:cc:00:00:01", "kind": "mdns", "name": "Pixel", "service": "_x._tcp"}
        ],
        "health": {"dns_log_quiet": False},
    }
    batch.update(overrides)
    return batch


def encode(batch: dict[str, Any]) -> bytes:
    return json.dumps(batch, separators=(",", ":")).encode()


def signed_headers(
    body: bytes, batch: dict[str, Any], key: bytes = KEY, **header_overrides: str
) -> dict[str, str]:
    fields = {
        "collector_id": str(batch["collector_id"]),
        "key_id": str(batch["key_id"]),
        "boot_id": str(batch["boot_id"]),
        "seq": str(batch["seq"]),
        "sent_ts": str(batch["sent_ts"]),
        "batch_id": str(batch["batch_id"]),
    }
    sig = auth.sign(key, *fields.values(), body=body)
    headers = {
        "X-Vigie-Collector-Id": fields["collector_id"],
        "X-Vigie-Key-Id": fields["key_id"],
        "X-Vigie-Boot-Id": fields["boot_id"],
        "X-Vigie-Seq": fields["seq"],
        "X-Vigie-Sent-Ts": fields["sent_ts"],
        "X-Vigie-Batch-Id": fields["batch_id"],
        "X-Vigie-Signature": sig,
        "Content-Type": "application/json",
    }
    headers.update(header_overrides)
    return headers


@dataclass
class Env:
    settings: Settings
    client: TestClient
    clock: list[float]

    def post(self, batch: dict[str, Any], **header_overrides: str):
        body = encode(batch)
        return self.client.post(
            "/v1/batch", content=body, headers=signed_headers(body, batch, **header_overrides)
        )

    def post_raw(self, body: bytes, batch: dict[str, Any], key: bytes = KEY):
        return self.client.post("/v1/batch", content=body, headers=signed_headers(body, batch, key))

    def inventory(self):
        return open_inventory(self.settings.inventory_path)

    def add_collector(self, collector_id: str, key_id: str, key: bytes) -> None:
        (self.settings.secrets_dir / f"collector_key_{key_id}").write_text(key.hex())
        conn = self.inventory()
        store.provision_collector(conn, collector_id, key_id)
        conn.close()


@pytest.fixture
def make_env(tmp_path: Path) -> Callable[..., Env]:
    clients: list[TestClient] = []

    def factory(**settings_overrides: Any) -> Env:
        data = tmp_path / "data"
        secrets = tmp_path / "secrets"
        data.mkdir(exist_ok=True)
        secrets.mkdir(exist_ok=True)
        (secrets / f"collector_key_{KEY_ID}").write_text(KEY.hex())
        settings = Settings(data_dir=data, secrets_dir=secrets, **settings_overrides)
        conn = open_inventory(settings.inventory_path)
        store.provision_collector(conn, COLLECTOR, KEY_ID)
        conn.close()
        clock = [NOW]
        client = TestClient(create_app(settings, clock=lambda: clock[0]))
        client.__enter__()
        clients.append(client)
        return Env(settings, client, clock)

    yield factory
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def env(make_env: Callable[..., Env]) -> Env:
    return make_env(rate_limit_per_window=1000)


REAL_PREVIEW_LOCK = "/tmp/vigie-gui-preview-18745.lock"  # noqa: S108 -- the path under guard.


def _is_real_preview_lock(path) -> bool:
    """True for any spelling (bytes, Path, `//`, `/./`, `..`, relative to the cwd) of the lock."""
    try:
        name = os.path.normpath(os.path.abspath(os.fsdecode(path)))
        return "/" + name.lstrip("/") == REAL_PREVIEW_LOCK  # POSIX keeps a leading `//`
    except (TypeError, ValueError):  # an int fd or other non-path: not a path spelling
        return False


@pytest.fixture(autouse=True)
def never_touch_the_real_preview_lock(request, monkeypatch):
    """GUI preview tests must never open the user's real preview lock (they patch LOCK)."""
    if not request.module.__name__.startswith(("test_gui_preview", "gui_preview")):
        return

    def guard(real_open):
        def guarded(path, *args, **kwargs):
            if _is_real_preview_lock(path):
                raise AssertionError(f"{request.node.nodeid} opened the real preview lock")
            return real_open(path, *args, **kwargs)

        return guarded

    monkeypatch.setattr(os, "open", guard(os.open))
    monkeypatch.setattr(io, "open", guard(io.open))
    monkeypatch.setattr(builtins, "open", guard(builtins.open))
