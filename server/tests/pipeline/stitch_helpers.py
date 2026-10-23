"""Builders for stitching tests: explicit activity windows through the real pipeline (`Data` +
`appear`), a seeded overrides.db, and a bare hand-placed inventory (`Inv`) for unit-level probes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from pipeline_helpers import T0, Data

from vigie_api.schema import open_overrides
from vigie_ingest.db import open_inventory
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import RunStats, run_once
from vigie_pipeline.schema import apply_pipeline_migrations
from vigie_pipeline.snapshot import EMPTY, Rule, Snapshot
from vigie_pipeline.stitch import stitch
from vigie_pipeline.stitch_compute import Compute
from vigie_pipeline.stitch_hood import Hood, load_obs
from vigie_pipeline.stitch_types import Obs, fold

OPT55 = "[1,121,3,6,15,119,252]"
OPT60 = "android-dhcp-14"
HOST = "Daves-Phone"
MDNS = "Daves Phone"
NOW = T0 + 6 * 3600
RULE = "11111111-rule"


def mac(n: int) -> str:
    return f"ae:00:00:00:00:{n:02x}"  # locally administered => randomized


def flood_mac(n: int) -> str:
    return f"ae:00:00:00:{n >> 8:02x}:{n & 255:02x}"


def appear(
    data: Data,
    n: int,
    start: int,
    end: int,
    *,
    host: str | None = HOST,
    mdns: str | None = MDNS,
    opt55: str | None = OPT55,
    opt60: str | None = OPT60,
    step: int = 60,
    collector: str = "rtr-1",
) -> str:
    """One MAC (mac(n)) active over [start, end] (relative to T0), seen with a signature."""
    m = mac(n)
    data.add_batch(
        T0 + start,
        collector=collector,
        received=T0 + end,  # a batch is received after the rows it carries
        leases=[(m, host, opt55, opt60)],
        sightings=[(m, "mdns", mdns)] if mdns else (),
        dns=[(m, T0 + t) for t in range(start, end + 1, step)],
    )
    return m


def device_of(data: Data, mac_addr: str) -> str:
    return data.q("SELECT device_id FROM observations WHERE mac=?", mac_addr)[0][0]


def source_of(data: Data, mac_addr: str) -> str:
    return data.q("SELECT link_source FROM observations WHERE mac=?", mac_addr)[0][0]


def run(data: Data, now: float = NOW, **kw) -> RunStats:
    return run_once(PipelineConfig(data_dir=data.root, **kw), now=now)


def run_at(data: Data, now: float, **kw) -> RunStats:
    return run_once(PipelineConfig(data_dir=data.root, **kw), now=now)


def dump(data: Data, *tables: str) -> list[list[sqlite3.Row]]:
    return [data.q(f"SELECT * FROM {t}") for t in tables]  # noqa: S608


def kinds(data: Data, kind: str) -> list[sqlite3.Row]:
    return data.q("SELECT * FROM events WHERE kind=? ORDER BY seq", kind)


def suggestions(data: Data) -> list[sqlite3.Row]:
    return data.q("SELECT * FROM suggestions ORDER BY created_at, id")


def candidates(data: Data) -> list[sqlite3.Row]:
    return data.q("SELECT * FROM identity_candidates ORDER BY created_at, id")


class Overrides:
    """Read-write overrides.db built through the api's own migrations (the test plays vigie-api)."""

    def __init__(self, root: Path) -> None:
        self.path = root / "overrides.db"
        self.conn = open_overrides(self.path)

    def rule(self, rid: str, device_id: str, sig: dict, **kw: str | None) -> None:
        self.conn.execute(
            "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by,"
            " expires_at, revoked_at) VALUES (?,?,?,?,?,?,?)",
            (rid, device_id, json.dumps(sig), "2026-10-01T00:00:00Z", "owner",
             kw.get("expires_at"), kw.get("revoked_at")),
        )  # fmt: skip

    def override(self, device_id: str, group: str | None, version: int = 1) -> None:
        self.conn.execute(
            "INSERT INTO device_overrides (device_id, group_id, version, updated_at, updated_by)"
            " VALUES (?,?,?,?,?)",
            (device_id, group, version, "2026-10-01T00:00:00Z", "owner"),
        )

    def decide(self, suggestion_id: str, state: str) -> None:
        self.conn.execute(
            "INSERT INTO suggestion_decisions (suggestion_id, state, decided_by, decided_at)"
            " VALUES (?,?,?,?)",
            (suggestion_id, state, "owner", "2026-10-01T00:00:00Z"),
        )

    def link(self, from_device: str, into_device: str) -> None:
        self.conn.execute(
            "INSERT INTO identity_links VALUES (?,?,?,?,?)",
            (from_device, into_device, "m1", "2026-10-01T00:00:00Z", "owner"),
        )

    def close(self) -> None:
        self.conn.close()


def sig(**kw: object) -> dict:
    base: dict[str, object] = {"opt55": "1,121,3,6,15,119,252", "opt60": OPT60, "hostname": HOST}
    base.update(kw)
    return base


def seeded(data: Data, *, a_end: int = 300, group: str | None = "iot", rule_sig: dict | None = None,
           rule_kw: dict | None = None):  # fmt: skip
    """Device A exists (mac 1), a human rule says its signature is A, optionally in `group`."""
    a = appear(data, 1, 0, a_end)
    run(data)
    ov = Overrides(data.root)
    dev = device_of(data, a)
    ov.rule(RULE, dev, rule_sig or sig(), **(rule_kw or {}))
    if group is not None:
        ov.override(dev, group, version=3)
    return ov, dev


def seeded_d(data: Data, end: int, *, step: int = 60):
    """The original device O (mac 1, rule target, iot) active over [0, end]; run at end + 1."""
    o = appear(data, 1, 0, end, step=step)
    run_at(data, T0 + end + 1)
    ov = Overrides(data.root)
    dev = device_of(data, o)
    ov.rule(RULE, dev, sig())
    ov.override(dev, "iot", version=3)
    return ov, dev


# ---- a bare inventory with hand-placed rows (no shards, no ingest) ------------------------------

NOW_ABS = 1_800_000_000
OLD = "2026-01-01T00:00:00Z"
RULE_SNAP = Snapshot({}, (Rule("r1", "D", "1,2,3", "x", "victim", None),), {"iot": 1},
                     {"D": (1, "iot")}, {})  # fmt: skip


class Inv:
    """A bare inventory.db with hand-placed MACs and activity."""

    def __init__(self, tmp_path: Path) -> None:
        self.cfg = PipelineConfig(data_dir=tmp_path)
        self.db = open_inventory(tmp_path / "inventory.db")
        apply_pipeline_migrations(self.db)
        self.n = 0
        self.db.execute("BEGIN")

    def mac(self, dev, host, mdns, src, fs, ivs, *, rand=1, newdev=True, fp="1,2,3",
            last_seen: str | None = None, vc: str = "x") -> str:  # fmt: skip
        m = f"ae:{self.n >> 16 & 255:02x}:{self.n >> 8 & 255:02x}:{self.n & 255:02x}:00:01"
        self.n += 1
        if newdev:
            self.db.execute(
                "INSERT INTO devices (id, first_seen, last_seen) VALUES (?,?,?)", (dev, fs, fs)
            )
        self.db.execute(
            "INSERT INTO observations (mac, device_id, is_randomized, dhcp_fingerprint,"
            " vendor_class, hostname, mdns_name, link_source, first_seen, last_seen,"
            " hostname_fold, mdns_fold) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (m, dev, rand, fp, vc, host, mdns, src, fs, last_seen or fs,
             fold(host) if host else None, fold(mdns) if mdns else None),
        )  # fmt: skip
        self.act(m, ivs)
        self.db.execute(  # the server-clock anchor a real fold records (long ago by default)
            "INSERT OR IGNORE INTO mac_first_received (mac, received) VALUES (?,?)",
            (m, NOW_ABS - 10**6),
        )
        return m

    def act(self, m, ivs) -> None:
        self.db.executemany(
            'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
            [(m, s, e) for s, e in ivs],
        )

    def attachment(self, m: str, rule_id: str, target: str, host, mdns, views, fp="1,2,3") -> None:
        self.db.execute(
            "INSERT INTO rule_attachments (mac, rule_id, target, hostname, mdns_name, opt55,"
            " opt60, views, attached_at) VALUES (?,?,?,?,?,?,'x',?,'t')",
            (m, rule_id, target, host, mdns, fp, json.dumps(views)),
        )

    def commit(self) -> None:
        if self.db.in_transaction:
            self.db.execute("COMMIT")

    def stitch(self, snap=EMPTY, now=NOW_ABS, clock=None):
        self.commit()
        return stitch(self.db, snap, self.cfg, now, clock)

    def count(self, kind: str) -> int:
        return self.db.execute("SELECT COUNT(*) FROM events WHERE kind=?", (kind,)).fetchone()[0]

    def state(self, dev: str) -> list[tuple]:
        return [
            tuple(r)
            for r in self.db.execute(
                "SELECT device_b, state FROM identity_candidates WHERE device_a=?", (dev,)
            )
        ]

    def link_of(self, m: str) -> tuple:
        row = self.db.execute("SELECT device_id, link_source FROM observations WHERE mac=?", (m,))
        return tuple(row.fetchone())

    def totals(self) -> tuple[int, int]:
        q = "SELECT COUNT(*) FROM "
        return (self.db.execute(q + "identity_candidates").fetchone()[0],
                self.db.execute(q + "suggestions").fetchone()[0])  # fmt: skip

    def compute(self, snap=EMPTY, now=NOW_ABS) -> Compute:
        self.commit()
        return Compute(self.db, snap, self.cfg, now)

    def hood(self, m: str, snap=EMPTY, now=NOW_ABS) -> tuple[Compute, Hood, Obs]:
        """The neighbourhood of a MAC as the rule path builds it (own keys, target = own device)."""
        cp = self.compute(snap, now)
        c = load_obs(self.db, snap, m)
        assert c is not None
        hood = cp._hood()
        hood.add_keys(c)
        hood.load(m)
        cp._gather_peers(hood, c.canon, [c])
        return cp, hood, c

    def compatible(self, m: str, known: set[str] | None = None) -> set[str]:
        cp, hood, c = self.hood(m)
        return cp._compatible(hood, c, hood.names_of(c.canon) if known is None else known)


@pytest.fixture
def inv(tmp_path: Path) -> Inv:
    return Inv(tmp_path)
