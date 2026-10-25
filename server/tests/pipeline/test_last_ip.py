"""The IP is sensor evidence, never an identity key or a destination address."""
from __future__ import annotations

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401

from vigie_ingest.db import connect, ensure_shard, utc_day
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

MAC = '00:11:22:33:44:55'


def batch(data: Data, ip: str, ts: int = T0, source: str = 'lease', received=None):
    key = data.add_batch(ts, received=received, **{
        'leases' if source == 'lease' else 'neigh':
        [(MAC, None, None, None)] if source == 'lease' else [MAC]
    })
    db = connect(ensure_shard(data.root, utc_day(ts)))
    sql = ('UPDATE raw_lease SET ip=? WHERE batch_id=?' if source == 'lease'
           else 'UPDATE raw_neigh SET ip=? WHERE batch_id=?')
    db.execute(sql, (ip, key))
    db.close()
    return key


def run(data):
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 100)


def latest(data):
    return tuple(data.q('SELECT ip,observed_at,source FROM mac_last_ip WHERE mac=?', MAC)[0])


def test_latest_ip_uses_observation_time_and_does_not_regress(data):
    batch(data, '192.168.1.20', T0 + 5)
    run(data)
    assert latest(data) == ('192.168.1.20', T0 + 5, 'lease')
    batch(data, '192.168.1.10', T0, received=T0 + 20)
    run(data)
    assert latest(data) == ('192.168.1.20', T0 + 5, 'lease')
    batch(data, '2001:0db8:0:0::1', T0 + 30, 'neigh')
    run(data)
    assert latest(data) == ('2001:db8::1', T0 + 30, 'neigh')
    run(data)
    assert data.q('SELECT count(*) FROM mac_last_ip')[0][0] == 1


def test_ties_are_deterministic_across_sources_and_batch_arrival(data):
    batch(data, '192.168.1.30', source='neigh')
    batch(data, '192.168.1.10')
    batch(data, '192.168.1.20')
    run(data)
    assert latest(data) == ('192.168.1.20', T0, 'lease')
    batch(data, '192.168.1.05')  # invalid spelling cannot replace validated evidence
    run(data)
    assert latest(data) == ('192.168.1.20', T0, 'lease')


@pytest.mark.parametrize('ip', ['bad', '0.0.0.0',  # noqa: S104 - invalid address fixture
                              '::', '224.0.0.1', 'ff02::1',
                                    'fe80::1%eth0', '127.0.0.1', '::1', '255.255.255.255'])
def test_invalid_or_nonclient_addresses_are_not_projected(data, ip):
    batch(data, ip)
    run(data)
    assert not data.q('SELECT * FROM mac_last_ip')


def test_absent_ip_and_implausible_observation_clock(data):
    data.add_batch(dns=[(MAC, T0)])
    batch(data, '192.168.1.10', T0 + 10000, received=T0)
    run(data)
    assert not data.q('SELECT * FROM mac_last_ip')


def test_upgrade_from_v9_preserves_identity_and_processing_cursor(tmp_path, monkeypatch):
    import vigie_pipeline.schema as schema

    path = tmp_path / 'inventory.db'
    migrations = schema.PIPELINE_MIGRATIONS
    with monkeypatch.context() as old:
        old.setattr(schema, 'PIPELINE_MIGRATIONS', migrations[:9])
        db = schema.open_pipeline_inventory(path, migrate=True)
        db.execute("INSERT INTO devices (id,first_seen,last_seen) VALUES ('identity','a','b')")
        db.execute("INSERT INTO pipeline_cursor VALUES ('collector',42,'batch','time')")
        db.close()
    db = schema.open_pipeline_inventory(path)
    assert tuple(db.execute('SELECT id,first_seen,last_seen FROM devices').fetchone()) == (
        'identity', 'a', 'b'
    )
    assert tuple(db.execute('SELECT * FROM pipeline_cursor').fetchone()) == (
        'collector', 42, 'batch', 'time'
    )
    assert db.execute('SELECT count(*) FROM mac_last_ip').fetchone()[0] == 0
    assert db.execute('SELECT max(version) FROM pipeline_schema').fetchone()[0] == 10
    db.close()
