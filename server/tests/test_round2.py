"""Round-2 review findings (N1-N6)."""

from __future__ import annotations

from conftest import COLLECTOR, NOW, Env, encode, make_batch
from test_review import inv, rows

from vigie_ingest import db, store
from vigie_ingest.models import Batch


def _parsed(batch: dict) -> Batch:
    return Batch.model_validate_json(encode(batch))


def _apply(env: Env, batch: dict):
    return store.apply_batch(
        env.settings.inventory_path, env.settings.data_dir, _parsed(batch), NOW, 300
    )


def _revoke(env: Env) -> None:
    conn = env.inventory()
    store.revoke_collector(conn, COLLECTOR)
    conn.close()


def test_n1_retry_of_applied_batch_while_revoked_does_not_delete_rows(env: Env) -> None:
    batch = make_batch(seq=1)
    assert env.post(batch).status_code == 200
    _revoke(env)
    assert _apply(env, batch) == "duplicate"
    assert len(rows(env, "raw_dns")) == 1 and len(rows(env, "raw_flow")) == 1
    assert inv(env, "SELECT COUNT(*) FROM batches")[0][0] == 1


def test_n1_commit_inventory_checks_duplicate_before_revoked(env: Env) -> None:
    batch = make_batch(seq=1)
    env.post(batch)
    _revoke(env)
    conn = env.inventory()
    with db.immediate(conn):
        assert store._commit_inventory(conn, _parsed(batch), NOW, 300) == "duplicate"
    conn.close()


def test_n2_same_batch_id_different_content_cannot_alter_stored_rows(env: Env) -> None:
    batch = make_batch(seq=1)
    assert env.post(batch).status_code == 200
    changed = {**batch, "dns": [{**batch["dns"][0], "qname": "evil.example"}]}
    assert _apply(env, changed) == "duplicate"
    assert [r["qname"] for r in rows(env, "raw_dns")] == ["example.com"]
