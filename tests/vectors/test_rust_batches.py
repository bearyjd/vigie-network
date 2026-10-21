"""Cross-language check of what the Rust collector emits.

Runs `cargo run --example emit_samples` in collector/ and, for every sample:
  * validates the body with the REAL server models (vigie_ingest.models.Batch) and with
    api/batch.schema.json (jsonschema, if installed),
  * checks the header envelope matches the body the way the server does,
  * verifies the Rust-produced HMAC signature with the REAL vigie_ingest.auth code,
  * checks a one-byte tamper breaks the signature.

Usage:  VIGIE_INGEST_SRC=<dir containing vigie_ingest/> python3 -I tests/vectors/test_rust_batches.py
        (or via pytest). Needs pydantic; jsonschema is optional.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
src = os.environ.get("VIGIE_INGEST_SRC")
if not src:
    sys.exit("set VIGIE_INGEST_SRC to the directory that contains vigie_ingest/")
sys.path.insert(0, src)

from vigie_ingest import auth  # noqa: E402
from vigie_ingest.models import Batch  # noqa: E402

KEY = bytes(range(32))
MAX_BODY = 256 * 1024


def load_samples() -> list[dict]:
    out = subprocess.run(
        ["cargo", "run", "-q", "-p", "vigie-collector", "--example", "emit_samples"],
        cwd=ROOT / "collector",
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def header(sample: dict, name: str) -> str:
    return sample["headers"][name]


def test_rust_batches_validate_and_verify() -> None:
    samples = load_samples()
    assert len(samples) == 4
    schema = None
    try:
        import jsonschema

        schema_path = Path(os.environ.get("VIGIE_SCHEMA", ROOT / "api" / "batch.schema.json"))
        schema = json.loads(schema_path.read_text()) if schema_path.exists() else None
    except ImportError:
        pass
    for s in samples:
        body = bytes.fromhex(s["body_hex"])
        assert len(body) <= MAX_BODY, (s["name"], len(body))
        batch = Batch.model_validate_json(body, context={"max_spool_age_s": 86400})
        if schema is not None:
            jsonschema.Draft202012Validator(schema).validate(json.loads(body))
        # Envelope: signed headers equal the body fields (server _matches_envelope).
        assert batch.collector_id == header(s, "X-Vigie-Collector-Id")
        assert batch.key_id == header(s, "X-Vigie-Key-Id")
        assert batch.boot_id == header(s, "X-Vigie-Boot-Id")
        assert str(batch.seq) == header(s, "X-Vigie-Seq")
        assert str(batch.sent_ts) == header(s, "X-Vigie-Sent-Ts")
        assert batch.batch_id == header(s, "X-Vigie-Batch-Id")
        # Rust signature verifies with the server's own code.
        msg = auth.signing_string(
            header(s, "X-Vigie-Collector-Id"),
            header(s, "X-Vigie-Key-Id"),
            header(s, "X-Vigie-Boot-Id"),
            header(s, "X-Vigie-Seq"),
            header(s, "X-Vigie-Sent-Ts"),
            header(s, "X-Vigie-Batch-Id"),
            body,
        )
        sig = header(s, "X-Vigie-Signature")
        assert auth.verify(KEY, sig, msg), s["name"]
        tampered = auth.signing_string(
            header(s, "X-Vigie-Collector-Id"),
            header(s, "X-Vigie-Key-Id"),
            header(s, "X-Vigie-Boot-Id"),
            header(s, "X-Vigie-Seq"),
            header(s, "X-Vigie-Sent-Ts"),
            header(s, "X-Vigie-Batch-Id"),
            body[:-1] + b" ",
        )
        assert not auth.verify(KEY, sig, tampered)
    flood = next(s for s in samples if s["name"] == "flood truncated")
    batch = Batch.model_validate_json(bytes.fromhex(flood["body_hex"]), context={"max_spool_age_s": 86400})
    assert batch.truncated.get("dns", 0) > 0 and batch.truncated.get("conntrack", 0) > 0, batch.truncated
    first = Batch.model_validate_json(bytes.fromhex(samples[0]["body_hex"]), context={"max_spool_age_s": 86400})
    assert first.dropped_batches == 2, "first sent batch carries the drop counter"
    assert batch.dropped_batches == 0, "reported once, then cleared after the first success"
    print(f"schema validation active: {schema is not None}; flood body {len(bytes.fromhex(flood['body_hex']))} bytes")
    assert any(c.proto == "other" and c.dst_ip is None for c in batch.conntrack)
    hostile = next(s for s in samples if s["name"].startswith("hostile"))
    hb = Batch.model_validate_json(bytes.fromhex(hostile["body_hex"]), context={"max_spool_age_s": 86400})
    assert hb.health is not None and hb.health.dns_log_quiet is True


if __name__ == "__main__":
    test_rust_batches_validate_and_verify()
    print("ok: Rust batches validate against the server models and signatures verify")
