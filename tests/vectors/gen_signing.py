"""Generate tests/vectors/signing.json with the REAL server code (vigie_ingest.auth).

Usage: VIGIE_INGEST_SRC=<dir containing vigie_ingest/> python3 -I tests/vectors/gen_signing.py
The server source lives on branch feat/ingest-api (server/src). Output is deterministic.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

src = os.environ.get("VIGIE_INGEST_SRC")
if not src:
    sys.exit("set VIGIE_INGEST_SRC to the directory that contains vigie_ingest/")
sys.path.insert(0, src)

from vigie_ingest import auth  # noqa: E402

KEY = bytes(range(32))
BID = "01927f3e-8a1b-7c2d-9e4f-0123456789ab"
U = "café 日本語 \U0001f600 ‮"

CASES = [
    ("empty body", "c1", "k1", "boot1", 0, 0, BID, b""),
    ("minimal json", "c1", "k1", "boot1", 1, 1760000000, BID, b"{}"),
    (
        "unicode body",
        "router.lan",
        "key_2024-10",
        "b.o_o-t",
        42,
        1760000060,
        BID,
        json.dumps({"hostname": U}, ensure_ascii=False).encode(),
    ),
    ("unicode escaped", "c1", "k1", "boot1", 7, 1760000060, BID, json.dumps({"hostname": U}).encode()),
    ("pipe in body", "c1", "k1", "boot1", 3, 1760000000, BID, b'{"a":"x|y|z|1|2|3"}'),
    ("non-utf8 bytes", "c1", "k1", "boot1", 4, 1760000000, BID, bytes(range(256))),
    ("newlines and nul", "c1", "k1", "boot1", 5, 1760000000, BID, b"a\r\nb\x00c\n"),
    ("seq int64 max", "c1", "k1", "boot1", 2**63 - 1, 1760000000, BID, b'{"seq":max}'),
    ("sent_ts max", "c1", "k1", "boot1", 9, 2**40, BID, b"{}"),
    ("64-char idents", "c" * 64, "k" * 64, "b" * 64, 10, 1760000000, BID, b"{}"),
    ("256 KiB body", "c1", "k1", "boot1", 11, 1760000000, BID, b'{"x":"' + b"A" * (256 * 1024 - 8) + b'"}'),
    ("all-0xff body", "c1", "k1", "boot1", 12, 1760000000, BID, b"\xff" * 1000),
]

vectors = []
for name, cid, kid, boot, seq, ts, batch, body in CASES:
    fields = (cid, kid, boot, str(seq), str(ts), batch)
    vectors.append(
        {
            "name": name,
            "collector_id": cid,
            "key_id": kid,
            "boot_id": boot,
            "seq": str(seq),
            "sent_ts": str(ts),
            "batch_id": batch,
            "body_hex": body.hex(),
            "signing_string": auth.signing_string(*fields, body=body).decode(),
            "signature": auth.sign(KEY, *fields, body=body),
        }
    )

out = {"key_hex": KEY.hex(), "vectors": vectors}
path = Path(__file__).with_name("signing.json")
path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
print(f"wrote {len(vectors)} vectors to {path}")
