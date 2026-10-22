#!/usr/bin/env python3
"""Stages (f): drive the real API over TLS. Usage: assert_api.py phase1|phase2 RUN_DIR

phase1: read views, transient filtering, PATCH (name + group) with If-Match.
phase2: after a second pipeline pass, the human data must have survived.
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

LAPTOP = "3c:22:fb:11:22:33"
CAMERA = "ec:71:db:aa:bb:cc"
PHONE = ("c2:11:22:33:44:01", "c2:11:22:33:44:02", "c2:11:22:33:44:03")
FAILS: list[str] = []


def check(ok: bool, what: str) -> None:
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        FAILS.append(what)


class Api:
    def __init__(self, run: Path) -> None:
        port = (run / "api_port").read_text().strip()
        self.base = f"https://127.0.0.1:{port}"
        self.token = (run / "token").read_text().strip()
        self.ctx = ssl.create_default_context(cafile=str(run / "apicerts" / "server.crt"))

    def call(self, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None):
        req = urllib.request.Request(self.base + path, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, data=data, context=self.ctx, timeout=10) as r:
                return r.status, json.loads(r.read()), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null"), dict(e.headers)


def device_of(api: Api, mac: str) -> str:
    st, body, _ = api.call("GET", f"/macs/{mac}")
    check(st == 200, f"GET /macs/{mac} -> {st}")
    return body["data"]["device_id"] if st == 200 else ""


def main() -> int:
    phase, run = sys.argv[1], Path(sys.argv[2])
    api = Api(run)
    ids_file = run / "ids.json"
    st, body, _ = api.call("GET", "/healthz")
    check(st == 200 and body.get("data") == "ok", "GET /healthz")
    st, body, _ = api.call("GET", "/devices")
    shown = body["data"] if st == 200 else []
    check(st == 200, "GET /devices")
    print(f"     /devices (default) -> {len(shown)} devices: {[d['status'] for d in shown]}")
    st, body, _ = api.call("GET", "/devices?include_transient=1")
    everything = body["data"] if st == 200 else []
    print(f"     /devices?include_transient=1 -> {len(everything)} devices")
    laptop, camera = device_of(api, LAPTOP), device_of(api, CAMERA)
    phones = [device_of(api, m) for m in PHONE]
    shown_ids = {d["id"] for d in shown}
    check(laptop in shown_ids and camera in shown_ids, "stable device and camera listed by default")
    check(not (set(phones) & shown_ids), "rolling-MAC devices hidden by default (transient)")
    check({laptop, camera, *phones} <= {d["id"] for d in everything}, "include_transient=1 shows all")
    for mac, dev in [(LAPTOP, laptop), (CAMERA, camera), *zip(PHONE, phones)]:
        st, body, _ = api.call("GET", f"/devices/{dev}")
        macs = {m["mac"]: m for m in body["data"]["macs"]} if st == 200 else {}
        want = {LAPTOP: "alice-laptop", CAMERA: "cam-front"}.get(mac, "Pixel-8")
        check(mac in macs and macs[mac]["hostname"] == want, f"{mac} hostname {want!r}")
    st, body, _ = api.call("GET", "/events")
    kinds = [e["kind"] for e in body["data"]] if st == 200 else []
    print(f"     /events kinds: {kinds}")
    check(kinds.count("new_device") >= 5, "5 new_device events")
    st, body, hdr = api.call("GET", f"/devices/{laptop}")
    etag = {k.lower(): v for k, v in hdr.items()}.get("etag", "")

    if phase == "phase1":
        st, _, _ = api.call("PATCH", f"/devices/{laptop}", {"name": "Alice laptop"})
        check(st == 428, f"PATCH without If-Match -> {st} (want 428)")
        st, body, _ = api.call(
            "PATCH", f"/devices/{laptop}", {"name": "Alice laptop", "group_id": "trusted"},
            {"If-Match": etag},
        )
        check(st == 200, f"PATCH name+group with If-Match {etag} -> {st} {body.get('error')}")
        st, _, _ = api.call(
            "PATCH", f"/devices/{laptop}", {"name": "stale"}, {"If-Match": etag}
        )
        check(st == 412, f"PATCH with stale If-Match -> {st} (want 412)")
        ids_file.write_text(json.dumps({"laptop": laptop}))
    else:
        want = json.loads(ids_file.read_text())["laptop"]
        check(want == laptop, "laptop device id unchanged by the second pipeline pass")
    st, body, _ = api.call("GET", f"/devices/{laptop}")
    d = body["data"] if st == 200 else {}
    check(d.get("name") == "Alice laptop", f"effective name {d.get('name')!r}")
    check(d.get("group_id") == "trusted", f"effective group {d.get('group_id')!r}")
    check(d.get("override_version", 0) >= 1, f"override_version {d.get('override_version')}")
    st, body, _ = api.call("GET", "/devices?group=trusted")
    check(st == 200 and [x["id"] for x in body["data"]] == [laptop], "GET /devices?group=trusted")
    print("FAILURES:", FAILS or "none")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
