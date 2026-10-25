# Read-only GUI development preview

The GUI is implemented on the isolated `feat/read-only-gui` worktree. It is not deployed to the running monitoring API, pipeline or router. The current real 48-hour soak continues unchanged. The browser preview uses 55 synthetic identities, documentation-only IPv4/IPv6 addresses, a deliberately suspicious HTML-like device name, unknown types, missing/partial hours, a learning baseline and one synthetic incident. It does not describe household devices or real network activity.

## Open the current local preview

URL: `http://127.0.0.1:18745/ui/?preview=synthetic`

Source ID: `synthetic-preview` (filled only for the explicit synthetic-preview URL). The page displays a visible synthetic-preview banner. Inventory spans the synthetic database; coverage/activity/incidents use the selected source.

The sample token is read-only and stored only in `/tmp/vigie-gui-preview-20261025-v1/read-token.private`, inside a private `0700` directory with `0600` files. Open that file locally and paste its contents into the masked token field, then Connect. If `wl-copy` is available, the user can copy it privately with:

```sh
wl-copy < /tmp/vigie-gui-preview-20261025-v1/read-token.private
```

The assistant does not change the clipboard. The token is not bundled in public assets, URL, cookies or browser storage. Disconnect clears it from page memory and aborts outstanding requests. JSON API routes still require authentication; read-only tokens cannot write. The UI shell is public and serves only five packaged assets.

Preview PID: `1923379`; native start ticks `13763246`; bound only to `127.0.0.1:18745`. It automatically exits after 8 hours from this preview process launch. A numeric PID alone is not a safe stop target after it exits. To stop the current preview early, run this identity-checked command on the native Tower; it refuses a different owner, start time or command and sends TERM through a pinned process descriptor:

```sh
python3 - <<'PYTHON'
import json, os, pathlib, signal
record = pathlib.Path("/tmp/vigie-gui-preview-20261025-v1/server-identity-attempt3.private.json")
proof = json.loads(record.read_text())
assert proof["pid"] == 1923379 and proof["start_ticks"] == "13763246"
fd = os.pidfd_open(proof["pid"])
try:
    process = pathlib.Path("/proc") / str(proof["pid"])
    assert process.stat().st_uid == os.getuid()
    start = (process / "stat").read_text().rsplit(") ", 1)[1].split()[19]
    command = (process / "cmdline").read_bytes().replace(bytes([0]), b" ").decode().strip()
    assert start == proof["start_ticks"] and command == proof["command"]
    signal.pidfd_send_signal(fd, signal.SIGTERM)
finally:
    os.close(fd)
PYTHON
```

The private manifest, current server log and `server-identity-attempt3.private.json` are in `/tmp/vigie-gui-preview-20261025-v1/`. The previous process log is retained as `server-attempt2.log`, with its original identity record unchanged. A future preview gets a fresh directory; never overwrite a failed/existing seed. The PID identifies this development process, not a production service.

## Reproduce with existing native dependencies

The current preview runs an offline-built wheel installed into `/tmp/vigie-gui-wheel-target-attempt3`; its package location was verified outside the checkout. Current wheel SHA256: `373f3a06ae4c0b5501cb27d012822c799b0c37f370b5f71c3f57b1d5c260ee4c`. All five installed and served asset hashes match source. No runtime dependency or frontend build system was added. Start uses explicit own database paths, ignoring inherited `VIGIE_*` database settings:

```sh
PYTHONPATH=/tmp/vigie-gui-wheel-target-attempt3 \
  /tmp/vigie-pr9-native-server-env/bin/python \
  /tmp/vigie-gui-mvp/tools/gui/preview.py serve \
  --directory /tmp/vigie-gui-preview-20261025-v1
```

On the container workspace, prefix the command with `host-spawn /usr/bin/env` and place `PYTHONPATH=...` after `env`. The server uses no production DB/config/token mounts and opens no connection to the live API. No LAN listener, reverse proxy, firewall change or production deployment is performed.

For another isolated instance after stopping the existing preview, create a NEW direct `/tmp/vigie-gui-preview-*` directory with the script's `seed` action, then `serve`. Only loopback port `18745` is supported; existing directories, symlinked/shared database files and non-synthetic manifests are refused. The seed command prints a safe manifest and token filepath, never the token.

## Verification and future delivery

Backend tests cover public shell versus protected JSON, read-only CLI issuance and HTTP `403` write rejection, old token flags, exact assets/GET+HEAD, traversal/symlink refusal, security headers on UI redirects/errors, installed-wheel assets and isolated seed/auth/pagination/activity/incident responses. The browser review exercises real API journeys, text-only untrusted rendering, storage/network boundaries, stale requests and failure states. UI results do not prove device classification accuracy, mature baselines or completion of the real 48-hour soak.

A source build uses the existing pinned backend constraints and offline mode. The packaged assets were loaded from an installed wheel, not a source-path fallback. Git push, hosted CI, source merge, runtime image build and production rollout remain separate steps; this preview performs none of them.

## Reproduce browser QA with existing tools

On the native Tower, use the existing Playwright/Chromium installation; no dependency installation is required:

```sh
python3 tools/gui/browser_qa.py \
  --manifest /tmp/vigie-gui-preview-20261025-v1/manifest.json \
  --output /tmp/vigie-gui-qa-NEW \
  --browser-executable /home/user/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome
```

Use a new output directory for each attempt. The QA tool reads the synthetic token privately, masks the token field for screenshots, and creates a private per-run browser font cache/configuration without changing host fonts or user caches. Backend regression validation remains 1,468 passed and one known expected failure with 95.30% coverage; the two final CSS/DOM presentation changes were followed by 23 focused fixtures and installed-wheel/served-asset checks rather than repeating that full suite.
