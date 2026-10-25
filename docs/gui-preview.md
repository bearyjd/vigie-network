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

## Manage the owned preview safely

Run these commands on the native Tower from the GUI worktree. The controller uses only Python's standard library, so status/start/stop need no manual `PYTHONPATH` or foreground server shell:

```sh
/usr/bin/python3 tools/gui/preview.py status --directory /tmp/vigie-gui-preview-20261025-v1
/usr/bin/python3 tools/gui/preview.py start --directory /tmp/vigie-gui-preview-20261025-v1
/usr/bin/python3 tools/gui/preview.py stop --directory /tmp/vigie-gui-preview-20261025-v1
```

Start reuses the existing verified synthetic seed; it never reseeds or overwrites databases. It remembers the installed package directory and child interpreter from the previous managed start. For the first managed start, the current default package is `/tmp/vigie-gui-wheel-target-attempt3` and the child interpreter is `/tmp/vigie-pr9-native-server-env/bin/python`. Override them explicitly for a newly reviewed wheel:

```sh
/usr/bin/python3 tools/gui/preview.py start \
  --directory /tmp/vigie-gui-preview-20261025-v1 \
  --package-dir /tmp/vigie-gui-wheel-target-attempt3 \
  --python /tmp/vigie-pr9-native-server-env/bin/python
```

The native controller must support Linux process descriptors; it refuses before spawning on Python builds without them. The cached Python3.12 application interpreter is used only for the detached server. The server still binds only to `127.0.0.1:18745`, receives no production credential/configuration environment, uses private logs and stdin `/dev/null`, and exits after eight server-runtime hours.

Status is read-only and prints the safe URL, source, token filepath, managed state and available process/log metadata; it never reads or prints the token. Start reports an already-running owned preview without restarting it, and refuses an occupied foreign port or an uncertain/changed process. Stop checks UID, boot ID, process start ticks and the complete recorded argument list, then uses a pinned process descriptor for TERM. It never guesses a PID, signals a process group or forces KILL.

One fixed private lock protects port18745 across all preview directories. Each start preserves a new `managed-*.jsonl` attempt journal and `managed-*.log`, with an atomic `manager-current.json` pointer. Failed attempts, existing legacy logs and identity records remain intact. A partial or malformed receipt is refused rather than adopted. Do not remove receipts to bypass an uncertain state.

The legacy preview PID1923379 is currently **unmanaged** by these new commands. The manager intentionally refuses to adopt or stop it. A separately identity-checked transition is required after the new helper's independent review; no transition has been performed during code preparation. This paragraph will be updated after that verified transition.

### Trust checks and recovery

Before spawning, `start` verifies: the package directory, every ancestor and **every entry below it** are owned by root or the current user, not group/world-writable, and contain no symlinks; the child interpreter is resolved and its binary, launch directory, venv root (the folder holding `pyvenv.cfg`) and every `lib*/python*/site-packages` tree get the same check. Anything else is refused with no child and no receipt.

A start that is interrupted (Ctrl-C, SIGTERM, SIGHUP) terminates only its own retained child, records the outcome and re-raises. `stopped`, `startup-failed` (child exited) and `failed-before-spawn` receipts are terminal: their PIDs are never probed, so a reused PID cannot block a new start. If the controller is killed outright (SIGKILL, power loss) between spawning and recording the child, `status` reports `orphaned` only when exactly one process of the current user has the receipt's full argv and owns the receipt's listener; `stop` then re-verifies it, records it and sends TERM through the same pidfd-guarded path. Anything less certain stays `uncertain` and is never signalled.

**Known limitation (fixed port):** the preview always uses loopback port 18745. Another local user or process that binds the port first only causes `start` to refuse (`unmanaged listener`); the manager never adopts or signals it. A process that squats the port blocks the preview until it exits; there is no port fallback by design, because the documented URL and the QA tools pin that origin.

## Reproduce with existing native dependencies

The current preview runs an offline-built wheel installed into `/tmp/vigie-gui-wheel-target-attempt3`; its package location was verified outside the checkout. Current wheel SHA256: `373f3a06ae4c0b5501cb27d012822c799b0c37f370b5f71c3f57b1d5c260ee4c`. All five installed and served asset hashes match source. No runtime dependency or frontend build system was added. Start uses explicit own database paths, ignoring inherited `VIGIE_*` database settings:

```sh
PYTHONPATH=/tmp/vigie-gui-wheel-target-attempt3 \
  /tmp/vigie-pr9-native-server-env/bin/python \
  /tmp/vigie-gui-mvp/tools/gui/preview.py serve \
  --directory /tmp/vigie-gui-preview-20261025-v1
```

On the container workspace, prefix the command with `host-spawn /usr/bin/env` and place `PYTHONPATH=...` after `env`. The server uses no production DB/config/token mounts and opens no connection to the live API. No LAN listener, reverse proxy, firewall change or production deployment is performed.

For another isolated instance after stopping the existing preview, create a NEW direct `/tmp/vigie-gui-preview-*` directory with the script's `seed` action, then `serve`. Only loopback port `18745` is supported. Seed refuses existing directories; serve/start reuse only privately owned synthetic files and refuse symlinked/shared databases or a non-synthetic manifest. The seed command prints a safe manifest and token filepath, never the token.

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

The preview-manager safety fixtures cover process identity reuse/drift, unmanaged listeners, readiness ownership, symlink/partial/malformed receipts, shared-lock exclusion, child environment/stdin/privacy, startup failures and TERM-only stopping. Tests use temporary namespaces and mocked children; they do not stop the current preview. A new managed start still requires independent review before any real process transition.
