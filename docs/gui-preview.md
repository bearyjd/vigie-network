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

Before spawning, `start` verifies: the package directory, every ancestor and **every entry below it** are owned by root or the current user, not group/world-writable, and contain no symlinks; the child interpreter is resolved and its binary, launch directory, venv root (the folder holding `pyvenv.cfg`) and every `lib*/python*/site-packages` tree get the same check. The check also follows every symlink hop of the launch path: each hop must be root/us-owned (the symlink itself, not only its directory) and sit in a directory that is not group/world-writable, except that a **sticky** world-writable directory such as `/tmp` is accepted only for a hop symlink owned by you (another user could otherwise own or swap it). It also requires a venv's `pyvenv.cfg` `home` to be exactly the resolved binary's directory, and walks the stdlib below that prefix (`lib*/python3*`, no symlinks; base `site-packages` only when it is on `sys.path`, i.e. a non-venv interpreter or a venv whose `include-system-site-packages` is true). The key is read like `site.py` does: case-insensitive, an absent key means true, and any value other than true/false is refused.

`python -I` still processes every `*.pth` file in the walked site-packages directories, so their **content** is vetted too. A `.pth` is accepted only if (a) it is one of three known-benign files matched by name and exact SHA-256 (`_virtualenv.pth`, coverage's `a1_coverage.pth`, setuptools' `distutils-precedence.pth`), or (b) every line is blank, a comment or a plain directory line, read exactly as `site.py` reads it: UTF-8 with an optional BOM (undecodable bytes are refused), a comment only when `#` is in column 0, lines split exactly as `site.py` 3.12+ does (`str.splitlines()`; a file containing a lone `\r`, `\v`, `\f`, `\x1c`-`\x1e`, `\x85`, U+2028 or U+2029 is refused whole, because Python versions disagree on those breaks), and any other line with leading or trailing whitespace, starting `import`, or containing `;` or NUL is refused. A directory line that exists must be a symlink-free directory (at most 100,000 entries, so a `/` line is refused rather than walked) whose ancestors and whole tree are root/us-owned and not group/world-writable (so an editable install of another worktree's `server/src` works only while that tree is clean). A missing directory is accepted only if its nearest existing ancestor is root/us-owned and not group/world-writable (a sticky `/tmp` is not enough): otherwise another local user could create it after the check and `site.py` would put it on `sys.path`. `a1_coverage.pth` is allowlisted for the real default environment and is inert only because the child environment is exactly `PATH` and `LC_ALL` (a pinned test); a `COVERAGE_PROCESS_START` in the child would make it load a coverage rcfile and plugins. Anything else, including setuptools-style editable finders (`import __editable__...`), is refused: reinstall with a path-style editable install or a built wheel. A `sitecustomize` or `usercustomize` file (any extension, including `__pycache__` variants) anywhere in a vetted tree (stdlib, site-packages, a `.pth` target, `--package-dir`) is refused unless pinned by name and SHA-256 (none are). An unreadable subdirectory is a refusal, never skipped. A venv is launched by its own path (so `pyvenv.cfg` is found); a plain interpreter by its resolved path. The child runs `python -I -B` (no environment, user site or script-directory `sys.path`; the vetted package directory is passed as `--package-dir`). Termination signals are blocked while the child is forked and the child clears that mask, so an interrupted start either records the child or leaves a prepared-only receipt that `status`/`stop` recover. Anything else is refused with no child and no receipt. A directory line containing a `..` segment is refused (site.py joins it to the unresolved site directory, so the vet and the child could disagree), a venv `lib`/`lib64` that is a symlink to anything other than its sibling `lib`/`lib64` is refused for the same reason, and an existing target directory must itself not be group/world-writable, sticky or not (a sticky `1777` directory still lets another user add importable files). A file named `sitecustomize`/`usercustomize` is refused by name without being read.

A start that is interrupted (Ctrl-C, SIGTERM, SIGHUP) terminates only its own retained child, records the outcome and re-raises. `stopped`, `startup-failed` (child exited) and `failed-before-spawn` receipts are terminal: their PIDs are never probed, so a reused PID cannot block a new start. If the controller is killed outright (SIGKILL, power loss) between spawning and recording the child, `status` reports `orphaned` only when exactly one process of the current user has the receipt's full argv and owns the receipt's listener; `stop` then re-verifies it, records it and sends TERM through the same pidfd-guarded path. Anything less certain stays `uncertain` and is never signalled.

### Status values `starting` and `uncertain`, and recovery

`status` is read-only: it never creates the lock file and never holds the lock while it reads the receipt or scans processes; it only takes and drops a shared lock to probe it (before reading, and again after any scan-derived result, re-reading the receipt each time), so concurrent `status` calls never affect each other and a loop of `status` calls cannot keep `start`/`stop` waiting (they retry the lock with a short, growing backoff). A receipt read that fails while no lock is held is retried a few times with a short backoff before it is reported, because a writer may have just finished; a torn receipt row is `starting` while a `start`/`stop` holds the lock and the usual retained-failure error when none does. `starting` means a `start` or `stop` (which includes a `stop` adopting an orphan) holds the lock right now, in any phase (including between the `spawned` and `ready` receipts, up to about 12 seconds), or a new attempt replaced the receipt while `status` was scanning: run `status` again in a moment. `start` and `stop` wait up to 2 seconds for a concurrent command before failing with `another preview command holds the lock (PID <n>)`; the holder writes `PID START_TICKS BOOT_ID` into the lock file and clears it on release, and the PID is shown only if that exact process (same start time and boot) is alive, so a recycled PID is never blamed. The holder line proves process identity, not lock ownership: any live process can be named in it. `status` reports `holder_pid` only when that process is yours and its interpreter command line runs this `preview.py` script (the first non-flag argument, absolute or relative to that process's own working directory; `-c`/`-m` forms never qualify) with the action `start` or `stop`, which recognises the process but still does not prove it holds the lock; any other named process is reported as `unverified_holder_pid` (state `starting`, no advice), and the lock error then says `unverified PID <n>`. That a holder line matches a live process does not prove it holds the lock, so never signal an unverified PID. `status` reports `lock_age_seconds`; it says `starting` while the lock is younger than 60 seconds, and stays `starting` for an older lock whose holder line is unverifiable (dead, recycled or unparseable) or unverified, because nothing then proves a wedge. An older lock with a verified live start/stop holder is `wedged-start` (for example the holder was suspended with Ctrl-Z or is stuck in uninterruptible I/O) and `status` prints an `advice` line. Before any signal, read `/proc/<PID>/cmdline` and confirm it is this `preview.py start` or `stop` command; never signal a PID whose command line differs. Check `grep State /proc/<PID>/status`, then resume a suspended holder with `fg` or `kill -CONT <PID>` so it finishes, or terminate it with `kill -TERM <PID>` if it is yours and stuck, then run `status` (and `stop` if a child was left). A lock file that is not a regular single-link file owned by you with mode `0600` is refused with a message naming the file and its mode; fix its mode; if another user owns it you cannot remove it from the sticky `/tmp`, so ask the administrator or wait. `status` opens the lock non-blocking, so a FIFO or other special file planted at the path is refused (exit 2 with that message) instead of hanging it. **Known limitation:** the lock path lives in the shared, sticky `/tmp`, so another local user can still occupy it and make `start`/`stop`/`status` refuse (never hang, never act); if that file belongs to another user you cannot remove it from the sticky `/tmp` (only its owner or root can), so ask them or the administrator; if it is yours, remove it only after confirming no preview command runs.

`uncertain` is deliberately sticky: a same-user process with the receipt's exact command line is alive, or something still holds the port, but the manager cannot prove it is the recorded child, so it will not signal it. `status` then prints `candidate_pids` (PIDs only, no command line or token). If `status` reports `uncertain` with `managed: true` and a `pid`, the recorded child is alive but is not (yet) proven ready and listening: run `stop`, which re-verifies the recorded identity and signals it through a pinned descriptor; do not kill it by hand. Otherwise, to recover by hand: (1) for each PID, `tr '\0' ' ' < /proc/<PID>/cmdline; echo` and `ls -l /proc/<PID>/exe`, and confirm it runs `preview.py serve --directory <your preview directory>` as your user and is the process you expect; (2) send it a polite stop, `kill -TERM <PID>` (never `-KILL`, never a process group, never a PID you have not verified); (3) wait a few seconds and run `status` again: it reports `stopped` once no matching process or listener remains and `start` is allowed again. If `status` still reports `uncertain` and `managed` is false with no `candidate_pids`, another process holds port 18745; identify it with `ss -ltnp 'sport = :18745'` and stop it only if it is yours. Do not delete receipts to bypass this state.

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

## Coverage banner and incident inbox

A status banner (`role="status"`, `aria-live="polite"`) sits above every view. It reads the same
`/coverage` data as the Overview, so the other views fetch that endpoint too; a failure there never
fails the view itself. Each state starts with a text prefix, so colour is never the only cue:

- `Checking` while the first fetch is in flight.
- `Unavailable` when the fetch failed or the response is malformed. It is never green.
- `Unknown` when no coverage rows exist yet. Silence is not health.
- `Warning` when the evidence is old or incomplete. It names the first reason and the issue count.
  Reasons: the source or parsed-DNS observation is stale (older than 120 s) or missing; any hour is
  partial or missing (an open hour that already ended counts as missing); no hour is qualified yet (all open, so the baseline is still accumulating);
  `monitoring_unavailable` is not a list or is capped; the summary is capped or its cap is unknown;
  processing is `Stalled` (oldest pending batch over 180 s) or `Unknown`; or the collector reports
  unavailable monitoring scopes. Errors on the side of Warning: a missing flag is a gap, not a pass.
  A fresh pending batch (`Awaiting processing`) is normal flow and does not warn.
- `OK` only when none of the above applies, e.g. `OK · coverage current; 23 qualified hours, 1
  accumulating`. Open hours are shown as accumulating and never count as qualified. The age check
  reruns every few seconds, so an `OK` banner turns `Warning` as the observation ages. Changing
  view, selecting or paging keeps the previous banner text until a new snapshot arrives; only the
  first load and a collector or range change show `Checking`.
- API strings are shown only when they are text or finite numbers; anything else reads
  `Unavailable`, and a banner that cannot be computed reads `Unavailable`, never its old state.

The Incidents view is a local inbox that needs no notification publisher. Incidents the API marks
`attention` come first, newest first, with ties kept in API order; payloads without `attention` fall
back to the incident state. The Decision column shows `acknowledged`, `expected`,
`snoozed until <UTC>`, `snooze expired · needs attention`, `needs review` or `no decision`. Only `resolved` and `superseded` count as closed; any other state
(garbage, missing) reads `... · unknown state` and needs review; a
decision the API still flags gets ` · needs attention` appended, so the label and the filter always agree. Unrecognised
`review` or `attention` values show `unknown decision` and sort as needing attention. The All / Needs
attention / Quiet filter changes only the view and is kept in the URL hash (`#filter=attention`),
never in browser storage. The API returns at most 25 incidents per page and a longer list is rejected as malformed rather
than truncated; the pager counts the rows the filter leaves, and a filter that hides rows says
`Showing X of N incidents on this page`. An empty list says
absence of incidents is not proof of health. The GUI is intentionally read-only: it has no
acknowledge, snooze or expected controls and issues only GET requests; decisions are made through
the authenticated API.

## Verification and future delivery

Backend tests cover public shell versus protected JSON, read-only CLI issuance and HTTP `403` write rejection, old token flags, exact assets/GET+HEAD, traversal/symlink refusal, security headers on UI redirects/errors, installed-wheel assets and isolated seed/auth/pagination/activity/incident responses. The browser review exercises real API journeys, text-only untrusted rendering, storage/network boundaries, stale requests and failure states. UI results do not prove device classification accuracy, mature baselines or completion of the real 48-hour soak.

The native preview-manager lane (`server/tests/api/test_gui_preview_native.py`) runs the real `start`/`stop` end to end against a real interpreter, preferring the uv-managed Python (no distro-patched stdlib symlinks). Locally it skips with a reason when no trustable interpreter exists; when the `CI` environment variable is set the same condition is still a skip (a hosted runner's tool cache is group/world-writable and refused by design; the trust check is never weakened) but with a loud `NOT EXERCISED` warning annotation, and a CI-only test asserts the venv-based trust checks still run.

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
