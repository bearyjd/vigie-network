# Read-only GUI implementation — approved scope

User authorized GUI development; implement on isolated feat/read-only-gui at reviewed681e5488. Production API/pipeline/router/soak remain unchanged. No new runtime dependency, push, merge or production deployment.

## Map and interface

FastAPI create_app currently defines only JSON routes and existing write privilege guards. tokens.create_token already supports read-only; public token CLI lacks issuance flag. Hatchling packages all three src packages; verify static inclusion from installed wheel. Existing native Python3.12/uv dev environment supplies FastAPI/Starlette/httpx/pytest/ruff.

Frontend lane owns five packaged assets under server/src/vigie_api/ui/: index.html, styles.css, app.js, client.js, views.js. References stay relative under /ui/, external ES modules and CSS only; fixed same-origin GET calls, memory-only bearer, no browser storage/cookies or external requests. Frontend gets collector_id synthetic-preview for seeded preview, with visible synthetic-preview indication.

Backend lane owns server/src/vigie_api/ui_static.py, app mount, narrow CLI flag, backend tests, wheel verification, isolated preview seed/start documentation. Serve only exact five asset names and index root; no SPA fallback. Static shell anonymous; JSON endpoints retain existing401/auth and403write guards. /ui redirects/errors/assets receive restrictive CSP(defaultnone; script/style/connect/img/fontself; frameancestors/object/base none; form-actionself), no-referrer, nosniff, private/no-store. No inline executable JS/style and no directory/source/config/credential exposure. Existing API/OpenAPI contracts remain unchanged; mounted static app stays outside OpenAPI.

CLI tokens create --read-only is mutually exclusive with existing --rules-write and leaves existing default app token behavior unchanged. Store/audit only existing hash+token ID semantics; print once exactly as existing CLI.

## Test-first seams and verification

1. Backend tests: only intended assets/GET+HEAD, anonymous shell versus protected JSON, encoded traversal/backslash/unknown/nested assets/unsupported verbs, securityheaders including errors/redirects; readonly CLI actualGET200/write403 and flag mutual exclusion/default compatibility.
2. Run focused tests then lint/full server suite in background. Installed wheel must contain and actually serve all five assets from separate target outside source tree; no dependency updates.
3. Frontend lane tests state/security boundaries and real browser journey; root coordinates independent review and browser verification. No test mutates production databases/configuration.
4. Preview: separate synthetic seed DBs/private0600 sample readonly token under new0700/tmpdirectory, explicit Settings DB paths ignoring inherited live environment, loopback127.0.0.1:18745 only. No production token/DB/config mounts or proxy and no live production calls. Clearly label synthetic collector/device/evidence and visible preview banner.
5. Only after tests and independent review start preview, verify bound listener and GET UI/API auth, report exact URL and bounded-process PID/start/stop commands. Keep preview running for user review; do not call this production deployment or48h acceptance.

## Official references checked before implementation

- https://fastapi.tiangolo.com/tutorial/static-files/ — mounted StaticFiles is an independent app excluded from API OpenAPI.
- https://starlette.dev/staticfiles/ — StaticFiles directory/package mounting, follow_symlink=False,404/405 semantics. Use existing version API, no newer frontend helper/dependencies.
