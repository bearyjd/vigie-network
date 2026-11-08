# Contributing

How to build, test and land a change. Deployment and operations live in [`deploy.md`](deploy.md);
the configuration reference is the commented [`deploy/.env.example`](../deploy/.env.example).

## Prerequisites

`uv`, `cargo` (stable), `openssl`, `python3` (3.12) and `node` (the offline GUI contract checks).
`scripts/ci.sh` refuses to start when one is missing. Pins used by hosted CI are in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## Checks

<!-- AUTO-GENERATED from scripts/ci.sh --list and server/pyproject.toml; do not edit by hand -->

| Command | What it runs |
|---|---|
| `scripts/ci.sh` | The full gate: every stage below, stopping at the first failure. Only this invocation counts as the full gate. |
| `scripts/ci.sh --list` | Lists the stages: `server`, `trafficgen`, `rust`, `deploy`, `contracts`, `e2e`. |
| `scripts/ci.sh STAGE ...` | A subset, for example `scripts/ci.sh server contracts`. |
| `cd server && uv sync && uv run pytest` | Server tests without containers; coverage must stay at or above 80% (`--cov-fail-under=80`). |
| `cd server && uv run ruff check .` and `uv run ruff format --check .` | Lint and format (line length 100, Python 3.12). |
| `python -I tools/docs_private_info_lint.py` | Docs private-information lint over `docs/**`, `README.md` and `.trail/learnings/**`; also a hosted CI gate. |
| `scripts/image_smoke.sh` | Builds the server image and smoke-tests it; a hosted CI step. |

<!-- END AUTO-GENERATED -->

## Working rules

- **Tests first.** Write the failing test, then the change. A new guard needs a test that fails
  when the guard is removed; check this by breaking the guard in a scratch copy.
- **Use the project environment.** `server/.venv` pins the Starlette version the rate-limit and
  API-auth tests expect; a system Python with an older Starlette fails them on `main` too.
- **Deploy tests run isolated.** The `deploy` stage runs the deploy tests with `python3 -I`.
  The soak meter tests need Linux memfd sealing and child supervision, so they error inside
  restricted sandboxes; that is an environment limit, not a regression.
- **No private information in git.** Documentation uses placeholders such as `ha.example.invalid`.
  No home paths, real hostnames, LAN addresses or webhook ids. The lint above enforces part of this.
- **Do not leave debug output** (`print`, stray logging) behind.

## Landing a change

1. Branch from `main`; one concern per pull request. Commit messages follow
   `<type>: <description>` with types `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`.
2. Run the relevant stage locally, then the full gate before asking for review.
3. Open a pull request with a test plan. Hosted CI runs the private-info lint, the full gate and
   the image smoke test; it must be green.
4. A change that touches verdict logic, authentication, input handling, the filesystem or external
   calls gets an independent review (and a security review for those areas) before merge. The
   author does not approve their own change.
5. Merge only with CI green. Delete the branch afterwards.

## Soak and deployment changes

Anything that changes the soak verdict rules, the soak runner or the images used on the validation
host invalidates earlier runs as evidence: a passing 48-hour run must be recorded after the final
rule change. See [`deploy.md`](deploy.md) and [`monitoring.md`](monitoring.md).
