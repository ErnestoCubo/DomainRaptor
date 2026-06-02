---
applyTo: "{.github/workflows/**,Dockerfile,docker-compose*.yml,infra/**,pyproject.toml,alembic/**,scripts/**}"
description: "DevOps rules — owned by devops-engineer. CI/CD, packaging, releases, runtime envs."
---

# DevOps rules

Owner: **`devops-engineer`**. Runs in parallel with `qa-reviewer` and
`security-officer` on PRs that touch the paths above.

## CI matrix (HARD RULE 14)

- Every Python version declared in `pyproject.toml`
  `classifiers`/`requires-python` has a CI job.
- Today: 3.10, 3.11, 3.12, 3.13.
- Strategy: `fail-fast: false` so all versions report.

## DRY between local and CI (HARD RULE 15)

- A command runs from exactly one source. Either `scripts/<name>.sh` or
  `pyproject.toml [tool.uv.scripts]`. CI calls the script; dev runs the
  same script locally.
- Forbidden: copy-pasting `uv run pytest …` flags inside a workflow.

## Reproducible builds (HARD RULE 16)

- CI: `uv sync --locked` (fail if `uv.lock` out of date).
- Release: build wheel/sdist from the locked env.
- Never `pip install` directly in CI.

## Caching

- `astral-sh/setup-uv` with cache enabled.
- Cache keyed by `uv.lock` hash; invalidates on dep changes.

## Secrets in CI (HARD RULE 17)

- GitHub OIDC for publish (PyPI trusted publishing already in
  `publish.yml`). Mirror for any future deploy.
- No `${{ secrets.X }}` echoed. Use `add-mask` if interpolating.
- No PATs. If a job needs cross-repo access, use a GitHub App with
  scoped permissions.

## Releases

- `release-please` owns `develop → main` PRs and CHANGELOG.
- Tags signed (GPG/sigstore when enabled).
- Wheel/sdist signed; provenance attestation via GitHub Attestations.

## Dockerfile (HARD RULE 18)

When created:
- Multi-stage: `builder` (with uv) → `runtime` (slim/distroless).
- Pinned base by digest: `FROM python:3.12-slim@sha256:…`.
- `USER nonroot` (uid 65532 in distroless).
- `HEALTHCHECK CMD dr --version || exit 1`.
- `.dockerignore` excludes `.venv/`, `.git/`, `tests/`, `docs/`, `wiki/`.

## docker-compose (dev)

`docker-compose.yml` at repo root for local backend dev:
- `postgres:16-alpine` with healthcheck.
- `mysql:8` with healthcheck.
- Volumes for persistence, env vars for credentials.
- `make compose-up` / `compose-down` wrappers in `scripts/`.

## Observability

- Logs structured (JSON) when env `DR_LOG_FORMAT=json`.
- Metrics: `domainraptor.metrics` module (future). OpenTelemetry-friendly.
- Healthcheck endpoint when a daemon mode exists.

## Migrations

- `alembic upgrade head` runs at container start (entrypoint script),
  not at app start, to keep app idempotent.
- New migrations go to `alembic/versions/`, auto-generated then
  hand-reviewed.

## Workflow naming

- `ci.yml`, `release-please.yml`, `publish.yml`, `wiki.yml`, `ai-audit.yml`.
- Jobs: `<purpose>-<py-version>` (`test-3.12`).
- Reusable workflows in `.github/workflows/_*.yml` (underscore prefix).
