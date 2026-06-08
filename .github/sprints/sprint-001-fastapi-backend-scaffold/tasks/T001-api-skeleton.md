---
id: T001
sprint: 001
title: Scaffold services/api application with enforced import boundary
implements: [REQ-001]
status: review
owner: agent
depends_on: []
estimate: M
risk: medium
files_touched:
  - services/api/pyproject.toml
  - services/api/app/__init__.py
  - services/api/app/main.py
  - services/api/tests/__init__.py
  - services/api/tests/test_boundary.py
  - pyproject.toml
---

# T001 — Scaffold services/api application with enforced import boundary

## Context

Foundation for the whole platform (REQ-001). Creates the isolated, uv-managed
FastAPI application under `services/api/` and the test that enforces the narrow
import contract against `src/domainraptor`.

## Objective

Stand up an importable, testable FastAPI app skeleton with an enforced
dependency boundary.

## Acceptance criteria

- [ ] `services/api/` exists with its own `pyproject.toml` (uv-managed) and a
      minimal `app.main:app` FastAPI instance that imports/boots cleanly.
- [ ] `services/api` imports from `src/domainraptor` only:
      `storage/_engine.py`, `core/types.py`, `core/exceptions.py`.
- [ ] A boundary test (import-linter contract or equivalent AST/grep check)
      fails if `src/domainraptor` imports `services/api`, or if `services/api`
      imports a disallowed `src/domainraptor` module.
- [ ] Tests added / modified
- [ ] `uv run pytest -q` green
- [ ] `uv run ruff check .` clean
- [ ] `uv run bandit -r src/` clean for changed paths

## Plan

1. Create `services/api/pyproject.toml` (fastapi, uvicorn, deps added per later tasks).
2. Add `app/main.py` exposing `app = FastAPI(...)` with no routes yet.
3. Add `test_boundary.py` asserting the import contract both directions.
4. Wire the new package into the workspace config as needed.

## Risks & mitigations

- Risk: accidental tight coupling to internal modules → Mitigation: boundary
  test fails the build on any disallowed import.

## Verification

`implementation-validator` confirms the app boots and the boundary test fails
on an injected illegal import.
