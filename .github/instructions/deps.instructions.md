---
applyTo: "{pyproject.toml,uv.lock}"
description: "Dependency management — when to add, how to bump, audit policy."
---

# Dependency rules

## When to add a new dep

Before adding, justify in the PR description:
1. **Maturity**: ≥ 1.0.0, ≥ 1 year old, active maintenance.
2. **Alternatives considered**: stdlib first, then well-known options.
3. **Surface area**: only the part of the lib we actually need.

Reject if any of:
- Single-maintainer hobby project.
- License incompatible with MIT (GPL, AGPL).
- Pulls in heavy transitive deps for trivial functionality.

## How to add

```bash
uv add <package>                      # runtime
uv add --dev <package>                # dev only
uv add --optional postgres <package>  # optional extra
uv lock --upgrade-package <package>   # refresh lock
```

Always commit `uv.lock` alongside `pyproject.toml`. CI uses `uv sync
--locked` (no surprise upgrades).

## Bumps

- Routine: `chore(deps): bump <pkg> to X.Y.Z`.
- Security: `fix(deps): bump <pkg> to X.Y.Z (CVE-YYYY-NNNNN)`.
- Major (breaking): `chore(deps)!: bump <pkg> to X.0.0` with migration
  notes in the body.

## Audit (HARD RULE)

- `uv pip audit` (or `pip-audit` against the venv) must pass without
  `high`/`critical` CVEs.
- If a CVE has no fix yet, document in the PR with: affected versions,
  mitigation in our code, remediation date.

## Python version

- `requires-python = ">=3.10"` today. Bump only via a dedicated
  migration sprint (owner: `devops-engineer`).
- Classifiers in `pyproject.toml` must match the CI matrix (HARD RULE 14).

## Optional extras

Keep extras minimal and named by use case:
- `dev` → tooling.
- `postgres`, `mysql` → DB drivers.
- `docs` → mkdocs.
Avoid creating an extra for a single dep used everywhere.
