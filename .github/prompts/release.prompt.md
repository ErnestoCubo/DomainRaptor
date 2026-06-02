---
description: Pre-release checklist on develop — gates green, conventional commits, push.
---

# /release

Run the release readiness check against the current branch (expected:
`develop` or a feature branch ready to merge).

1. **Gates** (block on any failure):
   ```bash
   uv run pytest -q
   uv run ruff check .
   uv run ruff format --check .
   uv run bandit -r src/
   uv run mypy src/domainraptor
   ```
2. **Commit log sanity**: list commits since last release tag, verify
   each follows Conventional Commits (see `/memories/repo/commits.md`).
3. **Push**: only if gates green and we're on `develop` or
   `feat/T###-<slug>`. Autopilot per `copilot-instructions.md`.
4. **release-please** owns the `develop → main` PR. Do NOT manually
   bump version. To force a release on docs-only changes, add footer
   `Release-As: X.Y.Z` to the next commit.
5. Report:
   - Branch + commits ahead of `origin`.
   - Gate results.
   - Whether push happened or why it was skipped.
