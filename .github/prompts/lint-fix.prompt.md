---
description: Run ruff check --fix and ruff format on changed paths, validate with pre-commit.
---

# /lint-fix

1. Identify changed files: `git diff --name-only`.
2. Run:
   ```bash
   uv run ruff check --fix <changed paths>
   uv run ruff format <changed paths>
   ```
3. Re-run check to confirm zero warnings:
   ```bash
   uv run ruff check <changed paths>
   ```
4. If any `# noqa` was needed, add a justification per
   `src.instructions.md` (HARD RULE 2). No bare `# noqa`.
5. Optionally run pre-commit on changed files:
   ```bash
   uv run pre-commit run --files <changed paths>
   ```
6. Report what was fixed automatically vs. what needs manual attention.
