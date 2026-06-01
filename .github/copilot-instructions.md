# DomainRaptor — Copilot Instructions

These instructions apply globally to every chat turn in this repository.
Scoped rules live in `.github/instructions/*.instructions.md` and load only
for files matching their `applyTo` glob.

## Stack & tooling

- **Python**: ≥ 3.10 today, target 3.12 for the next migration sprint.
- **Package manager**: `uv` is canonical. Never use plain `pip`, never use
  the system Python. Always invoke commands through `uv run …`.
- **Frameworks**: SQLAlchemy 2.x Core (not Declarative), Alembic, httpx,
  Typer, Textual, pytest, ruff, bandit, pre-commit.
- **Project layout**: `src/domainraptor/{cli,tui,core,discovery,enrichment,
  exploitation,assessment,storage,reporting,utils}`.

## Canonical commands

```bash
uv sync --extra dev --extra postgres --extra mysql --extra docs   # bootstrap
uv run pytest -q                                                  # tests
uv run ruff check .                                               # lint
uv run ruff format .                                              # format
uv run bandit -r src/                                             # security
uv run mypy src/domainraptor                                      # types
uv run alembic upgrade head                                       # migrations
uv run pre-commit run --all-files                                 # full gate
```

When invoking a Python script use `uv run python …`, never `python …`.

## Git hygiene

- **Never stage**: `*.png:Zone.Identifier`, `nmap.html`, anything inside
  `.venv/`, ad-hoc dumps. Use explicit `git add <paths>` then `git add -u`
  for tracked-only updates.
- **Pre-commit reformat loop**: if a commit fails because pre-commit
  reformatted files, retry once with `git add -u && git commit -m "…"`.
- **Branches**: feature work on `feat/<topic>` branched from `develop`.
  Implementer tasks go on `feat/T###-<slug>` (see sprint docs).
- **Release train**: `feat/* → develop → release → main`, then
  `release-please` opens a versioning PR on `main` that becomes the tag
  + GitHub Release + PyPI publish. The two promotion legs
  (`develop → release` and `release → main`) are agent-driven by
  `@release-manager` + `@pr-opener`, merged by `@pr-merger` only with
  human confirmation. Direct push to `develop`, `release` or `main` is
  forbidden. See `wiki/Release-Process.md`.

## Conventional Commits (mandatory)

`release-please` parses commit titles to compute version bumps. Use the
allowed types: `feat`, `fix`, `perf`, `revert`, `docs`, `refactor`, `test`,
`build`, `ci`, `chore`. Scopes used in this repo: `cli`, `tui`, `core`,
`discovery`, `enrichment`, `exploitation`, `assessment`, `storage`,
`reporting`, `deps`, `ci`, `docs`, `agents`, `sprints`. Add `!` or
`BREAKING CHANGE:` footer for majors. Force a release with `Release-As: X.Y.Z`.

### Version bump table

| Commit prefix | Bump on next release | Notes |
|---|---|---|
| `feat:` | minor | new user-facing capability |
| `feat!:` or `BREAKING CHANGE:` footer | major (minor while pre-1.0, see `release-please-config.json`) | API break |
| `fix:` | patch | bug fix |
| `perf:` | patch | perf improvement |
| `revert:` | patch | undo a previous change |
| `docs:` | none | shows in CHANGELOG "Documentation" |
| `refactor:` | none | shows in CHANGELOG "Code Refactoring" |
| `test:` / `build:` / `ci:` / `chore:` | none | hidden from CHANGELOG |
| any commit with footer `Release-As: X.Y.Z` | forced to exactly `X.Y.Z` | use sparingly |

Promotion PRs (`develop → release`, `release → main`) MUST use the
`chore(release):` prefix — release-please ignores them for bumps; only
the feature commits squashed into `develop` count.

## Autopilot policy

When the user signals autopilot, commit AND push without confirmation **iff**
`uv run pytest -q` is green and the relevant `uv run ruff check` /
`uv run bandit -r src/` are clean for changed paths. Otherwise stop and report.

## Hard rules (block merge — checked by qa-reviewer, security-officer,
devops-engineer and ai-governance-reviewer)

1. **Exceptions**: no `except: pass`, no bare `except Exception:` without
   re-raise, no `try/except/continue` that hides errors. Every `except`
   must either log with `logger.exception(...)` *and* re-raise with
   `raise X("…") from e`, or convert to a domain exception in
   `core/exceptions.py`.
2. **Ruff**: zero warnings. `# noqa` only with a specific code AND an
   inline justification: `# noqa: E402 - import after importorskip`.
3. **Bandit**: zero `medium`/`high`. `low` requires `# nosec B### -- reason`.
4. **DRY (strict)**: duplication detected by `sprint-deduper` or
   `qa-reviewer` blocks merge. Applies to code AND to requirements.
5. **Tests**: every task adds or modifies tests; coverage cannot drop.
6. **Type hints** mandatory on new code; mypy strict on modified files.
7. **Logging**: `logging.getLogger(__name__)`, never `print()`.
8. **Secrets**: `detect-secrets` baseline must pass; never log API keys.
9. **Dependencies**: `uv pip audit` must pass without `high`/`critical`
   CVEs unless documented with a remediation date.
10. **Detect-secrets** baseline kept current in any PR touching config/CI.
11. **No `verify=False`** or `ssl._create_unverified_context` in production
    code paths.
12. **Safe logging**: never log full HTTP bodies/headers; always redact
    `Authorization`, `X-Api-Key`, cookies.
13. **IaC scans** (future): `checkov`/`trivy` mandatory when `infra/`,
    `Dockerfile` or `*.tf` are introduced.
14. **CI matrix** covers every Python version declared in `pyproject.toml`
    `classifiers` / `requires-python`.
15. **No duplicated commands** between workflows and local scripts — share
    a single source (`scripts/` or `[tool.uv.scripts]`).
16. **Reproducible builds**: CI uses `uv lock --locked`, never raw `pip`.
17. **OIDC for CI secrets**; nothing hardcoded, nothing printed to logs.
18. **Dockerfile**: multi-stage, non-root user, pinned base by digest,
    `HEALTHCHECK` defined.
19. **Single source for rules**: a rule lives in exactly one
    `.github/instructions/*.md` file. Referenced elsewhere, never copied.
20. **Each agent declares** `description` (with ≥3 invocation triggers)
    and minimal `tools`.
21. **CI validates** YAML frontmatter of every `.agent.md` / `.prompt.md`
    / `.instructions.md` (workflow `ai-audit.yml`).
22. **Memory consistency**: `/memories/repo/` must not contradict
    versioned instructions. `ai-auditor` runs weekly and flags drift.
23. **Separation of duties**: `ai-auditor` and `ai-governance-reviewer`
    cannot be merged or rewrite each other.
24. **Trace meta-changes**: every commit touching `.github/{agents,prompts,
    instructions}/**` references an `AUDIT-*.md` or issue.
25. **No self-review**: no agent approves PRs that change its own
    `.agent.md`.
26. **Quorum to weaken rules**: relaxing rules 1–26 requires explicit
    human approval plus an `ai-governance-reviewer` report.

## Style

- Docstrings/comments are minimal. Don't add docs to code you didn't change.
- No premature abstraction. Don't extract a helper for a single call site.
- No error handling for impossible scenarios. Validate only at boundaries.
- Type hints: use `from __future__ import annotations`; `TYPE_CHECKING`
  imports for cycle avoidance.

## Pointers

- Commit conventions detail: see `/memories/repo/commits.md`.
- Scoped rules: `.github/instructions/`.
- Reusable prompts: `.github/prompts/` (invoke with `/<name>`).
- Agent roster: `.github/agents/` (invoke with `@<name>`).
- Sprint methodology: `.github/sprints/_template/README.md`.
- Release train (branches, gates, promotion agents): `wiki/Release-Process.md`.
- PR / release agents: `@pr-opener`, `@pr-merger`, `@release-manager`.
