---
applyTo: "tests/**/*.py"
description: "Test rules — fixtures, mocking, coverage, naming."
---

# `tests/` rules

## Layout

- One test file per source module: `src/.../foo.py` → `tests/test_foo.py`.
- Integration tests under `tests/integration/` (currently flat — migrate
  when sprint warrants).
- Sample data → `tests/conftest.py::SampleDataFactory` (Phase 2.3 refactor).
  Do not inline large dicts in tests.

## Mocking

- HTTP: `respx` for `httpx` clients, or `pytest-httpx`. Mock at the
  transport layer, never monkey-patch internals.
- Storage: in-memory SQLite via `create_engine_from_url("sqlite:///:memory:")`
  + `init_schema(engine)`. For Sql repositories, see
  `tests/test_storage_sql_repository.py` for the canonical pattern.
- Time: `freezegun` if needed; otherwise inject a `datetime` factory.

## Optional dependencies

When testing against an optional dep:
```python
import pytest
pytest.importorskip("sqlalchemy")

from domainraptor.storage._sql_repository import SqlScanRepository  # noqa: E402 - import after importorskip
```
The `# noqa: E402 - import after importorskip` is the only sanctioned
exception to import-order rules.

## Naming

- Test functions: `test_<unit>_<scenario>_<expected>()`.
- Test classes: `Test<Subject>`, group related scenarios.
- Parametrize boundary/regression cases instead of duplicating tests.

## Coverage (HARD RULE)

- Every task adds or modifies tests. PRs that touch `src/` without
  touching `tests/` are rejected by `qa-reviewer` unless explicitly
  justified (e.g. docs-only refactor of comments).
- Project coverage must not drop. Check with `uv run pytest --cov`.

## Async

- `pytest-asyncio` is in `auto` mode (see `pyproject.toml`).
- `async def test_…` works without decorators.

## Fixtures

- Shared fixtures → `tests/conftest.py`.
- Per-module fixtures → top of that test file.
- Prefer `@pytest.fixture` over setUp-style classes.

## What NOT to do

- Don't test private helpers (`_foo`) directly; test through the public API.
- Don't hit real network. Any test that does is `@pytest.mark.integration`
  and skipped by default.
- Don't sleep. Use event-based waits or mock the clock.
