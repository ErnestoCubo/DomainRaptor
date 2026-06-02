---
applyTo: "src/**/*.py"
description: "Source code rules for DomainRaptor — exceptions, types, architecture patterns, security."
---

# `src/` rules

These rules **block merge** when violated. They are enforced by
`qa-reviewer`, `security-officer` and `implementation-validator`.

## Exception handling (HARD RULE)

Forbidden:
```python
try:
    do_thing()
except Exception:           # bare/broad without re-raise
    pass                    # silent swallow
```
```python
for item in items:
    try:
        process(item)
    except Exception:       # silently skipping errors
        continue
```

Required pattern — choose ONE:

1. **Log and re-raise**:
   ```python
   try:
       call()
   except SomeError as e:
       logger.exception("call failed for %s", target)
       raise
   ```
2. **Convert to domain exception** (`core/exceptions.py`):
   ```python
   except httpx.HTTPError as e:
       raise SourceError(f"shodan failed: {e}") from e
   ```
3. **Narrow handler with explicit recovery**, documented:
   ```python
   except FileNotFoundError:
       # legitimate: config is optional
       return default_config()
   ```

## Architecture patterns (use existing, don't reinvent)

- **HTTP clients**: extend `discovery.base.BaseClient` /
  `enrichment.base.BaseClient`. Use the shared HTTP factory.
- **Discovery results**: inherit from `discovery._host.HostInformation`.
  Only declare provider-specific fields in the subclass.
- **Provider → domain mapping**: live in `discovery/_mappers/<provider>.py`
  and `enrichment/_mappers/<provider>.py`. Construct results with
  **keyword arguments only**.
- **Storage**: use `storage._factory.get_scan_repository()` /
  `get_watch_repository()`. Never instantiate `Sql*Repository` directly
  from CLI/TUI code.
- **Sample data for tests**: `tests/conftest.py::SampleDataFactory`.

## Type hints

- Mandatory on all new code.
- `from __future__ import annotations` at the top of every new module.
- Use `if TYPE_CHECKING:` for cycle-prone imports.
- `mypy` strict on modified files: `uv run mypy <changed paths>`.

## Imports

- Group: stdlib → third-party → `domainraptor.*`. Ruff `I` enforces this.
- Absolute imports only (`from domainraptor.x import Y`).
- Avoid `*` imports.

## Logging (HARD RULE)

- `logger = logging.getLogger(__name__)` at module top.
- Never `print()` outside CLI presentation layer.
- **Never log secrets**: redact `Authorization`, `X-Api-Key`, cookies,
  full HTTP bodies, full headers. Use `utils.redact()` if/when available.

## Security hot paths

- HTTP: build URLs with explicit base + path; never `f"https://{user_input}"`
  unless the input passed `core.validators.validate_domain()`.
- Subprocess: `subprocess.run([...], shell=False, check=True, timeout=N)`.
  Never `shell=True`.
- YAML: `yaml.safe_load`, never `yaml.load`.
- SQL: SQLAlchemy Core with bound parameters. No string concatenation.
- TLS: never `verify=False`, never `_create_unverified_context`.

## Style (DRY + minimalism)

- No premature abstraction — don't extract a helper for one call site.
- Don't add docstrings/comments to code you didn't change.
- Don't add error handling for impossible scenarios.
- Validate only at system boundaries (HTTP in, CLI in, file in).

## Ruff & Bandit (HARD RULE)

- Zero warnings/errors after `uv run ruff check`.
- `# noqa` only with code + justification:
  `# noqa: E402 - import after importorskip`.
- Zero bandit `medium`/`high`. `low` → `# nosec B### -- reason`.
- Silencing without justification is a merge blocker.
