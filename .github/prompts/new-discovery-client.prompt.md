---
description: Scaffold a new OSINT discovery client following project patterns.
---

# /new-discovery-client `<provider>`

Create a new discovery source. Arguments:
- `<provider>`: short name, e.g. `binaryedge`, `fofa`.

## Files to create / modify

1. `src/domainraptor/discovery/<provider>_client.py`
   - Class `<Provider>Client(BaseClient)` with `__init__(self, config: ClientConfig)`.
   - `<Provider>HostResult(HostInformation)` if provider returns host
     intel. Add only provider-specific fields. Keyword args only.
   - Public methods: `search_domain()`, `search_host()` as applicable.
   - Use the shared HTTP factory.
   - Domain exceptions from `core/exceptions.py` (`SourceAPIKeyError`,
     `SourceRateLimitError`, `SourceNotFoundError`, `SourceError`).
2. `src/domainraptor/discovery/_mappers/<provider>.py`
   - Pure function `to_<provider>_host(raw: dict) -> <Provider>HostResult`.
   - Construct with kwargs only.
3. `src/domainraptor/discovery/__init__.py`
   - Re-export the client class.
4. Registration in the discovery orchestrator (if applicable).
5. `tests/test_discovery_<provider>.py`
   - Use `respx` to mock httpx.
   - Sample data via `SampleDataFactory` (extend if needed).
   - Cover: happy path, auth error, rate limit, empty result, malformed.
6. `wiki/Commands-Discover.md` — add a section for the new source.
7. `core/config.py` — add the API key field if needed.

## Hard rules

- No new dependency unless justified per `deps.instructions.md`.
- Logging: redact `Authorization` headers (HARD RULE 12).
- TLS verification ON (HARD RULE 11).
- Tests pass `uv run pytest tests/test_discovery_<provider>.py -q`.

## Commit message

```
feat(discovery): add <provider> client

Adds discovery client for <provider> with host search support, mapper,
and unit tests with mocked HTTP transport.
```
