"""Pure mappers for enrichment client API responses.

Keep response-parsing free of network/state concerns so it's directly
unit-testable from a raw dict, and the client classes shrink to HTTP
orchestration plus a one-line delegate. Clients still expose the
historical ``_parse_*`` private methods as thin wrappers so existing
tests that call them keep working.
"""
