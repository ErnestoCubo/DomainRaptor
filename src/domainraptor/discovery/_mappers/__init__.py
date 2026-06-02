"""Pure mappers for discovery client API responses.

Keeps response-parsing free of network/state concerns so it's directly
unit-testable from a raw dict, and the client classes shrink to
HTTP orchestration plus a one-line delegate. Clients still expose the
historical `_parse_*` private methods as thin wrappers — existing tests
that call `client._parse_host_result(data)` keep working.
"""
