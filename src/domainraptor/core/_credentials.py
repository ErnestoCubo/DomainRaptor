"""Resolve API credentials from constructor → config → environment.

Centralises the 3-tier lookup pattern repeated across every API client.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence

from domainraptor.core.exceptions import SourceAPIKeyError

logger = logging.getLogger(__name__)


def resolve_api_key(
    api_key: str | None,
    config_key: str | None,
    env_vars: Sequence[str],
    service_name: str,
) -> str | None:
    """Return the first non-empty credential from the standard lookup chain.

    Lookup order:
        1. ``api_key`` (explicit constructor argument)
        2. ``config_key`` (value already on the client config object)
        3. each var in ``env_vars`` (process environment)

    Args:
        api_key: Explicit constructor-provided key (may be ``None``).
        config_key: Key stored in the client/source config (may be ``None``).
        env_vars: Ordered list of environment variable names to consult.
        service_name: Human-readable service name (used only for debug logging).

    Returns:
        Resolved key, or ``None`` if no source supplied one.
    """
    if api_key:
        return api_key
    if config_key:
        return config_key
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            return value
    logger.debug(
        "%s: no API key configured (checked args, config, env=%s)",
        service_name,
        list(env_vars),
    )
    return None


def require_api_key(
    api_key: str | None,
    service_name: str,
    *,
    source: str | None = None,
) -> str:
    """Return ``api_key`` or raise :class:`SourceAPIKeyError` if missing/empty."""
    if not api_key:
        raise SourceAPIKeyError(
            f"{service_name} API key is required but not configured",
            source=source or service_name.lower(),
        )
    return api_key


__all__ = ["require_api_key", "resolve_api_key"]
