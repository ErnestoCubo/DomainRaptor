"""Centralised HTTP client factory.

Wraps `httpx.Client` construction so every client in the codebase gets the
same sane defaults: ``follow_redirects=True`` and an opt-out via explicit
kwargs.  Centralising this gives us one place to add retries, proxies,
instrumentation, or transport-level tweaks later without touching every
caller.

This factory intentionally stays a thin wrapper — it does **not** own
client lifetime.  Callers either keep the returned client around (lazy
property pattern in long-lived classes) or use it as a context manager
for one-shot requests.
"""

from __future__ import annotations

from typing import Any

import httpx


def create_http_client(
    *,
    timeout: float = 30.0,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
    verify: bool = True,
    **extra: Any,
) -> httpx.Client:
    """Create an `httpx.Client` with project-standard defaults.

    Args:
        timeout: Per-request timeout in seconds.
        headers: Default headers applied to every request.
        follow_redirects: Whether to follow HTTP redirects automatically.
        verify: SSL certificate verification. Disable only for the SSL
            analyzer scanning misconfigured targets.
        **extra: Forwarded verbatim to `httpx.Client`.
    """
    return httpx.Client(
        timeout=timeout,
        headers=headers or {},
        follow_redirects=follow_redirects,
        verify=verify,
        **extra,
    )
