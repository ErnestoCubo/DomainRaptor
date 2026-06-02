"""Unified exception hierarchy for DomainRaptor data sources.

All source clients (discovery, enrichment, exploitation) should raise these
exceptions instead of defining per-source hierarchies. Per-source aliases
(e.g. ``ShodanAPIKeyError = SourceAPIKeyError``) are kept inside each client
module for backward compatibility.
"""

from __future__ import annotations


class SourceError(Exception):
    """Base exception for any data-source error.

    Attributes:
        source: Short identifier of the source (e.g. ``"shodan"``).
    """

    source: str = "unknown"

    def __init__(self, message: str = "", *, source: str | None = None) -> None:
        super().__init__(message)
        if source is not None:
            self.source = source


class SourceAPIKeyError(SourceError):
    """API key is missing, malformed, or rejected by the provider."""


class SourceRateLimitError(SourceError):
    """Provider returned a rate-limit response (HTTP 429 or equivalent)."""


class SourceQuotaExceededError(SourceError):
    """Account quota (daily/monthly) has been exhausted."""


class SourceNotFoundError(SourceError):
    """Requested resource (host, domain, CVE…) was not found upstream."""


__all__ = [
    "SourceAPIKeyError",
    "SourceError",
    "SourceNotFoundError",
    "SourceQuotaExceededError",
    "SourceRateLimitError",
]
