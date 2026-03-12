"""Base classes for security assessment clients."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Generic, TypeVar

import httpx

from domainraptor.core.types import ConfigIssue, SeverityLevel, Vulnerability

logger = logging.getLogger(__name__)

T = TypeVar("T", Vulnerability, ConfigIssue)


@dataclass
class AssessmentConfig:
    """Configuration for assessment clients."""

    timeout: int = 30
    verify_ssl: bool = True
    follow_redirects: bool = True
    user_agent: str = "DomainRaptor/1.0"


class BaseAssessmentClient(ABC, Generic[T]):
    """Abstract base class for security assessment clients."""

    name: str = "base"

    def __init__(self, config: AssessmentConfig | None = None) -> None:
        self.config = config or AssessmentConfig()
        self._http_client: httpx.Client | None = None

    @property
    def http_client(self) -> httpx.Client:
        """Lazy-initialized HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.Client(
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                follow_redirects=self.config.follow_redirects,
                headers={"User-Agent": self.config.user_agent},
            )
        return self._http_client

    def close(self) -> None:
        """Close HTTP client."""
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None

    def __enter__(self) -> BaseAssessmentClient[T]:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @abstractmethod
    def assess(self, target: str) -> list[T]:
        """Perform assessment on target."""
        ...

    def assess_safe(self, target: str) -> list[T]:
        """Assess with error handling, returns empty list on failure."""
        try:
            return self.assess(target)
        except Exception as e:
            logger.error(f"{self.name}: Assessment failed for {target}: {e}")
            return []


class VulnerabilityScanner(BaseAssessmentClient[Vulnerability]):
    """Base class for vulnerability scanners."""

    @abstractmethod
    def assess(self, target: str) -> list[Vulnerability]:
        """Scan target for vulnerabilities."""
        ...


class ConfigurationChecker(BaseAssessmentClient[ConfigIssue]):
    """Base class for configuration checkers."""

    category: str = "general"

    @abstractmethod
    def assess(self, target: str) -> list[ConfigIssue]:
        """Check target for configuration issues."""
        ...


# Severity mapping helpers
SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 4,
    SeverityLevel.HIGH: 3,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 1,
    SeverityLevel.INFO: 0,
}


def filter_by_min_severity(
    items: list[T],
    min_severity: SeverityLevel,
) -> list[T]:
    """Filter items by minimum severity level."""
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    return [
        item
        for item in items
        if SEVERITY_ORDER.get(item.severity, 0) >= min_level
    ]


def sort_by_severity(items: list[T], reverse: bool = True) -> list[T]:
    """Sort items by severity (highest first by default)."""
    return sorted(
        items,
        key=lambda x: SEVERITY_ORDER.get(x.severity, 0),
        reverse=reverse,
    )
