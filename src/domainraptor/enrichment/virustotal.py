"""VirusTotal API client for reputation and threat intelligence.

VirusTotal provides:
- Domain/IP reputation scores
- Malware detection results
- Passive DNS data
- Subdomain enumeration

Free tier limits (API v3):
- Standard: 500 requests/day, 4 requests/min
- Basic: 1 lookup/min, 1 lookup/day, 31 lookups/month

This client defaults to basic tier limits for safety.
To use standard tier, set VT_RATE_LIMIT_TIER=standard.

Docs: https://developers.virustotal.com/reference
"""

from __future__ import annotations

import contextlib
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from domainraptor.core.types import Asset, AssetType
from domainraptor.discovery.base import BaseClient, ClientConfig

logger = logging.getLogger(__name__)


class VirusTotalError(Exception):
    """Base exception for VirusTotal client errors."""

    pass


class VirusTotalAPIKeyError(VirusTotalError):
    """Raised when API key is missing or invalid."""

    pass


class VirusTotalRateLimitError(VirusTotalError):
    """Raised when rate limit is exceeded."""

    pass


class VirusTotalQuotaExceededError(VirusTotalError):
    """Raised when daily quota is exceeded."""

    pass


class VirusTotalNotFoundError(VirusTotalError):
    """Raised when resource not found."""

    pass


@dataclass
class ReputationResult:
    """Result from VirusTotal reputation lookup."""

    resource: str  # Domain or IP
    resource_type: str  # "domain" or "ip"
    malicious: int = 0  # Engines detecting as malicious
    suspicious: int = 0  # Engines detecting as suspicious
    harmless: int = 0  # Engines detecting as harmless
    undetected: int = 0  # Engines with no detection
    total_engines: int = 0
    reputation_score: int = 0  # VT community score
    last_analysis_date: datetime | None = None
    categories: dict[str, str] = field(default_factory=dict)  # Engine -> category
    tags: list[str] = field(default_factory=list)
    whois: str = ""
    registrar: str = ""
    as_owner: str = ""
    country: str = ""
    last_dns_records: list[dict[str, Any]] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        """Check if resource is considered malicious (2+ detections)."""
        return self.malicious >= 2

    @property
    def is_suspicious(self) -> bool:
        """Check if resource is suspicious (1+ malicious or 3+ suspicious)."""
        return self.malicious >= 1 or self.suspicious >= 3

    @property
    def detection_ratio(self) -> str:
        """Human-readable detection ratio."""
        if self.total_engines == 0:
            return "0/0"
        return f"{self.malicious}/{self.total_engines}"


class VirusTotalClient(BaseClient[ReputationResult]):
    """Client for VirusTotal v3 API.

    Provides:
    - Domain/IP reputation lookups
    - Subdomain enumeration
    - DNS records
    - Threat intelligence

    Example:
        >>> client = VirusTotalClient(api_key="your-api-key")
        >>> rep = client.get_domain_report("example.com")
        >>> print(f"Malicious: {rep.is_malicious} ({rep.detection_ratio})")
    """

    name = "virustotal"
    is_free = True  # Has free tier
    requires_api_key = True

    BASE_URL = "https://www.virustotal.com/api/v3"

    # Rate limiting constants
    # Basic tier: 1 request/min (60 seconds between requests)
    # Standard tier: 4 requests/min (15 seconds between requests)
    RATE_LIMIT_BASIC = 60.0  # 60 seconds for basic tier
    RATE_LIMIT_STANDARD = 15.0  # 15 seconds for standard tier

    # Daily quotas
    DAILY_QUOTA_BASIC = 1  # Basic tier: 1/day
    DAILY_QUOTA_STANDARD = 500  # Standard tier: 500/day

    def __init__(
        self,
        api_key: str | None = None,
        config: ClientConfig | None = None,
        rate_limit_tier: str | None = None,
    ) -> None:
        """Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key. Falls back to VIRUSTOTAL_API_KEY env var.
            config: Optional client configuration.
            rate_limit_tier: Rate limit tier - "basic" (most restrictive)
                           or "standard" (500 req/day, 4 req/min).
                           Defaults to VT_RATE_LIMIT_TIER env var or "basic".
        """
        # Get tier: explicit parameter > env var > default "basic"
        if rate_limit_tier is not None:
            tier = rate_limit_tier.lower()
        else:
            tier = os.environ.get("VT_RATE_LIMIT_TIER", "basic").lower()
        self._tier = tier if tier in ("basic", "standard") else "basic"

        # Set rate limit based on tier
        min_interval = (
            self.RATE_LIMIT_STANDARD if self._tier == "standard" else self.RATE_LIMIT_BASIC
        )

        if config is None:
            config = ClientConfig(
                rate_limit=1.0 / min_interval,  # Convert to requests per second
                timeout=30,
            )

        super().__init__(config)

        self.api_key = api_key or config.api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self._last_request_time: float = 0
        self._min_request_interval = min_interval

        if not self.api_key:
            logger.debug("VirusTotal: No API key configured. Set VIRUSTOTAL_API_KEY env var.")

        logger.debug(f"VirusTotal: Using {self._tier} tier rate limits ({min_interval}s interval)")

    def _check_api_key(self) -> None:
        """Verify API key is set."""
        if not self.api_key:
            raise VirusTotalAPIKeyError(
                "VirusTotal API key required. Set VIRUSTOTAL_API_KEY environment variable "
                "or use 'domainraptor config set VIRUSTOTAL_API_KEY <key>'"
            )

    def query(self, target: str) -> list[ReputationResult]:
        """Query VirusTotal for information about a target.

        Implements the BaseClient abstract method.

        Args:
            target: Domain or IP address to query

        Returns:
            List containing the ReputationResult (always single item)
        """
        if self._is_ip(target):
            result = self.get_ip_report(target)
        else:
            result = self.get_domain_report(target)
        return [result]

    def _rate_limit(self) -> None:
        """Enforce rate limiting based on tier.

        Basic tier: 60 seconds between requests (1/min)
        Standard tier: 15 seconds between requests (4/min)
        """
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            sleep_time = self._min_request_interval - elapsed
            logger.debug(f"VirusTotal: Rate limiting ({self._tier}), sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _get_headers(self) -> dict[str, str]:
        """Get API request headers."""
        return {
            "x-apikey": self.api_key or "",
            "Accept": "application/json",
        }

    def _handle_response_errors(self, response: Any, context: str = "") -> None:
        """Handle common VirusTotal API errors."""
        import httpx

        if isinstance(response, httpx.Response):
            if response.status_code == 401:
                raise VirusTotalAPIKeyError("Invalid VirusTotal API key")
            if response.status_code == 429:
                error_data = response.json().get("error", {})
                code = error_data.get("code", "")
                if code == "QuotaExceededError":
                    raise VirusTotalQuotaExceededError(
                        "VirusTotal daily quota exceeded. Try again tomorrow."
                    )
                raise VirusTotalRateLimitError("VirusTotal rate limit exceeded. Waiting...")
            if response.status_code == 404:
                raise VirusTotalNotFoundError(f"Not found in VirusTotal: {context}")

    def get_domain_report(self, domain: str) -> ReputationResult:
        """Get reputation report for a domain.

        Args:
            domain: Domain to lookup

        Returns:
            ReputationResult with reputation data
        """
        self._check_api_key()
        self._rate_limit()

        logger.info(f"VirusTotal: Looking up domain {domain}")

        url = f"{self.BASE_URL}/domains/{domain}"

        try:
            response = self.get(url, headers=self._get_headers())
            self._handle_response_errors(response, domain)
            data = response.json()
        except VirusTotalError:
            raise
        except Exception as e:
            logger.error(f"VirusTotal: Failed to lookup {domain}: {e}")
            raise VirusTotalError(f"Failed to lookup domain {domain}: {e}") from e

        return self._parse_domain_result(data, domain)

    def _parse_domain_result(self, data: dict[str, Any], domain: str) -> ReputationResult:
        """Parse VirusTotal domain API response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        last_analysis = None
        if attrs.get("last_analysis_date"):
            with contextlib.suppress(ValueError, TypeError):
                last_analysis = datetime.fromtimestamp(attrs["last_analysis_date"])

        return ReputationResult(
            resource=domain,
            resource_type="domain",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_engines=sum(stats.values()) if stats else 0,
            reputation_score=attrs.get("reputation", 0),
            last_analysis_date=last_analysis,
            categories=attrs.get("categories", {}),
            tags=attrs.get("tags", []),
            whois=attrs.get("whois", ""),
            registrar=attrs.get("registrar", ""),
            last_dns_records=attrs.get("last_dns_records", []),
        )

    def get_ip_report(self, ip: str) -> ReputationResult:
        """Get reputation report for an IP address.

        Args:
            ip: IP address to lookup

        Returns:
            ReputationResult with reputation data
        """
        self._check_api_key()
        self._rate_limit()

        logger.info(f"VirusTotal: Looking up IP {ip}")

        url = f"{self.BASE_URL}/ip_addresses/{ip}"

        try:
            response = self.get(url, headers=self._get_headers())
            self._handle_response_errors(response, ip)
            data = response.json()
        except VirusTotalError:
            raise
        except Exception as e:
            logger.error(f"VirusTotal: Failed to lookup {ip}: {e}")
            raise VirusTotalError(f"Failed to lookup IP {ip}: {e}") from e

        return self._parse_ip_result(data, ip)

    def _parse_ip_result(self, data: dict[str, Any], ip: str) -> ReputationResult:
        """Parse VirusTotal IP API response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        last_analysis = None
        if attrs.get("last_analysis_date"):
            with contextlib.suppress(ValueError, TypeError):
                last_analysis = datetime.fromtimestamp(attrs["last_analysis_date"])

        return ReputationResult(
            resource=ip,
            resource_type="ip",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_engines=sum(stats.values()) if stats else 0,
            reputation_score=attrs.get("reputation", 0),
            last_analysis_date=last_analysis,
            tags=attrs.get("tags", []),
            as_owner=attrs.get("as_owner", ""),
            country=attrs.get("country", ""),
        )

    def get_subdomains(self, domain: str, limit: int = 100) -> list[Asset]:
        """Get subdomains for a domain from VirusTotal.

        Args:
            domain: Domain to enumerate subdomains for
            limit: Maximum number of subdomains to return

        Returns:
            List of subdomain Asset objects
        """
        self._check_api_key()
        self._rate_limit()

        logger.info(f"VirusTotal: Enumerating subdomains for {domain}")

        url = f"{self.BASE_URL}/domains/{domain}/subdomains"
        params = {"limit": min(limit, 40)}  # VT max is 40 per request

        try:
            response = self.get(url, headers=self._get_headers(), params=params)
            self._handle_response_errors(response, domain)
            data = response.json()
        except VirusTotalNotFoundError:
            logger.info(f"VirusTotal: No subdomains found for {domain}")
            return []
        except VirusTotalError:
            raise
        except Exception as e:
            logger.error(f"VirusTotal: Subdomain enumeration failed for {domain}: {e}")
            raise VirusTotalError(f"Subdomain enumeration failed: {e}") from e

        assets: list[Asset] = []
        for item in data.get("data", []):
            subdomain = item.get("id", "")
            if subdomain:
                assets.append(
                    Asset(
                        type=AssetType.SUBDOMAIN,
                        value=subdomain,
                        parent=domain,
                        source=self.name,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                    )
                )

        logger.info(f"VirusTotal: Found {len(assets)} subdomains for {domain}")
        return assets

    def get_dns_records(self, domain: str) -> list[dict[str, Any]]:
        """Get DNS records for a domain from VirusTotal's passive DNS.

        Args:
            domain: Domain to get DNS records for

        Returns:
            List of DNS record dictionaries
        """
        try:
            report = self.get_domain_report(domain)
            return report.last_dns_records
        except VirusTotalError:
            return []

    def query_safe(
        self,
        target: str,
        include_subdomains: bool = True,
    ) -> tuple[ReputationResult | None, list[Asset], list[str]]:
        """Safely query VirusTotal, returning None on error.

        This method never raises exceptions - all errors are captured
        and returned in the errors list.

        Args:
            target: Domain or IP to query
            include_subdomains: Whether to enumerate subdomains (for domains)

        Returns:
            Tuple of (reputation_result, subdomains, errors)
        """
        reputation: ReputationResult | None = None
        subdomains: list[Asset] = []
        errors: list[str] = []

        # Get reputation
        try:
            if self._is_ip(target):
                reputation = self.get_ip_report(target)
            else:
                reputation = self.get_domain_report(target)
        except VirusTotalAPIKeyError as e:
            errors.append(f"VirusTotal: {e}")
            return None, [], errors
        except VirusTotalQuotaExceededError as e:
            errors.append(f"VirusTotal: {e}")
            return None, [], errors
        except VirusTotalRateLimitError as e:
            errors.append(f"VirusTotal: {e}")
        except VirusTotalNotFoundError:
            logger.debug(f"Target {target} not found in VirusTotal")
        except VirusTotalError as e:
            errors.append(f"VirusTotal: {e}")
        except Exception as e:
            errors.append(f"VirusTotal unexpected error: {e}")

        # Get subdomains for domains
        if include_subdomains and not self._is_ip(target):
            try:
                subdomains = self.get_subdomains(target)
            except VirusTotalAPIKeyError:
                logger.debug("Skipping subdomains - API key error already reported")
            except VirusTotalQuotaExceededError:
                logger.debug("Skipping subdomains - quota exceeded already reported")
            except VirusTotalRateLimitError as e:
                errors.append(f"VirusTotal subdomains: {e}")
            except VirusTotalError as e:
                errors.append(f"VirusTotal subdomains: {e}")
            except Exception as e:
                errors.append(f"VirusTotal subdomains unexpected error: {e}")

        return reputation, subdomains, errors

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Check if target is a valid IP address.

        Validates IPv4 addresses with proper octet range (0-255).
        """
        import re

        if not target:
            return False

        ipv4_pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        match = re.match(ipv4_pattern, target)
        if match:
            # Validate each octet is 0-255
            return all(0 <= int(octet) <= 255 for octet in match.groups())
        return False
