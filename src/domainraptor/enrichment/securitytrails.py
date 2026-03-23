"""SecurityTrails API client for DNS intelligence and historical data.

SecurityTrails provides:
- Domain information (DNS, WHOIS)
- Subdomain enumeration
- Historical DNS records
- IP neighbors (domains on same IP)
- Associated domains

Free tier: 50 queries/month
Docs: https://docs.securitytrails.com/reference
"""

from __future__ import annotations

import contextlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from domainraptor.core.types import Asset, AssetType
from domainraptor.discovery.base import BaseClient, ClientConfig

logger = logging.getLogger(__name__)


class SecurityTrailsError(Exception):
    """Base exception for SecurityTrails client errors."""

    pass


class SecurityTrailsAPIKeyError(SecurityTrailsError):
    """Raised when API key is missing or invalid."""

    pass


class SecurityTrailsRateLimitError(SecurityTrailsError):
    """Raised when rate limit is exceeded."""

    pass


class SecurityTrailsQuotaExceededError(SecurityTrailsError):
    """Raised when monthly quota is exceeded."""

    pass


class SecurityTrailsNotFoundError(SecurityTrailsError):
    """Raised when domain not found."""

    pass


@dataclass
class HistoricalDnsRecord:
    """Historical DNS record from SecurityTrails."""

    record_type: str  # A, AAAA, MX, NS, etc.
    values: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    organizations: list[str] = field(default_factory=list)


@dataclass
class DomainInfo:
    """Domain information from SecurityTrails."""

    domain: str
    alexa_rank: int | None = None
    apex_domain: str = ""
    current_dns: dict[str, list[str]] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    subdomain_count: int = 0
    historical_dns: dict[str, list[HistoricalDnsRecord]] = field(default_factory=dict)


class SecurityTrailsClient(BaseClient[DomainInfo]):
    """Client for SecurityTrails API.

    Provides:
    - Domain information lookup
    - Subdomain enumeration
    - Historical DNS data
    - IP neighbors

    Example:
        >>> client = SecurityTrailsClient(api_key="your-api-key")
        >>> info = client.get_domain("example.com")
        >>> print(f"Subdomains: {info.subdomain_count}")
    """

    name = "securitytrails"
    is_free = True  # Has free tier
    requires_api_key = True

    BASE_URL = "https://api.securitytrails.com/v1"

    def __init__(
        self,
        api_key: str | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        """Initialize SecurityTrails client.

        Args:
            api_key: SecurityTrails API key. Falls back to SECURITYTRAILS_API_KEY env var.
            config: Optional client configuration.
        """
        if config is None:
            config = ClientConfig(
                rate_limit=2.0,  # 2 requests per second max
                timeout=30,
            )

        super().__init__(config)

        self.api_key = api_key or config.api_key or os.environ.get("SECURITYTRAILS_API_KEY")

        if not self.api_key:
            logger.debug(
                "SecurityTrails: No API key configured. Set SECURITYTRAILS_API_KEY env var."
            )

    def _check_api_key(self) -> None:
        """Verify API key is set."""
        if not self.api_key:
            raise SecurityTrailsAPIKeyError(
                "SecurityTrails API key required. Set SECURITYTRAILS_API_KEY environment "
                "variable or use 'domainraptor config set SECURITYTRAILS_API_KEY <key>'"
            )

    def query(self, target: str) -> list[DomainInfo]:
        """Query SecurityTrails for information about a target.

        Implements the BaseClient abstract method.

        Args:
            target: Domain to query (IPs are not supported)

        Returns:
            List containing the DomainInfo (always single item)
        """
        if self._is_ip(target):
            return []
        result = self.get_domain(target)
        return [result]

    def _get_headers(self) -> dict[str, str]:
        """Get API request headers."""
        return {
            "APIKEY": self.api_key or "",
            "Accept": "application/json",
        }

    def _handle_response_errors(self, response: Any, context: str = "") -> None:
        """Handle common SecurityTrails API errors."""
        import httpx

        if isinstance(response, httpx.Response):
            if response.status_code == 401:
                raise SecurityTrailsAPIKeyError("Invalid SecurityTrails API key")
            if response.status_code == 403:
                try:
                    error_msg = response.json().get("message", "")
                    if "quota" in error_msg.lower():
                        raise SecurityTrailsQuotaExceededError(
                            "SecurityTrails monthly quota exceeded."
                        )
                except (ValueError, KeyError):
                    logger.debug("Could not parse error message from SecurityTrails response")
                raise SecurityTrailsAPIKeyError(
                    "SecurityTrails access denied. Check API key permissions."
                )
            if response.status_code == 429:
                raise SecurityTrailsRateLimitError(
                    "SecurityTrails rate limit exceeded. Try again later."
                )
            if response.status_code == 404:
                raise SecurityTrailsNotFoundError(f"Domain not found in SecurityTrails: {context}")

    def get_domain(self, domain: str) -> DomainInfo:
        """Get information about a domain.

        Args:
            domain: Domain to lookup

        Returns:
            DomainInfo with domain data
        """
        self._check_api_key()
        logger.info(f"SecurityTrails: Looking up domain {domain}")

        url = f"{self.BASE_URL}/domain/{domain}"

        try:
            response = self.get(url, headers=self._get_headers())
            self._handle_response_errors(response, domain)
            data = response.json()
        except SecurityTrailsError:
            raise
        except Exception as e:
            logger.error(f"SecurityTrails: Failed to lookup {domain}: {e}")
            raise SecurityTrailsError(f"Failed to lookup domain {domain}: {e}") from e

        return self._parse_domain_result(data, domain)

    def _parse_domain_result(self, data: dict[str, Any], domain: str) -> DomainInfo:
        """Parse SecurityTrails domain API response."""
        current_dns: dict[str, list[str]] = {}

        # Parse current DNS records
        dns_data = data.get("current_dns", {})
        for record_type in ["a", "aaaa", "mx", "ns", "soa", "txt"]:
            records = dns_data.get(record_type, {})
            values = records.get("values", [])
            if values:
                # Extract IP/value from nested structure
                extracted = []
                for v in values:
                    if isinstance(v, dict):
                        extracted.append(v.get("ip", v.get("value", str(v))))
                    else:
                        extracted.append(str(v))
                current_dns[record_type.upper()] = extracted

        return DomainInfo(
            domain=domain,
            alexa_rank=data.get("alexa_rank"),
            apex_domain=data.get("apex_domain", domain),
            current_dns=current_dns,
            subdomain_count=data.get("subdomain_count", 0),
        )

    def get_subdomains(self, domain: str) -> list[Asset]:
        """Get subdomains for a domain.

        Args:
            domain: Domain to enumerate subdomains for

        Returns:
            List of subdomain Asset objects
        """
        self._check_api_key()
        logger.info(f"SecurityTrails: Enumerating subdomains for {domain}")

        url = f"{self.BASE_URL}/domain/{domain}/subdomains"
        params = {"children_only": "false", "include_inactive": "true"}

        try:
            response = self.get(url, headers=self._get_headers(), params=params)
            self._handle_response_errors(response, domain)
            data = response.json()
        except SecurityTrailsNotFoundError:
            logger.info(f"SecurityTrails: No subdomains found for {domain}")
            return []
        except SecurityTrailsError:
            raise
        except Exception as e:
            logger.error(f"SecurityTrails: Subdomain enumeration failed for {domain}: {e}")
            raise SecurityTrailsError(f"Subdomain enumeration failed: {e}") from e

        assets: list[Asset] = []
        subdomains = data.get("subdomains", [])

        for sub in subdomains:
            full_domain = f"{sub}.{domain}"
            assets.append(
                Asset(
                    type=AssetType.SUBDOMAIN,
                    value=full_domain,
                    parent=domain,
                    source=self.name,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                )
            )

        logger.info(f"SecurityTrails: Found {len(assets)} subdomains for {domain}")
        return assets

    def get_dns_history(self, domain: str, record_type: str = "a") -> list[HistoricalDnsRecord]:
        """Get historical DNS records for a domain.

        Args:
            domain: Domain to get history for
            record_type: Record type (a, aaaa, mx, ns, soa, txt)

        Returns:
            List of HistoricalDnsRecord objects
        """
        self._check_api_key()
        logger.info(f"SecurityTrails: Getting DNS history for {domain} ({record_type})")

        url = f"{self.BASE_URL}/history/{domain}/dns/{record_type.lower()}"

        try:
            response = self.get(url, headers=self._get_headers())
            self._handle_response_errors(response, domain)
            data = response.json()
        except SecurityTrailsNotFoundError:
            return []
        except SecurityTrailsError:
            raise
        except Exception as e:
            logger.error(f"SecurityTrails: DNS history failed for {domain}: {e}")
            raise SecurityTrailsError(f"DNS history lookup failed: {e}") from e

        return self._parse_dns_history(data, record_type)

    def _parse_dns_history(
        self, data: dict[str, Any], record_type: str
    ) -> list[HistoricalDnsRecord]:
        """Parse SecurityTrails DNS history response."""
        records: list[HistoricalDnsRecord] = []

        for item in data.get("records", []):
            values = item.get("values", [])
            extracted_values = []
            organizations = []

            for v in values:
                if isinstance(v, dict):
                    extracted_values.append(v.get("ip", v.get("value", str(v))))
                    if v.get("ip_organization"):
                        organizations.append(v["ip_organization"])
                else:
                    extracted_values.append(str(v))

            first_seen = None
            last_seen = None
            if item.get("first_seen"):
                with contextlib.suppress(ValueError, TypeError):
                    first_seen = datetime.strptime(item["first_seen"], "%Y-%m-%d")
            if item.get("last_seen"):
                with contextlib.suppress(ValueError, TypeError):
                    last_seen = datetime.strptime(item["last_seen"], "%Y-%m-%d")

            records.append(
                HistoricalDnsRecord(
                    record_type=record_type.upper(),
                    values=extracted_values,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    organizations=list(set(organizations)),
                )
            )

        return records

    def get_associated_domains(self, domain: str) -> list[str]:
        """Get domains associated with the same organization/registrant.

        Args:
            domain: Domain to find associations for

        Returns:
            List of associated domain names
        """
        self._check_api_key()
        logger.info(f"SecurityTrails: Finding associated domains for {domain}")

        url = f"{self.BASE_URL}/domain/{domain}/associated"

        try:
            response = self.get(url, headers=self._get_headers())
            self._handle_response_errors(response, domain)
            data = response.json()
        except SecurityTrailsNotFoundError:
            return []
        except SecurityTrailsError:
            raise
        except Exception as e:
            logger.error(f"SecurityTrails: Associated domains failed for {domain}: {e}")
            return []

        records = data.get("records", [])
        return [r.get("hostname", "") for r in records if r.get("hostname")]

    def get_ip_neighbors(self, ip: str) -> list[str]:
        """Get domains hosted on the same IP.

        Args:
            ip: IP address to check

        Returns:
            List of domain names on the same IP
        """
        self._check_api_key()
        logger.info(f"SecurityTrails: Finding IP neighbors for {ip}")

        url = f"{self.BASE_URL}/ips/nearby/{ip}"

        try:
            response = self.get(url, headers=self._get_headers())
            self._handle_response_errors(response, ip)
            data = response.json()
        except SecurityTrailsNotFoundError:
            return []
        except SecurityTrailsError:
            raise
        except Exception as e:
            logger.error(f"SecurityTrails: IP neighbors failed for {ip}: {e}")
            return []

        blocks = data.get("blocks", [])
        domains: list[str] = []
        for block in blocks:
            domains.extend(site for site in block.get("sites", []) if site)

        return domains

    def query_safe(
        self,
        target: str,
        include_history: bool = False,
    ) -> tuple[DomainInfo | None, list[Asset], list[str]]:
        """Safely query SecurityTrails, returning None on error.

        This method never raises exceptions - all errors are captured
        and returned in the errors list.

        Args:
            target: Domain to query (IPs not supported)
            include_history: Whether to fetch historical DNS data

        Returns:
            Tuple of (domain_info, subdomains, errors)
        """
        domain_info: DomainInfo | None = None
        subdomains: list[Asset] = []
        errors: list[str] = []

        # SecurityTrails is domain-focused, skip IPs
        if self._is_ip(target):
            return None, [], []

        # Get domain info
        try:
            domain_info = self.get_domain(target)
        except SecurityTrailsAPIKeyError as e:
            errors.append(f"SecurityTrails: {e}")
            return None, [], errors
        except SecurityTrailsQuotaExceededError as e:
            errors.append(f"SecurityTrails: {e}")
            return None, [], errors
        except SecurityTrailsRateLimitError as e:
            errors.append(f"SecurityTrails: {e}")
        except SecurityTrailsNotFoundError:
            logger.debug(f"Domain {target} not found in SecurityTrails")
        except SecurityTrailsError as e:
            errors.append(f"SecurityTrails: {e}")
        except Exception as e:
            errors.append(f"SecurityTrails unexpected error: {e}")

        # Get subdomains
        try:
            subdomains = self.get_subdomains(target)
        except SecurityTrailsAPIKeyError:
            logger.debug("Skipping subdomains - API key error already reported")
        except SecurityTrailsQuotaExceededError:
            logger.debug("Skipping subdomains - quota exceeded already reported")
        except SecurityTrailsRateLimitError as e:
            errors.append(f"SecurityTrails subdomains: {e}")
        except SecurityTrailsError as e:
            errors.append(f"SecurityTrails subdomains: {e}")
        except Exception as e:
            errors.append(f"SecurityTrails subdomains unexpected error: {e}")

        # Optionally get historical DNS
        if include_history and domain_info:
            history: dict[str, list[HistoricalDnsRecord]] = {}
            for record_type in ["a", "aaaa", "mx", "ns"]:
                try:
                    hist = self.get_dns_history(target, record_type)
                    if hist:
                        history[record_type.upper()] = hist
                except SecurityTrailsError as e:  # noqa: PERF203
                    errors.append(f"SecurityTrails history ({record_type}): {e}")
                except Exception as e:
                    errors.append(f"SecurityTrails history unexpected: {e}")

            domain_info.historical_dns = history

        return domain_info, subdomains, errors

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
