"""Shodan API client for port/service discovery and enrichment.

Shodan provides:
- Host information (ports, banners, vulnerabilities)
- DNS subdomain enumeration
- Search by SSL cert, organization, ASN

Free tier: ~100 queries/month
Docs: https://shodan.readthedocs.io/
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from domainraptor.core.types import Asset, AssetType, Service, SeverityLevel, Vulnerability
from domainraptor.discovery.base import BaseClient, ClientConfig

logger = logging.getLogger(__name__)


class ShodanError(Exception):
    """Base exception for Shodan client errors."""

    pass


class ShodanAPIKeyError(ShodanError):
    """Raised when API key is missing or invalid."""

    pass


class ShodanRateLimitError(ShodanError):
    """Raised when rate limit is exceeded."""

    pass


class ShodanNotFoundError(ShodanError):
    """Raised when host/domain not found in Shodan."""

    pass


@dataclass
class ShodanHostResult:
    """Result from Shodan host lookup."""

    ip: str
    hostnames: list[str] = field(default_factory=list)
    country: str = ""
    city: str = ""
    org: str = ""
    asn: str = ""
    isp: str = ""
    os: str | None = None
    ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    last_update: datetime | None = None
    tags: list[str] = field(default_factory=list)


class ShodanClient(BaseClient[ShodanHostResult]):
    """Client for Shodan API.

    Provides:
    - Host information lookup (ports, services, vulns)
    - DNS subdomain enumeration
    - Reverse DNS lookup

    Example:
        >>> client = ShodanClient(api_key="your-api-key")
        >>> host = client.host_info("8.8.8.8")
        >>> print(f"Ports: {host.ports}")
    """

    name = "shodan"
    is_free = False
    requires_api_key = True

    BASE_URL = "https://api.shodan.io"

    def __init__(
        self,
        api_key: str | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        """Initialize Shodan client.

        Args:
            api_key: Shodan API key. Falls back to SHODAN_API_KEY env var.
            config: Optional client configuration.
        """
        if config is None:
            config = ClientConfig(
                rate_limit=1.0,  # 1 request per second
                timeout=30,
            )

        super().__init__(config)

        # Get API key from parameter, config, or environment
        self.api_key = api_key or config.api_key or os.environ.get("SHODAN_API_KEY")

        if not self.api_key:
            logger.debug("Shodan: No API key configured. Set SHODAN_API_KEY env var.")

    def _check_api_key(self) -> None:
        """Verify API key is set."""
        if not self.api_key:
            raise ShodanAPIKeyError(
                "Shodan API key required. Set SHODAN_API_KEY environment variable "
                "or use 'domainraptor config set SHODAN_API_KEY <key>'"
            )

    def _handle_response_errors(self, response: Any, context: str = "") -> None:
        """Handle common Shodan API errors."""
        import httpx

        if isinstance(response, httpx.Response):
            if response.status_code == 401:
                raise ShodanAPIKeyError("Invalid Shodan API key")
            if response.status_code == 429:
                raise ShodanRateLimitError("Shodan rate limit exceeded. Try again later.")
            if response.status_code == 404:
                raise ShodanNotFoundError(f"Not found in Shodan: {context}")

    def host_info(self, ip: str, history: bool = False) -> ShodanHostResult:
        """Get information about a host from Shodan.

        Args:
            ip: IP address to lookup
            history: Include historical data (paid feature)

        Returns:
            ShodanHostResult with host information
        """
        self._check_api_key()
        logger.info(f"Shodan: Looking up host {ip}")

        params: dict[str, str] = {"key": self.api_key}  # type: ignore[dict-item]
        if history:
            params["history"] = "true"

        url = f"{self.BASE_URL}/shodan/host/{ip}"

        try:
            response = self.get(url, params=params)
            self._handle_response_errors(response, ip)
            data = response.json()
        except ShodanError:
            raise
        except Exception as e:
            logger.error(f"Shodan: Failed to lookup {ip}: {e}")
            raise ShodanError(f"Failed to lookup host {ip}: {e}") from e

        return self._parse_host_result(data)

    def _parse_host_result(self, data: dict[str, Any]) -> ShodanHostResult:
        """Parse Shodan host API response."""
        services: list[Service] = []

        for item in data.get("data", []):
            port = item.get("port", 0)
            transport = item.get("transport", "tcp")

            service = Service(
                port=port,
                protocol=transport,
                service_name=item.get("product", "") or item.get("_shodan", {}).get("module", ""),
                version=item.get("version", "") or "",
                banner=item.get("data", "")[:500] if item.get("data") else "",
                cpe=item.get("cpe", []) or [],
                metadata={
                    "module": item.get("_shodan", {}).get("module", ""),
                    "ssl": bool(item.get("ssl")),
                    "http": item.get("http", {}),
                },
            )
            services.append(service)

        last_update = None
        if data.get("last_update"):
            with contextlib.suppress(ValueError, AttributeError):
                last_update = datetime.fromisoformat(data["last_update"].replace("Z", "+00:00"))

        # Handle vulns - can be dict (older API) or list (newer API)
        raw_vulns = data.get("vulns", [])
        if isinstance(raw_vulns, dict):
            vuln_list = list(raw_vulns.keys())
        elif isinstance(raw_vulns, list):
            vuln_list = raw_vulns
        else:
            vuln_list = []

        return ShodanHostResult(
            ip=data.get("ip_str", ""),
            hostnames=data.get("hostnames", []),
            country=data.get("country_name", "") or data.get("country_code", ""),
            city=data.get("city", "") or "",
            org=data.get("org", "") or "",
            asn=data.get("asn", "") or "",
            isp=data.get("isp", "") or "",
            os=data.get("os"),
            ports=data.get("ports", []),
            services=services,
            vulns=vuln_list,
            last_update=last_update,
            tags=data.get("tags", []),
        )

    def dns_domain(self, domain: str) -> list[Asset]:
        """Get subdomains for a domain from Shodan DNS.

        Args:
            domain: Domain to enumerate subdomains for

        Returns:
            List of subdomain Asset objects
        """
        self._check_api_key()
        logger.info(f"Shodan: Enumerating subdomains for {domain}")

        url = f"{self.BASE_URL}/dns/domain/{domain}"
        params = {"key": self.api_key}

        try:
            response = self.get(url, params=params)
            self._handle_response_errors(response, domain)
            data = response.json()
        except ShodanNotFoundError:
            logger.info(f"Shodan: No DNS data for {domain}")
            return []
        except ShodanError:
            raise
        except Exception as e:
            logger.error(f"Shodan: DNS lookup failed for {domain}: {e}")
            raise ShodanError(f"DNS lookup failed: {e}") from e

        assets: list[Asset] = []
        subdomains = data.get("subdomains", [])

        for sub in subdomains:
            full_domain = f"{sub}.{domain}" if sub != domain else domain
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

        logger.info(f"Shodan: Found {len(assets)} subdomains for {domain}")
        return assets

    def dns_resolve(self, hostnames: list[str]) -> dict[str, str]:
        """Resolve hostnames to IPs using Shodan DNS.

        Args:
            hostnames: List of hostnames to resolve

        Returns:
            Dict mapping hostname to IP
        """
        self._check_api_key()

        if not hostnames:
            return {}

        url = f"{self.BASE_URL}/dns/resolve"
        params = {
            "key": self.api_key,
            "hostnames": ",".join(hostnames[:100]),  # Max 100 per request
        }

        try:
            response = self.get(url, params=params)
            self._handle_response_errors(response)
            return response.json()
        except ShodanError:
            raise
        except Exception as e:
            logger.error(f"Shodan: DNS resolve failed: {e}")
            return {}

    def reverse_dns(self, ips: list[str]) -> dict[str, list[str]]:
        """Reverse DNS lookup for IPs.

        Args:
            ips: List of IP addresses

        Returns:
            Dict mapping IP to list of hostnames
        """
        self._check_api_key()

        if not ips:
            return {}

        url = f"{self.BASE_URL}/dns/reverse"
        params = {
            "key": self.api_key,
            "ips": ",".join(ips[:100]),
        }

        try:
            response = self.get(url, params=params)
            self._handle_response_errors(response)
            return response.json()
        except ShodanError:
            raise
        except Exception as e:
            logger.error(f"Shodan: Reverse DNS failed: {e}")
            return {}

    def get_vulns_for_host(self, ip: str) -> list[Vulnerability]:
        """Get vulnerabilities for a host.

        Args:
            ip: IP address to check

        Returns:
            List of Vulnerability objects
        """
        try:
            host = self.host_info(ip)
        except ShodanNotFoundError:
            return []

        vulns: list[Vulnerability] = []
        for cve_id in host.vulns:
            severity = self._estimate_cve_severity(cve_id)
            vulns.append(
                Vulnerability(
                    id=cve_id,
                    title=f"CVE {cve_id} detected by Shodan",
                    severity=severity,
                    description=f"Vulnerability {cve_id} detected on {ip}",
                    affected_asset=ip,
                    source="shodan",
                    detected_at=datetime.now(),
                )
            )

        return vulns

    def _estimate_cve_severity(self, cve_id: str) -> SeverityLevel:
        """Estimate CVE severity (placeholder - would query NVD for real scores)."""
        # Without NVD lookup, default to MEDIUM
        # In future, could cache CVE scores from NVD
        return SeverityLevel.MEDIUM

    def query_safe(
        self,
        target: str,
        include_vulns: bool = True,
    ) -> tuple[list[Asset], list[Service], list[Vulnerability], list[str]]:
        """Safely query Shodan, returning empty results on error.

        This method never raises exceptions - all errors are captured
        and returned in the errors list.

        Args:
            target: Domain or IP to query
            include_vulns: Whether to extract vulnerabilities

        Returns:
            Tuple of (assets, services, vulnerabilities, errors)
        """
        assets: list[Asset] = []
        services: list[Service] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []

        # Try subdomain enumeration for domains
        if not self._is_ip(target):
            try:
                assets = self.dns_domain(target)
            except ShodanAPIKeyError as e:
                errors.append(f"Shodan: {e}")
                return assets, services, vulns, errors
            except ShodanRateLimitError as e:
                errors.append(f"Shodan: {e}")
            except ShodanError as e:
                errors.append(f"Shodan DNS: {e}")
            except Exception as e:
                errors.append(f"Shodan DNS unexpected error: {e}")

        # Try host lookup for IPs
        if self._is_ip(target):
            try:
                host = self.host_info(target)
                services = host.services

                if include_vulns:
                    vulns.extend(
                        Vulnerability(
                            id=cve_id,
                            title=f"CVE {cve_id}",
                            severity=SeverityLevel.MEDIUM,
                            affected_asset=target,
                            source="shodan",
                        )
                        for cve_id in host.vulns
                    )
            except ShodanAPIKeyError as e:
                if not errors:  # Don't duplicate API key error
                    errors.append(f"Shodan: {e}")
            except ShodanRateLimitError as e:
                errors.append(f"Shodan: {e}")
            except ShodanNotFoundError:
                logger.debug(f"Host {target} not found in Shodan database")
            except ShodanError as e:
                errors.append(f"Shodan host: {e}")
            except Exception as e:
                errors.append(f"Shodan host unexpected error: {e}")

        return assets, services, vulns, errors

    def query(self, target: str) -> list[ShodanHostResult]:
        """Query Shodan for a target (IP or domain).

        For IPs: Returns host information.
        For domains: Returns empty (use dns_domain for subdomain enumeration).

        Args:
            target: IP address or domain

        Returns:
            List containing ShodanHostResult for IPs, empty for domains
        """
        if self._is_ip(target):
            try:
                return [self.host_info(target)]
            except ShodanNotFoundError:
                return []
        # For domains, use dns_domain() separately
        return []

    def search_by_org(self, org: str, limit: int = 100) -> list[ShodanHostResult]:
        """Search Shodan for hosts belonging to an organization.

        Uses Shodan's search API with the org: filter to find all hosts
        associated with a specific organization name.

        Args:
            org: Organization name to search for (e.g., "Google LLC")
            limit: Maximum number of results to return (default: 100)

        Returns:
            List of ShodanHostResult objects for matching hosts
        """
        self._check_api_key()
        logger.info(f"Shodan: Searching for hosts by org '{org}'")

        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": f'org:"{org}"',
        }

        results: list[ShodanHostResult] = []

        try:
            response = self.get(url, params=params)
            self._handle_response_errors(response, f"org:{org}")
            data = response.json()

            for match in data.get("matches", [])[:limit]:
                result = ShodanHostResult(
                    ip=match.get("ip_str", ""),
                    hostnames=match.get("hostnames", []),
                    country=match.get("location", {}).get("country_name", ""),
                    city=match.get("location", {}).get("city", "") or "",
                    org=match.get("org", "") or "",
                    asn=match.get("asn", "") or "",
                    isp=match.get("isp", "") or "",
                    os=match.get("os"),
                    ports=[match.get("port", 0)],
                    services=[],
                    vulns=list(match.get("vulns", {}).keys())
                    if isinstance(match.get("vulns"), dict)
                    else match.get("vulns", []),
                    tags=match.get("tags", []),
                )
                results.append(result)

            logger.info(f"Shodan: Found {len(results)} hosts for org '{org}'")
        except ShodanError:
            raise
        except Exception as e:
            logger.error(f"Shodan: Org search failed for {org}: {e}")
            raise ShodanError(f"Org search failed: {e}") from e

        return results

    def search_by_ssl(self, domain: str, limit: int = 100) -> list[ShodanHostResult]:
        """Search Shodan for hosts with SSL certificates for a domain.

        Uses Shodan's search API with ssl.cert.subject.cn filter to find
        hosts serving SSL certificates for the specified domain.

        Args:
            domain: Domain to search for in SSL certificates
            limit: Maximum number of results to return (default: 100)

        Returns:
            List of ShodanHostResult objects for matching hosts
        """
        self._check_api_key()
        logger.info(f"Shodan: Searching for SSL certs containing '{domain}'")

        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": f'ssl.cert.subject.cn:"{domain}"',
        }

        results: list[ShodanHostResult] = []

        try:
            response = self.get(url, params=params)
            self._handle_response_errors(response, f"ssl:{domain}")
            data = response.json()

            for match in data.get("matches", [])[:limit]:
                result = ShodanHostResult(
                    ip=match.get("ip_str", ""),
                    hostnames=match.get("hostnames", []),
                    country=match.get("location", {}).get("country_name", ""),
                    city=match.get("location", {}).get("city", "") or "",
                    org=match.get("org", "") or "",
                    asn=match.get("asn", "") or "",
                    isp=match.get("isp", "") or "",
                    os=match.get("os"),
                    ports=[match.get("port", 0)],
                    services=[],
                    vulns=list(match.get("vulns", {}).keys())
                    if isinstance(match.get("vulns"), dict)
                    else match.get("vulns", []),
                    tags=match.get("tags", []),
                )
                results.append(result)

            logger.info(f"Shodan: Found {len(results)} hosts with SSL certs for '{domain}'")
        except ShodanError:
            raise
        except Exception as e:
            logger.error(f"Shodan: SSL search failed for {domain}: {e}")
            raise ShodanError(f"SSL search failed: {e}") from e

        return results

    def search_by_asn(self, asn: str, limit: int = 100) -> list[ShodanHostResult]:
        """Search Shodan for hosts in a specific ASN.

        Args:
            asn: Autonomous System Number (e.g., "AS15169" or "15169")
            limit: Maximum number of results to return (default: 100)

        Returns:
            List of ShodanHostResult objects for matching hosts
        """
        self._check_api_key()
        # Normalize ASN format
        asn_normalized = asn.upper() if asn.upper().startswith("AS") else f"AS{asn}"
        logger.info(f"Shodan: Searching for hosts in {asn_normalized}")

        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": f"asn:{asn_normalized}",
        }

        results: list[ShodanHostResult] = []

        try:
            response = self.get(url, params=params)
            self._handle_response_errors(response, f"asn:{asn_normalized}")
            data = response.json()

            for match in data.get("matches", [])[:limit]:
                result = ShodanHostResult(
                    ip=match.get("ip_str", ""),
                    hostnames=match.get("hostnames", []),
                    country=match.get("location", {}).get("country_name", ""),
                    city=match.get("location", {}).get("city", "") or "",
                    org=match.get("org", "") or "",
                    asn=match.get("asn", "") or "",
                    isp=match.get("isp", "") or "",
                    os=match.get("os"),
                    ports=[match.get("port", 0)],
                    services=[],
                    vulns=list(match.get("vulns", {}).keys())
                    if isinstance(match.get("vulns"), dict)
                    else match.get("vulns", []),
                    tags=match.get("tags", []),
                )
                results.append(result)

            logger.info(f"Shodan: Found {len(results)} hosts in {asn_normalized}")
        except ShodanError:
            raise
        except Exception as e:
            logger.error(f"Shodan: ASN search failed for {asn_normalized}: {e}")
            raise ShodanError(f"ASN search failed: {e}") from e

        return results

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Check if target is a valid IP address.

        Validates IPv4 addresses with proper octet range (0-255).
        """
        if not target:
            return False

        # IPv4 validation with proper range check
        ipv4_pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        match = re.match(ipv4_pattern, target)
        if match:
            # Validate each octet is 0-255
            return all(0 <= int(octet) <= 255 for octet in match.groups())

        # IPv6 validation (simplified - full addresses)
        ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
        return bool(re.match(ipv6_pattern, target))
