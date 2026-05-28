"""ZoomEye API client for host and service discovery.

ZoomEye is a search engine for cyberspace (Chinese alternative to Shodan).
Provides:
- Host/IP information lookup
- Web application discovery
- Subdomain enumeration
- Vulnerability information

Free tier: 10,000 credits/month (1 credit per query)
Docs: https://www.zoomeye.org/doc
"""

from __future__ import annotations

import contextlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from domainraptor.core.types import Asset, AssetType, Service
from domainraptor.discovery.base import BaseClient, ClientConfig

logger = logging.getLogger(__name__)


class ZoomEyeError(Exception):
    """Base exception for ZoomEye client errors."""

    pass


class ZoomEyeAPIKeyError(ZoomEyeError):
    """Raised when API key is missing or invalid."""

    pass


class ZoomEyeRateLimitError(ZoomEyeError):
    """Raised when rate limit is exceeded."""

    pass


class ZoomEyeNotFoundError(ZoomEyeError):
    """Raised when host/domain not found."""

    pass


@dataclass
class ZoomEyeHostResult:
    """Result from ZoomEye host lookup."""

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
    device_type: str = ""
    banner: str = ""


class ZoomEyeClient(BaseClient[ZoomEyeHostResult]):
    """Client for ZoomEye API.

    ZoomEye provides two types of searches:
    - /host/search: Search for devices and hosts
    - /web/search: Search for web applications

    Example:
        >>> client = ZoomEyeClient(api_key="your-api-key")
        >>> results = client.search_host("port:22")
        >>> print(f"Found {len(results)} hosts")
    """

    name = "zoomeye"
    is_free = False
    requires_api_key = True

    # Use api.zoomeye.ai for international access (api.zoomeye.org is China-only)
    BASE_URL = "https://api.zoomeye.ai"

    def __init__(
        self,
        api_key: str | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        """Initialize ZoomEye client.

        Args:
            api_key: ZoomEye API key. Falls back to ZOOMEYE_API_KEY env var.
            config: Optional client configuration.
        """
        if config is None:
            config = ClientConfig(
                rate_limit=1.0,  # 1 request per second
                timeout=30,
            )

        super().__init__(config)

        # Get API key from parameter, config, or environment
        self.api_key = api_key or config.api_key or os.environ.get("ZOOMEYE_API_KEY")

        if not self.api_key:
            logger.debug("ZoomEye: No API key configured. Set ZOOMEYE_API_KEY env var.")

    def _check_api_key(self) -> None:
        """Verify API key is set."""
        if not self.api_key:
            raise ZoomEyeAPIKeyError(
                "ZoomEye API key required. Set ZOOMEYE_API_KEY environment variable "
                "or use 'domainraptor config set ZOOMEYE_API_KEY <key>'"
            )

    def _get_headers(self) -> dict[str, str]:
        """Get headers with API key."""
        return {
            "API-KEY": self.api_key or "",
            "Content-Type": "application/json",
        }

    def _handle_response_errors(self, response: Any, context: str = "") -> None:
        """Handle common ZoomEye API errors."""
        import httpx

        if isinstance(response, httpx.Response):
            if response.status_code == 401:
                raise ZoomEyeAPIKeyError("Invalid ZoomEye API key")
            if response.status_code == 402:
                raise ZoomEyeError(
                    "ZoomEye: Insufficient credits. "
                    "Host/web searches require a paid plan. "
                    "Use domain_search() for free subdomain enumeration."
                )
            if response.status_code == 403:
                raise ZoomEyeAPIKeyError("ZoomEye API key lacks required permissions")
            if response.status_code == 429:
                raise ZoomEyeRateLimitError("ZoomEye rate limit exceeded. Try again later.")
            if response.status_code == 404:
                raise ZoomEyeNotFoundError(f"Not found: {context}")

    def search_host(
        self,
        query: str,
        page: int = 1,
        limit: int = 20,
    ) -> list[ZoomEyeHostResult]:
        """Search for hosts in ZoomEye.

        Args:
            query: ZoomEye dork query (e.g., "port:22", "app:nginx", "country:US")
            page: Page number (1-indexed)
            limit: Results per page (max 20)

        Returns:
            List of ZoomEyeHostResult
        """
        self._check_api_key()
        logger.info(f"ZoomEye: Searching hosts with query: {query}")

        url = f"{self.BASE_URL}/host/search"
        params = {
            "query": query,
            "page": page,
        }

        try:
            response = self.get(url, params=params, headers=self._get_headers())
            self._handle_response_errors(response, query)
            data = response.json()
        except ZoomEyeError:
            raise
        except Exception as e:
            logger.error(f"ZoomEye: Search failed: {e}")
            raise ZoomEyeError(f"Search failed: {e}") from e

        results: list[ZoomEyeHostResult] = []
        for match in data.get("matches", [])[:limit]:
            result = self._parse_host_match(match)
            results.append(result)

        logger.info(f"ZoomEye: Found {len(results)} hosts")
        return results

    def search_web(
        self,
        query: str,
        page: int = 1,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search for web applications in ZoomEye.

        Args:
            query: ZoomEye dork query (e.g., "site:example.com", "header:nginx")
            page: Page number (1-indexed)
            limit: Results per page (max 20)

        Returns:
            List of web application results
        """
        self._check_api_key()
        logger.info(f"ZoomEye: Searching web apps with query: {query}")

        url = f"{self.BASE_URL}/web/search"
        params = {
            "query": query,
            "page": page,
        }

        try:
            response = self.get(url, params=params, headers=self._get_headers())
            self._handle_response_errors(response, query)
            data = response.json()
        except ZoomEyeError:
            raise
        except Exception as e:
            logger.error(f"ZoomEye: Web search failed: {e}")
            raise ZoomEyeError(f"Web search failed: {e}") from e

        return data.get("matches", [])[:limit]

    def search_by_ip(self, ip: str) -> ZoomEyeHostResult | None:
        """Search for a specific IP in ZoomEye.

        Args:
            ip: IP address to lookup

        Returns:
            ZoomEyeHostResult or None if not found
        """
        results = self.search_host(f'ip:"{ip}"', limit=1)
        return results[0] if results else None

    def search_by_domain(self, domain: str, limit: int = 100) -> list[ZoomEyeHostResult]:
        """Search for hosts related to a domain.

        Args:
            domain: Domain to search (e.g., "example.com")
            limit: Maximum results to return

        Returns:
            List of ZoomEyeHostResult
        """
        results = self.search_host(f'hostname:"{domain}"', limit=limit)
        return results

    def domain_search(self, domain: str, limit: int = 100) -> list[dict[str, Any]]:
        """Search for subdomains using ZoomEye domain search API.

        This endpoint works with free accounts and doesn't consume host search credits.

        Args:
            domain: Domain to search (e.g., "example.com")
            limit: Maximum results to return

        Returns:
            List of subdomain records with name, timestamp, and IPs
        """
        self._check_api_key()
        logger.info(f"ZoomEye: Domain search for: {domain}")

        url = f"{self.BASE_URL}/domain/search"
        params = {
            "q": domain,
            "type": 0,  # 0 = subdomain search
        }

        try:
            response = self.get(url, params=params, headers=self._get_headers())
            self._handle_response_errors(response, domain)
            data = response.json()
        except ZoomEyeError:
            raise
        except Exception as e:
            logger.error(f"ZoomEye: Domain search failed: {e}")
            raise ZoomEyeError(f"Domain search failed: {e}") from e

        results = data.get("list", [])[:limit]
        logger.info(f"ZoomEye: Found {len(results)} subdomains (total: {data.get('total', 0)})")
        return results

    def search_by_org(self, org: str, limit: int = 100) -> list[ZoomEyeHostResult]:
        """Search for hosts by organization name.

        Args:
            org: Organization name
            limit: Maximum results

        Returns:
            List of ZoomEyeHostResult
        """
        results = self.search_host(f'org:"{org}"', limit=limit)
        return results

    def search_by_port(
        self, port: int, country: str | None = None, limit: int = 100
    ) -> list[ZoomEyeHostResult]:
        """Search for hosts by open port.

        Args:
            port: Port number
            country: Optional country code filter
            limit: Maximum results

        Returns:
            List of ZoomEyeHostResult
        """
        query = f"port:{port}"
        if country:
            query += f" country:{country}"
        return self.search_host(query, limit=limit)

    def search_by_service(self, service: str, limit: int = 100) -> list[ZoomEyeHostResult]:
        """Search for hosts by service/application.

        Args:
            service: Service name (e.g., "nginx", "apache", "openssh")
            limit: Maximum results

        Returns:
            List of ZoomEyeHostResult
        """
        return self.search_host(f'app:"{service}"', limit=limit)

    def search_by_asn(self, asn: str, limit: int = 100) -> list[ZoomEyeHostResult]:
        """Search for hosts by ASN.

        Args:
            asn: ASN number (with or without 'AS' prefix)
            limit: Maximum results

        Returns:
            List of ZoomEyeHostResult
        """
        # Normalize ASN format
        asn_num = asn.upper().replace("AS", "")
        return self.search_host(f"asn:{asn_num}", limit=limit)

    def search_by_cidr(self, cidr: str, limit: int = 100) -> list[ZoomEyeHostResult]:
        """Search for hosts in a CIDR range.

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            limit: Maximum results

        Returns:
            List of ZoomEyeHostResult
        """
        return self.search_host(f'cidr:"{cidr}"', limit=limit)

    def _parse_host_match(self, match: dict[str, Any]) -> ZoomEyeHostResult:
        """Parse ZoomEye host match from API response."""
        portinfo = match.get("portinfo", {})
        geoinfo = match.get("geoinfo", {})

        # Extract service info
        services: list[Service] = []
        port = portinfo.get("port", 0)
        if port:
            service = Service(
                port=port,
                protocol=portinfo.get("protocol", "tcp"),
                service_name=portinfo.get("service", "") or portinfo.get("app", ""),
                version=portinfo.get("version", "") or "",
                banner=portinfo.get("banner", "")[:500] if portinfo.get("banner") else "",
                metadata={
                    "device": portinfo.get("device", ""),
                    "os": portinfo.get("os", ""),
                    "extrainfo": portinfo.get("extrainfo", ""),
                },
            )
            services.append(service)

        # Parse last update
        last_update = None
        timestamp = match.get("timestamp")
        if timestamp:
            with contextlib.suppress(ValueError):
                last_update = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        return ZoomEyeHostResult(
            ip=match.get("ip", ""),
            hostnames=portinfo.get("hostname", [])
            if isinstance(portinfo.get("hostname"), list)
            else [],
            country=geoinfo.get("country", {}).get("names", {}).get("en", "") or "",
            city=geoinfo.get("city", {}).get("names", {}).get("en", "") or "",
            org=geoinfo.get("organization", "") or "",
            asn=geoinfo.get("asn", "") or "",
            isp=geoinfo.get("isp", "") or "",
            os=portinfo.get("os", "") or None,
            ports=[port] if port else [],
            services=services,
            vulns=[],  # ZoomEye doesn't provide CVEs in basic search
            last_update=last_update,
            device_type=portinfo.get("device", "") or "",
            banner=portinfo.get("banner", "")[:500] if portinfo.get("banner") else "",
        )

    def get_resources_info(self) -> dict[str, Any]:
        """Get account resources/credits info.

        Returns:
            Dict with account info including remaining credits
        """
        self._check_api_key()
        url = f"{self.BASE_URL}/resources-info"

        try:
            response = self.get(url, headers=self._get_headers())
            self._handle_response_errors(response)
            return response.json()
        except ZoomEyeError:
            raise
        except Exception as e:
            logger.error(f"ZoomEye: Failed to get resources info: {e}")
            raise ZoomEyeError(f"Failed to get resources info: {e}") from e

    def get_subdomains(self, domain: str, limit: int = 100) -> list[Asset]:
        """Get subdomains for a domain from ZoomEye.

        Uses the domain search endpoint which works with free accounts.

        Args:
            domain: Root domain to enumerate
            limit: Maximum subdomains to return

        Returns:
            List of subdomain Assets
        """
        self._check_api_key()
        logger.info(f"ZoomEye: Finding subdomains for {domain}")

        # Use domain search endpoint (works with free accounts)
        results = self.domain_search(domain, limit=limit)

        assets: list[Asset] = []
        seen = set()

        for result in results:
            name = result.get("name", "")
            if name and name.endswith(domain) and name not in seen:
                seen.add(name)
                assets.append(
                    Asset(
                        type=AssetType.SUBDOMAIN,
                        value=name,
                        parent=domain,
                        source=self.name,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        metadata={
                            "ips": result.get("ip", []),
                            "timestamp": result.get("timestamp"),
                        },
                    )
                )

        logger.info(f"ZoomEye: Found {len(assets)} subdomains for {domain}")
        return assets
        return assets

    def query(self, target: str) -> list[ZoomEyeHostResult]:
        """Query ZoomEye for a target (IP or domain).

        For IPs: Returns host information via IP search.
        For domains: Returns hosts with matching hostnames.

        Args:
            target: IP address or domain

        Returns:
            List of ZoomEyeHostResult
        """
        import re

        # Check if target is an IP
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, target):
            result = self.search_by_ip(target)
            return [result] if result else []
        # Search by domain/hostname
        return self.search_by_domain(target)
