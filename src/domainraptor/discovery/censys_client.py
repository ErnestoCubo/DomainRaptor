"""Censys API client for host and certificate discovery.

Censys provides internet-wide scanning data:
- Host/IP information
- Certificate transparency data
- Banner grabbing
- Subdomain enumeration via certificates

Free tier: 250 queries/month
Docs: https://search.censys.io/api
"""

from __future__ import annotations

import base64
import contextlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from domainraptor.core.types import Asset, AssetType, Service
from domainraptor.discovery.base import BaseClient, ClientConfig

logger = logging.getLogger(__name__)


class CensysError(Exception):
    """Base exception for Censys client errors."""

    pass


class CensysAPIKeyError(CensysError):
    """Raised when API credentials are missing or invalid."""

    pass


class CensysRateLimitError(CensysError):
    """Raised when rate limit is exceeded."""

    pass


class CensysNotFoundError(CensysError):
    """Raised when host/domain not found."""

    pass


@dataclass
class CensysHostResult:
    """Result from Censys host lookup."""

    ip: str
    hostnames: list[str] = field(default_factory=list)
    country: str = ""
    city: str = ""
    autonomous_system: str = ""
    asn: str = ""
    os: str | None = None
    ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    last_update: datetime | None = None
    labels: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


@dataclass
class CensysCertificateResult:
    """Result from Censys certificate search."""

    fingerprint_sha256: str
    names: list[str] = field(default_factory=list)
    issuer: str = ""
    subject: str = ""
    validity_start: datetime | None = None
    validity_end: datetime | None = None
    key_algorithm: str = ""
    key_size: int = 0


class CensysClient(BaseClient[CensysHostResult]):
    """Client for Censys Platform API (v3).

    Censys provides:
    - /global/asset/host/{ip}: Get host details
    - /global/search/query: Search hosts (requires paid subscription)
    - /global/asset/certificate/{fp}: Get certificate details

    Authentication: Bearer token (Personal Access Token - PAT)

    Example:
        >>> client = CensysClient(api_token="censys_xxx_yyy")
        >>> result = client.get_host("8.8.8.8")
    """

    name = "censys"
    is_free = False
    requires_api_key = True

    BASE_URL = "https://api.platform.censys.io/v3"

    def __init__(
        self,
        api_token: str | None = None,
        api_id: str | None = None,
        api_secret: str | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        """Initialize Censys client.

        Args:
            api_token: Censys PAT (Personal Access Token). Falls back to CENSYS_API_TOKEN env var.
            api_id: Deprecated. Legacy API ID for backwards compatibility.
            api_secret: Deprecated. Legacy API Secret for backwards compatibility.
            config: Optional client configuration.
        """
        if config is None:
            config = ClientConfig(
                rate_limit=0.4,  # 0.4 requests per second (2.5s between requests for free tier)
                timeout=30,
            )

        super().__init__(config)

        # Get credentials from parameters or environment
        # Priority: api_token > CENSYS_API_TOKEN > CENSYS_API_KEY (if PAT format) > legacy api_id/secret
        self.api_token = api_token or os.environ.get("CENSYS_API_TOKEN")

        # Check if CENSYS_API_KEY is a PAT (format: censys_xxx_yyy)
        if not self.api_token:
            api_key = os.environ.get("CENSYS_API_KEY", "")
            if api_key.startswith("censys_"):
                self.api_token = api_key

        # Backwards compatibility with legacy API ID/Secret
        if not self.api_token:
            self.api_id = api_id or os.environ.get("CENSYS_API_ID")
            self.api_secret = api_secret or os.environ.get("CENSYS_API_SECRET")
        else:
            self.api_id = None
            self.api_secret = None

        if not self.api_token and not (self.api_id and self.api_secret):
            logger.debug("Censys: No API credentials configured. Set CENSYS_API_TOKEN env var.")

    def _check_api_key(self) -> None:
        """Verify API credentials are set."""
        if not self.api_token and not (self.api_id and self.api_secret):
            raise CensysAPIKeyError(
                "Censys API credentials required. Set CENSYS_API_TOKEN environment variable "
                "or use 'domainraptor config set CENSYS_API_TOKEN <token>'"
            )

    def _get_auth_header(self) -> dict[str, str]:
        """Get authentication header."""
        if self.api_token:
            # v3 API uses Bearer token
            return {
                "Authorization": f"Bearer {self.api_token}",
                "Accept": "application/json",
            }
        # Legacy v2 API uses Basic Auth
        credentials = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
        return {
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
        }

    def _handle_response_errors(self, response: Any, context: str = "") -> None:
        """Handle common Censys API errors."""
        import httpx

        if isinstance(response, httpx.Response):
            if response.status_code == 401:
                raise CensysAPIKeyError("Invalid Censys API credentials")
            if response.status_code == 403:
                raise CensysAPIKeyError(
                    "Censys API: This endpoint requires a paid subscription. "
                    "Free users can only access individual host lookups."
                )
            if response.status_code == 429:
                raise CensysRateLimitError("Censys rate limit exceeded. Try again later.")
            if response.status_code == 404:
                raise CensysNotFoundError(f"Not found in Censys: {context}")

    def search_hosts(
        self,
        query: str,
        per_page: int = 25,
        cursor: str | None = None,
    ) -> tuple[list[CensysHostResult], str | None]:
        """Search for hosts in Censys.

        Note: This endpoint requires a paid Censys subscription.
        Free users should use get_host() for individual IP lookups.

        Args:
            query: Censys search query
            per_page: Results per page (max 100)
            cursor: Pagination cursor

        Returns:
            Tuple of (list of results, next cursor)
        """
        import httpx

        self._check_api_key()
        logger.info(f"Censys: Searching hosts with query: {query}")

        url = f"{self.BASE_URL}/global/search/query"
        payload: dict[str, Any] = {
            "query": query,
            "per_page": min(per_page, 100),
        }
        if cursor:
            payload["cursor"] = cursor

        try:
            response = self.post(url, json=payload, headers=self._get_auth_header())
            self._handle_response_errors(response, query)
            data = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                raise CensysAPIKeyError(
                    "Censys search requires a paid subscription. "
                    "Free users can use 'get_host()' for individual IP lookups."
                ) from e
            if e.response.status_code == 401:
                raise CensysAPIKeyError("Invalid Censys API credentials") from e
            raise CensysError(f"Censys API error: {e.response.status_code}") from e
        except CensysError:
            raise
        except Exception as e:
            logger.error(f"Censys: Search failed: {e}")
            raise CensysError(f"Search failed: {e}") from e

        results: list[CensysHostResult] = []
        for hit in data.get("result", {}).get("hits", []):
            result = self._parse_host_hit(hit)
            results.append(result)

        next_cursor = data.get("result", {}).get("links", {}).get("next")
        logger.info(f"Censys: Found {len(results)} hosts")
        return results, next_cursor

    def search_hosts_all(self, query: str, limit: int = 100) -> list[CensysHostResult]:
        """Search and paginate through all results up to limit.

        Note: This endpoint requires a paid Censys subscription.

        Args:
            query: Censys search query
            limit: Maximum total results

        Returns:
            List of CensysHostResult
        """
        all_results: list[CensysHostResult] = []
        cursor = None

        while len(all_results) < limit:
            remaining = limit - len(all_results)
            per_page = min(remaining, 100)

            results, cursor = self.search_hosts(query, per_page=per_page, cursor=cursor)
            all_results.extend(results)

            if not cursor or not results:
                break

        return all_results[:limit]

    def get_host(self, ip: str) -> CensysHostResult | None:
        """Get detailed information about a specific host.

        This endpoint works with free Censys accounts.

        Args:
            ip: IP address to lookup

        Returns:
            CensysHostResult or None if not found
        """
        self._check_api_key()
        logger.info(f"Censys: Looking up host {ip}")

        url = f"{self.BASE_URL}/global/asset/host/{ip}"

        try:
            response = self.get(url, headers=self._get_auth_header())
            self._handle_response_errors(response, ip)
            data = response.json()
        except CensysNotFoundError:
            logger.info(f"Censys: Host {ip} not found")
            return None
        except CensysError:
            raise
        except Exception as e:
            logger.error(f"Censys: Host lookup failed: {e}")
            raise CensysError(f"Host lookup failed: {e}") from e

        # v3 API returns result.resource instead of just result
        resource = data.get("result", {}).get("resource", {})
        if not resource:
            # Fallback for v2 format
            resource = data.get("result", {})
        return self._parse_host_detail(resource)

    def search_certificates(
        self,
        query: str,
        per_page: int = 25,
        cursor: str | None = None,
    ) -> tuple[list[CensysCertificateResult], str | None]:
        """Search for certificates in Censys.

        Note: This endpoint requires a paid Censys subscription (v3 API).
        Free users will receive a CensysAPIKeyError.

        Args:
            query: Censys certificate search query
            per_page: Results per page (max 100)
            cursor: Pagination cursor

        Returns:
            Tuple of (list of results, next cursor)
        """
        import httpx

        self._check_api_key()
        logger.info(f"Censys: Searching certificates with query: {query}")

        # v3 API uses unified search endpoint
        url = f"{self.BASE_URL}/global/search/query"
        payload: dict[str, Any] = {
            "query": query,
            "per_page": min(per_page, 100),
            "asset_type": "certificate",
        }
        if cursor:
            payload["cursor"] = cursor

        try:
            response = self.post(url, json=payload, headers=self._get_auth_header())
            self._handle_response_errors(response, query)
            data = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (403, 404):
                raise CensysAPIKeyError(
                    "Censys certificate search requires a paid subscription."
                ) from e
            if e.response.status_code == 401:
                raise CensysAPIKeyError("Invalid Censys API credentials") from e
            raise CensysError(f"Censys API error: {e.response.status_code}") from e
        except CensysError:
            raise
        except Exception as e:
            logger.error(f"Censys: Certificate search failed: {e}")
            raise CensysError(f"Certificate search failed: {e}") from e

        results: list[CensysCertificateResult] = []
        for hit in data.get("result", {}).get("hits", []):
            result = self._parse_certificate_hit(hit)
            results.append(result)

        next_cursor = data.get("result", {}).get("links", {}).get("next")
        logger.info(f"Censys: Found {len(results)} certificates")
        return results, next_cursor

    def search_by_domain(self, domain: str, limit: int = 100) -> list[CensysHostResult]:
        """Search for hosts by domain name.

        Args:
            domain: Domain to search
            limit: Maximum results

        Returns:
            List of CensysHostResult
        """
        query = f'dns.names: "{domain}" or services.tls.certificates.leaf.names: "{domain}"'
        return self.search_hosts_all(query, limit=limit)

    def search_by_org(self, org: str, limit: int = 100) -> list[CensysHostResult]:
        """Search for hosts by organization.

        Args:
            org: Organization name
            limit: Maximum results

        Returns:
            List of CensysHostResult
        """
        query = f'autonomous_system.name: "{org}"'
        return self.search_hosts_all(query, limit=limit)

    def search_by_asn(self, asn: str, limit: int = 100) -> list[CensysHostResult]:
        """Search for hosts by ASN.

        Args:
            asn: ASN number (with or without 'AS' prefix)
            limit: Maximum results

        Returns:
            List of CensysHostResult
        """
        asn_num = asn.upper().replace("AS", "")
        query = f"autonomous_system.asn: {asn_num}"
        return self.search_hosts_all(query, limit=limit)

    def search_by_port(
        self, port: int, protocol: str = "tcp", limit: int = 100
    ) -> list[CensysHostResult]:
        """Search for hosts by open port.

        Args:
            port: Port number
            protocol: Protocol (tcp/udp)
            limit: Maximum results

        Returns:
            List of CensysHostResult
        """
        query = f"services.port: {port}"
        return self.search_hosts_all(query, limit=limit)

    def search_by_service(self, service: str, limit: int = 100) -> list[CensysHostResult]:
        """Search for hosts by service.

        Args:
            service: Service name (e.g., "SSH", "HTTP", "NGINX")
            limit: Maximum results

        Returns:
            List of CensysHostResult
        """
        query = f'services.service_name: "{service}"'
        return self.search_hosts_all(query, limit=limit)

    def search_by_ssl_cert(self, domain: str, limit: int = 100) -> list[CensysHostResult]:
        """Search for hosts with SSL certificates for domain.

        Args:
            domain: Domain name in certificate
            limit: Maximum results

        Returns:
            List of CensysHostResult
        """
        query = f'services.tls.certificates.leaf.names: "{domain}"'
        return self.search_hosts_all(query, limit=limit)

    def search_by_cidr(self, cidr: str, limit: int = 100) -> list[CensysHostResult]:
        """Search for hosts in CIDR range.

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            limit: Maximum results

        Returns:
            List of CensysHostResult
        """
        query = f"ip: {cidr}"
        return self.search_hosts_all(query, limit=limit)

    def query(self, target: str) -> list[CensysHostResult]:
        """Query Censys for a target (IP or domain).

        For IPs: Returns host information via direct lookup.
        For domains: Returns hosts with matching DNS names or certificates.

        Args:
            target: IP address or domain

        Returns:
            List of CensysHostResult
        """
        import re

        # Check if target is an IP
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, target):
            result = self.get_host(target)
            return [result] if result else []
        # Search by domain
        return self.search_by_domain(target)

    def get_subdomains(self, domain: str, limit: int = 100) -> list[Asset]:
        """Get subdomains via certificate transparency.

        Args:
            domain: Root domain to enumerate
            limit: Maximum subdomains to return

        Returns:
            List of subdomain Assets
        """
        self._check_api_key()
        logger.info(f"Censys: Finding subdomains for {domain} via certificates")

        query = f'names: "*.{domain}"'
        certs, _ = self.search_certificates(query, per_page=min(limit, 100))

        assets: list[Asset] = []
        seen = set()

        for cert in certs:
            for name in cert.names:
                # Skip wildcard and non-matching domains
                if name.startswith("*"):
                    continue
                if not name.endswith(domain):
                    continue
                if name in seen:
                    continue

                seen.add(name)
                assets.append(
                    Asset(
                        type=AssetType.SUBDOMAIN,
                        value=name,
                        parent=domain,
                        source=self.name,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                    )
                )

        logger.info(f"Censys: Found {len(assets)} subdomains for {domain}")
        return assets

    def _parse_host_hit(self, hit: dict[str, Any]) -> CensysHostResult:
        """Parse Censys host search hit."""
        services: list[Service] = []

        for svc in hit.get("services", []):
            port = svc.get("port", 0)
            service = Service(
                port=port,
                protocol=svc.get("transport_protocol", "tcp"),
                service_name=svc.get("service_name", "") or "",
                banner=svc.get("banner", "")[:500] if svc.get("banner") else "",
                metadata={
                    "extended_service_name": svc.get("extended_service_name", ""),
                },
            )
            services.append(service)

        autonomy = hit.get("autonomous_system", {})

        last_update = None
        if hit.get("last_updated_at"):
            with contextlib.suppress(ValueError):
                last_update = datetime.fromisoformat(hit["last_updated_at"].replace("Z", "+00:00"))

        return CensysHostResult(
            ip=hit.get("ip", ""),
            hostnames=hit.get("dns", {}).get("reverse_dns", {}).get("names", []) or [],
            country=hit.get("location", {}).get("country", "") or "",
            city=hit.get("location", {}).get("city", "") or "",
            autonomous_system=autonomy.get("name", "") or "",
            asn=str(autonomy.get("asn", "")) if autonomy.get("asn") else "",
            ports=[s.port for s in services],
            services=services,
            last_update=last_update,
            labels=hit.get("labels", []) or [],
            protocols=list({s.protocol for s in services}),
        )

    def _parse_host_detail(self, result: dict[str, Any]) -> CensysHostResult:
        """Parse Censys host detail response."""
        services: list[Service] = []

        for svc in result.get("services", []):
            port = svc.get("port", 0)
            service = Service(
                port=port,
                protocol=svc.get("transport_protocol", "tcp"),
                service_name=svc.get("service_name", "") or "",
                version=svc.get("software", [{}])[0].get("version", "")
                if svc.get("software")
                else "",
                banner=svc.get("banner", "")[:500] if svc.get("banner") else "",
                metadata={
                    "tls": svc.get("tls", {}),
                    "http": svc.get("http", {}),
                },
            )
            services.append(service)

        autonomy = result.get("autonomous_system", {})

        last_update = None
        if result.get("last_updated_at"):
            with contextlib.suppress(ValueError):
                last_update = datetime.fromisoformat(
                    result["last_updated_at"].replace("Z", "+00:00")
                )

        return CensysHostResult(
            ip=result.get("ip", ""),
            hostnames=result.get("dns", {}).get("reverse_dns", {}).get("names", []) or [],
            country=result.get("location", {}).get("country", "") or "",
            city=result.get("location", {}).get("city", "") or "",
            autonomous_system=autonomy.get("name", "") or "",
            asn=str(autonomy.get("asn", "")) if autonomy.get("asn") else "",
            os=result.get("operating_system", {}).get("product", "") or None,
            ports=[s.port for s in services],
            services=services,
            last_update=last_update,
            labels=result.get("labels", []) or [],
            protocols=list({s.protocol for s in services}),
        )

    def _parse_certificate_hit(self, hit: dict[str, Any]) -> CensysCertificateResult:
        """Parse Censys certificate search hit."""
        validity_start = None
        validity_end = None

        parsed = hit.get("parsed", {})
        validity = parsed.get("validity_period", {})

        if validity.get("not_before"):
            with contextlib.suppress(ValueError):
                validity_start = datetime.fromisoformat(
                    validity["not_before"].replace("Z", "+00:00")
                )

        if validity.get("not_after"):
            with contextlib.suppress(ValueError):
                validity_end = datetime.fromisoformat(validity["not_after"].replace("Z", "+00:00"))

        return CensysCertificateResult(
            fingerprint_sha256=hit.get("fingerprint_sha256", ""),
            names=hit.get("names", []) or [],
            issuer=parsed.get("issuer_dn", "") or "",
            subject=parsed.get("subject_dn", "") or "",
            validity_start=validity_start,
            validity_end=validity_end,
            key_algorithm=parsed.get("subject_key_info", {})
            .get("key_algorithm", {})
            .get("name", "")
            or "",
            key_size=parsed.get("subject_key_info", {}).get("key_size", 0) or 0,
        )

    def get_account_info(self) -> dict[str, Any]:
        """Get account quota/usage information.

        Returns:
            Dict with account info including remaining queries
        """
        self._check_api_key()
        url = f"{self.BASE_URL}/account"

        try:
            response = self.get(url, headers=self._get_auth_header())
            self._handle_response_errors(response)
            return response.json()
        except CensysError:
            raise
        except Exception as e:
            logger.error(f"Censys: Failed to get account info: {e}")
            raise CensysError(f"Failed to get account info: {e}") from e
