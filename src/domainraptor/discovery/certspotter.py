"""CertSpotter (SSLMate) Certificate Transparency client.

CertSpotter is a free Certificate Transparency monitoring service operated by
SSLMate. It exposes a JSON API that returns the DNS names from every
certificate issued for a domain (and optionally its subdomains).

We use it as a more reliable fallback for crt.sh, which is a single-host
service that frequently returns 502 / 504 / connection-reset errors when its
Postgres backend is overloaded or rebuilding. CertSpotter's unauthenticated
endpoint is rate-limited but does not require an API key for casual lookups,
which matches DomainRaptor's "free-by-default" discovery posture.

API reference: https://sslmate.com/help/reference/certspotter-api
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from domainraptor.core.types import Asset, AssetType
from domainraptor.discovery.base import ClientConfig, SubdomainClient

logger = logging.getLogger(__name__)


class CertSpotterClient(SubdomainClient):
    """Client for SSLMate's CertSpotter CT monitoring API.

    Free, no API key required for moderate use. Returns DNS names parsed
    from issued certificates, which we treat as discovered subdomains.

    Example:
        >>> client = CertSpotterClient()
        >>> subdomains = client.query("example.com")
        >>> for asset in subdomains:
        ...     print(asset.value)
    """

    name = "certspotter"
    is_free = True
    requires_api_key = False

    BASE_URL = "https://api.certspotter.com/v1"

    def __init__(self, config: ClientConfig | None = None) -> None:
        if config is None:
            config = ClientConfig(
                # SSLMate documents a ~1 req/sec budget for unauthenticated use.
                rate_limit=1.0,
                timeout=30,
            )
        super().__init__(config)

    def query(self, target: str) -> list[Asset]:
        """Query CertSpotter for certificates issued for ``target``.

        Args:
            target: Domain to search for (e.g., ``"example.com"``).

        Returns:
            List of :class:`Asset` objects for discovered subdomains.
        """
        logger.info("certspotter: querying certificates for %s", target)

        url = f"{self.BASE_URL}/issuances?domain={target}&include_subdomains=true&expand=dns_names"

        try:
            response = self.get(url)
            data: list[dict[str, Any]] = response.json()
        except Exception as exc:
            logger.error("certspotter: failed to query %s: %s", target, exc)
            return []

        if not isinstance(data, list) or not data:
            logger.info("certspotter: no certificates found for %s", target)
            return []

        subdomains: set[str] = set()
        for entry in data:
            for name in entry.get("dns_names", []) or []:
                self._extract_domain(str(name), target, subdomains)

        assets = [
            Asset(
                type=AssetType.SUBDOMAIN,
                value=subdomain,
                parent=target,
                source=self.name,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )
            for subdomain in sorted(subdomains)
        ]

        logger.info("certspotter: found %d unique subdomains for %s", len(assets), target)
        return assets

    @staticmethod
    def _extract_domain(name: str, target: str, subdomains: set[str]) -> None:
        """Add ``name`` to ``subdomains`` if it is a valid sub/equal of ``target``."""
        name = name.strip().lower()
        if name.startswith("*."):
            name = name[2:]
        if not name:
            return
        if not (name == target or name.endswith("." + target)):
            return
        if len(name) > 253:
            return
        if name.startswith(("-", ".")) or name.endswith(("-", ".")):
            return
        subdomains.add(name)
