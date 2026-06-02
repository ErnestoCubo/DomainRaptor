"""Wayback Machine subdomain discovery client.

The Internet Archive's CDX server indexes historical snapshots of the web. By
querying for `*.{domain}` and collapsing on hostname we obtain the set of
subdomains that have been publicly reachable at some point. Old/forgotten
subdomains are a frequent source of attack surface.

API: https://web.archive.org/cdx/search/cdx
No API key required.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from domainraptor.core.types import Asset, AssetType
from domainraptor.discovery.base import ClientConfig, SubdomainClient

logger = logging.getLogger(__name__)


class WaybackClient(SubdomainClient):
    """Discover historical subdomains via the Wayback Machine CDX API."""

    name = "wayback"
    is_free = True
    requires_api_key = False

    BASE_URL = "https://web.archive.org/cdx/search/cdx"
    DEFAULT_LIMIT = 5000

    def __init__(self, config: ClientConfig | None = None) -> None:
        if config is None:
            config = ClientConfig(rate_limit=0.5, timeout=60)
        super().__init__(config)

    def _extract_host(self, original: str) -> str | None:
        """Extract a hostname from a CDX 'original' URL field."""
        if not original:
            return None
        if "://" not in original:
            original = f"http://{original}"
        try:
            netloc = urlparse(original).netloc
        except ValueError:
            return None
        if not netloc:
            return None
        host = netloc.split("@")[-1].split(":")[0].lower().strip()
        return host or None

    def query(self, target: str) -> list[Asset]:
        """Query Wayback CDX for subdomains of the target domain."""
        target = target.lower().strip()
        params = {
            "url": f"*.{target}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(self.DEFAULT_LIMIT),
        }

        logger.info("wayback: querying CDX for *.%s", target)
        try:
            response = self.get(self.BASE_URL, params=params)
            data = response.json()
        except Exception as exc:
            logger.error("wayback: query failed for %s: %s", target, exc, exc_info=True)
            return []

        if not data or len(data) < 2:
            logger.info("wayback: no historical URLs for %s", target)
            return []

        # CDX returns the header as the first row, e.g. [["original"], ...]
        rows = data[1:]
        seen: set[str] = set()
        for row in rows:
            if not row:
                continue
            host = self._extract_host(str(row[0]))
            if not host or not host.endswith(target):
                continue
            if host == target:
                continue
            seen.add(host)

        assets = [
            Asset(
                type=AssetType.SUBDOMAIN,
                value=host,
                parent=target,
                source=self.name,
                metadata={"discovered_via": "wayback_cdx"},
            )
            for host in sorted(seen)
        ]
        logger.info("wayback: found %d historical subdomains for %s", len(assets), target)
        return assets
