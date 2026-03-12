"""HackerTarget API client for subdomain enumeration.

HackerTarget provides free subdomain lookup via their API.
Limited to 100 requests per day on free tier.
"""

from __future__ import annotations

import logging
from datetime import datetime

from domainraptor.core.types import Asset, AssetType
from domainraptor.discovery.base import ClientConfig, SubdomainClient

logger = logging.getLogger(__name__)


class HackerTargetClient(SubdomainClient):
    """Client for HackerTarget subdomain enumeration API.

    Free tier allows 100 requests per day.
    No API key required for basic usage.

    Example:
        >>> client = HackerTargetClient()
        >>> subdomains = client.query("example.com")
    """

    name = "hackertarget"
    is_free = True
    requires_api_key = False

    BASE_URL = "https://api.hackertarget.com"

    def __init__(self, config: ClientConfig | None = None) -> None:
        if config is None:
            config = ClientConfig(
                rate_limit=0.5,  # Respect the free service
                timeout=30,
            )
        super().__init__(config)

    def query(self, target: str) -> list[Asset]:
        """Query HackerTarget for subdomains.

        Args:
            target: Domain to search for

        Returns:
            List of Asset objects for discovered subdomains
        """
        logger.info(f"HackerTarget: Querying subdomains for {target}")

        url = f"{self.BASE_URL}/hostsearch/?q={target}"

        try:
            response = self.get(url)
            text = response.text
        except Exception as e:
            logger.error(f"HackerTarget: Request failed for {target}: {e}")
            return []

        # Check for error responses
        if text.startswith("error"):
            logger.warning(f"HackerTarget: API error: {text}")
            return []

        if "API count exceeded" in text:
            logger.error("HackerTarget: Daily API limit exceeded")
            return []

        # Parse response (format: subdomain,ip per line)
        assets: list[Asset] = []
        seen: set[str] = set()

        for line in text.strip().split("\n"):
            if not line or "," not in line:
                continue

            parts = line.split(",", 1)
            subdomain = parts[0].strip().lower()

            # Skip if already seen or not a subdomain of target
            if subdomain in seen:
                continue
            if not subdomain.endswith(target):
                continue

            seen.add(subdomain)

            # Get IP if available
            ip = parts[1].strip() if len(parts) > 1 else None

            assets.append(
                Asset(
                    type=AssetType.SUBDOMAIN,
                    value=subdomain,
                    parent=target,
                    source=self.name,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    metadata={"ip": ip} if ip else {},
                )
            )

        logger.info(f"HackerTarget: Found {len(assets)} subdomains for {target}")
        return assets

    def reverse_ip_lookup(self, ip: str) -> list[Asset]:
        """Find domains hosted on an IP address.

        Args:
            ip: IP address to look up

        Returns:
            List of Asset objects for domains found
        """
        logger.info(f"HackerTarget: Reverse IP lookup for {ip}")

        url = f"{self.BASE_URL}/reverseiplookup/?q={ip}"

        try:
            response = self.get(url)
            text = response.text
        except Exception as e:
            logger.error(f"HackerTarget: Reverse lookup failed for {ip}: {e}")
            return []

        if text.startswith("error") or "API count exceeded" in text:
            return []

        assets: list[Asset] = []
        seen: set[str] = set()

        for line in text.strip().split("\n"):
            domain = line.strip().lower()
            if domain and domain not in seen:
                seen.add(domain)
                assets.append(
                    Asset(
                        type=AssetType.DOMAIN,
                        value=domain,
                        parent=ip,
                        source=self.name,
                    )
                )

        return assets

    def dns_lookup(self, target: str) -> dict[str, list[str]]:
        """Perform DNS lookup via HackerTarget.

        Args:
            target: Domain to look up

        Returns:
            Dict mapping record types to values
        """
        url = f"{self.BASE_URL}/dnslookup/?q={target}"

        try:
            response = self.get(url)
            text = response.text
        except Exception:
            return {}

        records: dict[str, list[str]] = {}

        for line in text.strip().split("\n"):
            if ":" in line:
                rtype, value = line.split(":", 1)
                rtype = rtype.strip().upper()
                value = value.strip()
                if rtype not in records:
                    records[rtype] = []
                records[rtype].append(value)

        return records

    def http_headers(self, target: str) -> dict[str, str]:
        """Get HTTP headers for a target.

        Args:
            target: Domain or URL to check

        Returns:
            Dict of HTTP headers
        """
        url = f"{self.BASE_URL}/httpheaders/?q={target}"

        try:
            response = self.get(url)
            text = response.text
        except Exception:
            return {}

        headers: dict[str, str] = {}

        for line in text.strip().split("\n"):
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.strip()] = value.strip()

        return headers
