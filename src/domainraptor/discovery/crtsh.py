"""crt.sh Certificate Transparency client.

crt.sh is a free service that queries Certificate Transparency logs
to find certificates issued for a domain, which reveals subdomains.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime

from domainraptor.core.types import Asset, AssetType, Certificate
from domainraptor.discovery.base import ClientConfig, SubdomainClient

logger = logging.getLogger(__name__)


class CrtShClient(SubdomainClient):
    """Client for crt.sh Certificate Transparency log search.

    crt.sh provides free access to CT logs without requiring an API key.
    Rate limit: ~1 request per second recommended.

    Example:
        >>> client = CrtShClient()
        >>> subdomains = client.query("example.com")
        >>> for asset in subdomains:
        ...     print(asset.value)
    """

    name = "crt_sh"
    is_free = True
    requires_api_key = False

    BASE_URL = "https://crt.sh"

    def __init__(self, config: ClientConfig | None = None) -> None:
        if config is None:
            config = ClientConfig(
                rate_limit=0.5,  # Be nice to the free service
                timeout=60,  # CT queries can be slow
            )
        super().__init__(config)

    def query(self, target: str) -> list[Asset]:
        """Query crt.sh for certificates and extract subdomains.

        Args:
            target: Domain to search for (e.g., "example.com")

        Returns:
            List of Asset objects representing discovered subdomains
        """
        logger.info(f"crt.sh: Querying certificates for {target}")

        # Query crt.sh JSON API
        url = f"{self.BASE_URL}/?q=%.{target}&output=json"

        try:
            response = self.get(url)
            data = response.json()
        except Exception as e:
            logger.error(f"crt.sh: Failed to query {target}: {e}")
            return []

        if not data:
            logger.info(f"crt.sh: No certificates found for {target}")
            return []

        # Extract unique subdomains from certificate names
        subdomains: set[str] = set()

        for entry in data:
            # common_name field
            cn = entry.get("common_name", "")
            if cn:
                self._extract_domains(cn, target, subdomains)

            # name_value field contains SANs (Subject Alternative Names)
            name_value = entry.get("name_value", "")
            if name_value:
                # SANs are newline-separated
                for name in name_value.split("\n"):
                    self._extract_domains(name.strip(), target, subdomains)

        # Convert to Asset objects
        assets: list[Asset] = []
        for subdomain in sorted(subdomains):
            assets.append(
                Asset(
                    type=AssetType.SUBDOMAIN,
                    value=subdomain,
                    parent=target,
                    source=self.name,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                )
            )

        logger.info(f"crt.sh: Found {len(assets)} unique subdomains for {target}")
        return assets

    def query_certificates(self, target: str) -> list[Certificate]:
        """Query crt.sh and return detailed certificate information.

        Args:
            target: Domain to search for

        Returns:
            List of Certificate objects with full details
        """
        logger.info(f"crt.sh: Querying certificate details for {target}")

        url = f"{self.BASE_URL}/?q=%.{target}&output=json"

        try:
            response = self.get(url)
            data = response.json()
        except Exception as e:
            logger.error(f"crt.sh: Failed to query certificates for {target}: {e}")
            return []

        if not data:
            return []

        # Deduplicate by certificate ID
        seen_ids: set[int] = set()
        certificates: list[Certificate] = []

        for entry in data:
            cert_id = entry.get("id")
            if cert_id in seen_ids:
                continue
            seen_ids.add(cert_id)

            # Parse dates
            not_before = self._parse_date(entry.get("not_before", ""))
            not_after = self._parse_date(entry.get("not_after", ""))

            # Calculate expiry
            is_expired = False
            days_until_expiry = 0
            if not_after:
                days_until_expiry = (not_after - datetime.now()).days
                is_expired = days_until_expiry < 0

            # Extract SANs
            san_str = entry.get("name_value", "")
            san = [s.strip() for s in san_str.split("\n") if s.strip()]

            cert = Certificate(
                subject=entry.get("common_name", ""),
                issuer=entry.get("issuer_name", ""),
                serial_number=entry.get("serial_number", ""),
                not_before=not_before or datetime.now(),
                not_after=not_after or datetime.now(),
                san=san,
                is_expired=is_expired,
                days_until_expiry=days_until_expiry,
            )
            certificates.append(cert)

        logger.info(f"crt.sh: Found {len(certificates)} certificates for {target}")
        return certificates

    def _extract_domains(self, name: str, target: str, subdomains: set[str]) -> None:
        """Extract valid domain names from a certificate name field.

        Args:
            name: Domain name from certificate
            target: Parent domain to filter by
            subdomains: Set to add valid subdomains to
        """
        # Clean up the name
        name = name.strip().lower()

        # Skip wildcards as-is, but note the domain
        if name.startswith("*."):
            name = name[2:]

        # Skip if it doesn't end with the target domain
        if not name.endswith(target) and name != target:
            return

        # Validate domain format
        if not self._is_valid_domain(name):
            return

        subdomains.add(name)

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Check if string is a valid domain name."""
        # Basic domain validation
        if not domain or len(domain) > 253:
            return False

        # Must not start/end with hyphen or dot
        if domain.startswith(("-", ".")) or domain.endswith(("-", ".")):
            return False

        # Check each label
        labels = domain.split(".")
        if len(labels) < 2:
            return False

        for label in labels:
            if not label or len(label) > 63:
                return False
            # Labels must be alphanumeric with hyphens (not at start/end)
            if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label):
                return False

        return True

    @staticmethod
    def _parse_date(date_str: str) -> datetime | None:
        """Parse date string from crt.sh API."""
        if not date_str:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str.split("+")[0].split("Z")[0], fmt)
            except ValueError:
                continue

        return None
