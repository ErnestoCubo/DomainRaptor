"""WHOIS lookup client using python-whois.

Retrieves domain registration information including registrar,
creation/expiration dates, nameservers, and contact info.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import whois

from domainraptor.core.types import Asset, AssetType

logger = logging.getLogger(__name__)


@dataclass
class WhoisInfo:
    """Parsed WHOIS information for a domain."""

    domain: str
    registrar: str | None = None
    registrar_url: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    status: list[str] | None = None
    nameservers: list[str] | None = None
    dnssec: bool = False

    # Contact information (often redacted)
    registrant_name: str | None = None
    registrant_org: str | None = None
    registrant_country: str | None = None
    admin_email: str | None = None
    tech_email: str | None = None

    # Additional
    raw: dict[str, Any] | None = None

    @property
    def days_until_expiry(self) -> int | None:
        """Calculate days until domain expiration."""
        if self.expiration_date is None:
            return None
        return (self.expiration_date - datetime.now()).days

    @property
    def is_expired(self) -> bool:
        """Check if domain has expired."""
        if self.expiration_date is None:
            return False
        return self.expiration_date < datetime.now()

    @property
    def age_days(self) -> int | None:
        """Calculate domain age in days."""
        if self.creation_date is None:
            return None
        return (datetime.now() - self.creation_date).days


class WhoisClient:
    """WHOIS lookup client.

    Uses python-whois library for WHOIS queries.
    Note: WHOIS servers may rate limit queries.

    Example:
        >>> client = WhoisClient()
        >>> info = client.query("example.com")
        >>> print(f"Registrar: {info.registrar}")
        >>> print(f"Expires: {info.expiration_date}")
    """

    name = "whois"
    is_free = True
    requires_api_key = False

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def query(self, target: str) -> WhoisInfo | None:
        """Perform WHOIS lookup for a domain.

        Args:
            target: Domain name to look up

        Returns:
            WhoisInfo object with parsed data, or None on failure
        """
        logger.info(f"WHOIS: Querying {target}")

        try:
            w = whois.whois(target)
        except Exception as e:
            logger.error(f"WHOIS: Query failed for {target}: {e}")
            return None

        if w is None or w.domain_name is None:
            logger.warning(f"WHOIS: No data returned for {target}")
            return None

        # Parse domain name (may be list)
        domain = self._get_first(w.domain_name)
        if domain:
            domain = domain.lower()

        # Parse dates
        creation_date = self._parse_date(w.creation_date)
        expiration_date = self._parse_date(w.expiration_date)
        updated_date = self._parse_date(w.updated_date)

        # Parse nameservers
        nameservers = self._normalize_list(w.name_servers)
        if nameservers:
            nameservers = [ns.lower().rstrip(".") for ns in nameservers]

        # Parse status
        status = self._normalize_list(w.status)

        # Check DNSSEC
        dnssec = False
        if hasattr(w, "dnssec"):
            dnssec_val = w.dnssec
            if isinstance(dnssec_val, str):
                dnssec = dnssec_val.lower() in ("signed", "signeddelegation", "yes", "true")
            elif isinstance(dnssec_val, bool):
                dnssec = dnssec_val

        info = WhoisInfo(
            domain=domain or target,
            registrar=self._get_first(w.registrar),
            registrar_url=getattr(w, "registrar_url", None),
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            status=status,
            nameservers=nameservers,
            dnssec=dnssec,
            registrant_name=getattr(w, "registrant_name", None),
            registrant_org=self._get_first(getattr(w, "org", None)),
            registrant_country=self._get_first(getattr(w, "country", None)),
            admin_email=getattr(w, "admin_email", None),
            tech_email=getattr(w, "tech_email", None),
            raw=dict(w) if w else None,
        )

        logger.info(f"WHOIS: Successfully queried {target}")
        return info

    def query_nameserver_assets(self, target: str) -> list[Asset]:
        """Query WHOIS and return nameservers as Asset objects.

        Args:
            target: Domain to query

        Returns:
            List of Asset objects for nameservers
        """
        info = self.query(target)
        if info is None or info.nameservers is None:
            return []

        assets: list[Asset] = []
        for ns in info.nameservers:
            assets.append(
                Asset(
                    type=AssetType.DOMAIN,
                    value=ns,
                    parent=target,
                    source=self.name,
                    metadata={"role": "nameserver"},
                )
            )

        return assets

    def check_expiry(self, target: str) -> dict[str, Any]:
        """Check domain expiration status.

        Args:
            target: Domain to check

        Returns:
            Dict with expiration details
        """
        info = self.query(target)
        if info is None:
            return {"error": "WHOIS query failed"}

        return {
            "domain": info.domain,
            "expiration_date": info.expiration_date.isoformat() if info.expiration_date else None,
            "days_until_expiry": info.days_until_expiry,
            "is_expired": info.is_expired,
            "creation_date": info.creation_date.isoformat() if info.creation_date else None,
            "age_days": info.age_days,
        }

    @staticmethod
    def _get_first(value: Any) -> Any:
        """Get first item if value is a list, otherwise return value."""
        if isinstance(value, list):
            return value[0] if value else None
        return value

    @staticmethod
    def _normalize_list(value: Any) -> list[str] | None:
        """Normalize value to a list of strings."""
        if value is None:
            return None
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value if v]
        return None

    def _parse_date(self, value: Any) -> datetime | None:
        """Parse date value which may be a list or single value."""
        value = self._get_first(value)

        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            # Try common formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d",
                "%d-%b-%Y",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
        return None
