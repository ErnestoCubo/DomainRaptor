"""DNS resolver client using dnspython.

Performs DNS record enumeration for domains including A, AAAA, MX, TXT,
NS, CNAME, SOA, and other record types.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, ClassVar

import dns.exception
import dns.resolver
import dns.reversename

from domainraptor.core.types import Asset, AssetType, DnsRecord

logger = logging.getLogger(__name__)


@dataclass
class DnsConfig:
    """Configuration for DNS resolver."""

    nameservers: list[str] | None = None  # Use system default if None
    timeout: float = 5.0
    lifetime: float = 10.0  # Total time for all retries
    retry_servfail: bool = True


class DnsClient:
    """DNS resolver client for record enumeration.

    Uses dnspython for reliable DNS lookups with support for
    all common record types.

    Example:
        >>> client = DnsClient()
        >>> records = client.query("example.com")
        >>> for record in records:
        ...     print(f"{record.record_type}: {record.value}")
    """

    name = "dns"
    is_free = True
    requires_api_key = False

    # Record types to query by default
    DEFAULT_RECORD_TYPES: ClassVar[list[str]] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    # Additional record types for deep scans
    EXTENDED_RECORD_TYPES: ClassVar[list[str]] = ["SRV", "CAA", "PTR", "DNSKEY", "DS", "NAPTR"]

    def __init__(self, config: DnsConfig | None = None) -> None:
        self.config = config or DnsConfig()
        self._resolver: dns.resolver.Resolver | None = None

    @property
    def resolver(self) -> dns.resolver.Resolver:
        """Lazy-initialized DNS resolver."""
        if self._resolver is None:
            self._resolver = dns.resolver.Resolver()

            if self.config.nameservers:
                self._resolver.nameservers = self.config.nameservers

            self._resolver.timeout = self.config.timeout
            self._resolver.lifetime = self.config.lifetime
            self._resolver.retry_servfail = self.config.retry_servfail

        return self._resolver

    def query(
        self,
        target: str,
        record_types: list[str] | None = None,
        include_extended: bool = False,
    ) -> list[DnsRecord]:
        """Query DNS records for a domain.

        Args:
            target: Domain to query
            record_types: Specific record types to query (default: common types)
            include_extended: Include extended record types (SRV, CAA, etc.)

        Returns:
            List of DnsRecord objects
        """
        if record_types is None:
            record_types = list(self.DEFAULT_RECORD_TYPES)
            if include_extended:
                record_types.extend(self.EXTENDED_RECORD_TYPES)

        logger.info(f"DNS: Querying {target} for {len(record_types)} record types")

        records: list[DnsRecord] = []

        for rtype in record_types:
            try:
                answers = self.resolver.resolve(target, rtype)

                for rdata in answers:
                    record = self._parse_record(rtype, rdata, answers.rrset.ttl)
                    if record:
                        records.append(record)

            except dns.resolver.NoAnswer:
                logger.debug(f"DNS: No {rtype} records for {target}")
            except dns.resolver.NXDOMAIN:
                logger.warning(f"DNS: Domain {target} does not exist")
                break  # No point querying more record types
            except dns.resolver.NoNameservers:
                logger.error(f"DNS: No nameservers available for {target}")
                break
            except dns.exception.Timeout:
                logger.warning(f"DNS: Timeout querying {rtype} for {target}")
            except Exception as e:
                logger.debug(f"DNS: Error querying {rtype} for {target}: {e}")

        logger.info(f"DNS: Found {len(records)} records for {target}")
        return records

    def resolve_ip(self, target: str) -> list[Asset]:
        """Resolve a domain to IP addresses.

        Args:
            target: Domain to resolve

        Returns:
            List of Asset objects for discovered IPs
        """
        assets: list[Asset] = []

        # IPv4
        try:
            answers = self.resolver.resolve(target, "A")
            for rdata in answers:
                assets.append(
                    Asset(
                        type=AssetType.IP,
                        value=str(rdata),
                        parent=target,
                        source=self.name,
                        metadata={"ip_version": 4},
                    )
                )
        except Exception as e:
            logger.debug(f"DNS: No A records for {target}: {e}")

        # IPv6
        try:
            answers = self.resolver.resolve(target, "AAAA")
            for rdata in answers:
                assets.append(
                    Asset(
                        type=AssetType.IP,
                        value=str(rdata),
                        parent=target,
                        source=self.name,
                        metadata={"ip_version": 6},
                    )
                )
        except Exception as e:
            logger.debug(f"DNS: No AAAA records for {target}: {e}")

        return assets

    def reverse_lookup(self, ip: str) -> str | None:
        """Perform reverse DNS lookup for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            Hostname if found, None otherwise
        """
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, "PTR")

            if answers:
                # Remove trailing dot
                return str(answers[0]).rstrip(".")
        except Exception as e:
            logger.debug(f"DNS: Reverse lookup failed for {ip}: {e}")

        return None

    def check_dnssec(self, target: str) -> dict[str, Any]:
        """Check DNSSEC configuration for a domain.

        Args:
            target: Domain to check

        Returns:
            Dict with DNSSEC status and details
        """
        result = {
            "enabled": False,
            "dnskey": False,
            "ds": False,
            "validated": False,
        }

        # Check for DNSKEY records
        try:
            answers = self.resolver.resolve(target, "DNSKEY")
            if answers:
                result["dnskey"] = True
                result["enabled"] = True
        except Exception:
            pass

        # Check for DS records (delegation signer)
        try:
            answers = self.resolver.resolve(target, "DS")
            if answers:
                result["ds"] = True
        except Exception:
            pass

        return result

    def check_email_security(self, target: str) -> dict[str, Any]:
        """Check email security records (SPF, DMARC, DKIM hint).

        Args:
            target: Domain to check

        Returns:
            Dict with email security configuration status
        """
        result = {
            "spf": {"configured": False, "record": None},
            "dmarc": {"configured": False, "record": None},
            "dkim_selector_hint": None,
        }

        # Check SPF (in TXT records)
        try:
            answers = self.resolver.resolve(target, "TXT")
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith("v=spf1"):
                    result["spf"]["configured"] = True
                    result["spf"]["record"] = txt_value
                    break
        except Exception:
            pass

        # Check DMARC
        try:
            answers = self.resolver.resolve(f"_dmarc.{target}", "TXT")
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith("v=DMARC1"):
                    result["dmarc"]["configured"] = True
                    result["dmarc"]["record"] = txt_value
                    break
        except Exception:
            pass

        return result

    def _parse_record(
        self,
        rtype: str,
        rdata: Any,
        ttl: int,
    ) -> DnsRecord | None:
        """Parse DNS response data into DnsRecord object."""
        value = str(rdata)
        priority = None

        # Handle MX records (have priority)
        if rtype == "MX":
            priority = rdata.preference
            value = str(rdata.exchange).rstrip(".")

        # Handle SOA records
        elif rtype == "SOA":
            value = f"mname={rdata.mname} rname={rdata.rname} serial={rdata.serial}"

        # Handle SRV records
        elif rtype == "SRV":
            priority = rdata.priority
            value = f"{rdata.target}:{rdata.port} (weight={rdata.weight})"

        # Clean up trailing dots from domain names
        if rtype in ("NS", "CNAME", "PTR"):
            value = value.rstrip(".")

        # Clean up TXT records (remove quotes)
        if rtype == "TXT":
            value = value.strip('"')

        return DnsRecord(
            record_type=rtype,
            value=value,
            ttl=ttl,
            priority=priority,
        )
