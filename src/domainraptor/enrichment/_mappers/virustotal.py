"""VirusTotal API response → domain dataclass."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from domainraptor.enrichment.virustotal import ReputationResult


def parse_domain_result(data: dict[str, Any], domain: str) -> ReputationResult:
    """Parse VirusTotal ``/domains/{domain}`` response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    last_analysis = None
    if attrs.get("last_analysis_date"):
        with contextlib.suppress(ValueError, TypeError):
            last_analysis = datetime.fromtimestamp(attrs["last_analysis_date"])

    return ReputationResult(
        resource=domain,
        resource_type="domain",
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        total_engines=sum(stats.values()) if stats else 0,
        reputation_score=attrs.get("reputation", 0),
        last_analysis_date=last_analysis,
        categories=attrs.get("categories", {}),
        tags=attrs.get("tags", []),
        whois=attrs.get("whois", ""),
        registrar=attrs.get("registrar", ""),
        last_dns_records=attrs.get("last_dns_records", []),
    )


def parse_ip_result(data: dict[str, Any], ip: str) -> ReputationResult:
    """Parse VirusTotal ``/ip_addresses/{ip}`` response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    last_analysis = None
    if attrs.get("last_analysis_date"):
        with contextlib.suppress(ValueError, TypeError):
            last_analysis = datetime.fromtimestamp(attrs["last_analysis_date"])

    return ReputationResult(
        resource=ip,
        resource_type="ip",
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        total_engines=sum(stats.values()) if stats else 0,
        reputation_score=attrs.get("reputation", 0),
        last_analysis_date=last_analysis,
        tags=attrs.get("tags", []),
        as_owner=attrs.get("as_owner", ""),
        country=attrs.get("country", ""),
    )
