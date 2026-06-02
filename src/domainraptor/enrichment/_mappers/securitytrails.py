"""SecurityTrails API response → domain dataclasses."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from domainraptor.enrichment.securitytrails import DomainInfo, HistoricalDnsRecord


def parse_domain_result(data: dict[str, Any], domain: str) -> DomainInfo:
    """Parse SecurityTrails ``/domain/{domain}`` response."""
    current_dns: dict[str, list[str]] = {}

    dns_data = data.get("current_dns", {})
    for record_type in ["a", "aaaa", "mx", "ns", "soa", "txt"]:
        records = dns_data.get(record_type, {})
        values = records.get("values", [])
        if values:
            extracted = []
            for v in values:
                if isinstance(v, dict):
                    extracted.append(v.get("ip", v.get("value", str(v))))
                else:
                    extracted.append(str(v))
            current_dns[record_type.upper()] = extracted

    return DomainInfo(
        domain=domain,
        alexa_rank=data.get("alexa_rank"),
        apex_domain=data.get("apex_domain", domain),
        current_dns=current_dns,
        subdomain_count=data.get("subdomain_count", 0),
    )


def parse_dns_history(data: dict[str, Any], record_type: str) -> list[HistoricalDnsRecord]:
    """Parse SecurityTrails ``/history/{domain}/dns/{type}`` response."""
    records: list[HistoricalDnsRecord] = []

    for item in data.get("records", []):
        values = item.get("values", [])
        extracted_values = []
        organizations = []

        for v in values:
            if isinstance(v, dict):
                extracted_values.append(v.get("ip", v.get("value", str(v))))
                if v.get("ip_organization"):
                    organizations.append(v["ip_organization"])
            else:
                extracted_values.append(str(v))

        first_seen = None
        last_seen = None
        if item.get("first_seen"):
            with contextlib.suppress(ValueError, TypeError):
                first_seen = datetime.strptime(item["first_seen"], "%Y-%m-%d")
        if item.get("last_seen"):
            with contextlib.suppress(ValueError, TypeError):
                last_seen = datetime.strptime(item["last_seen"], "%Y-%m-%d")

        records.append(
            HistoricalDnsRecord(
                record_type=record_type.upper(),
                values=extracted_values,
                first_seen=first_seen,
                last_seen=last_seen,
                organizations=list(set(organizations)),
            )
        )

    return records
