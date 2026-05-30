"""Censys API response → domain dataclass."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from domainraptor.core.types import Service
from domainraptor.discovery.censys_client import CensysHostResult


def parse_host_hit(hit: dict[str, Any]) -> CensysHostResult:
    """Parse a Censys ``/v2/hosts/search`` hit entry."""
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


def parse_host_detail(result: dict[str, Any]) -> CensysHostResult:
    """Parse a Censys ``/v2/hosts/{ip}`` detail response."""
    services: list[Service] = []

    for svc in result.get("services", []):
        port = svc.get("port", 0)
        service = Service(
            port=port,
            protocol=svc.get("transport_protocol", "tcp"),
            service_name=svc.get("service_name", "") or "",
            version=svc.get("software", [{}])[0].get("version", "") if svc.get("software") else "",
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
            last_update = datetime.fromisoformat(result["last_updated_at"].replace("Z", "+00:00"))

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
