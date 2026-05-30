"""ZoomEye API response → domain dataclass."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from domainraptor.core.types import Service
from domainraptor.discovery.zoomeye_client import ZoomEyeHostResult


def parse_host_match(match: dict[str, Any]) -> ZoomEyeHostResult:
    """Parse a ZoomEye ``/host/search`` match entry."""
    portinfo = match.get("portinfo", {})
    geoinfo = match.get("geoinfo", {})

    services: list[Service] = []
    port = portinfo.get("port", 0)
    if port:
        service = Service(
            port=port,
            protocol=portinfo.get("protocol", "tcp"),
            service_name=portinfo.get("service", "") or portinfo.get("app", ""),
            version=portinfo.get("version", "") or "",
            banner=portinfo.get("banner", "")[:500] if portinfo.get("banner") else "",
            metadata={
                "device": portinfo.get("device", ""),
                "os": portinfo.get("os", ""),
                "extrainfo": portinfo.get("extrainfo", ""),
            },
        )
        services.append(service)

    last_update = None
    timestamp = match.get("timestamp")
    if timestamp:
        with contextlib.suppress(ValueError):
            last_update = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    return ZoomEyeHostResult(
        ip=match.get("ip", ""),
        hostnames=portinfo.get("hostname", [])
        if isinstance(portinfo.get("hostname"), list)
        else [],
        country=geoinfo.get("country", {}).get("names", {}).get("en", "") or "",
        city=geoinfo.get("city", {}).get("names", {}).get("en", "") or "",
        org=geoinfo.get("organization", "") or "",
        asn=geoinfo.get("asn", "") or "",
        isp=geoinfo.get("isp", "") or "",
        os=portinfo.get("os", "") or None,
        ports=[port] if port else [],
        services=services,
        vulns=[],  # ZoomEye doesn't provide CVEs in basic search
        last_update=last_update,
        device_type=portinfo.get("device", "") or "",
        banner=portinfo.get("banner", "")[:500] if portinfo.get("banner") else "",
    )
