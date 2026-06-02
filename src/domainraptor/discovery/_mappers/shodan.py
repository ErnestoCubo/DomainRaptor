"""Shodan API response → domain dataclass."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from domainraptor.core.types import Service
from domainraptor.discovery.shodan_client import ShodanHostResult


def parse_host_result(data: dict[str, Any]) -> ShodanHostResult:
    """Parse a Shodan ``/shodan/host/{ip}`` response."""
    services: list[Service] = []

    for item in data.get("data", []):
        port = item.get("port", 0)
        transport = item.get("transport", "tcp")

        service = Service(
            port=port,
            protocol=transport,
            service_name=item.get("product", "") or item.get("_shodan", {}).get("module", ""),
            version=item.get("version", "") or "",
            banner=item.get("data", "")[:500] if item.get("data") else "",
            cpe=item.get("cpe", []) or [],
            metadata={
                "module": item.get("_shodan", {}).get("module", ""),
                "ssl": bool(item.get("ssl")),
                "http": item.get("http", {}),
            },
        )
        services.append(service)

    last_update = None
    if data.get("last_update"):
        with contextlib.suppress(ValueError, AttributeError):
            last_update = datetime.fromisoformat(data["last_update"].replace("Z", "+00:00"))

    # Handle vulns - can be dict (older API) or list (newer API)
    raw_vulns = data.get("vulns", [])
    if isinstance(raw_vulns, dict):
        vuln_list = list(raw_vulns.keys())
    elif isinstance(raw_vulns, list):
        vuln_list = raw_vulns
    else:
        vuln_list = []

    return ShodanHostResult(
        ip=data.get("ip_str", ""),
        hostnames=data.get("hostnames", []),
        country=data.get("country_name", "") or data.get("country_code", ""),
        city=data.get("city", "") or "",
        org=data.get("org", "") or "",
        asn=data.get("asn", "") or "",
        isp=data.get("isp", "") or "",
        os=data.get("os"),
        ports=data.get("ports", []),
        services=services,
        vulns=vuln_list,
        last_update=last_update,
        tags=data.get("tags", []),
    )
