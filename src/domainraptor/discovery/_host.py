"""Shared host-information dataclass for discovery clients.

Each external host-intelligence provider (Shodan, Censys, ZoomEye, ...)
returns a similar set of fields describing a host: IP, hostnames,
geolocation, ASN, open ports, observed services, etc. Historically every
client carried its own `*HostResult` dataclass with overlapping fields,
which made cross-source aggregation in the discovery orchestrator
awkward.

:class:`HostInformation` is a common base dataclass holding the union of
those shared fields. Each provider keeps its own subclass to add fields
specific to that source (e.g. Shodan's ``vulns``/``tags`` or ZoomEye's
``device_type``). The base is concrete (not abstract) so it can be used
directly by future generic call sites that only need the common fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from domainraptor.core.types import Service


@dataclass
class HostInformation:
    """Base host-intelligence result shared across discovery providers."""

    ip: str
    hostnames: list[str] = field(default_factory=list)
    country: str = ""
    city: str = ""
    asn: str = ""
    os: str | None = None
    ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    last_update: datetime | None = None


__all__ = ["HostInformation"]
