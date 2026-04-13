"""Discovery module for DomainRaptor.

Provides clients for discovering assets related to a target domain
using various free and paid data sources.
"""

from domainraptor.discovery.base import BaseClient, ClientConfig, RateLimiter, SubdomainClient
from domainraptor.discovery.censys_client import (
    CensysCertificateResult,
    CensysClient,
    CensysHostResult,
)
from domainraptor.discovery.crtsh import CrtShClient
from domainraptor.discovery.dns import DnsClient, DnsConfig
from domainraptor.discovery.hackertarget import HackerTargetClient
from domainraptor.discovery.orchestrator import (
    DiscoveryOrchestrator,
    DiscoveryResult,
    create_default_orchestrator,
)
from domainraptor.discovery.shodan_client import ShodanClient, ShodanHostResult
from domainraptor.discovery.whois_client import WhoisClient, WhoisInfo
from domainraptor.discovery.zoomeye_client import ZoomEyeClient, ZoomEyeHostResult

__all__ = [
    "BaseClient",
    "CensysCertificateResult",
    "CensysClient",
    "CensysHostResult",
    "ClientConfig",
    "CrtShClient",
    "DiscoveryOrchestrator",
    "DiscoveryResult",
    "DnsClient",
    "DnsConfig",
    "HackerTargetClient",
    "RateLimiter",
    "ShodanClient",
    "ShodanHostResult",
    "SubdomainClient",
    "WhoisClient",
    "WhoisInfo",
    "ZoomEyeClient",
    "ZoomEyeHostResult",
    "create_default_orchestrator",
]
