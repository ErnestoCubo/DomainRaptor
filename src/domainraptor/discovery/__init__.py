"""Discovery module for DomainRaptor.

Provides clients for discovering assets related to a target domain
using various free and paid data sources.
"""

from domainraptor.discovery.base import BaseClient, ClientConfig, RateLimiter, SubdomainClient
from domainraptor.discovery.crtsh import CrtShClient
from domainraptor.discovery.dns import DnsClient, DnsConfig
from domainraptor.discovery.hackertarget import HackerTargetClient
from domainraptor.discovery.orchestrator import (
    DiscoveryOrchestrator,
    DiscoveryResult,
    create_default_orchestrator,
)
from domainraptor.discovery.whois_client import WhoisClient, WhoisInfo

__all__ = [
    "BaseClient",
    "ClientConfig",
    "CrtShClient",
    "DiscoveryOrchestrator",
    "DiscoveryResult",
    "DnsClient",
    "DnsConfig",
    "HackerTargetClient",
    "RateLimiter",
    "SubdomainClient",
    "WhoisClient",
    "WhoisInfo",
    "create_default_orchestrator",
]
