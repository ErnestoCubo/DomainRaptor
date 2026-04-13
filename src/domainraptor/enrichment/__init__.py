"""Enrichment module - threat intelligence and reputation clients.

Provides clients for enriching asset data with threat intelligence,
reputation scores, and historical information.
"""

from domainraptor.enrichment.securitytrails import (
    DomainInfo,
    HistoricalDnsRecord,
    SecurityTrailsClient,
)
from domainraptor.enrichment.virustotal import ReputationResult, VirusTotalClient

__all__ = [
    "DomainInfo",
    "HistoricalDnsRecord",
    "ReputationResult",
    "SecurityTrailsClient",
    "VirusTotalClient",
]
