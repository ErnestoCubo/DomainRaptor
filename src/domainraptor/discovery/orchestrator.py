"""Discovery orchestrator coordinating multiple discovery clients.

Manages parallel execution of discovery clients, result merging,
and deduplication of discovered assets.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from domainraptor.core.types import Asset, AssetType, Certificate, DnsRecord

logger = logging.getLogger(__name__)


class DiscoveryClient(Protocol):
    """Protocol for discovery clients."""

    name: str
    is_free: bool
    requires_api_key: bool

    def query(self, target: str) -> list[Asset]: ...


@dataclass
class DiscoveryResult:
    """Combined results from all discovery clients."""

    target: str
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None

    # Discovered assets by type
    subdomains: list[Asset] = field(default_factory=list)
    ips: list[Asset] = field(default_factory=list)
    domains: list[Asset] = field(default_factory=list)

    # Additional data
    certificates: list[Certificate] = field(default_factory=list)
    dns_records: list[DnsRecord] = field(default_factory=list)

    # Metadata
    sources_used: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def all_assets(self) -> list[Asset]:
        """Return all discovered assets."""
        return self.subdomains + self.ips + self.domains

    @property
    def unique_subdomains(self) -> set[str]:
        """Return unique subdomain values."""
        return {a.value for a in self.subdomains}

    @property
    def unique_ips(self) -> set[str]:
        """Return unique IP values."""
        return {a.value for a in self.ips}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "summary": {
                "total_subdomains": len(self.unique_subdomains),
                "total_ips": len(self.unique_ips),
                "total_domains": len(self.domains),
                "total_certificates": len(self.certificates),
                "total_dns_records": len(self.dns_records),
            },
            "sources_used": self.sources_used,
            "errors": self.errors,
            "subdomains": [a.value for a in self.subdomains],
            "ips": [a.value for a in self.ips],
        }


class DiscoveryOrchestrator:
    """Orchestrates multiple discovery clients.

    Coordinates parallel execution of discovery clients,
    merges results, and handles deduplication.

    Example:
        >>> from domainraptor.discovery import *
        >>> orchestrator = DiscoveryOrchestrator()
        >>> orchestrator.add_client(CrtShClient())
        >>> orchestrator.add_client(HackerTargetClient())
        >>> result = orchestrator.discover("example.com")
    """

    def __init__(
        self,
        max_workers: int = 4,
        include_dns: bool = True,
        include_whois: bool = True,
    ) -> None:
        self.max_workers = max_workers
        self.include_dns = include_dns
        self.include_whois = include_whois
        self._clients: list[DiscoveryClient] = []
        self._dns_client: Any = None
        self._whois_client: Any = None

    def add_client(self, client: DiscoveryClient) -> None:
        """Add a discovery client to the orchestrator."""
        self._clients.append(client)
        logger.debug(f"Added client: {client.name}")

    @property
    def dns_client(self) -> Any:
        """Lazy-initialized DNS client."""
        if self._dns_client is None and self.include_dns:
            from domainraptor.discovery.dns import DnsClient

            self._dns_client = DnsClient()
        return self._dns_client

    @property
    def whois_client(self) -> Any:
        """Lazy-initialized WHOIS client."""
        if self._whois_client is None and self.include_whois:
            from domainraptor.discovery.whois_client import WhoisClient

            self._whois_client = WhoisClient()
        return self._whois_client

    def discover(
        self,
        target: str,
        parallel: bool = True,
        resolve_ips: bool = True,
    ) -> DiscoveryResult:
        """Run discovery on a target domain.

        Args:
            target: Domain to discover assets for
            parallel: Run clients in parallel (recommended)
            resolve_ips: Resolve discovered domains to IPs

        Returns:
            DiscoveryResult with all discovered assets
        """
        logger.info(f"Starting discovery for {target}")

        result = DiscoveryResult(target=target)

        if not self._clients:
            logger.warning("No discovery clients configured")
            result.completed_at = datetime.now()
            return result

        # Run discovery clients
        if parallel:
            self._discover_parallel(target, result)
        else:
            self._discover_sequential(target, result)

        # Run DNS enumeration
        if self.dns_client:
            try:
                logger.info(f"Running DNS enumeration for {target}")
                dns_records = self.dns_client.query(target)
                result.dns_records.extend(dns_records)
                result.sources_used.append("dns")

                # Resolve IPs for target
                if resolve_ips:
                    ip_assets = self.dns_client.resolve_ip(target)
                    self._merge_assets(result.ips, ip_assets)
            except Exception as e:
                logger.error(f"DNS enumeration failed: {e}")
                result.errors["dns"] = str(e)

        # Optionally resolve IPs for all discovered subdomains
        if resolve_ips and self.dns_client:
            self._resolve_subdomain_ips(result)

        # Deduplicate results
        self._deduplicate(result)

        result.completed_at = datetime.now()
        logger.info(
            f"Discovery complete for {target}: "
            f"{len(result.unique_subdomains)} subdomains, "
            f"{len(result.unique_ips)} IPs"
        )

        return result

    def _discover_parallel(self, target: str, result: DiscoveryResult) -> None:
        """Run discovery clients in parallel using thread pool."""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_client = {
                executor.submit(client.query, target): client for client in self._clients
            }

            for future in as_completed(future_to_client):
                client = future_to_client[future]
                try:
                    assets = future.result()
                    self._process_client_results(client.name, assets, result)
                    result.sources_used.append(client.name)
                except Exception as e:
                    logger.error(f"Client {client.name} failed: {e}")
                    result.errors[client.name] = str(e)

    def _run_client_safe(self, client: Any, target: str) -> tuple[list[Asset], str | None]:
        """Run a discovery client safely waiting for success or error."""
        try:
            logger.info(f"Running client: {client.name}")
            assets = client.query(target)
            return assets, None
        except Exception as e:
            logger.error(f"Client {client.name} failed: {e}")
            return [], str(e)

    def _discover_sequential(self, target: str, result: DiscoveryResult) -> None:
        """Run discovery clients sequentially."""
        for client in self._clients:
            assets, error = self._run_client_safe(client, target)
            if error:
                result.errors[client.name] = error
            else:
                self._process_client_results(client.name, assets, result)
                result.sources_used.append(client.name)

    def _process_client_results(
        self,
        source: str,
        assets: list[Asset],
        result: DiscoveryResult,
    ) -> None:
        """Process and categorize assets from a client."""
        for asset in assets:
            if asset.type == AssetType.SUBDOMAIN:
                self._merge_assets(result.subdomains, [asset])
            elif asset.type == AssetType.IP:
                self._merge_assets(result.ips, [asset])
            elif asset.type == AssetType.DOMAIN:
                self._merge_assets(result.domains, [asset])

        logger.debug(f"Processed {len(assets)} assets from {source}")

    def _merge_assets(self, target_list: list[Asset], new_assets: list[Asset]) -> None:
        """Merge new assets into target list, updating existing entries."""
        existing = {a.value: a for a in target_list}

        for asset in new_assets:
            if asset.value in existing:
                # Update existing asset with additional source info
                existing_asset = existing[asset.value]
                if asset.source not in (existing_asset.metadata.get("sources") or []):
                    sources = existing_asset.metadata.get("sources", [])
                    if not sources:
                        sources = [existing_asset.source]
                    sources.append(asset.source)
                    existing_asset.metadata["sources"] = sources
                # Update last_seen
                if asset.last_seen:
                    existing_asset.last_seen = asset.last_seen
            else:
                target_list.append(asset)
                existing[asset.value] = asset

    def _resolve_single_subdomain(self, subdomain: str) -> list[Asset]:
        """Resolve IPs for a single subdomain."""
        try:
            ip_assets = self.dns_client.resolve_ip(subdomain)  # type: ignore[union-attr]
            for ip_asset in ip_assets:
                ip_asset.parent = subdomain
            return ip_assets
        except Exception as e:
            logger.debug(f"Failed to resolve {subdomain}: {e}")
            return []

    def _resolve_subdomain_ips(self, result: DiscoveryResult) -> None:
        """Resolve IPs for discovered subdomains and update metadata."""
        if not self.dns_client:
            return

        # Limit to avoid too many DNS queries
        max_resolve = 50
        to_resolve = list(result.unique_subdomains)[:max_resolve]

        logger.info(f"Resolving IPs for {len(to_resolve)} subdomains")

        # Create a map of subdomain value -> Asset for updating metadata
        subdomain_map = {a.value.lower(): a for a in result.subdomains}

        for subdomain in to_resolve:
            ip_assets = self._resolve_single_subdomain(subdomain)
            self._merge_assets(result.ips, ip_assets)

            # Update subdomain metadata with resolved IP
            if ip_assets:
                subdomain_key = subdomain.lower()
                if subdomain_key in subdomain_map:
                    # Store first IP in metadata for display
                    subdomain_map[subdomain_key].metadata["ip"] = ip_assets[0].value
                    # Store all IPs if multiple
                    if len(ip_assets) > 1:
                        subdomain_map[subdomain_key].metadata["all_ips"] = [
                            a.value for a in ip_assets
                        ]

    def _deduplicate(self, result: DiscoveryResult) -> None:
        """Deduplicate assets in result."""
        # Simple deduplication by value
        seen_subdomains: dict[str, Asset] = {}
        for asset in result.subdomains:
            key = asset.value.lower()
            if key not in seen_subdomains:
                seen_subdomains[key] = asset
        result.subdomains = list(seen_subdomains.values())

        seen_ips: dict[str, Asset] = {}
        for asset in result.ips:
            if asset.value not in seen_ips:
                seen_ips[asset.value] = asset
        result.ips = list(seen_ips.values())

        seen_domains: dict[str, Asset] = {}
        for asset in result.domains:
            key = asset.value.lower()
            if key not in seen_domains:
                seen_domains[key] = asset
        result.domains = list(seen_domains.values())


def create_default_orchestrator() -> DiscoveryOrchestrator:
    """Create an orchestrator with default free clients.

    Returns:
        DiscoveryOrchestrator configured with free discovery clients
    """
    from domainraptor.discovery.crtsh import CrtShClient
    from domainraptor.discovery.hackertarget import HackerTargetClient

    orchestrator = DiscoveryOrchestrator()
    orchestrator.add_client(CrtShClient())
    orchestrator.add_client(HackerTargetClient())

    return orchestrator
