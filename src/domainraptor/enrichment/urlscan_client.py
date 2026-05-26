"""URLScan.io enrichment client.

URLScan.io maintains a public database of web scans performed by users. We
query its search API to surface the technologies, IPs and ASNs detected for
the target domain in recent scans — a pure ASM signal, not an IoC lookup.

API:    https://urlscan.io/docs/api/
Search: https://urlscan.io/api/v1/search/
Result: https://urlscan.io/api/v1/result/<uuid>/

Anonymous searches are allowed but limited. An API key (URLSCAN_API_KEY) is
optional and unlocks higher rate limits and private scans.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from domainraptor.discovery.base import BaseClient, ClientConfig

logger = logging.getLogger(__name__)

SEARCH_URL = "https://urlscan.io/api/v1/search/"
RESULT_URL = "https://urlscan.io/api/v1/result/"


@dataclass
class UrlscanResult:
    """Summary of a single URLScan scan."""

    scan_id: str
    url: str
    domain: str
    ip: str = ""
    country: str = ""
    server: str = ""
    asn: str = ""
    asn_name: str = ""
    screenshot_url: str = ""
    result_url: str = ""
    indexed_at: str = ""


@dataclass
class UrlscanEnrichment:
    """Aggregated URLScan enrichment for a target."""

    target: str
    total_scans: int = 0
    results: list[UrlscanResult] = field(default_factory=list)
    unique_ips: list[str] = field(default_factory=list)
    unique_asns: list[str] = field(default_factory=list)
    unique_servers: list[str] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)


class UrlscanClient(BaseClient[UrlscanResult]):
    """Client for URLScan.io's public search API."""

    name = "urlscan"
    is_free = True
    requires_api_key = False

    def __init__(
        self,
        config: ClientConfig | None = None,
        api_key: str | None = None,
    ) -> None:
        api_key = api_key or os.environ.get("URLSCAN_API_KEY")
        headers: dict[str, str] = {}
        if api_key:
            headers["API-Key"] = api_key
        if config is None:
            config = ClientConfig(
                rate_limit=0.5,
                timeout=30,
                api_key=api_key,
                headers=headers,
            )
        else:
            config.api_key = config.api_key or api_key
            config.headers = {**config.headers, **headers}
        super().__init__(config)

    def query(self, target: str) -> list[UrlscanResult]:
        """Return recent URLScan results for the target domain."""
        target = target.lower().strip()
        params = {"q": f"page.domain:{target}", "size": "100"}

        try:
            response = self.get(SEARCH_URL, params=params)
            payload = response.json()
        except Exception as exc:
            logger.error("urlscan: search failed for %s: %s", target, exc)
            return []

        results: list[UrlscanResult] = []
        for hit in payload.get("results", []):
            if not isinstance(hit, dict):
                continue
            page = hit.get("page", {}) or {}
            task = hit.get("task", {}) or {}
            results.append(
                UrlscanResult(
                    scan_id=str(hit.get("_id", "")),
                    url=str(task.get("url", "") or page.get("url", "")),
                    domain=str(page.get("domain", "")),
                    ip=str(page.get("ip", "")),
                    country=str(page.get("country", "")),
                    server=str(page.get("server", "")),
                    asn=str(page.get("asn", "")),
                    asn_name=str(page.get("asnname", "")),
                    screenshot_url=str(hit.get("screenshot", "")),
                    result_url=str(hit.get("result", "")),
                    indexed_at=str(hit.get("indexedAt", "")),
                )
            )
        logger.info("urlscan: %d scans found for %s", len(results), target)
        return results

    def enrich(self, target: str) -> UrlscanEnrichment:
        """Run a query and return aggregated enrichment data."""
        results = self.query(target)
        ips: dict[str, None] = {}
        asns: dict[str, None] = {}
        servers: dict[str, None] = {}
        countries: dict[str, None] = {}
        for result in results:
            if result.ip:
                ips.setdefault(result.ip, None)
            if result.asn:
                asn_label = f"{result.asn} ({result.asn_name})" if result.asn_name else result.asn
                asns.setdefault(asn_label, None)
            if result.server:
                servers.setdefault(result.server, None)
            if result.country:
                countries.setdefault(result.country, None)
        return UrlscanEnrichment(
            target=target,
            total_scans=len(results),
            results=results,
            unique_ips=list(ips),
            unique_asns=list(asns),
            unique_servers=list(servers),
            countries=list(countries),
        )
