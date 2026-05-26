"""ASN / BGP lookup client.

Given an organization name or an ASN (autonomous system number), returns the
list of announced IP prefixes (CIDR ranges). This is a core ASM primitive:
the legitimate IP space of an organization is part of its attack surface.

Sources used (all free, no key):
- BGPView (https://bgpview.io/) — JSON API for ASN → prefix lookups and
  organization name → ASN search.
- Falls back to RIPEstat (https://stat.ripe.net/data/announced-prefixes/) when
  BGPView is unavailable.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from domainraptor.core.types import Asset, AssetType
from domainraptor.discovery.base import BaseClient, ClientConfig

logger = logging.getLogger(__name__)


BGPVIEW_URL = "https://api.bgpview.io"
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
ASN_RE = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)


@dataclass
class AsnInfo:
    """Information about an autonomous system."""

    asn: int
    name: str = ""
    description: str = ""
    country: str = ""
    prefixes_v4: list[str] = field(default_factory=list)
    prefixes_v6: list[str] = field(default_factory=list)

    @property
    def all_prefixes(self) -> list[str]:
        return [*self.prefixes_v4, *self.prefixes_v6]


class AsnClient(BaseClient[Asset]):
    """Lookup ASNs and their announced prefixes."""

    name = "asn"
    is_free = True
    requires_api_key = False

    def __init__(self, config: ClientConfig | None = None) -> None:
        if config is None:
            config = ClientConfig(rate_limit=1.0, timeout=30)
        super().__init__(config)

    @staticmethod
    def _parse_asn(query: str) -> int | None:
        match = ASN_RE.match(query.strip())
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

    def _search_asn_by_name(self, name: str) -> list[int]:
        """Use BGPView's full-text search to map a name to ASNs."""
        url = f"{BGPVIEW_URL}/search"
        try:
            response = self.get(url, params={"query_term": name})
            payload = response.json()
        except Exception as exc:
            logger.error("asn: search by name failed for %s: %s", name, exc)
            return []

        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        asns: list[int] = []
        for entry in data.get("asns", []):
            raw = entry.get("asn") if isinstance(entry, dict) else None
            if raw is None:
                continue
            try:
                asn_value = int(raw)
            except (TypeError, ValueError):
                logger.debug("asn: ignoring non-numeric ASN entry %r", raw)
                continue
            asns.append(asn_value)
        return asns

    def _fetch_bgpview_asn(self, asn: int) -> AsnInfo | None:
        try:
            details = self.get(f"{BGPVIEW_URL}/asn/{asn}").json()
            prefixes = self.get(f"{BGPVIEW_URL}/asn/{asn}/prefixes").json()
        except Exception as exc:
            logger.warning("asn: BGPView lookup failed for AS%d: %s", asn, exc)
            return None

        info_data = (details or {}).get("data", {}) if isinstance(details, dict) else {}
        pref_data = (prefixes or {}).get("data", {}) if isinstance(prefixes, dict) else {}

        info = AsnInfo(
            asn=asn,
            name=str(info_data.get("name", "")),
            description=str(info_data.get("description_short", "")),
            country=str(info_data.get("country_code", "")),
        )
        for ipv4 in pref_data.get("ipv4_prefixes", []) or []:
            prefix = ipv4.get("prefix") if isinstance(ipv4, dict) else None
            if prefix:
                info.prefixes_v4.append(str(prefix))
        for ipv6 in pref_data.get("ipv6_prefixes", []) or []:
            prefix = ipv6.get("prefix") if isinstance(ipv6, dict) else None
            if prefix:
                info.prefixes_v6.append(str(prefix))
        return info

    def _fetch_ripestat_asn(self, asn: int) -> AsnInfo | None:
        try:
            response = self.get(RIPESTAT_URL, params={"resource": f"AS{asn}"})
            payload = response.json()
        except Exception as exc:
            logger.warning("asn: RIPEstat lookup failed for AS%d: %s", asn, exc)
            return None

        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        info = AsnInfo(asn=asn, name=f"AS{asn}")
        for prefix_entry in data.get("prefixes", []) or []:
            prefix = prefix_entry.get("prefix") if isinstance(prefix_entry, dict) else None
            if not prefix:
                continue
            if ":" in prefix:
                info.prefixes_v6.append(str(prefix))
            else:
                info.prefixes_v4.append(str(prefix))
        return info

    def lookup_asn(self, asn: int) -> AsnInfo | None:
        """Fetch organization + prefixes for an ASN.

        Tries BGPView first, falls back to RIPEstat on failure.
        """
        info = self._fetch_bgpview_asn(asn)
        if info is None or not info.all_prefixes:
            ripe = self._fetch_ripestat_asn(asn)
            if ripe is not None:
                if info is None:
                    info = ripe
                else:
                    info.prefixes_v4 = ripe.prefixes_v4
                    info.prefixes_v6 = ripe.prefixes_v6
        return info

    def lookup(self, query: str) -> list[AsnInfo]:
        """Resolve a free-form query (ASN or organization name) to AsnInfo list."""
        asn = self._parse_asn(query)
        if asn is not None:
            info = self.lookup_asn(asn)
            return [info] if info else []

        asns = self._search_asn_by_name(query)
        results: list[AsnInfo] = []
        for found_asn in asns[:10]:  # cap to avoid runaway calls
            info = self.lookup_asn(found_asn)
            if info is not None:
                results.append(info)
        return results

    def query(self, target: str) -> list[Asset]:
        """Return announced prefixes as Asset objects (AssetType.IP)."""
        results = self.lookup(target)
        assets: list[Asset] = [
            Asset(
                type=AssetType.IP,
                value=prefix,
                source=self.name,
                metadata={
                    "asn": info.asn,
                    "asn_name": info.name,
                    "asn_description": info.description,
                    "country": info.country,
                    "is_cidr": True,
                },
            )
            for info in results
            for prefix in info.all_prefixes
        ]
        logger.info("asn: %d prefixes resolved for query %s", len(assets), target)
        return assets
