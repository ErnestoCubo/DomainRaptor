"""NVD (National Vulnerability Database) client for CVE enrichment.

NVD provides detailed CVE information including:
- Description
- CVSS scores (v2, v3, v4)
- Severity ratings
- References
- CWE mappings

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limits: ~50 requests per 30 seconds (no API key)
            ~50 requests per 5 seconds (with free API key)

Get API key at: https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class NVDError(Exception):
    """Base exception for NVD client errors."""

    pass


class NVDRateLimitError(NVDError):
    """Raised when rate limit is exceeded."""

    pass


@dataclass
class CVEInfo:
    """Detailed CVE information from NVD."""

    cve_id: str
    description: str = ""
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_v3_score: float | None = None
    cvss_v3_vector: str = ""
    cvss_v2_score: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_date: str = ""
    last_modified: str = ""
    exploitability_score: float | None = None
    impact_score: float | None = None


class NVDClient:
    """Client for NVD API to enrich CVE data.

    Example:
        >>> client = NVDClient()
        >>> info = client.get_cve("CVE-2022-1292")
        >>> print(f"{info.cve_id}: {info.description[:100]}...")
        >>> print(f"Severity: {info.severity} (CVSS: {info.cvss_v3_score})")
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None) -> None:
        """Initialize NVD client.

        Args:
            api_key: NVD API key for higher rate limits.
                     Falls back to NVD_API_KEY env var.
        """
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._last_request = 0.0
        # Rate limit: 0.6s without key, 0.1s with key
        self._min_interval = 0.1 if self.api_key else 0.6

        self._client = httpx.Client(timeout=30)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> NVDClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _rate_limit(self) -> None:
        """Enforce rate limiting."""
        elapsed = time.time() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    def get_cve(self, cve_id: str, max_retries: int = 3) -> CVEInfo | None:
        """Get detailed information for a CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2022-1292)
            max_retries: Max retry attempts on rate limit (with backoff)

        Returns:
            CVEInfo with details, or None if not found
        """
        self._rate_limit()

        params: dict[str, str] = {"cveId": cve_id}
        headers: dict[str, str] = {}

        if self.api_key:
            headers["apiKey"] = self.api_key

        for attempt in range(max_retries + 1):
            try:
                response = self._client.get(
                    self.BASE_URL,
                    params=params,
                    headers=headers,
                )

                if response.status_code == 429:
                    if attempt < max_retries:
                        # Exponential backoff: 2s, 4s, 8s
                        wait_time = 2 ** (attempt + 1)
                        logger.info(
                            f"Rate limited, waiting {wait_time}s (attempt {attempt + 1}/{max_retries})"
                        )
                        time.sleep(wait_time)
                        continue
                    raise NVDRateLimitError("NVD rate limit exceeded after retries.")

                if response.status_code == 404:
                    logger.warning(f"CVE not found in NVD: {cve_id}")
                    return None

                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    return None

                return self._parse_cve(vulnerabilities[0])

            except NVDError:
                raise
            except Exception as e:
                logger.error(f"NVD lookup failed for {cve_id}: {e}")
                return None

        return None  # Should not reach here

    def get_cves_batch(
        self,
        cve_ids: list[str],
        max_concurrent: int = 5,
    ) -> dict[str, CVEInfo]:
        """Get information for multiple CVEs.

        Note: NVD API doesn't support batch queries, so this makes
        sequential requests with rate limiting.

        Args:
            cve_ids: List of CVE identifiers
            max_concurrent: Not used (sequential only due to rate limits)

        Returns:
            Dict mapping CVE ID to CVEInfo
        """
        results: dict[str, CVEInfo] = {}

        for cve_id in cve_ids:
            try:
                info = self.get_cve(cve_id)
                if info:
                    results[cve_id] = info
            except NVDRateLimitError:  # noqa: PERF203
                logger.warning("Rate limit hit, pausing for 30s...")
                time.sleep(30)
                # Retry once
                info = self.get_cve(cve_id)
                if info:
                    results[cve_id] = info
            except Exception as e:
                logger.error(f"Failed to fetch {cve_id}: {e}")

        return results

    def _parse_cve(self, vuln_data: dict[str, Any]) -> CVEInfo:
        """Parse NVD API response for a single CVE."""
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")

        # Get English description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get CVSS v3 metrics (prefer v3.1 over v3.0)
        cvss_v3_score = None
        cvss_v3_vector = ""
        severity = "MEDIUM"
        exploitability = None
        impact = None

        metrics = cve.get("metrics", {})

        # Try CVSS v3.1 first
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            primary = cvss_v31[0]
            cvss_data = primary.get("cvssData", {})
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity", "MEDIUM")
            exploitability = primary.get("exploitabilityScore")
            impact = primary.get("impactScore")

        # Fall back to v3.0
        elif metrics.get("cvssMetricV30"):
            cvss_v30 = metrics["cvssMetricV30"][0]
            cvss_data = cvss_v30.get("cvssData", {})
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity", "MEDIUM")
            exploitability = cvss_v30.get("exploitabilityScore")
            impact = cvss_v30.get("impactScore")

        # Get CVSS v2 as fallback for severity
        cvss_v2_score = None
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            cvss_data = cvss_v2[0].get("cvssData", {})
            cvss_v2_score = cvss_data.get("baseScore")
            if not cvss_v3_score:
                # Use v2 severity if no v3
                v2_severity = cvss_v2[0].get("baseSeverity", "MEDIUM")
                severity = v2_severity

        # Get CWE IDs
        cwe_ids = []
        weaknesses = cve.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id.startswith("CWE-"):
                    cwe_ids.append(cwe_id)

        # Get references (limit to 10)
        references = []
        for ref in cve.get("references", [])[:10]:
            url = ref.get("url", "")
            if url:
                references.append(url)

        return CVEInfo(
            cve_id=cve_id,
            description=description,
            severity=severity.upper(),
            cvss_v3_score=cvss_v3_score,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_score=cvss_v2_score,
            cwe_ids=cwe_ids,
            references=references,
            published_date=cve.get("published", ""),
            last_modified=cve.get("lastModified", ""),
            exploitability_score=exploitability,
            impact_score=impact,
        )


def enrich_vulnerabilities(
    vulns: list[dict[str, Any]],
    show_progress: bool = False,
) -> list[dict[str, Any]]:
    """Enrich vulnerability data with NVD information.

    Args:
        vulns: List of vulnerability dicts with 'id' or 'cve_id' key
        show_progress: Print progress messages

    Returns:
        Enriched vulnerability list
    """
    if not vulns:
        return vulns

    client = NVDClient()

    try:
        for i, vuln in enumerate(vulns):
            cve_id = vuln.get("id") or vuln.get("cve_id") or vuln.get("vuln_id")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            if show_progress:
                logger.info(f"Fetching {cve_id} ({i + 1}/{len(vulns)})...")

            info = client.get_cve(cve_id)
            if info:
                vuln["description"] = info.description
                vuln["severity"] = info.severity
                vuln["cvss_score"] = info.cvss_v3_score or info.cvss_v2_score
                vuln["cvss_vector"] = info.cvss_v3_vector
                vuln["cwe_ids"] = info.cwe_ids
                vuln["references"] = info.references

    finally:
        client.close()

    return vulns
