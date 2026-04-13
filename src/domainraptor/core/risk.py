"""Risk Level calculation algorithm for DomainRaptor.

This module calculates a Risk Score (0-100) and Risk Level based on
multiple weighted factors:

- Vulnerabilities (40%): CVE severity, CVSS scores, known exploits
- Configuration (25%): Security headers, SSL/TLS issues, misconfigurations
- Exposure (25%): Attack surface size, sensitive ports, dev environments
- Reputation (10%): Blacklists, malicious indicators

For detailed documentation, see /docs/risk-algorithm.md
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from domainraptor.core.types import (
        Asset,
        Certificate,
        ConfigIssue,
        ScanResult,
        Service,
        Vulnerability,
    )


class RiskLevel(str, Enum):
    """Risk level classification."""

    CRITICAL = "CRITICAL"  # 80-100: Immediate action required
    HIGH = "HIGH"  # 60-79: Action within 7 days
    MEDIUM = "MEDIUM"  # 40-59: Plan mitigation
    LOW = "LOW"  # 20-39: Improvements recommended
    INFO = "INFO"  # 0-19: Minimal risk


# Weight configuration - can be customized
WEIGHT_VULNERABILITY = 0.40
WEIGHT_CONFIGURATION = 0.25
WEIGHT_EXPOSURE = 0.25
WEIGHT_REPUTATION = 0.10

# Vulnerability scoring points
VULN_CRITICAL_POINTS = 25
VULN_HIGH_POINTS = 15
VULN_MEDIUM_POINTS = 5
VULN_LOW_POINTS = 1
VULN_CVSS_HIGH_BONUS = 10  # For CVSS >= 9.0
VULN_EXPLOIT_BONUS = 15  # Max 30 for known exploits

# Configuration scoring points
CONFIG_CRITICAL_POINTS = 20
CONFIG_HIGH_POINTS = 12
CONFIG_MEDIUM_POINTS = 6
CONFIG_LOW_POINTS = 2
CONFIG_MISSING_HSTS = 8
CONFIG_MISSING_CSP = 6
CONFIG_DNSSEC_DISABLED = 5
CONFIG_CERT_EXPIRED = 15
CONFIG_CERT_SOON_30 = 8
CONFIG_CERT_SOON_90 = 3

# Exposure scoring points
EXPOSURE_SUBDOMAINS_50 = 10
EXPOSURE_SUBDOMAINS_20 = 5
EXPOSURE_DEV_STAGING = 8  # Max 24
EXPOSURE_SSH_PORT = 5
EXPOSURE_RDP_PORT = 8
EXPOSURE_DB_PORT = 10  # Each DB port
EXPOSURE_ADMIN_PORT = 3  # Each admin port
EXPOSURE_MANY_IPS = 5  # >10 unique IPs

# Reputation scoring points
REPUTATION_MALICIOUS = 30
REPUTATION_SUSPICIOUS = 10
REPUTATION_BLACKLIST = 20

# Sensitive port lists
SENSITIVE_PORTS_SSH = [22]
SENSITIVE_PORTS_RDP = [3389]
SENSITIVE_PORTS_DB = [
    3306,
    5432,
    27017,
    6379,
    1433,
    5984,
]  # MySQL, PostgreSQL, MongoDB, Redis, MSSQL, CouchDB
SENSITIVE_PORTS_ADMIN = [8080, 8443, 9000, 9090, 10000]

# Dev/staging patterns
DEV_STAGING_PATTERNS = [
    "dev.",
    "dev-",
    "staging.",
    "staging-",
    "test.",
    "test-",
    "uat.",
    "qa.",
    "demo.",
    "sandbox.",
    "local.",
    "internal.",
    "admin.",
    "backend.",
    "api-dev.",
    "api-test.",
]


@dataclass
class RiskFactor:
    """Individual risk factor contribution."""

    name: str
    points: float
    category: str  # vulnerability, configuration, exposure, reputation


@dataclass
class RiskAssessment:
    """Complete risk assessment result."""

    score: float  # 0-100 total score
    level: RiskLevel  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    vuln_contribution: float  # Points from vulnerabilities
    config_contribution: float  # Points from configuration
    exposure_contribution: float  # Points from exposure
    reputation_contribution: float  # Points from reputation
    top_factors: list[str] = field(default_factory=list)  # Top 5 factors
    all_factors: list[RiskFactor] = field(default_factory=list)  # All factors

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "risk_assessment": {
                "score": round(self.score, 1),
                "level": self.level.value,
                "breakdown": {
                    "vulnerabilities": round(self.vuln_contribution, 1),
                    "configuration": round(self.config_contribution, 1),
                    "exposure": round(self.exposure_contribution, 1),
                    "reputation": round(self.reputation_contribution, 1),
                },
                "top_factors": self.top_factors,
            }
        }


def calculate_risk_level(scan: ScanResult) -> RiskAssessment:
    """
    Calculate comprehensive risk level for a scan result.

    Args:
        scan: ScanResult with assets, vulnerabilities, config_issues, etc.

    Returns:
        RiskAssessment with score (0-100), level, and contributing factors.
    """
    all_factors: list[RiskFactor] = []

    # Calculate each category
    vuln_raw, vuln_factors = _calc_vuln_score(scan.vulnerabilities)
    config_raw, config_factors = _calc_config_score(scan.config_issues, scan.certificates)
    exposure_raw, exposure_factors = _calc_exposure_score(scan.assets, scan.services)
    reputation_raw, reputation_factors = _calc_reputation_score(scan)

    all_factors.extend(vuln_factors)
    all_factors.extend(config_factors)
    all_factors.extend(exposure_factors)
    all_factors.extend(reputation_factors)

    # Apply weights and cap at category maximum
    vuln_weighted = min(vuln_raw * WEIGHT_VULNERABILITY, 40)
    config_weighted = min(config_raw * WEIGHT_CONFIGURATION, 25)
    exposure_weighted = min(exposure_raw * WEIGHT_EXPOSURE, 25)
    reputation_weighted = min(reputation_raw * WEIGHT_REPUTATION, 10)

    # Total score (max 100)
    total = vuln_weighted + config_weighted + exposure_weighted + reputation_weighted
    total = min(total, 100)

    # Determine level
    level = (
        RiskLevel.CRITICAL
        if total >= 80
        else RiskLevel.HIGH
        if total >= 60
        else RiskLevel.MEDIUM
        if total >= 40
        else RiskLevel.LOW
        if total >= 20
        else RiskLevel.INFO
    )

    # Identify top factors
    top_factors = _identify_top_factors(all_factors, 5)

    return RiskAssessment(
        score=round(total, 1),
        level=level,
        vuln_contribution=round(vuln_weighted, 1),
        config_contribution=round(config_weighted, 1),
        exposure_contribution=round(exposure_weighted, 1),
        reputation_contribution=round(reputation_weighted, 1),
        top_factors=top_factors,
        all_factors=all_factors,
    )


def _calc_vuln_score(vulnerabilities: list[Vulnerability]) -> tuple[float, list[RiskFactor]]:
    """Calculate vulnerability score (raw points before weighting)."""
    score = 0.0
    factors: list[RiskFactor] = []
    exploit_bonus_used = 0

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for vuln in vulnerabilities:
        sev = (
            vuln.severity.value.upper()
            if hasattr(vuln.severity, "value")
            else str(vuln.severity).upper()
        )

        if sev == "CRITICAL":
            score += VULN_CRITICAL_POINTS
            severity_counts["CRITICAL"] += 1
        elif sev == "HIGH":
            score += VULN_HIGH_POINTS
            severity_counts["HIGH"] += 1
        elif sev == "MEDIUM":
            score += VULN_MEDIUM_POINTS
            severity_counts["MEDIUM"] += 1
        else:
            score += VULN_LOW_POINTS
            severity_counts["LOW"] += 1

        # CVSS bonus
        cvss = getattr(vuln, "cvss_score", None) or getattr(vuln, "metadata", {}).get(
            "cvss_score", 0
        )
        if cvss and float(cvss) >= 9.0:
            score += VULN_CVSS_HIGH_BONUS
            factors.append(
                RiskFactor(
                    name=f"CVSS {cvss} vulnerability: {vuln.id}",
                    points=VULN_CVSS_HIGH_BONUS,
                    category="vulnerability",
                )
            )

        # Known exploit bonus
        metadata = getattr(vuln, "metadata", {})
        has_exploit = (
            metadata.get("exploit_available")
            or metadata.get("has_exploit")
            or "exploit" in str(metadata.get("tags", "")).lower()
        )
        if has_exploit and exploit_bonus_used < 30:
            bonus = min(VULN_EXPLOIT_BONUS, 30 - exploit_bonus_used)
            score += bonus
            exploit_bonus_used += bonus
            factors.append(
                RiskFactor(name=f"Known exploit: {vuln.id}", points=bonus, category="vulnerability")
            )

    # Add severity count factors
    if severity_counts["CRITICAL"] > 0:
        factors.append(
            RiskFactor(
                name=f"{severity_counts['CRITICAL']} CRITICAL vulnerabilities found",
                points=severity_counts["CRITICAL"] * VULN_CRITICAL_POINTS,
                category="vulnerability",
            )
        )
    if severity_counts["HIGH"] > 0:
        factors.append(
            RiskFactor(
                name=f"{severity_counts['HIGH']} HIGH vulnerabilities found",
                points=severity_counts["HIGH"] * VULN_HIGH_POINTS,
                category="vulnerability",
            )
        )

    return score, factors


def _calc_config_score(
    config_issues: list[ConfigIssue], certificates: list[Certificate]
) -> tuple[float, list[RiskFactor]]:
    """Calculate configuration score (raw points before weighting)."""
    from datetime import datetime, timezone

    score = 0.0
    factors: list[RiskFactor] = []

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    missing_headers = {"hsts": False, "csp": False, "dnssec": False}

    for issue in config_issues:
        sev = (
            issue.severity.value.upper()
            if hasattr(issue.severity, "value")
            else str(issue.severity).upper()
        )

        if sev == "CRITICAL":
            score += CONFIG_CRITICAL_POINTS
            severity_counts["CRITICAL"] += 1
        elif sev == "HIGH":
            score += CONFIG_HIGH_POINTS
            severity_counts["HIGH"] += 1
        elif sev == "MEDIUM":
            score += CONFIG_MEDIUM_POINTS
            severity_counts["MEDIUM"] += 1
        else:
            score += CONFIG_LOW_POINTS
            severity_counts["LOW"] += 1

        # Check for specific issues
        issue_id_str = issue.id.lower()
        cat = issue.category.lower() if issue.category else ""

        if "hsts" in issue_id_str or "hsts" in cat:
            missing_headers["hsts"] = True
        if "csp" in issue_id_str or "content-security" in cat:
            missing_headers["csp"] = True
        if "dnssec" in issue_id_str or "dnssec" in cat:
            missing_headers["dnssec"] = True

    # Header-specific bonuses
    if missing_headers["hsts"]:
        score += CONFIG_MISSING_HSTS
        factors.append(
            RiskFactor(
                name="Missing HSTS header", points=CONFIG_MISSING_HSTS, category="configuration"
            )
        )
    if missing_headers["csp"]:
        score += CONFIG_MISSING_CSP
        factors.append(
            RiskFactor(
                name="Missing Content-Security-Policy header",
                points=CONFIG_MISSING_CSP,
                category="configuration",
            )
        )
    if missing_headers["dnssec"]:
        score += CONFIG_DNSSEC_DISABLED
        factors.append(
            RiskFactor(
                name="DNSSEC not enabled", points=CONFIG_DNSSEC_DISABLED, category="configuration"
            )
        )

    # Certificate issues
    now = datetime.now(timezone.utc)
    for cert in certificates:
        if cert.not_after:
            try:
                expiry = cert.not_after
                if expiry.tzinfo is None:
                    from datetime import timezone

                    expiry = expiry.replace(tzinfo=timezone.utc)

                days_left = (expiry - now).days

                if days_left < 0:
                    score += CONFIG_CERT_EXPIRED
                    factors.append(
                        RiskFactor(
                            name=f"SSL certificate expired: {cert.subject}",
                            points=CONFIG_CERT_EXPIRED,
                            category="configuration",
                        )
                    )
                elif days_left < 30:
                    score += CONFIG_CERT_SOON_30
                    factors.append(
                        RiskFactor(
                            name=f"SSL certificate expires in {days_left} days: {cert.subject}",
                            points=CONFIG_CERT_SOON_30,
                            category="configuration",
                        )
                    )
                elif days_left < 90:
                    score += CONFIG_CERT_SOON_90
                    factors.append(
                        RiskFactor(
                            name=f"SSL certificate expires in {days_left} days: {cert.subject}",
                            points=CONFIG_CERT_SOON_90,
                            category="configuration",
                        )
                    )
            except (TypeError, AttributeError):  # noqa: S110
                pass

    # Add severity count factors
    if severity_counts["CRITICAL"] > 0:
        factors.append(
            RiskFactor(
                name=f"{severity_counts['CRITICAL']} CRITICAL configuration issues",
                points=severity_counts["CRITICAL"] * CONFIG_CRITICAL_POINTS,
                category="configuration",
            )
        )

    return score, factors


def _calc_exposure_score(
    assets: list[Asset], services: list[Service]
) -> tuple[float, list[RiskFactor]]:
    """Calculate exposure score (raw points before weighting)."""
    from domainraptor.core.types import AssetType

    score = 0.0
    factors: list[RiskFactor] = []

    # Count subdomains
    subdomains = [a for a in assets if a.type == AssetType.SUBDOMAIN]
    subdomain_count = len(subdomains)

    if subdomain_count > 50:
        score += EXPOSURE_SUBDOMAINS_50
        factors.append(
            RiskFactor(
                name=f"Large attack surface: {subdomain_count} subdomains",
                points=EXPOSURE_SUBDOMAINS_50,
                category="exposure",
            )
        )
    elif subdomain_count > 20:
        score += EXPOSURE_SUBDOMAINS_20
        factors.append(
            RiskFactor(
                name=f"Moderate attack surface: {subdomain_count} subdomains",
                points=EXPOSURE_SUBDOMAINS_20,
                category="exposure",
            )
        )

    # Check for dev/staging environments
    dev_count = 0
    for subdomain in subdomains:
        for pattern in DEV_STAGING_PATTERNS:
            if pattern in subdomain.value.lower():
                if dev_count < 3:  # Max 24 points = 3 * 8
                    score += EXPOSURE_DEV_STAGING
                    factors.append(
                        RiskFactor(
                            name=f"Dev/staging environment exposed: {subdomain.value}",
                            points=EXPOSURE_DEV_STAGING,
                            category="exposure",
                        )
                    )
                dev_count += 1
                break

    # Count unique IPs
    ips = {a.value for a in assets if a.type == AssetType.IP}
    if len(ips) > 10:
        score += EXPOSURE_MANY_IPS
        factors.append(
            RiskFactor(
                name=f"Distributed infrastructure: {len(ips)} unique IPs",
                points=EXPOSURE_MANY_IPS,
                category="exposure",
            )
        )

    # Analyze open ports from services
    open_ports: set[int] = set()
    for svc in services:
        if svc.port:
            open_ports.add(svc.port)

    # Also check from asset metadata
    for asset in assets:
        if asset.type == AssetType.IP and asset.metadata.get("ports"):
            for p in asset.metadata["ports"]:
                open_ports.add(int(p))

    # Score sensitive ports
    for port in open_ports:
        if port in SENSITIVE_PORTS_SSH:
            score += EXPOSURE_SSH_PORT
            factors.append(
                RiskFactor(
                    name=f"SSH port ({port}) exposed to internet",
                    points=EXPOSURE_SSH_PORT,
                    category="exposure",
                )
            )
        elif port in SENSITIVE_PORTS_RDP:
            score += EXPOSURE_RDP_PORT
            factors.append(
                RiskFactor(
                    name=f"RDP port ({port}) exposed to internet",
                    points=EXPOSURE_RDP_PORT,
                    category="exposure",
                )
            )
        elif port in SENSITIVE_PORTS_DB:
            score += EXPOSURE_DB_PORT
            factors.append(
                RiskFactor(
                    name=f"Database port ({port}) exposed to internet",
                    points=EXPOSURE_DB_PORT,
                    category="exposure",
                )
            )
        elif port in SENSITIVE_PORTS_ADMIN:
            score += EXPOSURE_ADMIN_PORT
            factors.append(
                RiskFactor(
                    name=f"Admin port ({port}) exposed to internet",
                    points=EXPOSURE_ADMIN_PORT,
                    category="exposure",
                )
            )

    return score, factors


def _calc_reputation_score(scan: ScanResult) -> tuple[float, list[RiskFactor]]:
    """Calculate reputation score (raw points before weighting)."""
    score = 0.0
    factors: list[RiskFactor] = []

    # Check scan metadata for VT data
    vt_data = scan.metadata.get("virustotal", {})
    malicious = vt_data.get("malicious", 0)
    suspicious = vt_data.get("suspicious", 0)

    if malicious > 0:
        score += REPUTATION_MALICIOUS
        factors.append(
            RiskFactor(
                name=f"VirusTotal: {malicious} engines flagged as malicious",
                points=REPUTATION_MALICIOUS,
                category="reputation",
            )
        )

    if suspicious > 0:
        score += REPUTATION_SUSPICIOUS
        factors.append(
            RiskFactor(
                name=f"VirusTotal: {suspicious} engines flagged as suspicious",
                points=REPUTATION_SUSPICIOUS,
                category="reputation",
            )
        )

    # Check for blacklist mentions
    blacklist = vt_data.get("blacklist") or scan.metadata.get("blacklist_hits", 0)
    if blacklist:
        score += REPUTATION_BLACKLIST
        factors.append(
            RiskFactor(
                name="Domain appears on security blacklists",
                points=REPUTATION_BLACKLIST,
                category="reputation",
            )
        )

    # Check individual assets for reputation data
    for asset in scan.assets:
        if asset.metadata.get("malicious") and "VirusTotal" not in str(factors):
            score += REPUTATION_MALICIOUS
            factors.append(
                RiskFactor(
                    name=f"Asset flagged as malicious: {asset.value}",
                    points=REPUTATION_MALICIOUS,
                    category="reputation",
                )
            )
            break

    return score, factors


def _identify_top_factors(all_factors: list[RiskFactor], limit: int = 5) -> list[str]:
    """Identify top N risk factors by points."""
    sorted_factors = sorted(all_factors, key=lambda f: f.points, reverse=True)
    return [f.name for f in sorted_factors[:limit]]


def get_risk_level_display(level: RiskLevel) -> str:
    """Get display string for risk level with emoji."""
    displays = {
        RiskLevel.CRITICAL: "🔴 CRITICAL",
        RiskLevel.HIGH: "🟠 HIGH",
        RiskLevel.MEDIUM: "🟡 MEDIUM",
        RiskLevel.LOW: "🔵 LOW",
        RiskLevel.INFO: "⚪ INFO",
    }
    return displays.get(level, str(level.value))


def get_risk_level_description(level: RiskLevel) -> str:
    """Get detailed description for risk level."""
    descriptions = {
        RiskLevel.CRITICAL: "Immediate action required - critical security risks detected",
        RiskLevel.HIGH: "Significant risks - remediation recommended within 7 days",
        RiskLevel.MEDIUM: "Moderate risks - plan mitigation activities",
        RiskLevel.LOW: "Low risk - improvements recommended",
        RiskLevel.INFO: "Minimal risk - good security posture",
    }
    return descriptions.get(level, "")
