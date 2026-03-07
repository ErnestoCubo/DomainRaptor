"""DNS security configuration checker."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import dns.resolver
import dns.dnssec
import dns.exception
import dns.rdatatype

from domainraptor.assessment.base import AssessmentConfig, ConfigurationChecker
from domainraptor.core.types import ConfigIssue, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class DnsSecurityInfo:
    """DNS security configuration information."""

    domain: str
    # DNSSEC
    has_dnssec: bool = False
    dnssec_valid: bool = False
    dnssec_error: str = ""
    # SPF
    spf_record: str | None = None
    spf_issues: list[str] = field(default_factory=list)
    # DMARC
    dmarc_record: str | None = None
    dmarc_policy: str | None = None
    # DKIM (note: requires selector, so we can only check common ones)
    dkim_selectors_found: list[str] = field(default_factory=list)
    # CAA
    caa_records: list[str] = field(default_factory=list)
    # MX
    has_mx: bool = False
    # NS
    ns_records: list[str] = field(default_factory=list)


# Common DKIM selectors to check
COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",  # Microsoft
    "selector2",  # Microsoft
    "k1",  # Mailchimp
    "mandrill",
    "amazonses",
    "mail",
    "dkim",
    "smtp",
]


class DnsSecurityChecker(ConfigurationChecker):
    """Check DNS security configurations."""

    name = "dns_security"
    category = "dns"

    def __init__(self, config: AssessmentConfig | None = None) -> None:
        super().__init__(config)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0

    def assess(self, target: str) -> list[ConfigIssue]:
        """Assess DNS security configuration of target domain."""
        issues: list[ConfigIssue] = []

        # Clean domain
        domain = target.lower().strip()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[1].split("/")[0]

        logger.info(f"Checking DNS security for {domain}")

        # Get DNS security info
        info = self._get_dns_security_info(domain)

        # Check DNSSEC
        issues.extend(self._check_dnssec(info))

        # Check email security (SPF, DMARC, DKIM) only if domain has MX
        if info.has_mx:
            issues.extend(self._check_spf(info))
            issues.extend(self._check_dmarc(info))
            issues.extend(self._check_dkim(info))

        # Check CAA
        issues.extend(self._check_caa(info))

        # Check NS records
        issues.extend(self._check_ns(info))

        return issues

    def _get_dns_security_info(self, domain: str) -> DnsSecurityInfo:
        """Gather DNS security information for domain."""
        info = DnsSecurityInfo(domain=domain)

        # Check for MX records (to know if email security applies)
        try:
            mx_records = self.resolver.resolve(domain, "MX")
            info.has_mx = bool(mx_records)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            info.has_mx = False

        # Get NS records
        try:
            ns_records = self.resolver.resolve(domain, "NS")
            info.ns_records = [str(rr.target).rstrip(".") for rr in ns_records]
        except dns.exception.DNSException:
            pass

        # Check DNSSEC
        info.has_dnssec, info.dnssec_valid, info.dnssec_error = self._check_domain_dnssec(domain)

        # Get SPF record
        info.spf_record = self._get_txt_record(domain, "v=spf1")

        # Get DMARC record
        dmarc_domain = f"_dmarc.{domain}"
        info.dmarc_record = self._get_txt_record(dmarc_domain, "v=DMARC1")
        if info.dmarc_record:
            # Extract policy
            match = re.search(r'p=(\w+)', info.dmarc_record, re.IGNORECASE)
            if match:
                info.dmarc_policy = match.group(1).lower()

        # Check common DKIM selectors
        for selector in COMMON_DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            if self._has_dkim_record(dkim_domain):
                info.dkim_selectors_found.append(selector)

        # Get CAA records
        try:
            caa_records = self.resolver.resolve(domain, "CAA")
            info.caa_records = [str(rr) for rr in caa_records]
        except dns.exception.DNSException:
            pass

        return info

    def _check_domain_dnssec(self, domain: str) -> tuple[bool, bool, str]:
        """Check if domain has DNSSEC and if it's valid."""
        has_dnssec = False
        dnssec_valid = False
        error = ""

        try:
            # Check for DNSKEY records
            response = self.resolver.resolve(domain, "DNSKEY")
            if response:
                has_dnssec = True
                # Basic validation - if we got DNSKEY, assume valid
                # Full validation requires more complex DNSSEC chain verification
                dnssec_valid = True
        except dns.resolver.NoAnswer:
            # No DNSKEY but might have DS in parent
            pass
        except dns.resolver.NXDOMAIN:
            error = "Domain does not exist"
        except dns.exception.DNSException as e:
            error = str(e)

        # Try to check DS record in parent if no DNSKEY
        if not has_dnssec and not error:
            try:
                # Check parent zone for DS record (delegation signer)
                parts = domain.split(".")
                if len(parts) > 1:
                    # Can't directly query DS from child resolver
                    # This is a simplified check
                    pass
            except dns.exception.DNSException:
                pass

        return has_dnssec, dnssec_valid, error

    def _get_txt_record(self, domain: str, prefix: str) -> str | None:
        """Get TXT record starting with specific prefix."""
        try:
            records = self.resolver.resolve(domain, "TXT")
            for rr in records:
                txt = str(rr).strip('"')
                if txt.lower().startswith(prefix.lower()):
                    return txt
        except dns.exception.DNSException:
            pass
        return None

    def _has_dkim_record(self, dkim_domain: str) -> bool:
        """Check if DKIM record exists."""
        try:
            records = self.resolver.resolve(dkim_domain, "TXT")
            for rr in records:
                txt = str(rr).strip('"')
                if "v=dkim1" in txt.lower() or "p=" in txt:
                    return True
        except dns.exception.DNSException:
            pass
        return False

    def _check_dnssec(self, info: DnsSecurityInfo) -> list[ConfigIssue]:
        """Check DNSSEC configuration."""
        issues = []

        if not info.has_dnssec:
            issues.append(
                ConfigIssue(
                    id="DNS-001",
                    title="DNSSEC not enabled",
                    severity=SeverityLevel.MEDIUM,
                    category=self.category,
                    description="DNSSEC protects against DNS spoofing and cache poisoning attacks",
                    affected_asset=info.domain,
                    current_value="DNSSEC not configured",
                    recommended_value="DNSSEC enabled with valid signatures",
                    remediation="Enable DNSSEC at your domain registrar and DNS provider",
                )
            )
        elif not info.dnssec_valid and info.dnssec_error:
            issues.append(
                ConfigIssue(
                    id="DNS-002",
                    title="DNSSEC validation failed",
                    severity=SeverityLevel.HIGH,
                    category=self.category,
                    description=f"DNSSEC is configured but validation failed: {info.dnssec_error}",
                    affected_asset=info.domain,
                    current_value="Invalid DNSSEC",
                    recommended_value="Valid DNSSEC signatures",
                    remediation="Check DNSSEC configuration and ensure signatures are valid",
                )
            )

        return issues

    def _check_spf(self, info: DnsSecurityInfo) -> list[ConfigIssue]:
        """Check SPF configuration."""
        issues = []

        if not info.spf_record:
            issues.append(
                ConfigIssue(
                    id="DNS-010",
                    title="Missing SPF record",
                    severity=SeverityLevel.MEDIUM,
                    category=self.category,
                    description="SPF helps prevent email spoofing by specifying authorized mail servers",
                    affected_asset=info.domain,
                    current_value="No SPF record",
                    recommended_value="v=spf1 include:... -all",
                    remediation="Add an SPF TXT record to specify authorized email senders",
                )
            )
        else:
            # Check SPF policy
            spf = info.spf_record.lower()

            # Check for overly permissive SPF
            if "+all" in spf:
                issues.append(
                    ConfigIssue(
                        id="DNS-011",
                        title="SPF uses permissive +all",
                        severity=SeverityLevel.HIGH,
                        category=self.category,
                        description="SPF with +all allows any server to send email, defeating its purpose",
                        affected_asset=info.domain,
                        current_value="+all (allow all)",
                        recommended_value="-all (reject) or ~all (soft fail)",
                        remediation="Change +all to -all to enforce SPF policy",
                    )
                )
            elif "~all" in spf:
                issues.append(
                    ConfigIssue(
                        id="DNS-012",
                        title="SPF uses soft fail ~all",
                        severity=SeverityLevel.LOW,
                        category=self.category,
                        description="Soft fail may not be enforced by all receivers",
                        affected_asset=info.domain,
                        current_value="~all (soft fail)",
                        recommended_value="-all (hard fail)",
                        remediation="Consider changing ~all to -all for stricter enforcement",
                    )
                )
            elif "?all" in spf:
                issues.append(
                    ConfigIssue(
                        id="DNS-013",
                        title="SPF uses neutral ?all",
                        severity=SeverityLevel.MEDIUM,
                        category=self.category,
                        description="Neutral policy provides no protection against spoofing",
                        affected_asset=info.domain,
                        current_value="?all (neutral)",
                        recommended_value="-all (hard fail)",
                        remediation="Change ?all to -all to enforce SPF policy",
                    )
                )

        return issues

    def _check_dmarc(self, info: DnsSecurityInfo) -> list[ConfigIssue]:
        """Check DMARC configuration."""
        issues = []

        if not info.dmarc_record:
            issues.append(
                ConfigIssue(
                    id="DNS-020",
                    title="Missing DMARC record",
                    severity=SeverityLevel.MEDIUM,
                    category=self.category,
                    description="DMARC provides email authentication and reporting",
                    affected_asset=info.domain,
                    current_value="No DMARC record",
                    recommended_value="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
                    remediation="Add a DMARC TXT record at _dmarc.yourdomain.com",
                )
            )
        else:
            # Check DMARC policy
            if info.dmarc_policy == "none":
                issues.append(
                    ConfigIssue(
                        id="DNS-021",
                        title="DMARC policy set to none",
                        severity=SeverityLevel.LOW,
                        category=self.category,
                        description="DMARC p=none only monitors but doesn't protect against spoofing",
                        affected_asset=info.domain,
                        current_value="p=none (monitor only)",
                        recommended_value="p=quarantine or p=reject",
                        remediation="After monitoring, upgrade to p=quarantine or p=reject",
                    )
                )

            # Check for reporting address
            if "rua=" not in info.dmarc_record.lower():
                issues.append(
                    ConfigIssue(
                        id="DNS-022",
                        title="DMARC missing aggregate reporting (rua)",
                        severity=SeverityLevel.INFO,
                        category=self.category,
                        description="Without rua, you won't receive DMARC aggregate reports",
                        affected_asset=info.domain,
                        current_value="No rua specified",
                        recommended_value="rua=mailto:dmarc-reports@yourdomain.com",
                        remediation="Add rua= with an email address to receive reports",
                    )
                )

        return issues

    def _check_dkim(self, info: DnsSecurityInfo) -> list[ConfigIssue]:
        """Check DKIM configuration."""
        issues = []

        if not info.dkim_selectors_found:
            issues.append(
                ConfigIssue(
                    id="DNS-030",
                    title="No DKIM records found (common selectors)",
                    severity=SeverityLevel.LOW,
                    category=self.category,
                    description="DKIM cryptographically signs emails to prevent tampering. Note: Custom selectors may exist.",
                    affected_asset=info.domain,
                    current_value="No DKIM found for common selectors",
                    recommended_value="DKIM record at <selector>._domainkey.domain",
                    remediation="Configure DKIM with your email provider",
                )
            )

        return issues

    def _check_caa(self, info: DnsSecurityInfo) -> list[ConfigIssue]:
        """Check CAA (Certificate Authority Authorization) records."""
        issues = []

        if not info.caa_records:
            issues.append(
                ConfigIssue(
                    id="DNS-040",
                    title="Missing CAA records",
                    severity=SeverityLevel.LOW,
                    category=self.category,
                    description="CAA records specify which CAs can issue certificates for your domain",
                    affected_asset=info.domain,
                    current_value="No CAA records",
                    recommended_value='0 issue "letsencrypt.org"',
                    remediation="Add CAA records to restrict certificate issuance to trusted CAs",
                )
            )

        return issues

    def _check_ns(self, info: DnsSecurityInfo) -> list[ConfigIssue]:
        """Check nameserver configuration."""
        issues = []

        if len(info.ns_records) < 2:
            issues.append(
                ConfigIssue(
                    id="DNS-050",
                    title="Insufficient nameservers",
                    severity=SeverityLevel.MEDIUM,
                    category=self.category,
                    description=f"Only {len(info.ns_records)} nameserver(s) found. Multiple NS records provide redundancy.",
                    affected_asset=info.domain,
                    current_value=f"{len(info.ns_records)} NS record(s)",
                    recommended_value="At least 2 NS records",
                    remediation="Add additional nameservers for redundancy",
                )
            )

        # Check if all NS are from same provider (potential single point of failure)
        if len(info.ns_records) >= 2:
            providers = set()
            for ns in info.ns_records:
                # Extract base domain of NS
                parts = ns.split(".")
                if len(parts) >= 2:
                    providers.add(".".join(parts[-2:]))

            if len(providers) == 1:
                issues.append(
                    ConfigIssue(
                        id="DNS-051",
                        title="All nameservers from single provider",
                        severity=SeverityLevel.INFO,
                        category=self.category,
                        description="Using multiple DNS providers increases resilience",
                        affected_asset=info.domain,
                        current_value=f"All NS from {list(providers)[0]}",
                        recommended_value="NS records from multiple providers",
                        remediation="Consider using a secondary DNS provider for redundancy",
                    )
                )

        return issues

    def get_dns_security_info(self, target: str) -> DnsSecurityInfo:
        """Public method to get DNS security info for a target."""
        domain = target.lower().strip()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[1].split("/")[0]
        return self._get_dns_security_info(domain)
