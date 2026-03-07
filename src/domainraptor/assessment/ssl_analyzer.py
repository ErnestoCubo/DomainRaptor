"""SSL/TLS security analyzer using Python's ssl module."""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from domainraptor.assessment.base import AssessmentConfig, ConfigurationChecker
from domainraptor.core.types import ConfigIssue, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class SSLInfo:
    """SSL/TLS connection information."""

    hostname: str
    port: int
    protocol_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    cert_subject: dict[str, str] = field(default_factory=dict)
    cert_issuer: dict[str, str] = field(default_factory=dict)
    cert_not_before: datetime | None = None
    cert_not_after: datetime | None = None
    cert_san: list[str] = field(default_factory=list)
    supports_tls10: bool = False
    supports_tls11: bool = False
    supports_tls12: bool = False
    supports_tls13: bool = False
    supports_sslv3: bool = False
    has_valid_cert: bool = True
    cert_error: str = ""


# Weak ciphers that should be flagged
WEAK_CIPHERS = {
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "EXPORT",
    "ANON",
    "ADH",
    "AECDH",
}

# Minimum recommended cipher bits
MIN_CIPHER_BITS = 128


class SSLAnalyzer(ConfigurationChecker):
    """Analyze SSL/TLS configuration of a target."""

    name = "ssl_analyzer"
    category = "ssl"

    def __init__(self, config: AssessmentConfig | None = None) -> None:
        super().__init__(config)
        self.port = 443

    def assess(self, target: str) -> list[ConfigIssue]:
        """Assess SSL/TLS configuration of target."""
        issues: list[ConfigIssue] = []
        
        # Parse target (domain:port)
        hostname = target
        port = self.port
        if ":" in target:
            parts = target.rsplit(":", 1)
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        logger.info(f"Analyzing SSL/TLS for {hostname}:{port}")

        # Get SSL info
        ssl_info = self._get_ssl_info(hostname, port)
        if ssl_info is None:
            issues.append(
                ConfigIssue(
                    id="SSL-ERR",
                    title="SSL/TLS connection failed",
                    severity=SeverityLevel.HIGH,
                    category=self.category,
                    description=f"Could not establish SSL/TLS connection to {hostname}:{port}",
                    affected_asset=f"{hostname}:{port}",
                )
            )
            return issues

        # Check for deprecated protocols
        issues.extend(self._check_protocols(ssl_info))

        # Check cipher strength
        issues.extend(self._check_cipher(ssl_info))

        # Check certificate validity
        issues.extend(self._check_certificate(ssl_info))

        return issues

    def _get_ssl_info(self, hostname: str, port: int) -> SSLInfo | None:
        """Get SSL/TLS connection information."""
        ssl_info = SSLInfo(hostname=hostname, port=port)

        # Test main connection with highest available TLS
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection(
                (hostname, port), timeout=self.config.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get connection info
                    ssl_info.protocol_version = ssock.version() or ""
                    cipher = ssock.cipher()
                    if cipher:
                        ssl_info.cipher_name = cipher[0]
                        ssl_info.cipher_bits = cipher[2]

                    # Get certificate info
                    cert = ssock.getpeercert()
                    if cert:
                        ssl_info.cert_subject = self._parse_cert_name(
                            cert.get("subject", ())
                        )
                        ssl_info.cert_issuer = self._parse_cert_name(
                            cert.get("issuer", ())
                        )
                        ssl_info.cert_not_before = self._parse_cert_date(
                            cert.get("notBefore")
                        )
                        ssl_info.cert_not_after = self._parse_cert_date(
                            cert.get("notAfter")
                        )
                        # Get SAN
                        san = cert.get("subjectAltName", ())
                        ssl_info.cert_san = [
                            name for _, name in san if _ == "DNS"
                        ]

        except ssl.SSLCertVerificationError as e:
            ssl_info.has_valid_cert = False
            ssl_info.cert_error = str(e)
            logger.warning(f"Certificate verification failed: {e}")
            # Try without verification to still get info
            return self._get_ssl_info_insecure(hostname, port, ssl_info)
        except (socket.error, ssl.SSLError, TimeoutError) as e:
            logger.error(f"SSL connection failed: {e}")
            return None

        # Test protocol support
        ssl_info.supports_tls13 = self._test_protocol(hostname, port, ssl.TLSVersion.TLSv1_3)
        ssl_info.supports_tls12 = self._test_protocol(hostname, port, ssl.TLSVersion.TLSv1_2)
        ssl_info.supports_tls11 = self._test_protocol(hostname, port, ssl.TLSVersion.TLSv1_1)
        ssl_info.supports_tls10 = self._test_protocol(hostname, port, ssl.TLSVersion.TLSv1)

        return ssl_info

    def _get_ssl_info_insecure(
        self, hostname: str, port: int, ssl_info: SSLInfo
    ) -> SSLInfo:
        """Get SSL info without certificate verification."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection(
                (hostname, port), timeout=self.config.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_info.protocol_version = ssock.version() or ""
                    cipher = ssock.cipher()
                    if cipher:
                        ssl_info.cipher_name = cipher[0]
                        ssl_info.cipher_bits = cipher[2]
        except Exception as e:
            logger.error(f"Insecure SSL connection also failed: {e}")

        return ssl_info

    def _test_protocol(
        self, hostname: str, port: int, version: ssl.TLSVersion
    ) -> bool:
        """Test if server supports a specific TLS version."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version

        try:
            with socket.create_connection(
                (hostname, port), timeout=self.config.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    return True
        except (ssl.SSLError, socket.error, TimeoutError):
            return False

    def _parse_cert_name(self, name: tuple) -> dict[str, str]:
        """Parse certificate subject/issuer tuple."""
        result = {}
        for item in name:
            if item:
                for key, value in item:
                    result[key] = value
        return result

    def _parse_cert_date(self, date_str: str | None) -> datetime | None:
        """Parse certificate date string."""
        if not date_str:
            return None
        try:
            # Format: "Nov 25 00:00:00 2024 GMT"
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            return None

    def _check_protocols(self, ssl_info: SSLInfo) -> list[ConfigIssue]:
        """Check for deprecated TLS protocols."""
        issues = []

        if ssl_info.supports_sslv3:
            issues.append(
                ConfigIssue(
                    id="SSL-001",
                    title="SSLv3 protocol enabled",
                    severity=SeverityLevel.CRITICAL,
                    category=self.category,
                    description="SSLv3 is obsolete and vulnerable to POODLE attack",
                    affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                    current_value="SSLv3 enabled",
                    recommended_value="SSLv3 disabled",
                    remediation="Disable SSLv3 in your server configuration",
                )
            )

        if ssl_info.supports_tls10:
            issues.append(
                ConfigIssue(
                    id="SSL-002",
                    title="TLS 1.0 protocol enabled",
                    severity=SeverityLevel.MEDIUM,
                    category=self.category,
                    description="TLS 1.0 is deprecated and should be disabled per PCI DSS",
                    affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                    current_value="TLS 1.0 enabled",
                    recommended_value="TLS 1.0 disabled",
                    remediation="Disable TLS 1.0 in your server configuration",
                )
            )

        if ssl_info.supports_tls11:
            issues.append(
                ConfigIssue(
                    id="SSL-003",
                    title="TLS 1.1 protocol enabled",
                    severity=SeverityLevel.LOW,
                    category=self.category,
                    description="TLS 1.1 is deprecated by major browsers",
                    affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                    current_value="TLS 1.1 enabled",
                    recommended_value="TLS 1.1 disabled",
                    remediation="Disable TLS 1.1 in your server configuration",
                )
            )

        if not ssl_info.supports_tls12 and not ssl_info.supports_tls13:
            issues.append(
                ConfigIssue(
                    id="SSL-004",
                    title="No modern TLS protocol support",
                    severity=SeverityLevel.HIGH,
                    category=self.category,
                    description="Server does not support TLS 1.2 or 1.3",
                    affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                    current_value="No TLS 1.2/1.3",
                    recommended_value="TLS 1.2 and/or 1.3 enabled",
                    remediation="Enable TLS 1.2 and TLS 1.3 in your server configuration",
                )
            )

        return issues

    def _check_cipher(self, ssl_info: SSLInfo) -> list[ConfigIssue]:
        """Check cipher suite strength."""
        issues = []

        # Check for weak ciphers
        cipher_upper = ssl_info.cipher_name.upper()
        for weak in WEAK_CIPHERS:
            if weak in cipher_upper:
                issues.append(
                    ConfigIssue(
                        id="SSL-010",
                        title=f"Weak cipher suite in use: {weak}",
                        severity=SeverityLevel.HIGH,
                        category=self.category,
                        description=f"Cipher {ssl_info.cipher_name} contains weak algorithm {weak}",
                        affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                        current_value=ssl_info.cipher_name,
                        recommended_value="AES256-GCM or CHACHA20-POLY1305",
                        remediation="Configure server to use only strong cipher suites",
                    )
                )
                break

        # Check cipher bit strength
        if ssl_info.cipher_bits > 0 and ssl_info.cipher_bits < MIN_CIPHER_BITS:
            issues.append(
                ConfigIssue(
                    id="SSL-011",
                    title=f"Weak cipher key length: {ssl_info.cipher_bits} bits",
                    severity=SeverityLevel.MEDIUM,
                    category=self.category,
                    description=f"Cipher uses only {ssl_info.cipher_bits} bits, minimum recommended is {MIN_CIPHER_BITS}",
                    affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                    current_value=f"{ssl_info.cipher_bits} bits",
                    recommended_value=f">= {MIN_CIPHER_BITS} bits",
                    remediation="Configure server to use ciphers with at least 128-bit keys",
                )
            )

        return issues

    def _check_certificate(self, ssl_info: SSLInfo) -> list[ConfigIssue]:
        """Check certificate validity."""
        issues = []

        if not ssl_info.has_valid_cert:
            issues.append(
                ConfigIssue(
                    id="SSL-020",
                    title="Invalid SSL certificate",
                    severity=SeverityLevel.HIGH,
                    category=self.category,
                    description=f"Certificate validation failed: {ssl_info.cert_error}",
                    affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                    current_value="Invalid certificate",
                    recommended_value="Valid certificate from trusted CA",
                    remediation="Obtain and install a valid SSL certificate from a trusted CA",
                )
            )

        # Check expiration
        if ssl_info.cert_not_after:
            now = datetime.now()
            days_left = (ssl_info.cert_not_after - now).days

            if days_left < 0:
                issues.append(
                    ConfigIssue(
                        id="SSL-021",
                        title="SSL certificate has expired",
                        severity=SeverityLevel.CRITICAL,
                        category=self.category,
                        description=f"Certificate expired {abs(days_left)} days ago",
                        affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                        current_value=f"Expired on {ssl_info.cert_not_after.strftime('%Y-%m-%d')}",
                        recommended_value="Valid, non-expired certificate",
                        remediation="Renew the SSL certificate immediately",
                    )
                )
            elif days_left < 30:
                issues.append(
                    ConfigIssue(
                        id="SSL-022",
                        title="SSL certificate expiring soon",
                        severity=SeverityLevel.MEDIUM,
                        category=self.category,
                        description=f"Certificate expires in {days_left} days",
                        affected_asset=f"{ssl_info.hostname}:{ssl_info.port}",
                        current_value=f"Expires on {ssl_info.cert_not_after.strftime('%Y-%m-%d')}",
                        recommended_value="Certificate with > 30 days validity",
                        remediation="Renew the SSL certificate before expiration",
                    )
                )

        return issues

    def get_ssl_info(self, target: str) -> SSLInfo | None:
        """Public method to get SSL info for a target."""
        hostname = target
        port = self.port
        if ":" in target:
            parts = target.rsplit(":", 1)
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass
        return self._get_ssl_info(hostname, port)
