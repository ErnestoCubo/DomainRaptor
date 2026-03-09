"""HTTP security headers checker."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import httpx

from domainraptor.assessment.base import ConfigurationChecker
from domainraptor.core.types import ConfigIssue, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class SecurityHeaders:
    """Collection of security headers from a response."""

    url: str
    status_code: int = 0
    # Security headers
    strict_transport_security: str | None = None
    content_security_policy: str | None = None
    x_frame_options: str | None = None
    x_content_type_options: str | None = None
    x_xss_protection: str | None = None
    referrer_policy: str | None = None
    permissions_policy: str | None = None
    cross_origin_opener_policy: str | None = None
    cross_origin_resource_policy: str | None = None
    cross_origin_embedder_policy: str | None = None
    # Server info (potentially leaking)
    server: str | None = None
    x_powered_by: str | None = None
    x_aspnet_version: str | None = None
    # All headers for reference
    all_headers: dict[str, str] = field(default_factory=dict)


# Header configuration with severity and recommendations
SECURITY_HEADERS_CONFIG = {
    "strict-transport-security": {
        "severity": SeverityLevel.HIGH,
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "description": "HSTS tells browsers to always use HTTPS, preventing downgrade attacks",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "id": "HDR-001",
    },
    "content-security-policy": {
        "severity": SeverityLevel.MEDIUM,
        "title": "Missing Content-Security-Policy (CSP) header",
        "description": "CSP prevents XSS and data injection attacks by restricting resource sources",
        "recommended": "default-src 'self'; script-src 'self'; style-src 'self'",
        "id": "HDR-002",
    },
    "x-frame-options": {
        "severity": SeverityLevel.MEDIUM,
        "title": "Missing X-Frame-Options header",
        "description": "Prevents clickjacking attacks by disabling iframe embedding",
        "recommended": "DENY or SAMEORIGIN",
        "id": "HDR-003",
    },
    "x-content-type-options": {
        "severity": SeverityLevel.LOW,
        "title": "Missing X-Content-Type-Options header",
        "description": "Prevents MIME type sniffing attacks",
        "recommended": "nosniff",
        "id": "HDR-004",
    },
    "referrer-policy": {
        "severity": SeverityLevel.LOW,
        "title": "Missing Referrer-Policy header",
        "description": "Controls how much referrer information is sent with requests",
        "recommended": "strict-origin-when-cross-origin",
        "id": "HDR-005",
    },
    "permissions-policy": {
        "severity": SeverityLevel.LOW,
        "title": "Missing Permissions-Policy header",
        "description": "Controls browser features available to the page",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "id": "HDR-006",
    },
}

# Headers that leak information
LEAKY_HEADERS = {
    "server": {
        "severity": SeverityLevel.INFO,
        "title": "Server header reveals software version",
        "id": "HDR-010",
    },
    "x-powered-by": {
        "severity": SeverityLevel.LOW,
        "title": "X-Powered-By header reveals technology stack",
        "id": "HDR-011",
    },
    "x-aspnet-version": {
        "severity": SeverityLevel.LOW,
        "title": "X-AspNet-Version header reveals framework version",
        "id": "HDR-012",
    },
}


class HeadersChecker(ConfigurationChecker):
    """Check HTTP security headers."""

    name = "headers_checker"
    category = "headers"

    def assess(self, target: str) -> list[ConfigIssue]:
        """Assess HTTP security headers of target."""
        issues: list[ConfigIssue] = []

        # Ensure URL has scheme
        url = target
        if not url.startswith(("http://", "https://")):
            url = f"https://{target}"

        logger.info(f"Checking security headers for {url}")

        headers = self._fetch_headers(url)
        if headers is None:
            issues.append(
                ConfigIssue(
                    id="HDR-ERR",
                    title="Failed to fetch HTTP headers",
                    severity=SeverityLevel.HIGH,
                    category=self.category,
                    description=f"Could not connect to {url}",
                    affected_asset=url,
                )
            )
            return issues

        # Check missing security headers
        issues.extend(self._check_missing_headers(headers))

        # Check header values
        issues.extend(self._check_header_values(headers))

        # Check leaky headers
        issues.extend(self._check_leaky_headers(headers))

        return issues

    def _fetch_headers(self, url: str) -> SecurityHeaders | None:
        """Fetch headers from URL."""
        try:
            response = self.http_client.get(url)
            headers = SecurityHeaders(
                url=str(response.url),
                status_code=response.status_code,
                all_headers=dict(response.headers),
            )

            # Extract security headers (case-insensitive)
            h = response.headers
            headers.strict_transport_security = h.get("strict-transport-security")
            headers.content_security_policy = h.get("content-security-policy")
            headers.x_frame_options = h.get("x-frame-options")
            headers.x_content_type_options = h.get("x-content-type-options")
            headers.x_xss_protection = h.get("x-xss-protection")
            headers.referrer_policy = h.get("referrer-policy")
            headers.permissions_policy = h.get("permissions-policy")
            headers.cross_origin_opener_policy = h.get("cross-origin-opener-policy")
            headers.cross_origin_resource_policy = h.get("cross-origin-resource-policy")
            headers.cross_origin_embedder_policy = h.get("cross-origin-embedder-policy")
            headers.server = h.get("server")
            headers.x_powered_by = h.get("x-powered-by")
            headers.x_aspnet_version = h.get("x-aspnet-version")

            return headers

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching headers: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching headers: {e}")
            return None

    def _check_missing_headers(self, headers: SecurityHeaders) -> list[ConfigIssue]:
        """Check for missing security headers."""
        issues = []

        header_map = {
            "strict-transport-security": headers.strict_transport_security,
            "content-security-policy": headers.content_security_policy,
            "x-frame-options": headers.x_frame_options,
            "x-content-type-options": headers.x_content_type_options,
            "referrer-policy": headers.referrer_policy,
            "permissions-policy": headers.permissions_policy,
        }

        for header_name, value in header_map.items():
            if value is None:
                config = SECURITY_HEADERS_CONFIG.get(header_name)
                if config:
                    issues.append(
                        ConfigIssue(
                            id=config["id"],
                            title=config["title"],
                            severity=config["severity"],
                            category=self.category,
                            description=config["description"],
                            affected_asset=headers.url,
                            current_value="Not set",
                            recommended_value=config["recommended"],
                            remediation=f"Add {header_name} header to your server response",
                        )
                    )

        return issues

    def _check_header_values(self, headers: SecurityHeaders) -> list[ConfigIssue]:
        """Check security header values for weaknesses."""
        issues = []

        # Check HSTS max-age
        if headers.strict_transport_security:
            hsts = headers.strict_transport_security.lower()
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    issues.append(
                        ConfigIssue(
                            id="HDR-020",
                            title="HSTS max-age is too short",
                            severity=SeverityLevel.LOW,
                            category=self.category,
                            description=f"HSTS max-age is {max_age} seconds, recommended is at least 1 year",
                            affected_asset=headers.url,
                            current_value=f"max-age={max_age}",
                            recommended_value="max-age=31536000",
                            remediation="Increase HSTS max-age to at least 31536000 (1 year)",
                        )
                    )

            if "includesubdomains" not in hsts:
                issues.append(
                    ConfigIssue(
                        id="HDR-021",
                        title="HSTS missing includeSubDomains",
                        severity=SeverityLevel.INFO,
                        category=self.category,
                        description="HSTS should include subdomains for complete protection",
                        affected_asset=headers.url,
                        current_value=headers.strict_transport_security,
                        recommended_value="max-age=31536000; includeSubDomains",
                        remediation="Add includeSubDomains to HSTS header",
                    )
                )

        # Check X-Frame-Options value
        if headers.x_frame_options:
            xfo = headers.x_frame_options.upper()
            if xfo not in ("DENY", "SAMEORIGIN"):
                if xfo.startswith("ALLOW-FROM"):
                    issues.append(
                        ConfigIssue(
                            id="HDR-022",
                            title="X-Frame-Options uses deprecated ALLOW-FROM",
                            severity=SeverityLevel.LOW,
                            category=self.category,
                            description="ALLOW-FROM is deprecated and not supported in modern browsers",
                            affected_asset=headers.url,
                            current_value=headers.x_frame_options,
                            recommended_value="DENY or SAMEORIGIN (use CSP frame-ancestors for granular control)",
                            remediation="Use CSP frame-ancestors directive instead of ALLOW-FROM",
                        )
                    )

        # Check CSP for unsafe directives
        if headers.content_security_policy:
            csp = headers.content_security_policy.lower()
            unsafe_patterns = [
                ("unsafe-inline", "script-src"),
                ("unsafe-eval", "script-src"),
                ("*", "default-src"),
            ]
            for pattern, context in unsafe_patterns:
                if pattern in csp:
                    issues.append(
                        ConfigIssue(
                            id="HDR-023",
                            title=f"CSP contains '{pattern}' directive",
                            severity=SeverityLevel.MEDIUM if pattern != "*" else SeverityLevel.HIGH,
                            category=self.category,
                            description=f"'{pattern}' in CSP weakens protection against XSS",
                            affected_asset=headers.url,
                            current_value=f"Contains: {pattern}",
                            recommended_value=f"Remove {pattern} from {context}",
                            remediation=f"Remove '{pattern}' and use nonces or hashes instead",
                        )
                    )

        return issues

    def _check_leaky_headers(self, headers: SecurityHeaders) -> list[ConfigIssue]:
        """Check for headers that leak information."""
        issues = []

        leaky_map = {
            "server": headers.server,
            "x-powered-by": headers.x_powered_by,
            "x-aspnet-version": headers.x_aspnet_version,
        }

        for header_name, value in leaky_map.items():
            if value:
                config = LEAKY_HEADERS.get(header_name)
                if config:
                    # Check if it reveals version info
                    has_version = bool(re.search(r"[\d.]+", value))
                    severity = config["severity"]
                    if has_version:
                        severity = SeverityLevel.LOW  # Bump up if version disclosed

                    issues.append(
                        ConfigIssue(
                            id=config["id"],
                            title=config["title"],
                            severity=severity,
                            category=self.category,
                            description=f"Header reveals: {value}",
                            affected_asset=headers.url,
                            current_value=value,
                            recommended_value="Remove or redact this header",
                            remediation=f"Remove or hide the {header_name} header to prevent information disclosure",
                        )
                    )

        return issues

    def get_headers(self, target: str) -> SecurityHeaders | None:
        """Public method to get security headers for a target."""
        url = target
        if not url.startswith(("http://", "https://")):
            url = f"https://{target}"
        return self._fetch_headers(url)
