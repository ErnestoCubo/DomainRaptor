"""Sample data factory used by `tests/conftest.py`.

Centralises construction of the domain objects used in fixtures so that
adding a new attribute to ``Asset`` / ``Certificate`` / etc. requires
updating exactly one place instead of every fixture that ever built one.

Factory methods return fresh instances on every call (mirroring fixture
semantics) and accept overrides via keyword arguments so individual
tests can tweak just the field they care about without rebuilding the
whole object.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    Change,
    ChangeType,
    ConfigIssue,
    DnsRecord,
    Service,
    SeverityLevel,
    Vulnerability,
)


def _apply(defaults: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Return ``defaults`` merged with ``overrides`` (overrides win)."""
    if overrides:
        defaults.update(overrides)
    return defaults


class SampleDataFactory:
    """Factory for the sample objects used across the test suite."""

    # ---- Assets ----------------------------------------------------------

    @staticmethod
    def asset(**overrides: Any) -> Asset:
        return Asset(
            **_apply(
                {
                    "type": AssetType.SUBDOMAIN,
                    "value": "www.example.com",
                    "parent": "example.com",
                    "source": "test",
                    "metadata": {"resolved_ip": "93.184.216.34"},
                },
                overrides,
            )
        )

    @staticmethod
    def domain_asset(**overrides: Any) -> Asset:
        return Asset(
            **_apply(
                {
                    "type": AssetType.DOMAIN,
                    "value": "example.com",
                    "source": "test",
                },
                overrides,
            )
        )

    @staticmethod
    def ip_asset(**overrides: Any) -> Asset:
        return Asset(
            **_apply(
                {
                    "type": AssetType.IP,
                    "value": "93.184.216.34",
                    "parent": "example.com",
                    "source": "dns",
                    "metadata": {"ip_version": 4},
                },
                overrides,
            )
        )

    @staticmethod
    def asset_collection() -> list[Asset]:
        return [
            Asset(type=AssetType.DOMAIN, value="example.com", source="input"),
            Asset(
                type=AssetType.SUBDOMAIN,
                value="www.example.com",
                parent="example.com",
                source="crt_sh",
            ),
            Asset(
                type=AssetType.SUBDOMAIN,
                value="api.example.com",
                parent="example.com",
                source="dns",
            ),
            Asset(type=AssetType.IP, value="93.184.216.34", parent="example.com", source="dns"),
            Asset(
                type=AssetType.IP,
                value="2606:2800:220:1:248:1893:25c8:1946",
                parent="example.com",
                source="dns",
            ),
        ]

    # ---- DNS -------------------------------------------------------------

    @staticmethod
    def dns_records() -> list[DnsRecord]:
        return [
            DnsRecord(record_type="A", value="93.184.216.34", ttl=3600),
            DnsRecord(record_type="AAAA", value="2606:2800:220:1:248:1893:25c8:1946", ttl=3600),
            DnsRecord(record_type="MX", value="mail.example.com", ttl=3600, priority=10),
            DnsRecord(record_type="NS", value="ns1.example.com", ttl=86400),
            DnsRecord(record_type="TXT", value="v=spf1 include:_spf.example.com ~all", ttl=3600),
        ]

    # ---- Certificates ----------------------------------------------------

    @staticmethod
    def certificate(**overrides: Any) -> Certificate:
        now = datetime.now()
        return Certificate(
            **_apply(
                {
                    "subject": "example.com",
                    "issuer": "Let's Encrypt Authority X3",
                    "serial_number": "0123456789abcdef",
                    "not_before": now - timedelta(days=30),
                    "not_after": now + timedelta(days=60),
                    "san": ["example.com", "www.example.com"],
                    "fingerprint_sha256": "abc123def456",  # pragma: allowlist secret
                    "is_expired": False,
                    "days_until_expiry": 60,
                },
                overrides,
            )
        )

    @staticmethod
    def expired_certificate(**overrides: Any) -> Certificate:
        now = datetime.now()
        return Certificate(
            **_apply(
                {
                    "subject": "expired.example.com",
                    "issuer": "Let's Encrypt Authority X3",
                    "serial_number": "expired123",
                    "not_before": now - timedelta(days=400),
                    "not_after": now - timedelta(days=35),
                    "san": ["expired.example.com"],
                    "fingerprint_sha256": "expired456",  # pragma: allowlist secret
                    "is_expired": True,
                    "days_until_expiry": -35,
                },
                overrides,
            )
        )

    # ---- Services / Findings --------------------------------------------

    @staticmethod
    def service(**overrides: Any) -> Service:
        return Service(
            **_apply(
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service_name": "https",
                    "version": "nginx/1.18.0",
                    "banner": "nginx",
                    "cpe": ["cpe:/a:nginx:nginx:1.18.0"],
                },
                overrides,
            )
        )

    @staticmethod
    def vulnerability(**overrides: Any) -> Vulnerability:
        return Vulnerability(
            **_apply(
                {
                    "id": "CVE-2021-12345",
                    "title": "Test Vulnerability",
                    "severity": SeverityLevel.HIGH,
                    "description": "A test vulnerability for testing purposes",
                    "affected_asset": "example.com",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-12345"],
                    "remediation": "Update to the latest version",
                    "source": "test",
                },
                overrides,
            )
        )

    @staticmethod
    def config_issue(**overrides: Any) -> ConfigIssue:
        return ConfigIssue(
            **_apply(
                {
                    "id": "HDR-001",
                    "title": "Missing HSTS Header",
                    "severity": SeverityLevel.MEDIUM,
                    "category": "headers",
                    "description": "HTTP Strict Transport Security header is not set",
                    "affected_asset": "https://example.com",
                    "current_value": "",
                    "recommended_value": "max-age=31536000; includeSubDomains",
                    "remediation": "Add Strict-Transport-Security header to HTTP responses",
                },
                overrides,
            )
        )

    @staticmethod
    def change(**overrides: Any) -> Change:
        return Change(
            **_apply(
                {
                    "change_type": ChangeType.NEW,
                    "asset_type": AssetType.SUBDOMAIN,
                    "asset_value": "new.example.com",
                    "old_value": None,
                    "new_value": "new.example.com",
                    "description": "New subdomain discovered",
                },
                overrides,
            )
        )
