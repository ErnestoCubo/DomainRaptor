"""Pytest configuration and shared fixtures for DomainRaptor tests."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from domainraptor.core.config import AppConfig, OutputFormat, ScanMode, SourceConfig
from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    Change,
    ChangeType,
    ConfigIssue,
    DnsRecord,
    ScanResult,
    Service,
    SeverityLevel,
    Vulnerability,
)

if TYPE_CHECKING:
    from domainraptor.storage.database import Database


# =============================================================================
# Sample Data Fixtures
# =============================================================================


@pytest.fixture
def sample_asset() -> Asset:
    """Create a sample asset for testing."""
    return Asset(
        type=AssetType.SUBDOMAIN,
        value="www.example.com",
        parent="example.com",
        source="test",
        metadata={"resolved_ip": "93.184.216.34"},
    )


@pytest.fixture
def sample_domain_asset() -> Asset:
    """Create a sample domain asset."""
    return Asset(
        type=AssetType.DOMAIN,
        value="example.com",
        source="test",
    )


@pytest.fixture
def sample_ip_asset() -> Asset:
    """Create a sample IP asset."""
    return Asset(
        type=AssetType.IP,
        value="93.184.216.34",
        parent="example.com",
        source="dns",
        metadata={"ip_version": 4},
    )


@pytest.fixture
def sample_assets() -> list[Asset]:
    """Create a list of sample assets."""
    return [
        Asset(type=AssetType.DOMAIN, value="example.com", source="input"),
        Asset(
            type=AssetType.SUBDOMAIN, value="www.example.com", parent="example.com", source="crt_sh"
        ),
        Asset(
            type=AssetType.SUBDOMAIN, value="api.example.com", parent="example.com", source="dns"
        ),
        Asset(type=AssetType.IP, value="93.184.216.34", parent="example.com", source="dns"),
        Asset(
            type=AssetType.IP,
            value="2606:2800:220:1:248:1893:25c8:1946",
            parent="example.com",
            source="dns",
        ),
    ]


@pytest.fixture
def sample_dns_records() -> list[DnsRecord]:
    """Create sample DNS records."""
    return [
        DnsRecord(record_type="A", value="93.184.216.34", ttl=3600),
        DnsRecord(record_type="AAAA", value="2606:2800:220:1:248:1893:25c8:1946", ttl=3600),
        DnsRecord(record_type="MX", value="mail.example.com", ttl=3600, priority=10),
        DnsRecord(record_type="NS", value="ns1.example.com", ttl=86400),
        DnsRecord(record_type="TXT", value="v=spf1 include:_spf.example.com ~all", ttl=3600),
    ]


@pytest.fixture
def sample_certificate() -> Certificate:
    """Create a sample certificate."""
    return Certificate(
        subject="example.com",
        issuer="Let's Encrypt Authority X3",
        serial_number="0123456789abcdef",
        not_before=datetime.now() - timedelta(days=30),
        not_after=datetime.now() + timedelta(days=60),
        san=["example.com", "www.example.com"],
        fingerprint_sha256="abc123def456",  # pragma: allowlist secret
        is_expired=False,
        days_until_expiry=60,
    )


@pytest.fixture
def expired_certificate() -> Certificate:
    """Create an expired certificate."""
    return Certificate(
        subject="expired.example.com",
        issuer="Let's Encrypt Authority X3",
        serial_number="expired123",
        not_before=datetime.now() - timedelta(days=400),
        not_after=datetime.now() - timedelta(days=35),
        san=["expired.example.com"],
        fingerprint_sha256="expired456",  # pragma: allowlist secret
        is_expired=True,
        days_until_expiry=-35,
    )


@pytest.fixture
def sample_service() -> Service:
    """Create a sample service."""
    return Service(
        port=443,
        protocol="tcp",
        service_name="https",
        version="nginx/1.18.0",
        banner="nginx",
        cpe=["cpe:/a:nginx:nginx:1.18.0"],
    )


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Create a sample vulnerability."""
    return Vulnerability(
        id="CVE-2021-12345",
        title="Test Vulnerability",
        severity=SeverityLevel.HIGH,
        description="A test vulnerability for testing purposes",
        affected_asset="example.com",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-12345"],
        remediation="Update to the latest version",
        source="test",
    )


@pytest.fixture
def sample_config_issue() -> ConfigIssue:
    """Create a sample configuration issue."""
    return ConfigIssue(
        id="HDR-001",
        title="Missing HSTS Header",
        severity=SeverityLevel.MEDIUM,
        category="headers",
        description="HTTP Strict Transport Security header is not set",
        affected_asset="https://example.com",
        current_value="",
        recommended_value="max-age=31536000; includeSubDomains",
        remediation="Add Strict-Transport-Security header to HTTP responses",
    )


@pytest.fixture
def sample_change() -> Change:
    """Create a sample change."""
    return Change(
        change_type=ChangeType.NEW,
        asset_type=AssetType.SUBDOMAIN,
        asset_value="new.example.com",
        old_value=None,
        new_value="new.example.com",
        description="New subdomain discovered",
    )


@pytest.fixture
def sample_scan_result(
    sample_assets: list[Asset],
    sample_dns_records: list[DnsRecord],
    sample_certificate: Certificate,
) -> ScanResult:
    """Create a sample scan result."""
    return ScanResult(
        target="example.com",
        scan_type="discover",
        started_at=datetime.now() - timedelta(minutes=5),
        completed_at=datetime.now(),
        status="completed",
        assets=sample_assets,
        dns_records=sample_dns_records,
        certificates=[sample_certificate],
    )


# =============================================================================
# Configuration Fixtures
# =============================================================================


@pytest.fixture
def default_config() -> AppConfig:
    """Create a default application configuration."""
    return AppConfig()


@pytest.fixture
def verbose_config() -> AppConfig:
    """Create a verbose configuration."""
    return AppConfig(verbose=True, debug=True)


@pytest.fixture
def stealth_config() -> AppConfig:
    """Create a stealth mode configuration."""
    return AppConfig(mode=ScanMode.STEALTH, timeout=60)


@pytest.fixture
def config_with_sources() -> AppConfig:
    """Create configuration with API sources."""
    return AppConfig(
        sources={
            "shodan": SourceConfig(name="shodan", api_key="test_key", rate_limit=1.0),
            "virustotal": SourceConfig(name="virustotal", api_key="test_vt_key", rate_limit=0.25),
        }
    )


# =============================================================================
# Database Fixtures
# =============================================================================


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Create a temporary database path."""
    return tmp_path / "test_domainraptor.db"


@pytest.fixture
def temp_database(temp_db_path: Path) -> Generator[Database, None, None]:
    """Create a temporary database for testing."""
    from domainraptor.storage.database import Database

    db = Database(temp_db_path)
    yield db
    db.close()
    if temp_db_path.exists():
        temp_db_path.unlink()


# =============================================================================
# Mock Fixtures
# =============================================================================


@pytest.fixture
def mock_http_response() -> MagicMock:
    """Create a mock HTTP response."""
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {}
    response.text = ""
    response.headers = {}
    return response


@pytest.fixture
def mock_dns_resolver() -> MagicMock:
    """Create a mock DNS resolver."""
    resolver = MagicMock()
    return resolver


@pytest.fixture
def mock_httpx_client() -> Generator[MagicMock, None, None]:
    """Create a patched httpx client."""
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value = instance
        yield instance


# =============================================================================
# Test Helpers
# =============================================================================


@pytest.fixture
def temp_config_file(tmp_path: Path) -> Path:
    """Create a temporary config file."""
    config_path = tmp_path / "domainraptor.yaml"
    config_path.write_text(
        """
verbose: true
debug: false
mode: standard
timeout: 30
sources:
  shodan:
    enabled: true
    rate_limit: 1.0
  virustotal:
    enabled: true
    rate_limit: 0.25
"""
    )
    return config_path


@pytest.fixture
def temp_env_file(tmp_path: Path) -> Path:
    """Create a temporary .env file."""
    env_path = tmp_path / ".env"
    env_path.write_text(
        """
SHODAN_API_KEY=test_shodan_key
VIRUSTOTAL_API_KEY=test_vt_key
SECURITYTRAILS_API_KEY=test_st_key
"""
    )
    return env_path


# =============================================================================
# Parametrized Data
# =============================================================================


SEVERITY_LEVELS = [
    SeverityLevel.CRITICAL,
    SeverityLevel.HIGH,
    SeverityLevel.MEDIUM,
    SeverityLevel.LOW,
    SeverityLevel.INFO,
]

ASSET_TYPES = [
    AssetType.DOMAIN,
    AssetType.SUBDOMAIN,
    AssetType.IP,
    AssetType.PORT,
    AssetType.SERVICE,
    AssetType.CERTIFICATE,
    AssetType.EMAIL,
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]

SCAN_MODES = [ScanMode.QUICK, ScanMode.STANDARD, ScanMode.DEEP, ScanMode.STEALTH]

OUTPUT_FORMATS = [OutputFormat.TABLE, OutputFormat.JSON, OutputFormat.CSV, OutputFormat.YAML]
