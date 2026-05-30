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
    ConfigIssue,
    DnsRecord,
    ScanResult,
    Service,
    SeverityLevel,
    Vulnerability,
)

from ._factories import SampleDataFactory

if TYPE_CHECKING:
    from domainraptor.storage.database import Database


# =============================================================================
# Sample Data Fixtures
# =============================================================================


@pytest.fixture
def sample_asset() -> Asset:
    """Create a sample asset for testing."""
    return SampleDataFactory.asset()


@pytest.fixture
def sample_domain_asset() -> Asset:
    """Create a sample domain asset."""
    return SampleDataFactory.domain_asset()


@pytest.fixture
def sample_ip_asset() -> Asset:
    """Create a sample IP asset."""
    return SampleDataFactory.ip_asset()


@pytest.fixture
def sample_assets() -> list[Asset]:
    """Create a list of sample assets."""
    return SampleDataFactory.asset_collection()


@pytest.fixture
def sample_dns_records() -> list[DnsRecord]:
    """Create sample DNS records."""
    return SampleDataFactory.dns_records()


@pytest.fixture
def sample_certificate() -> Certificate:
    """Create a sample certificate."""
    return SampleDataFactory.certificate()


@pytest.fixture
def expired_certificate() -> Certificate:
    """Create an expired certificate."""
    return SampleDataFactory.expired_certificate()


@pytest.fixture
def sample_service() -> Service:
    """Create a sample service."""
    return SampleDataFactory.service()


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Create a sample vulnerability."""
    return SampleDataFactory.vulnerability()


@pytest.fixture
def sample_config_issue() -> ConfigIssue:
    """Create a sample configuration issue."""
    return SampleDataFactory.config_issue()


@pytest.fixture
def sample_change() -> Change:
    """Create a sample change."""
    return SampleDataFactory.change()


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
