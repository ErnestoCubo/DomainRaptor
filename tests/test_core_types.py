"""Tests for core types module."""

from __future__ import annotations

from datetime import datetime, timedelta

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
    WatchTarget,
)


class TestAssetType:
    """Tests for AssetType enum."""

    def test_asset_type_values(self) -> None:
        """Test that all asset types have correct string values."""
        assert AssetType.DOMAIN.value == "domain"
        assert AssetType.SUBDOMAIN.value == "subdomain"
        assert AssetType.IP.value == "ip"
        assert AssetType.PORT.value == "port"
        assert AssetType.SERVICE.value == "service"
        assert AssetType.CERTIFICATE.value == "certificate"
        assert AssetType.EMAIL.value == "email"

    def test_asset_type_from_string(self) -> None:
        """Test creating AssetType from string."""
        assert AssetType("domain") == AssetType.DOMAIN
        assert AssetType("ip") == AssetType.IP

    def test_asset_type_str(self) -> None:
        """Test AssetType string representation."""
        # str(Enum) returns 'EnumClass.MEMBER' format
        assert "DOMAIN" in str(AssetType.DOMAIN)
        # Value access returns the actual value
        assert AssetType.DOMAIN.value == "domain"


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_severity_levels(self) -> None:
        """Test severity level values."""
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.INFO.value == "info"

    def test_severity_comparison(self) -> None:
        """Test severity levels can be created from strings."""
        assert SeverityLevel("critical") == SeverityLevel.CRITICAL
        assert SeverityLevel("info") == SeverityLevel.INFO


class TestChangeType:
    """Tests for ChangeType enum."""

    def test_change_type_values(self) -> None:
        """Test change type values."""
        assert ChangeType.NEW.value == "new"
        assert ChangeType.REMOVED.value == "removed"
        assert ChangeType.MODIFIED.value == "modified"


class TestAsset:
    """Tests for Asset dataclass."""

    def test_asset_creation(self, sample_asset: Asset) -> None:
        """Test asset creation with all fields."""
        assert sample_asset.type == AssetType.SUBDOMAIN
        assert sample_asset.value == "www.example.com"
        assert sample_asset.parent == "example.com"
        assert sample_asset.source == "test"
        assert "resolved_ip" in sample_asset.metadata

    def test_asset_defaults(self) -> None:
        """Test asset default values."""
        asset = Asset(type=AssetType.DOMAIN, value="example.com")
        assert asset.parent is None
        assert asset.source == "unknown"
        assert asset.metadata == {}
        assert isinstance(asset.first_seen, datetime)
        assert isinstance(asset.last_seen, datetime)

    def test_asset_hash(self) -> None:
        """Test asset hashing for deduplication."""
        asset1 = Asset(type=AssetType.DOMAIN, value="example.com")
        asset2 = Asset(type=AssetType.DOMAIN, value="example.com", source="different")
        asset3 = Asset(type=AssetType.IP, value="example.com")

        assert hash(asset1) == hash(asset2)
        assert hash(asset1) != hash(asset3)

    def test_asset_equality(self) -> None:
        """Test asset equality comparison."""
        asset1 = Asset(type=AssetType.DOMAIN, value="example.com")
        asset2 = Asset(type=AssetType.DOMAIN, value="example.com")
        asset3 = Asset(type=AssetType.DOMAIN, value="different.com")

        assert asset1 == asset2
        assert asset1 != asset3
        assert asset1 != "not_an_asset"

    def test_asset_in_set(self) -> None:
        """Test assets can be used in sets for deduplication."""
        asset1 = Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="a")
        asset2 = Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="b")
        asset3 = Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="a")

        assets = {asset1, asset2, asset3}
        assert len(assets) == 2  # asset1 and asset2 are duplicates


class TestDnsRecord:
    """Tests for DnsRecord dataclass."""

    def test_dns_record_creation(self) -> None:
        """Test DNS record creation."""
        record = DnsRecord(record_type="A", value="93.184.216.34", ttl=3600)
        assert record.record_type == "A"
        assert record.value == "93.184.216.34"
        assert record.ttl == 3600
        assert record.priority is None

    def test_dns_mx_record(self) -> None:
        """Test MX record with priority."""
        record = DnsRecord(record_type="MX", value="mail.example.com", ttl=3600, priority=10)
        assert record.priority == 10

    def test_dns_record_defaults(self) -> None:
        """Test DNS record default values."""
        record = DnsRecord(record_type="TXT", value="v=spf1 -all")
        assert record.ttl is None
        assert record.priority is None


class TestCertificate:
    """Tests for Certificate dataclass."""

    def test_certificate_creation(self, sample_certificate: Certificate) -> None:
        """Test certificate creation."""
        assert sample_certificate.subject == "example.com"
        assert sample_certificate.issuer == "Let's Encrypt Authority X3"
        assert len(sample_certificate.san) == 2
        assert sample_certificate.is_expired is False
        assert sample_certificate.days_until_expiry == 60

    def test_expired_certificate(self, expired_certificate: Certificate) -> None:
        """Test expired certificate."""
        assert expired_certificate.is_expired is True
        assert expired_certificate.days_until_expiry < 0

    def test_certificate_defaults(self) -> None:
        """Test certificate default values."""
        cert = Certificate(
            subject="test.com",
            issuer="Test CA",
            serial_number="123",
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
        )
        assert cert.san == []
        assert cert.fingerprint_sha256 == ""
        assert cert.is_expired is False
        assert cert.days_until_expiry == 0


class TestService:
    """Tests for Service dataclass."""

    def test_service_creation(self, sample_service: Service) -> None:
        """Test service creation."""
        assert sample_service.port == 443
        assert sample_service.protocol == "tcp"
        assert sample_service.service_name == "https"
        assert "nginx" in sample_service.version

    def test_service_defaults(self) -> None:
        """Test service default values."""
        service = Service(port=80, protocol="tcp")
        assert service.service_name == ""
        assert service.version == ""
        assert service.banner == ""
        assert service.cpe == []
        assert service.metadata == {}


class TestVulnerability:
    """Tests for Vulnerability dataclass."""

    def test_vulnerability_creation(self, sample_vulnerability: Vulnerability) -> None:
        """Test vulnerability creation."""
        assert sample_vulnerability.id == "CVE-2021-12345"
        assert sample_vulnerability.severity == SeverityLevel.HIGH
        assert sample_vulnerability.cvss_score == 7.5

    def test_vulnerability_defaults(self) -> None:
        """Test vulnerability default values."""
        vuln = Vulnerability(
            id="TEST-001",
            title="Test Vuln",
            severity=SeverityLevel.LOW,
        )
        assert vuln.description == ""
        assert vuln.affected_asset == ""
        assert vuln.cvss_score is None
        assert vuln.references == []


class TestConfigIssue:
    """Tests for ConfigIssue dataclass."""

    def test_config_issue_creation(self, sample_config_issue: ConfigIssue) -> None:
        """Test config issue creation."""
        assert sample_config_issue.id == "HDR-001"
        assert sample_config_issue.category == "headers"
        assert sample_config_issue.severity == SeverityLevel.MEDIUM

    def test_config_issue_defaults(self) -> None:
        """Test config issue default values."""
        issue = ConfigIssue(
            id="TEST-001",
            title="Test Issue",
            severity=SeverityLevel.INFO,
            category="test",
        )
        assert issue.description == ""
        assert issue.affected_asset == ""
        assert issue.current_value == ""
        assert issue.recommended_value == ""


class TestChange:
    """Tests for Change dataclass."""

    def test_change_creation(self, sample_change: Change) -> None:
        """Test change creation."""
        assert sample_change.change_type == ChangeType.NEW
        assert sample_change.asset_type == AssetType.SUBDOMAIN
        assert sample_change.asset_value == "new.example.com"

    def test_change_modified(self) -> None:
        """Test modified change."""
        change = Change(
            change_type=ChangeType.MODIFIED,
            asset_type=AssetType.IP,
            asset_value="example.com",
            old_value="192.168.1.1",
            new_value="192.168.1.2",
            description="IP address changed",
        )
        assert change.old_value == "192.168.1.1"
        assert change.new_value == "192.168.1.2"

    def test_change_removed(self) -> None:
        """Test removed change."""
        change = Change(
            change_type=ChangeType.REMOVED,
            asset_type=AssetType.SUBDOMAIN,
            asset_value="old.example.com",
        )
        assert change.change_type == ChangeType.REMOVED


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_creation(self, sample_scan_result: ScanResult) -> None:
        """Test scan result creation."""
        assert sample_scan_result.target == "example.com"
        assert sample_scan_result.scan_type == "discover"
        assert sample_scan_result.status == "completed"
        assert len(sample_scan_result.assets) > 0

    def test_scan_result_duration(self) -> None:
        """Test scan result duration calculation."""
        start = datetime.now() - timedelta(minutes=5)
        end = datetime.now()
        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=start,
            completed_at=end,
        )
        duration = result.duration_seconds
        assert 299 <= duration <= 301  # ~5 minutes

    def test_scan_result_duration_running(self) -> None:
        """Test duration for still-running scan."""
        start = datetime.now() - timedelta(seconds=10)
        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=start,
            status="running",
        )
        duration = result.duration_seconds
        assert 9 <= duration <= 12

    def test_scan_result_is_complete(self) -> None:
        """Test is_complete property."""
        running = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
            status="running",
        )
        completed = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
            status="completed",
        )
        failed = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
            status="failed",
        )

        assert running.is_complete is False
        assert completed.is_complete is True
        assert failed.is_complete is True

    def test_scan_result_defaults(self) -> None:
        """Test scan result default values."""
        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )
        assert result.completed_at is None
        assert result.status == "running"
        assert result.assets == []
        assert result.dns_records == []
        assert result.certificates == []
        assert result.services == []
        assert result.vulnerabilities == []
        assert result.config_issues == []
        assert result.changes == []
        assert result.errors == []
        assert result.metadata == {}


class TestWatchTarget:
    """Tests for WatchTarget dataclass."""

    def test_watch_target_creation(self) -> None:
        """Test watch target creation."""
        target = WatchTarget(
            target="example.com",
            watch_type="domain",
            interval_hours=12,
        )
        assert target.target == "example.com"
        assert target.interval_hours == 12
        assert target.enabled is True

    def test_watch_target_defaults(self) -> None:
        """Test watch target default values."""
        target = WatchTarget(target="example.com", watch_type="domain")
        assert target.interval_hours == 24
        assert target.last_check is None
        assert target.next_check is None
        assert target.enabled is True
        assert target.notify_on == ["new", "removed", "modified"]

    def test_watch_target_disabled(self) -> None:
        """Test disabled watch target."""
        target = WatchTarget(
            target="example.com",
            watch_type="domain",
            enabled=False,
        )
        assert target.enabled is False
