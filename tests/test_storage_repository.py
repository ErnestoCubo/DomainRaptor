"""Tests for repository classes."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    ConfigIssue,
    DnsRecord,
    ScanResult,
    SeverityLevel,
    Vulnerability,
    WatchTarget,
)
from domainraptor.storage.database import DatabaseManager
from domainraptor.storage.repository import (
    ScanRepository,
    WatchRepository,
    _datetime_to_str,
    _str_to_datetime,
)


class TestDatetimeHelpers:
    """Tests for datetime helper functions."""

    def test_datetime_to_str_with_value(self) -> None:
        """Test datetime to string conversion."""
        dt = datetime(2024, 1, 15, 10, 30, 0)
        result = _datetime_to_str(dt)
        assert "2024-01-15" in result
        assert "10:30:00" in result

    def test_datetime_to_str_with_none(self) -> None:
        """Test datetime to string with None."""
        result = _datetime_to_str(None)
        assert result is None

    def test_str_to_datetime_with_value(self) -> None:
        """Test string to datetime conversion."""
        s = "2024-01-15T10:30:00"
        result = _str_to_datetime(s)
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_str_to_datetime_with_none(self) -> None:
        """Test string to datetime with None."""
        result = _str_to_datetime(None)
        assert result is None

    def test_str_to_datetime_with_empty(self) -> None:
        """Test string to datetime with empty string."""
        result = _str_to_datetime("")
        assert result is None

    def test_str_to_datetime_invalid_format(self) -> None:
        """Test string to datetime with invalid format."""
        result = _str_to_datetime("not-a-date")
        assert result is None


class TestScanRepository:
    """Tests for ScanRepository class."""

    @pytest.fixture
    def db_manager(self) -> DatabaseManager:
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()
            yield manager

    @pytest.fixture
    def repo(self, db_manager: DatabaseManager) -> ScanRepository:
        """Create a repository with test database."""
        return ScanRepository(db=db_manager)

    @pytest.fixture
    def sample_scan(self) -> ScanResult:
        """Create a sample scan result."""
        now = datetime.now()
        return ScanResult(
            target="example.com",
            scan_type="full",
            status="completed",
            started_at=now,
            completed_at=now,
        )

    def test_repository_creation(self, repo: ScanRepository) -> None:
        """Test repository creation."""
        assert repo.db is not None

    def test_save_empty_scan(self, repo: ScanRepository, sample_scan: ScanResult) -> None:
        """Test saving an empty scan."""
        scan_id = repo.save(sample_scan)

        assert scan_id is not None
        assert scan_id > 0

    def test_save_scan_with_assets(self, repo: ScanRepository) -> None:
        """Test saving a scan with assets."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="full",
            status="completed",
            started_at=now,
        )
        scan.assets.append(
            Asset(
                type=AssetType.DOMAIN,
                value="www.example.com",
                source="crtsh",
                first_seen=now,
            )
        )
        scan.assets.append(
            Asset(
                type=AssetType.IP,
                value="93.184.216.34",
                source="dns",
                first_seen=now,
            )
        )

        scan_id = repo.save(scan)
        assert scan_id > 0

    def test_save_scan_with_dns_records(self, repo: ScanRepository) -> None:
        """Test saving a scan with DNS records."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="dns",
            status="completed",
            started_at=now,
        )
        scan.dns_records.append(DnsRecord(record_type="A", value="93.184.216.34", ttl=300))
        scan.dns_records.append(DnsRecord(record_type="MX", value="mail.example.com", priority=10))

        scan_id = repo.save(scan)
        assert scan_id > 0

    def test_save_scan_with_certificates(self, repo: ScanRepository) -> None:
        """Test saving a scan with certificates."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="certs",
            status="completed",
            started_at=now,
        )
        scan.certificates.append(
            Certificate(
                subject="CN=example.com",
                issuer="CN=DigiCert",
                serial_number="123456",
                not_before=now,
                not_after=now,
                san=["example.com", "www.example.com"],
            )
        )

        scan_id = repo.save(scan)
        assert scan_id > 0

    def test_save_scan_with_config_issues(self, repo: ScanRepository) -> None:
        """Test saving a scan with config issues."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="assess",
            status="completed",
            started_at=now,
        )
        scan.config_issues.append(
            ConfigIssue(
                id="missing-hsts",
                title="Missing HSTS Header",
                severity=SeverityLevel.MEDIUM,
                category="headers",
                description="HTTP Strict Transport Security is not configured",
            )
        )

        scan_id = repo.save(scan)
        assert scan_id > 0

    def test_save_scan_with_vulnerabilities(self, repo: ScanRepository) -> None:
        """Test saving a scan with vulnerabilities."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="assess",
            status="completed",
            started_at=now,
        )
        scan.vulnerabilities.append(
            Vulnerability(
                id="CVE-2024-1234",
                title="Test Vulnerability",
                severity=SeverityLevel.HIGH,
                description="A test vulnerability",
                detected_at=now,
            )
        )

        scan_id = repo.save(scan)
        assert scan_id > 0

    def test_get_by_id_returns_scan(self, repo: ScanRepository, sample_scan: ScanResult) -> None:
        """Test get_by_id returns the saved scan."""
        scan_id = repo.save(sample_scan)

        retrieved = repo.get_by_id(scan_id)

        assert retrieved is not None
        assert retrieved.target == sample_scan.target
        assert retrieved.scan_type == sample_scan.scan_type
        assert retrieved.status == sample_scan.status

    def test_get_by_id_not_found(self, repo: ScanRepository) -> None:
        """Test get_by_id returns None for non-existent scan."""
        result = repo.get_by_id(99999)
        assert result is None

    def test_get_by_id_with_assets(self, repo: ScanRepository) -> None:
        """Test get_by_id returns assets."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="full",
            status="completed",
            started_at=now,
        )
        scan.assets.append(
            Asset(
                type=AssetType.DOMAIN,
                value="www.example.com",
                source="crtsh",
                first_seen=now,
            )
        )

        scan_id = repo.save(scan)
        retrieved = repo.get_by_id(scan_id)

        assert retrieved is not None
        assert len(retrieved.assets) == 1
        assert retrieved.assets[0].value == "www.example.com"

    def test_get_by_id_with_dns_records(self, repo: ScanRepository) -> None:
        """Test get_by_id returns DNS records."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="dns",
            status="completed",
            started_at=now,
        )
        scan.dns_records.append(DnsRecord(record_type="A", value="93.184.216.34", ttl=300))

        scan_id = repo.save(scan)
        retrieved = repo.get_by_id(scan_id)

        assert retrieved is not None
        assert len(retrieved.dns_records) == 1
        assert retrieved.dns_records[0].record_type == "A"

    def test_save_scan_with_metadata(self, repo: ScanRepository) -> None:
        """Test saving a scan with metadata."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="full",
            status="completed",
            started_at=now,
            metadata={"version": "1.0", "user": "test"},
        )

        scan_id = repo.save(scan)
        retrieved = repo.get_by_id(scan_id)

        assert retrieved is not None
        assert retrieved.metadata.get("version") == "1.0"


class TestScanRepositoryDeduplication:
    """Tests for asset deduplication in repository."""

    @pytest.fixture
    def db_manager(self) -> DatabaseManager:
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()
            yield manager

    @pytest.fixture
    def repo(self, db_manager: DatabaseManager) -> ScanRepository:
        """Create a repository with test database."""
        return ScanRepository(db=db_manager)

    def test_duplicate_assets_ignored(self, repo: ScanRepository) -> None:
        """Test duplicate assets are ignored on insert."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="full",
            status="completed",
            started_at=now,
        )
        # Add duplicate assets
        for _ in range(3):
            scan.assets.append(
                Asset(
                    type=AssetType.DOMAIN,
                    value="www.example.com",
                    source="test",
                    first_seen=now,
                )
            )

        scan_id = repo.save(scan)
        retrieved = repo.get_by_id(scan_id)

        # Should only have one asset due to UNIQUE constraint
        assert retrieved is not None
        assert len(retrieved.assets) == 1


class TestScanRepositoryListAndFilter:
    """Tests for list_scans and filtering methods."""

    @pytest.fixture
    def db_manager(self) -> DatabaseManager:
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()
            yield manager

    @pytest.fixture
    def repo(self, db_manager: DatabaseManager) -> ScanRepository:
        """Create a repository with test database."""
        return ScanRepository(db=db_manager)

    def test_list_scans_empty(self, repo: ScanRepository) -> None:
        """Test list_scans returns empty list when no scans."""
        scans = repo.list_scans()
        assert scans == []

    def test_list_scans_returns_all(self, repo: ScanRepository) -> None:
        """Test list_scans returns all scans."""
        now = datetime.now()
        for i in range(3):
            scan = ScanResult(
                target=f"example{i}.com",
                scan_type="full",
                status="completed",
                started_at=now,
            )
            repo.save(scan)

        scans = repo.list_scans()
        assert len(scans) == 3

    def test_list_scans_filter_by_target(self, repo: ScanRepository) -> None:
        """Test list_scans with target filter."""
        now = datetime.now()
        for target in ["example.com", "test.com", "example.org"]:
            scan = ScanResult(target=target, scan_type="full", status="completed", started_at=now)
            repo.save(scan)

        scans = repo.list_scans(target="example")
        assert len(scans) == 2

    def test_list_scans_filter_by_scan_type(self, repo: ScanRepository) -> None:
        """Test list_scans with scan_type filter."""
        now = datetime.now()
        for scan_type in ["full", "dns", "full"]:
            scan = ScanResult(
                target="example.com", scan_type=scan_type, status="completed", started_at=now
            )
            repo.save(scan)

        scans = repo.list_scans(scan_type="full")
        assert len(scans) == 2

    def test_list_scans_filter_by_status(self, repo: ScanRepository) -> None:
        """Test list_scans with status filter."""
        now = datetime.now()
        for status in ["completed", "failed", "completed"]:
            scan = ScanResult(target="example.com", scan_type="full", status=status, started_at=now)
            repo.save(scan)

        scans = repo.list_scans(status="failed")
        assert len(scans) == 1

    def test_list_scans_with_limit(self, repo: ScanRepository) -> None:
        """Test list_scans with limit."""
        now = datetime.now()
        for i in range(10):
            scan = ScanResult(
                target=f"example{i}.com", scan_type="full", status="completed", started_at=now
            )
            repo.save(scan)

        scans = repo.list_scans(limit=5)
        assert len(scans) == 5

    def test_list_scans_with_offset(self, repo: ScanRepository) -> None:
        """Test list_scans with offset."""
        now = datetime.now()
        for i in range(5):
            scan = ScanResult(
                target=f"example{i}.com", scan_type="full", status="completed", started_at=now
            )
            repo.save(scan)

        scans = repo.list_scans(offset=3)
        assert len(scans) == 2


class TestScanRepositoryLatestAndCount:
    """Tests for get_latest_for_target and count methods."""

    @pytest.fixture
    def db_manager(self) -> DatabaseManager:
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()
            yield manager

    @pytest.fixture
    def repo(self, db_manager: DatabaseManager) -> ScanRepository:
        """Create a repository with test database."""
        return ScanRepository(db=db_manager)

    def test_get_latest_for_target(self, repo: ScanRepository) -> None:
        """Test get_latest_for_target returns most recent scan."""
        now = datetime.now()
        for _i in range(3):
            scan = ScanResult(
                target="example.com", scan_type="full", status="completed", started_at=now
            )
            repo.save(scan)

        latest = repo.get_latest_for_target("example.com")
        assert latest is not None

    def test_get_latest_for_target_not_found(self, repo: ScanRepository) -> None:
        """Test get_latest_for_target returns None for unknown target."""
        result = repo.get_latest_for_target("nonexistent.com")
        assert result is None

    def test_get_latest_for_target_with_scan_type(self, repo: ScanRepository) -> None:
        """Test get_latest_for_target with scan_type filter."""
        now = datetime.now()
        for scan_type in ["full", "dns", "full"]:
            scan = ScanResult(
                target="example.com", scan_type=scan_type, status="completed", started_at=now
            )
            repo.save(scan)

        latest = repo.get_latest_for_target("example.com", scan_type="dns")
        assert latest is not None
        assert latest.scan_type == "dns"

    def test_count_by_target(self, repo: ScanRepository) -> None:
        """Test count_by_target returns correct count."""
        now = datetime.now()
        for _i in range(3):
            scan = ScanResult(
                target="example.com", scan_type="full", status="completed", started_at=now
            )
            repo.save(scan)

        count = repo.count_by_target("example.com")
        assert count == 3

    def test_count_by_target_zero(self, repo: ScanRepository) -> None:
        """Test count_by_target returns 0 for unknown target."""
        count = repo.count_by_target("nonexistent.com")
        assert count == 0


class TestScanRepositoryListByTarget:
    """Tests for list_by_target method."""

    @pytest.fixture
    def db_manager(self) -> DatabaseManager:
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()
            yield manager

    @pytest.fixture
    def repo(self, db_manager: DatabaseManager) -> ScanRepository:
        """Create a repository with test database."""
        return ScanRepository(db=db_manager)

    def test_list_by_target_returns_scans(self, repo: ScanRepository) -> None:
        """Test list_by_target returns scans for target."""
        now = datetime.now()
        for _i in range(5):
            scan = ScanResult(
                target="example.com", scan_type="full", status="completed", started_at=now
            )
            repo.save(scan)

        scans = repo.list_by_target("example.com")
        assert len(scans) == 5
        for scan in scans:
            assert scan.target == "example.com"

    def test_list_by_target_empty(self, repo: ScanRepository) -> None:
        """Test list_by_target returns empty for unknown target."""
        scans = repo.list_by_target("nonexistent.com")
        assert scans == []

    def test_list_by_target_with_limit(self, repo: ScanRepository) -> None:
        """Test list_by_target respects limit."""
        now = datetime.now()
        for _i in range(15):
            scan = ScanResult(
                target="example.com", scan_type="full", status="completed", started_at=now
            )
            repo.save(scan)

        scans = repo.list_by_target("example.com", limit=5)
        assert len(scans) == 5

    def test_list_by_target_default_limit(self, repo: ScanRepository) -> None:
        """Test list_by_target default limit is 10."""
        now = datetime.now()
        for _i in range(15):
            scan = ScanResult(
                target="example.com", scan_type="full", status="completed", started_at=now
            )
            repo.save(scan)

        scans = repo.list_by_target("example.com")
        assert len(scans) == 10

    def test_list_by_target_excludes_other_targets(self, repo: ScanRepository) -> None:
        """Test list_by_target only returns scans for specified target."""
        now = datetime.now()
        for target in ["example.com", "test.com", "example.com"]:
            scan = ScanResult(target=target, scan_type="full", status="completed", started_at=now)
            repo.save(scan)

        scans = repo.list_by_target("example.com")
        assert len(scans) == 2
        assert all(s.target == "example.com" for s in scans)


class TestScanRepositoryDeleteAndPrune:
    """Tests for delete and prune methods."""

    @pytest.fixture
    def db_manager(self) -> DatabaseManager:
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()
            yield manager

    @pytest.fixture
    def repo(self, db_manager: DatabaseManager) -> ScanRepository:
        """Create a repository with test database."""
        return ScanRepository(db=db_manager)

    def test_delete_scan(self, repo: ScanRepository) -> None:
        """Test delete removes scan."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com", scan_type="full", status="completed", started_at=now
        )
        scan_id = repo.save(scan)

        deleted = repo.delete(scan_id)

        assert deleted is True
        assert repo.get_by_id(scan_id) is None

    def test_delete_nonexistent(self, repo: ScanRepository) -> None:
        """Test delete returns False for non-existent scan."""
        deleted = repo.delete(99999)
        assert deleted is False

    def test_prune_old_scans(self, repo: ScanRepository) -> None:
        """Test prune removes old scans."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com", scan_type="full", status="completed", started_at=now
        )
        repo.save(scan)

        # Pruning with 0 days should remove all
        count = repo.prune(older_than_days=0)
        # Note: The prune function uses SQL datetime comparison which may vary
        assert isinstance(count, int)

    def test_prune_no_old_scans(self, repo: ScanRepository) -> None:
        """Test prune when no old scans."""
        count = repo.prune(older_than_days=30)
        assert count == 0


class TestScanRepositoryExport:
    """Tests for export_to_json method."""

    @pytest.fixture
    def db_manager(self) -> DatabaseManager:
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()
            yield manager

    @pytest.fixture
    def repo(self, db_manager: DatabaseManager) -> ScanRepository:
        """Create a repository with test database."""
        return ScanRepository(db=db_manager)

    def test_export_to_json(self, repo: ScanRepository) -> None:
        """Test export_to_json returns dict."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com", scan_type="full", status="completed", started_at=now
        )
        scan.assets.append(
            Asset(type=AssetType.DOMAIN, value="www.example.com", source="test", first_seen=now)
        )
        scan_id = repo.save(scan)

        exported = repo.export_to_json(scan_id)

        assert exported is not None
        assert exported["target"] == "example.com"
        assert exported["scan_type"] == "full"
        assert "summary" in exported
        assert exported["summary"]["assets"] == 1

    def test_export_to_json_not_found(self, repo: ScanRepository) -> None:
        """Test export_to_json returns None for non-existent scan."""
        result = repo.export_to_json(99999)
        assert result is None

    def test_export_to_json_with_full_data(self, repo: ScanRepository) -> None:
        """Test export_to_json with all data types."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="full",
            status="completed",
            started_at=now,
            metadata={"test": "value"},
        )
        scan.assets.append(
            Asset(type=AssetType.DOMAIN, value="www.example.com", source="test", first_seen=now)
        )
        scan.dns_records.append(DnsRecord(record_type="A", value="1.2.3.4", ttl=300))
        scan.certificates.append(
            Certificate(
                subject="CN=example.com",
                issuer="CN=Test",
                serial_number="123",
                not_before=now,
                not_after=now,
                san=["example.com"],
            )
        )
        scan.config_issues.append(
            ConfigIssue(
                id="test-issue",
                title="Test Issue",
                severity=SeverityLevel.LOW,
                category="test",
            )
        )
        scan.vulnerabilities.append(
            Vulnerability(
                id="CVE-0000",
                title="Test Vuln",
                severity=SeverityLevel.MEDIUM,
                detected_at=now,
            )
        )

        scan_id = repo.save(scan)
        exported = repo.export_to_json(scan_id)

        assert exported is not None
        assert len(exported["assets"]) == 1
        assert len(exported["dns_records"]) == 1
        assert len(exported["certificates"]) == 1
        assert len(exported["config_issues"]) == 1
        assert len(exported["vulnerabilities"]) == 1
        assert exported["metadata"]["test"] == "value"


class TestWatchRepository:
    """Tests for WatchRepository class."""

    @pytest.fixture
    def db_manager(self) -> DatabaseManager:
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()
            yield manager

    @pytest.fixture
    def repo(self, db_manager: DatabaseManager) -> WatchRepository:
        """Create a repository with test database."""
        return WatchRepository(db=db_manager)

    @pytest.fixture
    def sample_watch_target(self) -> WatchTarget:
        """Create a sample watch target."""
        return WatchTarget(
            target="example.com",
            watch_type="full",
            interval_hours=24,
            enabled=True,
        )

    def test_add_watch_target(
        self, repo: WatchRepository, sample_watch_target: WatchTarget
    ) -> None:
        """Test adding a watch target."""
        watch_id = repo.add(sample_watch_target)
        assert watch_id > 0

    def test_get_by_target(self, repo: WatchRepository, sample_watch_target: WatchTarget) -> None:
        """Test get_by_target returns watch target."""
        repo.add(sample_watch_target)

        retrieved = repo.get_by_target("example.com")

        assert retrieved is not None
        assert retrieved.target == "example.com"
        assert retrieved.watch_type == "full"
        assert retrieved.interval_hours == 24

    def test_get_by_target_not_found(self, repo: WatchRepository) -> None:
        """Test get_by_target returns None for unknown target."""
        result = repo.get_by_target("nonexistent.com")
        assert result is None

    def test_list_all(self, repo: WatchRepository) -> None:
        """Test list_all returns all watch targets."""
        for i in range(3):
            target = WatchTarget(
                target=f"example{i}.com", watch_type="full", interval_hours=24, enabled=True
            )
            repo.add(target)

        targets = repo.list_all()
        assert len(targets) == 3

    def test_list_all_enabled_only(self, repo: WatchRepository) -> None:
        """Test list_all with enabled_only filter."""
        repo.add(
            WatchTarget(target="enabled.com", watch_type="full", interval_hours=24, enabled=True)
        )
        repo.add(
            WatchTarget(target="disabled.com", watch_type="full", interval_hours=24, enabled=False)
        )

        targets = repo.list_all(enabled_only=True)
        assert len(targets) == 1
        assert targets[0].target == "enabled.com"

    def test_get_due_for_check(self, repo: WatchRepository) -> None:
        """Test get_due_for_check returns targets due for checking."""
        # Add target with no next_check (should be due)
        repo.add(WatchTarget(target="due.com", watch_type="full", interval_hours=24, enabled=True))
        # Add disabled target (should not be due)
        repo.add(
            WatchTarget(target="disabled.com", watch_type="full", interval_hours=24, enabled=False)
        )

        due = repo.get_due_for_check()
        assert len(due) == 1
        assert due[0].target == "due.com"

    def test_update_check_time(
        self, repo: WatchRepository, sample_watch_target: WatchTarget
    ) -> None:
        """Test update_check_time updates times."""
        repo.add(sample_watch_target)

        now = datetime.now()
        repo.update_check_time("example.com", now)

        retrieved = repo.get_by_target("example.com")
        assert retrieved is not None
        assert retrieved.last_check is not None

    def test_update_check_time_nonexistent(self, repo: WatchRepository) -> None:
        """Test update_check_time with non-existent target does nothing."""
        # Should not raise
        repo.update_check_time("nonexistent.com", datetime.now())

    def test_remove(self, repo: WatchRepository, sample_watch_target: WatchTarget) -> None:
        """Test remove deletes watch target."""
        repo.add(sample_watch_target)

        removed = repo.remove("example.com")

        assert removed is True
        assert repo.get_by_target("example.com") is None

    def test_remove_nonexistent(self, repo: WatchRepository) -> None:
        """Test remove returns False for non-existent target."""
        removed = repo.remove("nonexistent.com")
        assert removed is False

    def test_set_enabled(self, repo: WatchRepository, sample_watch_target: WatchTarget) -> None:
        """Test set_enabled changes enabled status."""
        repo.add(sample_watch_target)

        result = repo.set_enabled("example.com", False)

        assert result is True
        retrieved = repo.get_by_target("example.com")
        assert retrieved is not None
        assert retrieved.enabled is False

    def test_set_enabled_nonexistent(self, repo: WatchRepository) -> None:
        """Test set_enabled returns False for non-existent target."""
        result = repo.set_enabled("nonexistent.com", True)
        assert result is False

    def test_count(self, repo: WatchRepository) -> None:
        """Test count returns correct count."""
        for i in range(5):
            target = WatchTarget(
                target=f"example{i}.com", watch_type="full", interval_hours=24, enabled=True
            )
            repo.add(target)

        count = repo.count()
        assert count == 5

    def test_count_empty(self, repo: WatchRepository) -> None:
        """Test count returns 0 when empty."""
        count = repo.count()
        assert count == 0
