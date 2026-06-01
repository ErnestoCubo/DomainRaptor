"""Tests for SQLAlchemy-backed storage repositories."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

pytest.importorskip("sqlalchemy")

from domainraptor.core.types import (  # noqa: E402
    Asset,
    AssetType,
    Certificate,
    ConfigIssue,
    DnsRecord,
    ScanResult,
    Service,
    SeverityLevel,
    Vulnerability,
    WatchTarget,
)
from domainraptor.storage._engine import (  # noqa: E402
    create_engine_from_url,
    init_schema,
)
from domainraptor.storage._sql_repository import (  # noqa: E402
    SqlScanRepository,
    SqlWatchRepository,
)


@pytest.fixture
def engine():
    """In-memory sqlite engine with schema initialised."""
    eng = create_engine_from_url("sqlite:///:memory:")
    init_schema(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def scan_repo(engine) -> SqlScanRepository:
    return SqlScanRepository(engine)


@pytest.fixture
def watch_repo(engine) -> SqlWatchRepository:
    return SqlWatchRepository(engine)


@pytest.fixture
def rich_scan() -> ScanResult:
    now = datetime.now().replace(microsecond=0)
    scan = ScanResult(
        target="example.com",
        scan_type="full",
        status="completed",
        started_at=now,
        completed_at=now,
        metadata={"engine": "test"},
    )
    scan.assets.append(
        Asset(
            type=AssetType.DOMAIN,
            value="www.example.com",
            source="crtsh",
            first_seen=now,
            last_seen=now,
        )
    )
    scan.assets.append(
        Asset(
            type=AssetType.IP,
            value="93.184.216.34",
            source="dns",
            first_seen=now,
            last_seen=now,
        )
    )
    scan.dns_records.append(DnsRecord(record_type="A", value="93.184.216.34", ttl=300))
    scan.dns_records.append(DnsRecord(record_type="MX", value="mail.example.com", priority=10))
    scan.certificates.append(
        Certificate(
            subject="CN=example.com",
            issuer="CN=DigiCert",
            serial_number="123",
            not_before=now,
            not_after=now + timedelta(days=90),
            san=["example.com", "www.example.com"],
            fingerprint_sha256="abc",
            is_expired=False,
            days_until_expiry=90,
        )
    )
    scan.config_issues.append(
        ConfigIssue(
            id="missing-hsts",
            title="Missing HSTS",
            severity=SeverityLevel.MEDIUM,
            category="headers",
            description="No HSTS",
            affected_asset="example.com",
        )
    )
    scan.vulnerabilities.append(
        Vulnerability(
            id="CVE-2024-0001",
            title="Test CVE",
            severity=SeverityLevel.HIGH,
            description="Test",
            affected_asset="example.com",
            cvss_score=7.5,
            references=["https://example.com/cve"],
            detected_at=now,
            source="nvd",
        )
    )
    scan.services.append(
        Service(
            port=443,
            protocol="tcp",
            service_name="https",
            version="1.1",
            banner="nginx",
            cpe=["cpe:/a:nginx:nginx:1.1"],
            metadata={"ip": "93.184.216.34", "product": "nginx", "os": "linux"},
        )
    )
    return scan


class TestSqlScanRepository:
    def test_save_and_get(self, scan_repo: SqlScanRepository, rich_scan: ScanResult) -> None:
        scan_id = scan_repo.save(rich_scan)
        assert scan_id > 0
        loaded = scan_repo.get_by_id(scan_id)
        assert loaded is not None
        assert loaded.target == "example.com"
        assert loaded.metadata == {"engine": "test"}
        assert len(loaded.assets) == 2
        assert {a.value for a in loaded.assets} == {"www.example.com", "93.184.216.34"}
        assert len(loaded.dns_records) == 2
        assert len(loaded.certificates) == 1
        assert loaded.certificates[0].san == ["example.com", "www.example.com"]
        assert len(loaded.config_issues) == 1
        assert loaded.config_issues[0].severity == SeverityLevel.MEDIUM
        assert len(loaded.vulnerabilities) == 1
        assert loaded.vulnerabilities[0].cvss_score == 7.5
        assert len(loaded.services) == 1
        assert loaded.services[0].metadata["ip"] == "93.184.216.34"

    def test_get_by_id_missing(self, scan_repo: SqlScanRepository) -> None:
        assert scan_repo.get_by_id(9999) is None

    def test_list_scans_filters(self, scan_repo: SqlScanRepository, rich_scan: ScanResult) -> None:
        scan_repo.save(rich_scan)
        rows = scan_repo.list_scans(target="example")
        assert len(rows) == 1
        assert rows[0]["asset_count"] == 2
        assert rows[0]["issue_count"] == 1
        assert rows[0]["vuln_count"] == 1
        assert scan_repo.list_scans(scan_type="nope") == []
        assert scan_repo.list_scans(status="nope") == []

    def test_get_latest_for_target(
        self, scan_repo: SqlScanRepository, rich_scan: ScanResult
    ) -> None:
        scan_repo.save(rich_scan)
        latest = scan_repo.get_latest_for_target("example.com")
        assert latest is not None
        assert latest.target == "example.com"
        assert scan_repo.get_latest_for_target("missing.com") is None

    def test_list_by_target(self, scan_repo: SqlScanRepository, rich_scan: ScanResult) -> None:
        scan_repo.save(rich_scan)
        scan_repo.save(rich_scan)
        scans = scan_repo.list_by_target("example.com")
        assert len(scans) == 2

    def test_delete(self, scan_repo: SqlScanRepository, rich_scan: ScanResult) -> None:
        scan_id = scan_repo.save(rich_scan)
        assert scan_repo.delete(scan_id) is True
        assert scan_repo.get_by_id(scan_id) is None
        assert scan_repo.delete(9999) is False

    def test_prune(self, scan_repo: SqlScanRepository) -> None:
        old = ScanResult(
            target="old.com",
            scan_type="full",
            status="completed",
            started_at=datetime.now() - timedelta(days=60),
        )
        recent = ScanResult(
            target="new.com",
            scan_type="full",
            status="completed",
            started_at=datetime.now(),
        )
        scan_repo.save(old)
        scan_repo.save(recent)
        pruned = scan_repo.prune(older_than_days=30)
        assert pruned == 1
        assert scan_repo.count_by_target("old.com") == 0
        assert scan_repo.count_by_target("new.com") == 1

    def test_count_by_target(self, scan_repo: SqlScanRepository, rich_scan: ScanResult) -> None:
        scan_repo.save(rich_scan)
        scan_repo.save(rich_scan)
        assert scan_repo.count_by_target("example.com") == 2
        assert scan_repo.count_by_target("nope.com") == 0

    def test_export_to_json(self, scan_repo: SqlScanRepository, rich_scan: ScanResult) -> None:
        scan_id = scan_repo.save(rich_scan)
        exported = scan_repo.export_to_json(scan_id)
        assert exported is not None
        assert exported["target"] == "example.com"
        assert exported["summary"]["assets"] == 2
        assert exported["summary"]["vulnerabilities"] == 1
        assert scan_repo.export_to_json(9999) is None

    def test_asset_uniqueness(self, scan_repo: SqlScanRepository) -> None:
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="dns",
            status="completed",
            started_at=now,
        )
        scan.assets.append(
            Asset(type=AssetType.DOMAIN, value="x.example.com", source="a", first_seen=now)
        )
        scan.assets.append(
            Asset(type=AssetType.DOMAIN, value="x.example.com", source="b", first_seen=now)
        )
        scan_id = scan_repo.save(scan)
        loaded = scan_repo.get_by_id(scan_id)
        assert loaded is not None
        assert len(loaded.assets) == 1


class TestSqlWatchRepository:
    def test_add_and_get(self, watch_repo: SqlWatchRepository) -> None:
        wt = WatchTarget(
            target="watch.com",
            watch_type="domain",
            interval_hours=12,
            enabled=True,
            notify_on=["new", "removed"],
            metadata={"owner": "qa"},
        )
        wid = watch_repo.add(wt)
        assert wid > 0
        fetched = watch_repo.get_by_target("watch.com")
        assert fetched is not None
        assert fetched.interval_hours == 12
        assert fetched.notify_on == ["new", "removed"]
        assert fetched.metadata == {"owner": "qa"}

    def test_list_all_and_enabled_only(self, watch_repo: SqlWatchRepository) -> None:
        watch_repo.add(WatchTarget(target="a.com", watch_type="domain", enabled=True))
        watch_repo.add(WatchTarget(target="b.com", watch_type="domain", enabled=False))
        assert len(watch_repo.list_all()) == 2
        only = watch_repo.list_all(enabled_only=True)
        assert len(only) == 1
        assert only[0].target == "a.com"

    def test_due_for_check_and_update(self, watch_repo: SqlWatchRepository) -> None:
        past = datetime.now() - timedelta(hours=1)
        watch_repo.add(
            WatchTarget(
                target="due.com",
                watch_type="domain",
                enabled=True,
                next_check=past,
                interval_hours=6,
            )
        )
        watch_repo.add(
            WatchTarget(
                target="future.com",
                watch_type="domain",
                enabled=True,
                next_check=datetime.now() + timedelta(hours=1),
                interval_hours=6,
            )
        )
        due = watch_repo.get_due_for_check()
        assert {t.target for t in due} == {"due.com"}

        watch_repo.update_check_time("due.com", datetime.now())
        refreshed = watch_repo.get_by_target("due.com")
        assert refreshed is not None
        assert refreshed.last_check is not None
        assert refreshed.next_check is not None
        assert refreshed.next_check > refreshed.last_check

    def test_remove_and_set_enabled(self, watch_repo: SqlWatchRepository) -> None:
        watch_repo.add(WatchTarget(target="rm.com", watch_type="domain", enabled=True))
        assert watch_repo.set_enabled("rm.com", False) is True
        fetched = watch_repo.get_by_target("rm.com")
        assert fetched is not None and fetched.enabled is False
        assert watch_repo.remove("rm.com") is True
        assert watch_repo.get_by_target("rm.com") is None
        assert watch_repo.remove("missing.com") is False

    def test_count(self, watch_repo: SqlWatchRepository) -> None:
        assert watch_repo.count() == 0
        watch_repo.add(WatchTarget(target="x.com", watch_type="domain"))
        watch_repo.add(WatchTarget(target="y.com", watch_type="domain"))
        assert watch_repo.count() == 2
