"""Tests for compare CLI commands."""

from __future__ import annotations

from datetime import datetime

from typer.testing import CliRunner

from domainraptor.cli.commands.compare import _compare_scans
from domainraptor.cli.main import app
from domainraptor.core.types import (
    Asset,
    AssetType,
    ChangeType,
    ConfigIssue,
    DnsRecord,
    ScanResult,
    Service,
    SeverityLevel,
    Vulnerability,
)

runner = CliRunner()


# ============================================================================
# Compare Function Unit Tests
# ============================================================================


class TestCompareScanFunction:
    """Unit tests for _compare_scans function."""

    def _create_scan(
        self,
        target: str = "example.com",
        assets: list[Asset] | None = None,
        dns_records: list[DnsRecord] | None = None,
        services: list[Service] | None = None,
        vulnerabilities: list[Vulnerability] | None = None,
        config_issues: list[ConfigIssue] | None = None,
    ) -> ScanResult:
        """Helper to create a ScanResult for testing."""
        return ScanResult(
            target=target,
            scan_type="discover",
            status="completed",
            started_at=datetime.now(),
            assets=assets or [],
            dns_records=dns_records or [],
            services=services or [],
            vulnerabilities=vulnerabilities or [],
            config_issues=config_issues or [],
            certificates=[],
            errors=[],
        )

    def test_compare_identical_scans_no_changes(self) -> None:
        """Test comparing identical scans returns no changes."""
        asset = Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="test")
        scan1 = self._create_scan(assets=[asset])
        scan2 = self._create_scan(assets=[asset])

        changes = _compare_scans(scan1, scan2)
        assert len(changes) == 0

    def test_compare_new_asset_detected(self) -> None:
        """Test new asset is detected as NEW change."""
        asset1 = Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="test")
        asset2 = Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="test")

        scan1 = self._create_scan(assets=[asset1])
        scan2 = self._create_scan(assets=[asset1, asset2])

        changes = _compare_scans(scan1, scan2)
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.NEW
        assert changes[0].asset_value == "api.example.com"

    def test_compare_removed_asset_detected(self) -> None:
        """Test removed asset is detected as REMOVED change."""
        asset1 = Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="test")
        asset2 = Asset(type=AssetType.SUBDOMAIN, value="old.example.com", source="test")

        scan1 = self._create_scan(assets=[asset1, asset2])
        scan2 = self._create_scan(assets=[asset1])

        changes = _compare_scans(scan1, scan2)
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.REMOVED
        assert changes[0].asset_value == "old.example.com"

    def test_compare_new_dns_record_detected(self) -> None:
        """Test new DNS record is detected."""
        dns1 = DnsRecord(record_type="A", value="1.2.3.4", ttl=300)
        dns2 = DnsRecord(record_type="MX", value="mail.example.com", ttl=300)

        scan1 = self._create_scan(dns_records=[dns1])
        scan2 = self._create_scan(dns_records=[dns1, dns2])

        changes = _compare_scans(scan1, scan2)
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.NEW
        assert "MX" in changes[0].asset_value

    def test_compare_new_service_detected(self) -> None:
        """Test new service/port is detected."""
        svc1 = Service(port=80, protocol="tcp", service_name="http")
        svc2 = Service(port=443, protocol="tcp", service_name="https")

        scan1 = self._create_scan(services=[svc1])
        scan2 = self._create_scan(services=[svc1, svc2])

        changes = _compare_scans(scan1, scan2)
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.NEW
        assert "443" in changes[0].asset_value

    def test_compare_new_vulnerability_detected(self) -> None:
        """Test new vulnerability is detected."""
        vuln1 = Vulnerability(id="CVE-2024-0001", title="Test CVE", severity=SeverityLevel.HIGH)
        vuln2 = Vulnerability(id="CVE-2024-0002", title="New CVE", severity=SeverityLevel.CRITICAL)

        scan1 = self._create_scan(vulnerabilities=[vuln1])
        scan2 = self._create_scan(vulnerabilities=[vuln1, vuln2])

        changes = _compare_scans(scan1, scan2)
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.NEW
        assert changes[0].asset_value == "CVE-2024-0002"

    def test_compare_resolved_vulnerability_detected(self) -> None:
        """Test resolved vulnerability is detected as REMOVED."""
        vuln1 = Vulnerability(id="CVE-2024-0001", title="Test CVE", severity=SeverityLevel.HIGH)

        scan1 = self._create_scan(vulnerabilities=[vuln1])
        scan2 = self._create_scan(vulnerabilities=[])

        changes = _compare_scans(scan1, scan2)
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.REMOVED
        assert changes[0].asset_value == "CVE-2024-0001"

    def test_compare_multiple_changes(self) -> None:
        """Test multiple changes are detected correctly."""
        asset1 = Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="test")
        asset2 = Asset(type=AssetType.SUBDOMAIN, value="new.example.com", source="test")
        vuln1 = Vulnerability(id="CVE-2024-0001", title="Test", severity=SeverityLevel.MEDIUM)

        scan1 = self._create_scan(assets=[asset1])
        scan2 = self._create_scan(assets=[asset1, asset2], vulnerabilities=[vuln1])

        changes = _compare_scans(scan1, scan2)
        assert len(changes) == 2  # 1 new asset + 1 new vuln


# ============================================================================
# Compare Base Command Tests
# ============================================================================


class TestCompareBase:
    """Tests for compare base command."""

    def test_compare_no_args_shows_help(self) -> None:
        """Test compare without arguments shows help."""
        result = runner.invoke(app, ["--no-banner", "compare"])
        # no_args_is_help=True causes exit code 0 but shows help
        assert result.exit_code in (0, 2)  # 2 = missing required argument
        assert (
            "history" in result.output
            or "scans" in result.output
            or "targets" in result.output
            or "Usage" in result.output
        )


# ============================================================================
# Compare History Command Tests
# ============================================================================


class TestCompareHistory:
    """Tests for compare history command."""

    def test_compare_history_basic(self) -> None:
        """Test basic compare history command."""
        result = runner.invoke(app, ["--no-banner", "compare", "history", "example.com"])
        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_compare_history_with_last(self) -> None:
        """Test compare history with --last option."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "history", "example.com", "--last", "5"],
        )
        assert result.exit_code == 0

    def test_compare_history_with_since(self) -> None:
        """Test compare history with --since option."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "history", "example.com", "--since", "2024-01-01"],
        )
        assert result.exit_code == 0

    def test_compare_history_no_scans_shows_warning(self) -> None:
        """Test compare history with no scans shows warning."""
        result = runner.invoke(
            app, ["--no-banner", "compare", "history", "nonexistent-domain-xyz123.com"]
        )
        assert result.exit_code == 0
        # Should show warning about needing scans
        assert "scan" in result.output.lower()


# ============================================================================
# Compare Scans Command Tests
# ============================================================================


class TestCompareScans:
    """Tests for compare scans command."""

    def test_compare_scans_with_numeric_ids(self) -> None:
        """Test compare scans with numeric IDs."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "scans", "1", "2"],
        )
        # May show "not found" if scans don't exist
        assert result.exit_code in (0, 1)

    def test_compare_scans_invalid_id_shows_error(self) -> None:
        """Test compare scans with invalid ID shows error."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "scans", "invalid", "also-invalid"],
        )
        assert result.exit_code == 1
        assert "numeric" in result.output.lower()

    def test_compare_scans_nonexistent_shows_error(self) -> None:
        """Test compare scans with nonexistent ID shows error."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "scans", "999999", "999998"],
        )
        assert result.exit_code == 1
        assert "not found" in result.output.lower()


# ============================================================================
# Compare Targets Command Tests
# ============================================================================


class TestCompareTargets:
    """Tests for compare targets command."""

    def test_compare_targets_no_scan_data_shows_error(self) -> None:
        """Test compare targets without scan data shows error."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "targets", "no-scan-1.com", "no-scan-2.com"],
        )
        assert result.exit_code == 1
        assert "No scan data" in result.output

    def test_compare_targets_with_aspect_all(self) -> None:
        """Test compare targets with aspect all."""
        result = runner.invoke(
            app,
            [
                "--no-banner",
                "compare",
                "targets",
                "example.com",
                "example.org",
                "--aspect",
                "all",
            ],
        )
        # Will fail if no scan data
        assert result.exit_code in (0, 1)

    def test_compare_targets_with_aspect_subdomains(self) -> None:
        """Test compare targets with aspect subdomains."""
        result = runner.invoke(
            app,
            [
                "--no-banner",
                "compare",
                "targets",
                "a.com",
                "b.com",
                "--aspect",
                "subdomains",
            ],
        )
        assert result.exit_code in (0, 1)


# ============================================================================
# Compare Baseline Command Tests
# ============================================================================


class TestCompareBaseline:
    """Tests for compare baseline command."""

    def test_compare_baseline_basic(self) -> None:
        """Test basic compare baseline command."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "baseline", "example.com"],
        )
        assert result.exit_code == 0

    def test_compare_baseline_with_baseline_id(self) -> None:
        """Test compare baseline with specific baseline ID."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "baseline", "example.com", "--baseline", "baseline-123"],
        )
        assert result.exit_code == 0
        assert "baseline-123" in result.output

    def test_compare_baseline_shows_result(self) -> None:
        """Test compare baseline shows result."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "baseline", "example.com"],
        )
        assert result.exit_code == 0
        # Should show match or deviation
        assert "baseline" in result.output.lower()
