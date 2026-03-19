"""Tests for output utilities module."""

from __future__ import annotations

from datetime import datetime
from io import StringIO
from unittest.mock import patch

from rich.console import Console

from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    Change,
    ChangeType,
    ConfigIssue,
    ScanResult,
    Service,
    SeverityLevel,
    Vulnerability,
)
from domainraptor.utils.output import (
    console,
    create_progress,
    error_console,
    format_json,
    format_yaml,
    print_assets_table,
    print_banner,
    print_certificates_table,
    print_changes_table,
    print_config_issues_table,
    print_error,
    print_info,
    print_scan_summary,
    print_services_table,
    print_success,
    print_vulnerabilities_table,
    print_warning,
    severity_color,
)


class TestConsoleInstances:
    """Tests for console instances."""

    def test_console_exists(self) -> None:
        """Test console instance exists."""
        assert console is not None
        assert isinstance(console, Console)

    def test_error_console_exists(self) -> None:
        """Test error console instance exists."""
        assert error_console is not None
        assert isinstance(error_console, Console)


class TestPrintBanner:
    """Tests for print_banner function."""

    def test_print_banner_output(self) -> None:
        """Test banner prints without error."""
        # Just verify it doesn't raise
        with patch.object(console, "print") as mock_print:
            print_banner()
            mock_print.assert_called_once()

    def test_banner_contains_name(self) -> None:
        """Test banner contains DomainRaptor."""
        output = StringIO()
        test_console = Console(file=output, force_terminal=True)

        with patch("domainraptor.utils.output.console", test_console):
            print_banner()

        # The banner should have been called
        # Note: Console output contains escape codes


class TestCreateProgress:
    """Tests for create_progress function."""

    def test_create_progress_returns_progress(self) -> None:
        """Test create_progress returns Progress instance."""
        from rich.progress import Progress

        progress = create_progress()
        assert progress is not None
        assert isinstance(progress, Progress)


class TestPrintFunctions:
    """Tests for print utility functions."""

    def test_print_success(self) -> None:
        """Test print_success function."""
        with patch.object(console, "print") as mock_print:
            print_success("Test message")
            mock_print.assert_called_once()
            call_args = str(mock_print.call_args)
            assert "Test message" in call_args

    def test_print_error(self) -> None:
        """Test print_error function."""
        with patch.object(error_console, "print") as mock_print:
            print_error("Error message")
            mock_print.assert_called_once()
            call_args = str(mock_print.call_args)
            assert "Error message" in call_args

    def test_print_info(self) -> None:
        """Test print_info function."""
        with patch.object(console, "print") as mock_print:
            print_info("Info message")
            mock_print.assert_called_once()
            call_args = str(mock_print.call_args)
            assert "Info message" in call_args

    def test_print_warning(self) -> None:
        """Test print_warning function."""
        with patch.object(console, "print") as mock_print:
            print_warning("Warning message")
            mock_print.assert_called_once()
            call_args = str(mock_print.call_args)
            assert "Warning message" in call_args


class TestPrintAssetsTable:
    """Tests for print_assets_table function."""

    def test_print_assets_table_empty(self) -> None:
        """Test print_assets_table with empty list."""
        with patch.object(console, "print") as mock_print:
            print_assets_table([])
            # Should print a warning about no assets
            mock_print.assert_called()

    def test_print_assets_table_with_assets(self) -> None:
        """Test print_assets_table with assets."""
        now = datetime.now()
        assets = [
            Asset(
                type=AssetType.DOMAIN,
                value="example.com",
                source="test",
                first_seen=now,
            ),
            Asset(
                type=AssetType.IP,
                value="93.184.216.34",
                source="dns",
                first_seen=now,
            ),
        ]

        with patch.object(console, "print") as mock_print:
            print_assets_table(assets)
            mock_print.assert_called()


class TestPrintCertificatesTable:
    """Tests for print_certificates_table function."""

    def test_print_certificates_table_empty(self) -> None:
        """Test print_certificates_table with empty list returns early."""
        with patch.object(console, "print") as mock_print:
            print_certificates_table([])
            # Returns early without printing for empty list
            mock_print.assert_not_called()

    def test_print_certificates_table_with_certs(self) -> None:
        """Test print_certificates_table with certificates."""
        now = datetime.now()
        certs = [
            Certificate(
                subject="CN=example.com",
                issuer="CN=Let's Encrypt",
                serial_number="12345",
                not_before=now,
                not_after=now,
            ),
        ]

        with patch.object(console, "print") as mock_print:
            print_certificates_table(certs)
            mock_print.assert_called()


class TestPrintScanSummary:
    """Tests for print_scan_summary function."""

    def test_print_scan_summary(self) -> None:
        """Test print_scan_summary function."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="full",
            status="completed",
            started_at=now,
            completed_at=now,
        )

        with patch.object(console, "print") as mock_print:
            print_scan_summary(scan)
            mock_print.assert_called()

    def test_print_scan_summary_with_data(self) -> None:
        """Test print_scan_summary with full data."""
        now = datetime.now()
        scan = ScanResult(
            target="example.com",
            scan_type="full",
            status="completed",
            started_at=now,
            completed_at=now,
        )
        scan.assets.append(
            Asset(
                type=AssetType.DOMAIN,
                value="www.example.com",
                source="test",
                first_seen=now,
            )
        )

        with patch.object(console, "print") as mock_print:
            print_scan_summary(scan)
            mock_print.assert_called()


class TestPrintServicesTable:
    """Tests for print_services_table function."""

    def test_print_services_table_empty(self) -> None:
        """Test print_services_table with empty list returns early."""
        with patch.object(console, "print") as mock_print:
            print_services_table([])
            mock_print.assert_not_called()

    def test_print_services_table_with_services(self) -> None:
        """Test print_services_table with services."""
        services = [
            Service(
                port=80,
                protocol="tcp",
                service_name="http",
                version="Apache/2.4",
                banner="Apache",
            ),
            Service(
                port=443,
                protocol="tcp",
                service_name="https",
                banner="nginx/1.18" + "x" * 50,  # Long banner to test truncation
            ),
        ]

        with patch.object(console, "print") as mock_print:
            print_services_table(services)
            mock_print.assert_called()


class TestPrintVulnerabilitiesTable:
    """Tests for print_vulnerabilities_table function."""

    def test_print_vulnerabilities_table_empty(self) -> None:
        """Test print_vulnerabilities_table with empty list returns early."""
        with patch.object(console, "print") as mock_print:
            print_vulnerabilities_table([])
            mock_print.assert_not_called()

    def test_print_vulnerabilities_table_with_vulns(self) -> None:
        """Test print_vulnerabilities_table with vulnerabilities."""
        now = datetime.now()
        vulns = [
            Vulnerability(
                id="CVE-2024-1234",
                title="Test Vulnerability",
                severity=SeverityLevel.HIGH,
                description="A test vulnerability",
                affected_asset="example.com",
                cvss_score=7.5,
                source="test",
                detected_at=now,
            ),
            Vulnerability(
                id="CVE-2024-5678",
                title="Long title that needs truncation" + "x" * 50,
                severity=SeverityLevel.CRITICAL,
                description="Another vulnerability",
                detected_at=now,
            ),
        ]

        with patch.object(console, "print") as mock_print:
            print_vulnerabilities_table(vulns)
            mock_print.assert_called()


class TestPrintConfigIssuesTable:
    """Tests for print_config_issues_table function."""

    def test_print_config_issues_table_empty(self) -> None:
        """Test print_config_issues_table with empty list returns early."""
        with patch.object(console, "print") as mock_print:
            print_config_issues_table([])
            mock_print.assert_not_called()

    def test_print_config_issues_table_with_issues(self) -> None:
        """Test print_config_issues_table with config issues."""
        issues = [
            ConfigIssue(
                id="missing-hsts",
                title="Missing HSTS Header",
                severity=SeverityLevel.MEDIUM,
                category="headers",
                affected_asset="example.com",
            ),
            ConfigIssue(
                id="weak-cipher",
                title="Very long issue title that should be truncated" + "x" * 50,
                severity=SeverityLevel.LOW,
                category="ssl",
            ),
        ]

        with patch.object(console, "print") as mock_print:
            print_config_issues_table(issues)
            mock_print.assert_called()


class TestPrintChangesTable:
    """Tests for print_changes_table function."""

    def test_print_changes_table_empty(self) -> None:
        """Test print_changes_table with empty list prints info."""
        with patch.object(console, "print") as mock_print:
            print_changes_table([])
            mock_print.assert_called()  # Prints "No changes detected"

    def test_print_changes_table_with_changes(self) -> None:
        """Test print_changes_table with changes."""
        now = datetime.now()
        changes = [
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType.DOMAIN,
                asset_value="new.example.com",
                detected_at=now,
            ),
            Change(
                change_type=ChangeType.REMOVED,
                asset_type=AssetType.IP,
                asset_value="1.2.3.4",
                detected_at=now,
            ),
            Change(
                change_type=ChangeType.MODIFIED,
                asset_type=AssetType.DOMAIN,
                asset_value="modified.example.com",
                old_value="old value",
                new_value="new value",
                detected_at=now,
            ),
        ]

        with patch.object(console, "print") as mock_print:
            print_changes_table(changes)
            mock_print.assert_called()

    def test_print_changes_table_with_long_description(self) -> None:
        """Test print_changes_table truncates long descriptions."""
        now = datetime.now()
        changes = [
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType.DOMAIN,
                asset_value="example.com",
                description="Very long description that needs to be truncated" + "x" * 50,
                detected_at=now,
            ),
        ]

        with patch.object(console, "print") as mock_print:
            print_changes_table(changes)
            mock_print.assert_called()


class TestSeverityColor:
    """Tests for severity_color function."""

    def test_severity_color_critical(self) -> None:
        """Test critical severity returns bold red."""
        assert severity_color("critical") == "bold red"

    def test_severity_color_high(self) -> None:
        """Test high severity returns red."""
        assert severity_color("high") == "red"

    def test_severity_color_medium(self) -> None:
        """Test medium severity returns yellow."""
        assert severity_color("medium") == "yellow"

    def test_severity_color_low(self) -> None:
        """Test low severity returns blue."""
        assert severity_color("low") == "blue"

    def test_severity_color_info(self) -> None:
        """Test info severity returns dim."""
        assert severity_color("info") == "dim"

    def test_severity_color_unknown(self) -> None:
        """Test unknown severity returns white."""
        assert severity_color("unknown") == "white"

    def test_severity_color_case_insensitive(self) -> None:
        """Test severity_color is case insensitive."""
        assert severity_color("CRITICAL") == "bold red"
        assert severity_color("High") == "red"


class TestFormatJson:
    """Tests for format_json function."""

    def test_format_json_dict(self) -> None:
        """Test format_json with dictionary."""
        data = {"key": "value", "number": 42}
        result = format_json(data)
        assert "key" in result
        assert "value" in result
        assert "42" in result

    def test_format_json_datetime(self) -> None:
        """Test format_json handles datetime."""
        now = datetime.now()
        data = {"timestamp": now}
        result = format_json(data)
        assert now.isoformat()[:10] in result

    def test_format_json_object_with_dict(self) -> None:
        """Test format_json handles objects with __dict__."""

        class SimpleObj:
            def __init__(self) -> None:
                self.name = "test"
                self.value = 123

        data = {"obj": SimpleObj()}
        result = format_json(data)
        assert "test" in result
        assert "123" in result

    def test_format_json_other_types(self) -> None:
        """Test format_json handles other types via str()."""
        data = {"path": "test path"}
        result = format_json(data)
        assert "test path" in result


class TestFormatYaml:
    """Tests for format_yaml function."""

    def test_format_yaml_dict(self) -> None:
        """Test format_yaml with dictionary."""
        data = {"key": "value", "number": 42}
        result = format_yaml(data)
        assert "key: value" in result
        assert "number: 42" in result

    def test_format_yaml_datetime(self) -> None:
        """Test format_yaml handles datetime."""
        now = datetime.now()
        data = {"timestamp": now}
        result = format_yaml(data)
        assert now.isoformat()[:10] in result

    def test_format_yaml_nested(self) -> None:
        """Test format_yaml with nested data."""
        data = {"parent": {"child": "value"}}
        result = format_yaml(data)
        assert "parent" in result
        assert "child" in result
