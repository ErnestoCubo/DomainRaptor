"""Tests for assess CLI command."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from domainraptor.cli.main import app
from domainraptor.core.types import ConfigIssue, SeverityLevel

runner = CliRunner()


class TestAssessCallback:
    """Tests for main assess callback with --target option."""

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._assess_vulnerabilities")
    @patch("domainraptor.cli.commands.assess._assess_configuration")
    @patch("domainraptor.cli.commands.assess._assess_outdated")
    @patch("domainraptor.storage.ScanRepository")
    def test_full_assessment_success(
        self,
        mock_repo: MagicMock,
        mock_outdated: MagicMock,
        mock_config: MagicMock,
        mock_vulns: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test full assessment runs all checks."""
        # Setup mock progress
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        # Setup repository
        mock_repo.return_value.save.return_value = 1

        result = runner.invoke(app, ["assess", "--target", "example.com"])

        # Verify mocks were called
        mock_vulns.assert_called_once()
        mock_config.assert_called_once()
        mock_outdated.assert_called_once()

        assert result.exit_code == 0

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._assess_vulnerabilities")
    @patch("domainraptor.cli.commands.assess._assess_configuration")
    @patch("domainraptor.cli.commands.assess._assess_outdated")
    def test_full_assessment_no_save(
        self,
        mock_outdated: MagicMock,
        mock_config: MagicMock,
        mock_vulns: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test full assessment with --no-save."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "--target", "example.com", "--no-save"])

        assert result.exit_code == 0

    def test_assess_without_target_or_subcommand(self) -> None:
        """Test assess without target or subcommand exits."""
        result = runner.invoke(app, ["assess"])
        # Should exit with no action (no_args_is_help)
        assert result.exit_code in [0, 2]


class TestAssessVulnsCommand:
    """Tests for assess vulns subcommand."""

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._query_nvd")
    def test_assess_vulns_basic(
        self,
        mock_nvd: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test basic vulnerability assessment."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "vulns", "example.com"])

        assert result.exit_code == 0
        mock_nvd.assert_called_once()

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._query_nvd")
    def test_assess_vulns_no_cve_check(
        self,
        mock_nvd: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test vulnerability assessment without CVE check."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "vulns", "example.com", "--no-cve"])

        assert result.exit_code == 0
        mock_nvd.assert_not_called()

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._query_nvd")
    def test_assess_vulns_min_severity(
        self,
        mock_nvd: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test vulnerability assessment with min severity filter."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "vulns", "example.com", "--min-severity", "high"])

        assert result.exit_code == 0


class TestAssessConfigCommand:
    """Tests for assess config subcommand."""

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._check_ssl_config")
    @patch("domainraptor.cli.commands.assess._check_dns_config")
    @patch("domainraptor.cli.commands.assess._check_http_headers")
    def test_assess_config_all(
        self,
        mock_headers: MagicMock,
        mock_dns: MagicMock,
        mock_ssl: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test config assessment with all categories."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "config", "example.com"])

        assert result.exit_code == 0
        mock_ssl.assert_called_once()
        mock_dns.assert_called_once()
        mock_headers.assert_called_once()

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._check_ssl_config")
    @patch("domainraptor.cli.commands.assess._check_dns_config")
    @patch("domainraptor.cli.commands.assess._check_http_headers")
    def test_assess_config_ssl_only(
        self,
        mock_headers: MagicMock,
        mock_dns: MagicMock,
        mock_ssl: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test config assessment with SSL category only."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "config", "example.com", "--category", "ssl"])

        assert result.exit_code == 0
        mock_ssl.assert_called_once()
        mock_dns.assert_not_called()
        mock_headers.assert_not_called()

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._check_ssl_config")
    @patch("domainraptor.cli.commands.assess._check_dns_config")
    @patch("domainraptor.cli.commands.assess._check_http_headers")
    def test_assess_config_dns_only(
        self,
        mock_headers: MagicMock,
        mock_dns: MagicMock,
        mock_ssl: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test config assessment with DNS category only."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "config", "example.com", "--category", "dns"])

        assert result.exit_code == 0
        mock_ssl.assert_not_called()
        mock_dns.assert_called_once()
        mock_headers.assert_not_called()

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._check_ssl_config")
    @patch("domainraptor.cli.commands.assess._check_dns_config")
    @patch("domainraptor.cli.commands.assess._check_http_headers")
    def test_assess_config_headers_only(
        self,
        mock_headers: MagicMock,
        mock_dns: MagicMock,
        mock_ssl: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test config assessment with headers category only."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "config", "example.com", "--category", "headers"])

        assert result.exit_code == 0
        mock_ssl.assert_not_called()
        mock_dns.assert_not_called()
        mock_headers.assert_called_once()


class TestAssessOutdatedCommand:
    """Tests for assess outdated subcommand."""

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._check_outdated_software")
    def test_assess_outdated_basic(
        self,
        mock_outdated: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test basic outdated software check."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "outdated", "example.com"])

        assert result.exit_code == 0
        mock_outdated.assert_called_once()

    @patch("domainraptor.cli.commands.assess.create_progress")
    @patch("domainraptor.cli.commands.assess._check_outdated_software")
    def test_assess_outdated_include_minor(
        self,
        mock_outdated: MagicMock,
        mock_progress: MagicMock,
    ) -> None:
        """Test outdated software check with minor versions."""
        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["assess", "outdated", "example.com", "--include-minor"])

        assert result.exit_code == 0


class TestInternalFunctions:
    """Tests for internal assessment functions."""

    def test_assess_vulnerabilities(self) -> None:
        """Test _assess_vulnerabilities function."""
        from domainraptor.cli.commands.assess import _assess_vulnerabilities
        from domainraptor.core.config import AppConfig
        from domainraptor.core.types import ScanResult

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )
        config = AppConfig()

        # Should not raise
        _assess_vulnerabilities("example.com", result, config)

    @patch("domainraptor.cli.commands.assess.SSLAnalyzer")
    @patch("domainraptor.cli.commands.assess.DnsSecurityChecker")
    @patch("domainraptor.cli.commands.assess.HeadersChecker")
    def test_assess_configuration(
        self,
        mock_headers: MagicMock,
        mock_dns: MagicMock,
        mock_ssl: MagicMock,
    ) -> None:
        """Test _assess_configuration function."""
        from domainraptor.cli.commands.assess import _assess_configuration
        from domainraptor.core.config import AppConfig
        from domainraptor.core.types import ScanResult

        # Setup mocks
        mock_ssl.return_value.__enter__ = MagicMock()
        mock_ssl.return_value.__enter__.return_value.assess_safe.return_value = []
        mock_ssl.return_value.__exit__ = MagicMock(return_value=False)

        mock_dns.return_value.__enter__ = MagicMock()
        mock_dns.return_value.__enter__.return_value.assess_safe.return_value = []
        mock_dns.return_value.__exit__ = MagicMock(return_value=False)

        mock_headers.return_value.__enter__ = MagicMock()
        mock_headers.return_value.__enter__.return_value.assess_safe.return_value = []
        mock_headers.return_value.__exit__ = MagicMock(return_value=False)

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )
        config = AppConfig()

        _assess_configuration("example.com", result, config)

        # All checkers should be called
        mock_ssl.assert_called_once()
        mock_dns.assert_called_once()
        mock_headers.assert_called_once()

    def test_assess_outdated(self) -> None:
        """Test _assess_outdated function."""
        from domainraptor.cli.commands.assess import _assess_outdated
        from domainraptor.core.config import AppConfig
        from domainraptor.core.types import ScanResult

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )
        config = AppConfig()

        # Should not raise
        _assess_outdated("example.com", result, config)

    def test_query_nvd(self) -> None:
        """Test _query_nvd function."""
        from domainraptor.cli.commands.assess import _query_nvd
        from domainraptor.core.types import ScanResult

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

        # Should not raise
        _query_nvd("example.com", result, SeverityLevel.LOW)

    @patch("domainraptor.cli.commands.assess.SSLAnalyzer")
    def test_check_ssl_config_success(self, mock_ssl: MagicMock) -> None:
        """Test _check_ssl_config with successful check."""
        from domainraptor.cli.commands.assess import _check_ssl_config
        from domainraptor.core.types import ScanResult

        # Setup mock to return issues
        mock_instance = MagicMock()
        mock_instance.assess.return_value = [
            ConfigIssue(
                id="ssl-001",
                title="TLS 1.0 Enabled",
                description="TLS 1.0 is deprecated",
                severity=SeverityLevel.MEDIUM,
                category="ssl",
            )
        ]
        mock_ssl.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_ssl.return_value.__exit__ = MagicMock(return_value=False)

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

        _check_ssl_config("example.com", result)

        assert len(result.config_issues) == 1
        assert result.config_issues[0].title == "TLS 1.0 Enabled"

    @patch("domainraptor.cli.commands.assess.SSLAnalyzer")
    def test_check_ssl_config_error(self, mock_ssl: MagicMock) -> None:
        """Test _check_ssl_config with error."""
        from domainraptor.cli.commands.assess import _check_ssl_config
        from domainraptor.core.types import ScanResult

        # Setup mock to raise exception
        mock_instance = MagicMock()
        mock_instance.assess.side_effect = Exception("Connection failed")
        mock_ssl.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_ssl.return_value.__exit__ = MagicMock(return_value=False)

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

        _check_ssl_config("example.com", result)

        assert len(result.errors) == 1
        assert "SSL check failed" in result.errors[0]

    @patch("domainraptor.cli.commands.assess.DnsSecurityChecker")
    def test_check_dns_config_success(self, mock_dns: MagicMock) -> None:
        """Test _check_dns_config with successful check."""
        from domainraptor.cli.commands.assess import _check_dns_config
        from domainraptor.core.types import ScanResult

        # Setup mock
        mock_instance = MagicMock()
        mock_instance.assess.return_value = [
            ConfigIssue(
                id="dns-001",
                title="Missing DNSSEC",
                description="DNSSEC is not enabled",
                severity=SeverityLevel.MEDIUM,
                category="dns",
            )
        ]
        mock_dns.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_dns.return_value.__exit__ = MagicMock(return_value=False)

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

        _check_dns_config("example.com", result)

        assert len(result.config_issues) == 1

    @patch("domainraptor.cli.commands.assess.DnsSecurityChecker")
    def test_check_dns_config_error(self, mock_dns: MagicMock) -> None:
        """Test _check_dns_config with error."""
        from domainraptor.cli.commands.assess import _check_dns_config
        from domainraptor.core.types import ScanResult

        mock_instance = MagicMock()
        mock_instance.assess.side_effect = Exception("DNS error")
        mock_dns.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_dns.return_value.__exit__ = MagicMock(return_value=False)

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

        _check_dns_config("example.com", result)

        assert len(result.errors) == 1
        assert "DNS check failed" in result.errors[0]

    @patch("domainraptor.cli.commands.assess.HeadersChecker")
    def test_check_http_headers_success(self, mock_headers: MagicMock) -> None:
        """Test _check_http_headers with successful check."""
        from domainraptor.cli.commands.assess import _check_http_headers
        from domainraptor.core.types import ScanResult

        mock_instance = MagicMock()
        mock_instance.assess.return_value = [
            ConfigIssue(
                id="headers-001",
                title="Missing HSTS",
                description="HSTS header is not set",
                severity=SeverityLevel.MEDIUM,
                category="headers",
            )
        ]
        mock_headers.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_headers.return_value.__exit__ = MagicMock(return_value=False)

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

        _check_http_headers("example.com", result)

        assert len(result.config_issues) == 1

    @patch("domainraptor.cli.commands.assess.HeadersChecker")
    def test_check_http_headers_error(self, mock_headers: MagicMock) -> None:
        """Test _check_http_headers with error."""
        from domainraptor.cli.commands.assess import _check_http_headers
        from domainraptor.core.types import ScanResult

        mock_instance = MagicMock()
        mock_instance.assess.side_effect = Exception("Headers error")
        mock_headers.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_headers.return_value.__exit__ = MagicMock(return_value=False)

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

        _check_http_headers("example.com", result)

        assert len(result.errors) == 1
        assert "Headers check failed" in result.errors[0]

    def test_check_outdated_software(self) -> None:
        """Test _check_outdated_software function."""
        from domainraptor.cli.commands.assess import _check_outdated_software
        from domainraptor.core.types import ScanResult

        result = ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

        # Should not raise - currently a placeholder
        _check_outdated_software("example.com", result, include_minor=True)
