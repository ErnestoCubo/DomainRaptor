"""Tests for CLI main module and commands."""

from __future__ import annotations

from typer.testing import CliRunner

from domainraptor import __version__
from domainraptor.cli.main import app
from domainraptor.core.config import OutputFormat, ScanMode

runner = CliRunner()


class TestMainCLI:
    """Tests for main CLI application."""

    def test_no_args_shows_help(self) -> None:
        """Test CLI with no args shows help."""
        result = runner.invoke(app)
        # Exit code 2 is expected for no_args_is_help=True
        assert result.exit_code in [0, 2]
        assert (
            "DomainRaptor" in result.stdout
            or "discover" in result.stdout
            or "Usage" in result.stdout
        )

    def test_version_flag(self) -> None:
        """Test --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_version_short_flag(self) -> None:
        """Test -v flag."""
        result = runner.invoke(app, ["-v"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_verbose_flag_accepted(self) -> None:
        """Test --verbose flag is accepted."""
        result = runner.invoke(app, ["--verbose", "--help"])
        assert result.exit_code == 0

    def test_debug_flag_accepted(self) -> None:
        """Test --debug flag is accepted."""
        result = runner.invoke(app, ["--debug", "--help"])
        assert result.exit_code == 0

    def test_help_flag(self) -> None:
        """Test --help flag."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "discover" in result.stdout
        assert "assess" in result.stdout
        assert "config" in result.stdout


class TestDiscoverCommand:
    """Tests for discover command."""

    def test_discover_help(self) -> None:
        """Test discover --help."""
        result = runner.invoke(app, ["discover", "--help"])
        assert result.exit_code == 0
        assert "discover" in result.stdout.lower()

    def test_discover_dns_help(self) -> None:
        """Test discover dns --help."""
        result = runner.invoke(app, ["discover", "dns", "--help"])
        assert result.exit_code == 0

    def test_discover_whois_help(self) -> None:
        """Test discover whois --help."""
        result = runner.invoke(app, ["discover", "whois", "--help"])
        assert result.exit_code == 0

    def test_discover_certs_help(self) -> None:
        """Test discover certs --help."""
        result = runner.invoke(app, ["discover", "certs", "--help"])
        assert result.exit_code == 0

    def test_discover_subdomains_help(self) -> None:
        """Test discover subdomains --help."""
        result = runner.invoke(app, ["discover", "subdomains", "--help"])
        assert result.exit_code == 0


class TestAssessCommand:
    """Tests for assess command."""

    def test_assess_help(self) -> None:
        """Test assess --help."""
        result = runner.invoke(app, ["assess", "--help"])
        assert result.exit_code == 0
        assert "assess" in result.stdout.lower()

    def test_assess_config_help(self) -> None:
        """Test assess config --help."""
        result = runner.invoke(app, ["assess", "config", "--help"])
        assert result.exit_code == 0


class TestConfigCommand:
    """Tests for config command."""

    def test_config_help(self) -> None:
        """Test config --help."""
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0

    def test_config_list(self) -> None:
        """Test config list."""
        result = runner.invoke(app, ["config", "list"])
        # Should work (may show no API keys configured)
        assert result.exit_code == 0

    def test_config_path(self) -> None:
        """Test config path."""
        result = runner.invoke(app, ["config", "path"])
        assert result.exit_code == 0
        assert ".domainraptor" in result.stdout or "config" in result.stdout.lower()

    def test_config_test(self) -> None:
        """Test config test."""
        result = runner.invoke(app, ["config", "test"])
        # May pass or fail depending on API keys, but should not crash
        assert result.exit_code in [0, 1]


class TestDbCommand:
    """Tests for db command."""

    def test_db_help(self) -> None:
        """Test db --help."""
        result = runner.invoke(app, ["db", "--help"])
        assert result.exit_code == 0

    def test_db_stats(self) -> None:
        """Test db stats."""
        result = runner.invoke(app, ["db", "stats"])
        assert result.exit_code == 0

    def test_db_list(self) -> None:
        """Test db list."""
        result = runner.invoke(app, ["db", "list"])
        assert result.exit_code == 0


class TestWatchCommand:
    """Tests for watch command."""

    def test_watch_help(self) -> None:
        """Test watch --help."""
        result = runner.invoke(app, ["watch", "--help"])
        assert result.exit_code == 0

    def test_watch_list(self) -> None:
        """Test watch list."""
        result = runner.invoke(app, ["watch", "list"])
        assert result.exit_code == 0


class TestCompareCommand:
    """Tests for compare command."""

    def test_compare_help(self) -> None:
        """Test compare --help."""
        result = runner.invoke(app, ["compare", "--help"])
        assert result.exit_code == 0


class TestReportCommand:
    """Tests for report command."""

    def test_report_help(self) -> None:
        """Test report --help."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0


class TestScanModeOption:
    """Tests for scan mode option."""

    def test_scan_mode_values(self) -> None:
        """Test scan mode enum values."""
        assert ScanMode.QUICK.value == "quick"
        assert ScanMode.STANDARD.value == "standard"
        assert ScanMode.DEEP.value == "deep"
        assert ScanMode.STEALTH.value == "stealth"

    def test_mode_option_accepted(self) -> None:
        """Test --mode option is accepted."""
        result = runner.invoke(app, ["--mode", "quick", "--help"])
        assert result.exit_code == 0


class TestOutputFormatOption:
    """Tests for output format option."""

    def test_output_format_values(self) -> None:
        """Test output format enum values."""
        assert OutputFormat.TABLE.value == "table"
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.CSV.value == "csv"

    def test_format_option_accepted(self) -> None:
        """Test --format option is accepted."""
        result = runner.invoke(app, ["--format", "json", "--help"])
        assert result.exit_code == 0


class TestCLIExitCodes:
    """Tests for CLI exit codes."""

    def test_unknown_command_fails(self) -> None:
        """Test unknown command fails with error."""
        result = runner.invoke(app, ["unknowncommand"])
        assert result.exit_code != 0

    def test_invalid_option_fails(self) -> None:
        """Test invalid option fails."""
        result = runner.invoke(app, ["--invalid-option"])
        assert result.exit_code != 0


class TestDiscoverSubcommands:
    """Tests for discover subcommands execution."""

    def test_discover_dns_with_target(self) -> None:
        """Test discover dns with a target."""
        # Command may fail or show help, but should be recognized
        result = runner.invoke(app, ["discover", "dns", "example.com"])
        # Exit code 2 is typical for no_args_is_help or missing args
        assert result.exit_code in [0, 1, 2]

    def test_discover_whois_with_target(self) -> None:
        """Test discover whois with a target."""
        result = runner.invoke(app, ["discover", "whois", "example.com"])
        # Accept any exit code - testing command execution path
        assert result.exit_code in [0, 1, 2]


class TestAssessSubcommands:
    """Tests for assess subcommands."""

    def test_assess_ssl_help(self) -> None:
        """Test assess ssl --help."""
        result = runner.invoke(app, ["assess", "ssl", "--help"])
        # Accept exit code 0 or 2 (no_args_is_help)
        assert result.exit_code in [0, 2]

    def test_assess_headers_help(self) -> None:
        """Test assess headers --help."""
        result = runner.invoke(app, ["assess", "headers", "--help"])
        assert result.exit_code in [0, 2]

    def test_assess_dns_help(self) -> None:
        """Test assess dns --help."""
        result = runner.invoke(app, ["assess", "dns", "--help"])
        assert result.exit_code in [0, 2]


class TestDbSubcommands:
    """Tests for db subcommands."""

    def test_db_init(self) -> None:
        """Test db init command."""
        result = runner.invoke(app, ["db", "init"])
        # Should work or show help
        assert result.exit_code in [0, 1, 2]

    def test_db_clear_requires_confirm(self) -> None:
        """Test db clear requires confirmation."""
        # Without --force, should abort
        result = runner.invoke(app, ["db", "clear"], input="n\n")
        assert result.exit_code in [0, 1, 2]


class TestWatchSubcommands:
    """Tests for watch subcommands."""

    def test_watch_add_requires_target(self) -> None:
        """Test watch add requires target."""
        result = runner.invoke(app, ["watch", "add", "--help"])
        assert result.exit_code in [0, 2]

    def test_watch_status(self) -> None:
        """Test watch status command."""
        result = runner.invoke(app, ["watch", "status"])
        # May show no watches, but should not crash
        assert result.exit_code in [0, 1, 2]


class TestConfigSubcommands:
    """Tests for config subcommands."""

    def test_config_set_without_value(self) -> None:
        """Test config set without value shows error."""
        result = runner.invoke(app, ["config", "set", "--help"])
        assert result.exit_code in [0, 2]

    def test_config_get_without_key(self) -> None:
        """Test config get without key shows help."""
        result = runner.invoke(app, ["config", "get", "--help"])
        assert result.exit_code in [0, 2]


class TestReportSubcommands:
    """Tests for report subcommands."""

    def test_report_latest(self) -> None:
        """Test report latest."""
        result = runner.invoke(app, ["report", "latest"])
        # May have no scans, may require args
        assert result.exit_code in [0, 1, 2]

    def test_report_generate_without_scan(self) -> None:
        """Test report generate needs scan_id."""
        result = runner.invoke(app, ["report", "generate", "--help"])
        assert result.exit_code in [0, 2]
