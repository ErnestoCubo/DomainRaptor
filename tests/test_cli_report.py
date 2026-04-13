"""Tests for report CLI command."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

from typer.testing import CliRunner

from domainraptor.cli.main import app

runner = CliRunner()


# ============================================================================
# Report Callback Tests
# ============================================================================


class TestReportCallback:
    """Tests for report callback function."""

    def test_report_no_args_shows_message(self) -> None:
        """Test report without subcommand shows message."""
        result = runner.invoke(app, ["--no-banner", "report"])

        # With no_args_is_help=True, should show help
        assert result.exit_code == 2 or result.exit_code == 0


# ============================================================================
# Generate Command Tests
# ============================================================================


class TestGenerateCommand:
    """Tests for report generate command."""

    def test_generate_json_output(self) -> None:
        """Test generate command with JSON output."""
        result = runner.invoke(app, ["--no-banner", "report", "generate", "example.com"])

        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_generate_yaml_output(self) -> None:
        """Test generate command with YAML output."""
        result = runner.invoke(
            app, ["--no-banner", "report", "generate", "example.com", "--format", "yaml"]
        )

        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_generate_markdown_output(self) -> None:
        """Test generate command with Markdown output."""
        result = runner.invoke(
            app, ["--no-banner", "report", "generate", "example.com", "--format", "md"]
        )

        assert result.exit_code == 0
        assert "Security Report" in result.output

    def test_generate_html_output(self) -> None:
        """Test generate command with HTML output."""
        result = runner.invoke(
            app, ["--no-banner", "report", "generate", "example.com", "--format", "html"]
        )

        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output

    def test_generate_with_output_file(self) -> None:
        """Test generate command saves to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"

            result = runner.invoke(
                app,
                [
                    "--no-banner",
                    "report",
                    "generate",
                    "example.com",
                    "--output",
                    str(output_path),
                ],
            )

            assert result.exit_code == 0
            assert output_path.exists()
            assert "Report saved to" in result.output

    def test_generate_with_nested_output_dir(self) -> None:
        """Test generate creates nested directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "subdir" / "nested" / "report.json"

            result = runner.invoke(
                app,
                [
                    "--no-banner",
                    "report",
                    "generate",
                    "example.com",
                    "--output",
                    str(output_path),
                ],
            )

            assert result.exit_code == 0
            assert output_path.exists()

    def test_generate_with_history(self) -> None:
        """Test generate command with history flag."""
        result = runner.invoke(
            app,
            ["--no-banner", "report", "generate", "example.com", "--history"],
        )

        assert result.exit_code == 0

    def test_generate_without_remediation_flag(self) -> None:
        """Test generate command runs (remediation included by default)."""
        # Note: --remediation is True by default, just test normal invocation
        result = runner.invoke(
            app,
            ["--no-banner", "report", "generate", "example.com"],
        )

        assert result.exit_code == 0

    def test_generate_with_scan_id(self) -> None:
        """Test generate command with specific scan ID."""
        result = runner.invoke(
            app,
            [
                "--no-banner",
                "report",
                "generate",
                "example.com",
                "--scan",
                "abc123",
            ],
        )

        assert result.exit_code == 0

    def test_generate_with_template(self) -> None:
        """Test generate command with template."""
        result = runner.invoke(
            app,
            [
                "--no-banner",
                "report",
                "generate",
                "example.com",
                "--template",
                "custom",
            ],
        )

        assert result.exit_code == 0


# ============================================================================
# Summary Command Tests
# ============================================================================


class TestSummaryCommand:
    """Tests for report summary command."""

    def test_summary_displays(self) -> None:
        """Test summary command displays output."""
        result = runner.invoke(app, ["--no-banner", "report", "summary", "example.com"])

        assert result.exit_code == 0
        assert "Executive Summary" in result.output
        assert "example.com" in result.output

    def test_summary_with_output_file(self) -> None:
        """Test summary command saves to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "summary.md"

            result = runner.invoke(
                app,
                [
                    "--no-banner",
                    "report",
                    "summary",
                    "example.com",
                    "--output",
                    str(output_path),
                ],
            )

            assert result.exit_code == 0
            assert output_path.exists()
            assert "Summary saved to" in result.output


# ============================================================================
# List Command Tests
# ============================================================================


class TestListCommand:
    """Tests for report list command."""

    def test_list_shows_reports(self) -> None:
        """Test list command shows reports."""
        result = runner.invoke(app, ["--no-banner", "report", "list"])

        assert result.exit_code == 0
        assert "Recent Scans" in result.output

    def test_list_with_target_filter(self) -> None:
        """Test list command with target filter."""
        result = runner.invoke(app, ["--no-banner", "report", "list", "example.com"])

        assert result.exit_code == 0

    def test_list_with_limit(self) -> None:
        """Test list command with limit."""
        result = runner.invoke(app, ["--no-banner", "report", "list", "--limit", "5"])

        assert result.exit_code == 0


# ============================================================================
# Export Command Tests
# ============================================================================


class TestExportCommand:
    """Tests for report export command."""

    def test_export_json(self) -> None:
        """Test export command with JSON format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "export.json"

            result = runner.invoke(
                app,
                [
                    "--no-banner",
                    "report",
                    "export",
                    "example.com",
                    "--output",
                    str(output_path),
                    "--format",
                    "json",
                ],
            )

            assert result.exit_code == 0
            assert "Exported to" in result.output

    def test_export_yaml(self) -> None:
        """Test export command with YAML format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "export.yaml"

            result = runner.invoke(
                app,
                [
                    "--no-banner",
                    "report",
                    "export",
                    "example.com",
                    "--output",
                    str(output_path),
                    "--format",
                    "yaml",
                ],
            )

            assert result.exit_code == 0

    def test_export_table(self) -> None:
        """Test export command with table format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "export.txt"

            result = runner.invoke(
                app,
                [
                    "--no-banner",
                    "report",
                    "export",
                    "example.com",
                    "--output",
                    str(output_path),
                    "--format",
                    "table",
                ],
            )

            assert result.exit_code == 0

    def test_export_all_scans(self) -> None:
        """Test export command with all scans flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "export.json"

            result = runner.invoke(
                app,
                [
                    "--no-banner",
                    "report",
                    "export",
                    "example.com",
                    "--output",
                    str(output_path),
                    "--all",
                ],
            )

            assert result.exit_code == 0


# ============================================================================
# Schedule Command Tests
# ============================================================================


class TestScheduleCommand:
    """Tests for report schedule command."""

    def test_schedule_default_frequency(self) -> None:
        """Test schedule command with default frequency."""
        result = runner.invoke(app, ["--no-banner", "report", "schedule", "example.com"])

        assert result.exit_code == 0
        assert "scheduled" in result.output.lower()

    def test_schedule_daily(self) -> None:
        """Test schedule command with daily frequency."""
        result = runner.invoke(
            app,
            [
                "--no-banner",
                "report",
                "schedule",
                "example.com",
                "--frequency",
                "daily",
            ],
        )

        assert result.exit_code == 0
        assert "daily" in result.output.lower()

    def test_schedule_monthly(self) -> None:
        """Test schedule command with monthly frequency."""
        result = runner.invoke(
            app,
            [
                "--no-banner",
                "report",
                "schedule",
                "example.com",
                "--frequency",
                "monthly",
            ],
        )

        assert result.exit_code == 0
        assert "monthly" in result.output.lower()

    def test_schedule_with_recipients(self) -> None:
        """Test schedule command with recipients."""
        result = runner.invoke(
            app,
            [
                "--no-banner",
                "report",
                "schedule",
                "example.com",
                "--recipients",
                "admin@example.com,security@example.com",
            ],
        )

        assert result.exit_code == 0
        assert "Recipients" in result.output


# ============================================================================
# Helper Function Tests
# ============================================================================


class TestReportHelperFunctions:
    """Tests for report helper functions."""

    def test_build_report_data(self) -> None:
        """Test _build_report_data function."""
        from domainraptor.cli.commands.report import _build_report_data

        data = _build_report_data("example.com", False, False, None)

        assert data["target"] == "example.com"
        assert "summary" in data
        assert "assets" in data
        assert "vulnerabilities" in data

    def test_build_report_data_with_scan_id(self) -> None:
        """Test _build_report_data with specific scan ID."""
        from domainraptor.cli.commands.report import _build_report_data

        data = _build_report_data("example.com", True, True, "abc123")

        assert data["scan_id"] == "abc123"

    def test_format_report_json(self) -> None:
        """Test _format_report with JSON."""
        from domainraptor.cli.commands.report import _format_report

        data = {"target": "example.com", "summary": {}}
        result = _format_report(data, "json")

        assert "example.com" in result

    def test_format_report_yaml(self) -> None:
        """Test _format_report with YAML."""
        from domainraptor.cli.commands.report import _format_report

        data = {"target": "example.com", "summary": {}}
        result = _format_report(data, "yaml")

        assert "example.com" in result

    def test_format_report_md(self) -> None:
        """Test _format_report with Markdown."""
        from domainraptor.cli.commands.report import _format_report

        data = {
            "target": "example.com",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_assets": 10,
                "total_subdomains": 5,
                "total_services": 3,
                "total_vulnerabilities": 2,
                "config_issues": 1,
            },
            "vulnerabilities": [{"id": "CVE-123", "severity": "high", "title": "Test"}],
            "config_issues": [{"id": "SSL-001", "severity": "medium", "title": "Test"}],
        }
        result = _format_report(data, "md")

        assert "# Security Report" in result
        assert "example.com" in result
        assert "CVE-123" in result

    def test_format_report_html(self) -> None:
        """Test _format_report with HTML."""
        from domainraptor.cli.commands.report import _format_report

        data = {
            "target": "example.com",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_assets": 10,
                "total_vulnerabilities": 2,
                "config_issues": 1,
            },
            "vulnerabilities": [{"id": "CVE-123", "severity": "high", "title": "Test"}],
        }
        result = _format_report(data, "html")

        assert "<!DOCTYPE html>" in result
        assert "example.com" in result

    def test_format_report_unknown_defaults_json(self) -> None:
        """Test _format_report with unknown format defaults to JSON."""
        from domainraptor.cli.commands.report import _format_report

        data = {"target": "example.com"}
        result = _format_report(data, "unknown")

        # Should default to JSON
        assert "example.com" in result

    def test_format_markdown_no_vulns(self) -> None:
        """Test _format_markdown with no vulnerabilities."""
        from domainraptor.cli.commands.report import _format_markdown

        data = {
            "target": "example.com",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_assets": 0,
                "total_subdomains": 0,
                "total_services": 0,
                "total_vulnerabilities": 0,
                "config_issues": 0,
            },
            "vulnerabilities": [],
            "config_issues": [],
        }
        result = _format_markdown(data)

        assert "# Security Report" in result

    def test_format_html_multiple_vulns(self) -> None:
        """Test _format_html with multiple vulnerabilities."""
        from domainraptor.cli.commands.report import _format_html

        data = {
            "target": "example.com",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_assets": 10,
                "total_vulnerabilities": 3,
                "config_issues": 2,
            },
            "vulnerabilities": [
                {"id": "CVE-001", "severity": "critical", "title": "Critical Issue"},
                {"id": "CVE-002", "severity": "high", "title": "High Issue"},
                {"id": "CVE-003", "severity": "medium", "title": "Medium Issue"},
            ],
        }
        result = _format_html(data)

        assert "<!DOCTYPE html>" in result
        assert "CVE-001" in result
        assert "CVE-002" in result
        assert "CVE-003" in result
