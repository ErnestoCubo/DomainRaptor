"""Tests for compare CLI commands."""

from __future__ import annotations

from typer.testing import CliRunner

from domainraptor.cli.main import app

runner = CliRunner()


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
        assert "5" in result.output

    def test_compare_history_with_since(self) -> None:
        """Test compare history with --since option."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "history", "example.com", "--since", "2024-01-01"],
        )
        assert result.exit_code == 0

    def test_compare_history_shows_changes(self) -> None:
        """Test compare history shows changes."""
        result = runner.invoke(app, ["--no-banner", "compare", "history", "example.com"])
        assert result.exit_code == 0
        # Should show demo changes
        assert "change" in result.output.lower() or "Change" in result.output


# ============================================================================
# Compare Scans Command Tests
# ============================================================================


class TestCompareScans:
    """Tests for compare scans command."""

    def test_compare_scans_basic(self) -> None:
        """Test basic compare scans command."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "scans", "scan-id-1", "scan-id-2"],
        )
        assert result.exit_code == 0
        assert "scan-id-1" in result.output or "Comparing" in result.output

    def test_compare_scans_shows_comparison(self) -> None:
        """Test compare scans shows comparison info."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "scans", "abc123", "def456"],
        )
        assert result.exit_code == 0


# ============================================================================
# Compare Targets Command Tests
# ============================================================================


class TestCompareTargets:
    """Tests for compare targets command."""

    def test_compare_targets_basic(self) -> None:
        """Test basic compare targets command."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "targets", "example.com", "example.org"],
        )
        assert result.exit_code == 0
        assert "example.com" in result.output
        assert "example.org" in result.output

    def test_compare_targets_with_aspect_all(self) -> None:
        """Test compare targets with aspect all."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "targets", "example.com", "example.org", "--aspect", "all"],
        )
        assert result.exit_code == 0

    def test_compare_targets_with_aspect_subdomains(self) -> None:
        """Test compare targets with aspect subdomains."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "targets", "a.com", "b.com", "--aspect", "subdomains"],
        )
        assert result.exit_code == 0
        assert "subdomains" in result.output.lower()

    def test_compare_targets_shows_table(self) -> None:
        """Test compare targets shows comparison table."""
        result = runner.invoke(
            app,
            ["--no-banner", "compare", "targets", "example.com", "example.org"],
        )
        assert result.exit_code == 0
        # Should show comparison metrics
        assert "Subdomains" in result.output or "Metric" in result.output


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
