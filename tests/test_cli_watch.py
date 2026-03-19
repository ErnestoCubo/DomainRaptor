"""Tests for watch CLI command."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from domainraptor.cli.commands.watch import (
    _check_target,
    _parse_interval,
    _watch_targets,
)
from domainraptor.cli.main import app
from domainraptor.core.types import WatchTarget

runner = CliRunner()


class TestWatchHelperFunctions:
    """Tests for watch helper functions."""

    def test_parse_interval_hours(self) -> None:
        """Test parsing hours interval."""
        assert _parse_interval("1h") == 1
        assert _parse_interval("6h") == 6
        assert _parse_interval("24h") == 24

    def test_parse_interval_days(self) -> None:
        """Test parsing days interval."""
        assert _parse_interval("1d") == 24
        assert _parse_interval("7d") == 168

    def test_parse_interval_minutes(self) -> None:
        """Test parsing minutes interval (converted to hours)."""
        assert _parse_interval("60m") == 1
        assert _parse_interval("30m") == 1  # Min 1 hour

    def test_parse_interval_invalid(self) -> None:
        """Test parsing invalid interval."""
        assert _parse_interval("invalid") is None
        assert _parse_interval("") is None
        assert _parse_interval("abc") is None

    def test_check_target_returns_changes(self) -> None:
        """Test _check_target returns changes for demo target."""
        from domainraptor.core.config import AppConfig

        watch_target = WatchTarget(
            target="example.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )
        config = AppConfig()

        changes = _check_target(watch_target, config)
        # Demo target returns a sample change
        assert len(changes) == 1
        assert changes[0].asset_value == "new-api.example.com"

    def test_check_target_other_domain(self) -> None:
        """Test _check_target for non-example domains."""
        from domainraptor.core.config import AppConfig

        watch_target = WatchTarget(
            target="other.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )
        config = AppConfig()

        changes = _check_target(watch_target, config)
        assert changes == []


class TestWatchListCommand:
    """Tests for watch list command."""

    def test_watch_list_empty(self) -> None:
        """Test list command with no targets."""
        _watch_targets.clear()
        result = runner.invoke(app, ["--no-banner", "watch", "list"])
        assert result.exit_code == 0
        assert "No targets being watched" in result.stdout

    def test_watch_list_with_targets(self) -> None:
        """Test list command with watched targets."""
        _watch_targets.clear()
        _watch_targets["test.com"] = WatchTarget(
            target="test.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )

        result = runner.invoke(app, ["--no-banner", "watch", "list"])
        assert result.exit_code == 0
        assert "test.com" in result.stdout

        # Cleanup
        _watch_targets.clear()


class TestWatchAddCommand:
    """Tests for watch add command."""

    @patch("domainraptor.cli.commands.watch.create_progress")
    def test_watch_add_success(self, mock_progress: MagicMock) -> None:
        """Test adding a target to watch list."""
        _watch_targets.clear()

        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["--no-banner", "watch", "add", "newdomain.com"])

        assert result.exit_code == 0
        assert "newdomain.com" in _watch_targets

        # Cleanup
        _watch_targets.clear()

    @patch("domainraptor.cli.commands.watch.create_progress")
    def test_watch_add_with_interval(self, mock_progress: MagicMock) -> None:
        """Test adding a target with custom interval."""
        _watch_targets.clear()

        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(
            app, ["--no-banner", "watch", "add", "interval.com", "--interval", "6h"]
        )

        assert result.exit_code == 0
        assert _watch_targets["interval.com"].interval_hours == 6

        # Cleanup
        _watch_targets.clear()

    def test_watch_add_invalid_interval(self) -> None:
        """Test adding a target with invalid interval."""
        _watch_targets.clear()

        result = runner.invoke(
            app, ["--no-banner", "watch", "add", "invalid.com", "--interval", "invalid"]
        )

        assert result.exit_code == 1

        # Cleanup
        _watch_targets.clear()

    @patch("domainraptor.cli.commands.watch.create_progress")
    @patch("typer.confirm", return_value=False)
    def test_watch_add_already_watching_decline(
        self, mock_confirm: MagicMock, mock_progress: MagicMock
    ) -> None:
        """Test adding already watched target and declining update."""
        _watch_targets.clear()
        _watch_targets["existing.com"] = WatchTarget(
            target="existing.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )

        result = runner.invoke(app, ["--no-banner", "watch", "add", "existing.com"])

        # Should exit without error
        assert result.exit_code == 0

        # Cleanup
        _watch_targets.clear()


class TestWatchRemoveCommand:
    """Tests for watch remove command."""

    def test_watch_remove_not_found(self) -> None:
        """Test removing a target that isn't being watched."""
        _watch_targets.clear()

        result = runner.invoke(app, ["--no-banner", "watch", "remove", "notfound.com", "--force"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    def test_watch_remove_success(self) -> None:
        """Test removing a watched target."""
        _watch_targets.clear()
        _watch_targets["toremove.com"] = WatchTarget(
            target="toremove.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )

        result = runner.invoke(app, ["--no-banner", "watch", "remove", "toremove.com", "--force"])

        assert result.exit_code == 0
        assert "Removed" in result.stdout
        assert "toremove.com" not in _watch_targets

    @patch("typer.confirm", return_value=False)
    def test_watch_remove_decline(self, mock_confirm: MagicMock) -> None:
        """Test declining to remove a target."""
        _watch_targets.clear()
        _watch_targets["keep.com"] = WatchTarget(
            target="keep.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )

        runner.invoke(app, ["--no-banner", "watch", "remove", "keep.com"])

        # Cleanup
        _watch_targets.clear()


class TestWatchRunCommand:
    """Tests for watch run command."""

    def test_watch_run_no_targets(self) -> None:
        """Test run with no targets due."""
        _watch_targets.clear()

        result = runner.invoke(app, ["--no-banner", "watch", "run"])

        assert result.exit_code == 0
        assert "No targets due" in result.stdout

    def test_watch_run_target_not_found(self) -> None:
        """Test run with specific target not found."""
        _watch_targets.clear()

        result = runner.invoke(app, ["--no-banner", "watch", "run", "notfound.com"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    @patch("domainraptor.cli.commands.watch.create_progress")
    def test_watch_run_with_force(self, mock_progress: MagicMock) -> None:
        """Test force run on watched target."""
        _watch_targets.clear()
        _watch_targets["forcerun.com"] = WatchTarget(
            target="forcerun.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )

        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["--no-banner", "watch", "run", "forcerun.com", "--force"])

        assert result.exit_code == 0

        # Cleanup
        _watch_targets.clear()

    @patch("domainraptor.cli.commands.watch.create_progress")
    def test_watch_run_example_detects_changes(self, mock_progress: MagicMock) -> None:
        """Test run on example.com detects demo changes."""
        _watch_targets.clear()
        _watch_targets["example.com"] = WatchTarget(
            target="example.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )

        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["--no-banner", "watch", "run", "example.com", "--force"])

        assert result.exit_code == 0
        assert "change" in result.stdout.lower()

        # Cleanup
        _watch_targets.clear()


class TestWatchPauseCommand:
    """Tests for watch pause command."""

    def test_watch_pause_not_found(self) -> None:
        """Test pausing a target that isn't being watched."""
        _watch_targets.clear()

        result = runner.invoke(app, ["--no-banner", "watch", "pause", "notfound.com"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    def test_watch_pause_success(self) -> None:
        """Test pausing a watched target."""
        _watch_targets.clear()
        _watch_targets["topause.com"] = WatchTarget(
            target="topause.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
            enabled=True,
        )

        result = runner.invoke(app, ["--no-banner", "watch", "pause", "topause.com"])

        assert result.exit_code == 0
        assert _watch_targets["topause.com"].enabled is False

        # Cleanup
        _watch_targets.clear()


class TestWatchResumeCommand:
    """Tests for watch resume command."""

    def test_watch_resume_not_found(self) -> None:
        """Test resuming a target that isn't being watched."""
        _watch_targets.clear()

        result = runner.invoke(app, ["--no-banner", "watch", "resume", "notfound.com"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    def test_watch_resume_success(self) -> None:
        """Test resuming a paused target."""
        _watch_targets.clear()
        _watch_targets["toresume.com"] = WatchTarget(
            target="toresume.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
            enabled=False,
        )

        result = runner.invoke(app, ["--no-banner", "watch", "resume", "toresume.com"])

        assert result.exit_code == 0
        assert _watch_targets["toresume.com"].enabled is True

        # Cleanup
        _watch_targets.clear()


class TestWatchStatusCommand:
    """Tests for watch status command."""

    def test_watch_status_not_found(self) -> None:
        """Test status for a target that isn't being watched."""
        _watch_targets.clear()

        result = runner.invoke(app, ["--no-banner", "watch", "status", "notfound.com"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    def test_watch_status_success(self) -> None:
        """Test status for a watched target."""
        _watch_targets.clear()
        _watch_targets["status.com"] = WatchTarget(
            target="status.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
            enabled=True,
        )

        result = runner.invoke(app, ["--no-banner", "watch", "status", "status.com"])

        assert result.exit_code == 0
        assert "status.com" in result.stdout
        assert "domain" in result.stdout
        assert "24" in result.stdout

        # Cleanup
        _watch_targets.clear()


class TestWatchCallback:
    """Tests for watch callback (default behavior)."""

    def test_watch_no_subcommand_shows_help(self) -> None:
        """Test watch without subcommand shows help due to no_args_is_help=True."""
        _watch_targets.clear()

        result = runner.invoke(app, ["--no-banner", "watch"])

        # With no_args_is_help=True, shows help and exits with code 2
        assert result.exit_code == 2
        # Shows help text
        assert "Usage" in result.output or "watch" in result.output
