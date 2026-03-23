"""Tests for watch CLI command."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from domainraptor.cli.commands.watch import _parse_interval
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


class TestWatchListCommand:
    """Tests for watch list command."""

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_list_empty(self, mock_get_repo: MagicMock) -> None:
        """Test list command with no targets."""
        mock_repo = MagicMock()
        mock_repo.list_all.return_value = []
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "list"])
        assert result.exit_code == 0
        assert "No targets being watched" in result.stdout

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_list_with_targets(self, mock_get_repo: MagicMock) -> None:
        """Test list command with watched targets."""
        mock_repo = MagicMock()
        mock_repo.list_all.return_value = [
            WatchTarget(
                target="test.com",
                watch_type="domain",
                interval_hours=24,
                next_check=datetime.now(),
            )
        ]
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "list"])
        assert result.exit_code == 0
        assert "test.com" in result.stdout


class TestWatchAddCommand:
    """Tests for watch add command."""

    @patch("domainraptor.cli.commands.watch._get_scan_repo")
    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    @patch("domainraptor.cli.commands.watch.create_progress")
    def test_watch_add_success(
        self, mock_progress: MagicMock, mock_get_repo: MagicMock, mock_get_scan_repo: MagicMock
    ) -> None:
        """Test adding a target to watch list."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = None  # Not already watching
        mock_get_repo.return_value = mock_repo

        mock_scan_repo = MagicMock()
        mock_get_scan_repo.return_value = mock_scan_repo

        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["--no-banner", "watch", "add", "newdomain.com"])

        assert result.exit_code == 0
        mock_repo.add.assert_called_once()

    @patch("domainraptor.cli.commands.watch._get_scan_repo")
    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    @patch("domainraptor.cli.commands.watch.create_progress")
    def test_watch_add_with_interval(
        self, mock_progress: MagicMock, mock_get_repo: MagicMock, mock_get_scan_repo: MagicMock
    ) -> None:
        """Test adding a target with custom interval."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = None
        mock_get_repo.return_value = mock_repo

        mock_scan_repo = MagicMock()
        mock_get_scan_repo.return_value = mock_scan_repo

        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(
            app, ["--no-banner", "watch", "add", "interval.com", "--interval", "6h"]
        )

        assert result.exit_code == 0
        # Verify the saved target has correct interval
        saved_target = mock_repo.add.call_args[0][0]
        assert saved_target.interval_hours == 6

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_add_invalid_interval(self, mock_get_repo: MagicMock) -> None:
        """Test adding a target with invalid interval."""
        mock_repo = MagicMock()
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(
            app, ["--no-banner", "watch", "add", "invalid.com", "--interval", "invalid"]
        )

        assert result.exit_code == 1

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    @patch("typer.confirm", return_value=False)
    def test_watch_add_already_watching_decline(
        self, mock_confirm: MagicMock, mock_get_repo: MagicMock
    ) -> None:
        """Test adding already watched target and declining update."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = WatchTarget(
            target="existing.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "add", "existing.com"])

        # Should exit without error
        assert result.exit_code == 0


class TestWatchRemoveCommand:
    """Tests for watch remove command."""

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_remove_not_found(self, mock_get_repo: MagicMock) -> None:
        """Test removing a target that isn't being watched."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = None
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "remove", "notfound.com", "--force"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_remove_success(self, mock_get_repo: MagicMock) -> None:
        """Test removing a watched target."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = WatchTarget(
            target="toremove.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "remove", "toremove.com", "--force"])

        assert result.exit_code == 0
        assert "Removed" in result.stdout
        mock_repo.remove.assert_called_once_with("toremove.com")


class TestWatchRunCommand:
    """Tests for watch run command."""

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_run_no_targets(self, mock_get_repo: MagicMock) -> None:
        """Test run with no targets due."""
        mock_repo = MagicMock()
        mock_repo.list_all.return_value = []
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "run"])

        assert result.exit_code == 0
        # When no targets, it shows "Checking 0 target(s)"
        assert "Checking 0 target(s)" in result.stdout

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_run_target_not_found(self, mock_get_repo: MagicMock) -> None:
        """Test run with specific target not found."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = None
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "run", "notfound.com"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    @patch("domainraptor.cli.commands.watch._get_scan_repo")
    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    @patch("domainraptor.cli.commands.watch.create_progress")
    def test_watch_run_with_force(
        self, mock_progress: MagicMock, mock_get_repo: MagicMock, mock_get_scan_repo: MagicMock
    ) -> None:
        """Test force run on watched target."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = WatchTarget(
            target="forcerun.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
        )
        mock_get_repo.return_value = mock_repo

        mock_scan_repo = MagicMock()
        mock_scan_repo.get_latest_for_target.return_value = None
        mock_get_scan_repo.return_value = mock_scan_repo

        progress_instance = MagicMock()
        mock_progress.return_value.__enter__ = MagicMock(return_value=progress_instance)
        mock_progress.return_value.__exit__ = MagicMock(return_value=False)

        result = runner.invoke(app, ["--no-banner", "watch", "run", "forcerun.com", "--force"])

        assert result.exit_code == 0


class TestWatchPauseCommand:
    """Tests for watch pause command."""

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_pause_not_found(self, mock_get_repo: MagicMock) -> None:
        """Test pausing a target that isn't being watched."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = None
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "pause", "notfound.com"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_pause_success(self, mock_get_repo: MagicMock) -> None:
        """Test pausing a watched target."""
        watch_target = WatchTarget(
            target="topause.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
            enabled=True,
        )
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = watch_target
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "pause", "topause.com"])

        assert result.exit_code == 0
        mock_repo.set_enabled.assert_called_once_with("topause.com", False)


class TestWatchResumeCommand:
    """Tests for watch resume command."""

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_resume_not_found(self, mock_get_repo: MagicMock) -> None:
        """Test resuming a target that isn't being watched."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = None
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "resume", "notfound.com"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_resume_success(self, mock_get_repo: MagicMock) -> None:
        """Test resuming a paused target."""
        watch_target = WatchTarget(
            target="toresume.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
            enabled=False,
        )
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = watch_target
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "resume", "toresume.com"])

        assert result.exit_code == 0
        mock_repo.set_enabled.assert_called_once_with("toresume.com", True)


class TestWatchStatusCommand:
    """Tests for watch status command."""

    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_status_not_found(self, mock_get_repo: MagicMock) -> None:
        """Test status for a target that isn't being watched."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = None
        mock_get_repo.return_value = mock_repo

        result = runner.invoke(app, ["--no-banner", "watch", "status", "notfound.com"])

        assert result.exit_code == 1
        assert "Not watching" in result.output

    @patch("domainraptor.cli.commands.watch._get_scan_repo")
    @patch("domainraptor.cli.commands.watch._get_watch_repo")
    def test_watch_status_success(
        self, mock_get_repo: MagicMock, mock_get_scan_repo: MagicMock
    ) -> None:
        """Test status for a watched target."""
        mock_repo = MagicMock()
        mock_repo.get_by_target.return_value = WatchTarget(
            target="status.com",
            watch_type="domain",
            interval_hours=24,
            next_check=datetime.now(),
            enabled=True,
        )
        mock_get_repo.return_value = mock_repo

        mock_scan_repo = MagicMock()
        mock_scan_repo.list_by_target.return_value = []
        mock_get_scan_repo.return_value = mock_scan_repo

        result = runner.invoke(app, ["--no-banner", "watch", "status", "status.com"])

        assert result.exit_code == 0
        assert "status.com" in result.stdout


class TestWatchCallback:
    """Tests for watch callback (default behavior)."""

    def test_watch_no_subcommand_shows_help(self) -> None:
        """Test watch without subcommand shows help due to no_args_is_help=True."""
        result = runner.invoke(app, ["--no-banner", "watch"])

        # With no_args_is_help=True, shows help and exits with code 2
        assert result.exit_code == 2
        # Shows help text
        assert "Usage" in result.output or "watch" in result.output

        # With no_args_is_help=True, shows help and exits with code 2
        assert result.exit_code == 2
        # Shows help text
        assert "Usage" in result.output or "watch" in result.output
