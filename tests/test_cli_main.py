"""Tests for main CLI module."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from domainraptor import __version__
from domainraptor.cli.main import app, config_cmd, db_cmd, export_cmd, import_cmd

runner = CliRunner()


# ============================================================================
# Version Tests
# ============================================================================


class TestVersion:
    """Tests for version option."""

    def test_version_option(self) -> None:
        """Test --version shows version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output
        assert "DomainRaptor" in result.output

    def test_version_short_option(self) -> None:
        """Test -v shows version."""
        result = runner.invoke(app, ["-v"])
        assert result.exit_code == 0
        assert __version__ in result.output


# ============================================================================
# Main Callback Tests
# ============================================================================


class TestMainCallback:
    """Tests for main callback options."""

    def test_no_args_shows_help(self) -> None:
        """Test no args shows help."""
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
        assert "Usage" in result.output or "help" in result.output.lower()

    def test_verbose_option(self) -> None:
        """Test --verbose option."""
        result = runner.invoke(app, ["--no-banner", "--verbose", "discover", "--help"])
        assert result.exit_code == 0

    def test_debug_option_with_command(self) -> None:
        """Test --debug option with actual command."""
        result = runner.invoke(app, ["--no-banner", "--debug", "discover", "--help"])
        assert result.exit_code == 0

    def test_mode_option(self) -> None:
        """Test --mode option."""
        result = runner.invoke(app, ["--no-banner", "--mode", "deep", "discover", "--help"])
        assert result.exit_code == 0

    def test_mode_option_quick(self) -> None:
        """Test --mode quick option."""
        result = runner.invoke(app, ["--no-banner", "--mode", "quick", "discover", "--help"])
        assert result.exit_code == 0

    def test_format_option(self) -> None:
        """Test --format option."""
        result = runner.invoke(app, ["--no-banner", "--format", "json", "discover", "--help"])
        assert result.exit_code == 0

    def test_free_only_option(self) -> None:
        """Test --free-only option."""
        result = runner.invoke(app, ["--no-banner", "--free-only", "discover", "--help"])
        assert result.exit_code == 0

    def test_no_color_option(self) -> None:
        """Test --no-color option."""
        result = runner.invoke(app, ["--no-banner", "--no-color", "discover", "--help"])
        assert result.exit_code == 0

    def test_no_banner_option(self) -> None:
        """Test --no-banner option."""
        result = runner.invoke(app, ["--no-banner", "discover", "--help"])
        assert result.exit_code == 0
        assert "DomainRaptor" not in result.output or "discover" in result.output


# ============================================================================
# Config Function Tests (Direct Function Calls)
# Note: config_cmd is shadowed by config subcommand typer, so we test directly
# ============================================================================


class TestConfigFunction:
    """Tests for config_cmd function."""

    def test_config_show(self) -> None:
        """Test config with show flag."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {
            "config": MagicMock(
                mode=MagicMock(value="standard"),
                verbose=False,
                free_only=False,
                output_format=MagicMock(value="table"),
                db_path=Path(tempfile.gettempdir()) / "test.db",
                cache_ttl=3600,
            )
        }

        # Should not raise
        config_cmd(ctx, show=True, init=False, set_key=None)

    def test_config_init(self, tmp_path: Path) -> None:
        """Test config with init flag."""
        ctx = MagicMock(spec=typer.Context)
        mock_config = MagicMock()
        ctx.obj = {"config": mock_config}

        with patch.object(Path, "home", return_value=tmp_path):
            config_cmd(ctx, show=False, init=True, set_key=None)

        mock_config.save.assert_called_once()

    def test_config_set_valid(self) -> None:
        """Test config with set key=value."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}

        # Should not raise
        config_cmd(ctx, show=False, init=False, set_key="key=value")

    def test_config_set_invalid(self) -> None:
        """Test config with invalid set format."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}

        with pytest.raises(typer.Exit):
            config_cmd(ctx, show=False, init=False, set_key="invalidformat")

    def test_config_default_shows_config(self) -> None:
        """Test config with no options shows config."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {
            "config": MagicMock(
                mode=MagicMock(value="standard"),
                verbose=False,
                free_only=False,
                output_format=MagicMock(value="table"),
                db_path=Path(tempfile.gettempdir()) / "test.db",
                cache_ttl=3600,
            )
        }

        # Should not raise
        config_cmd(ctx, show=False, init=False, set_key=None)


# ============================================================================
# DB Function Tests (Direct Function Calls)
# Note: db_cmd is shadowed by db subcommand typer, so we test directly
# ============================================================================


class TestDbFunction:
    """Tests for db_cmd function."""

    def test_db_info_no_db(self) -> None:
        """Test db info when database doesn't exist."""
        ctx = MagicMock(spec=typer.Context)
        mock_db_path = MagicMock()
        mock_db_path.exists.return_value = False
        ctx.obj = {"config": MagicMock(db_path=mock_db_path)}

        db_cmd(ctx, info=True, vacuum=False, export_path=None, import_path=None)

    def test_db_info_with_db(self, tmp_path: Path) -> None:
        """Test db info when database exists."""
        db_file = tmp_path / "test.db"
        db_file.write_text("x" * 1024)

        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock(db_path=db_file)}

        db_cmd(ctx, info=True, vacuum=False, export_path=None, import_path=None)

    def test_db_vacuum(self) -> None:
        """Test db vacuum."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}

        db_cmd(ctx, info=False, vacuum=True, export_path=None, import_path=None)

    def test_db_export(self, tmp_path: Path) -> None:
        """Test db export."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}
        output_file = tmp_path / "export.db"

        db_cmd(ctx, info=False, vacuum=False, export_path=output_file, import_path=None)

    def test_db_import(self, tmp_path: Path) -> None:
        """Test db import."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}
        import_file = tmp_path / "import.db"
        import_file.write_text("data")

        db_cmd(ctx, info=False, vacuum=False, export_path=None, import_path=import_file)

    def test_db_default_shows_info(self) -> None:
        """Test db with no options shows info (recursive call)."""
        ctx = MagicMock(spec=typer.Context)
        mock_db_path = MagicMock()
        mock_db_path.exists.return_value = False
        ctx.obj = {"config": MagicMock(db_path=mock_db_path)}

        # This calls itself recursively with info=True
        db_cmd(ctx, info=False, vacuum=False, export_path=None, import_path=None)


# ============================================================================
# Import Function Tests (Direct Function Calls)
# ============================================================================


class TestImportFunction:
    """Tests for import_cmd function."""

    def test_import_basic(self, tmp_path: Path) -> None:
        """Test import command."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}
        import_file = tmp_path / "data.json"
        import_file.write_text('{"assets": []}')

        import_cmd(ctx, file_path=import_file, target=None, merge=True)

    def test_import_with_target(self, tmp_path: Path) -> None:
        """Test import with target."""
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}
        import_file = tmp_path / "data.json"
        import_file.write_text('{"assets": []}')

        import_cmd(ctx, file_path=import_file, target="example.com", merge=True)


# ============================================================================
# Export Function Tests (Direct Function Calls)
# ============================================================================


class TestExportFunction:
    """Tests for export_cmd function."""

    def test_export_basic(self, tmp_path: Path) -> None:
        """Test export command."""
        from domainraptor.core.config import OutputFormat

        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}
        output_file = tmp_path / "out.json"

        export_cmd(ctx, target="example.com", output=output_file, format_type=OutputFormat.JSON)

    def test_export_csv(self, tmp_path: Path) -> None:
        """Test export as CSV."""
        from domainraptor.core.config import OutputFormat

        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {"config": MagicMock()}
        output_file = tmp_path / "out.csv"

        export_cmd(ctx, target="example.com", output=output_file, format_type=OutputFormat.CSV)
