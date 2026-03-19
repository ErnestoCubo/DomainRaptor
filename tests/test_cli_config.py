"""Tests for domainraptor.cli.commands.config module."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from domainraptor.cli.commands.config import (
    API_KEYS,
    _get_config_dir,
    _get_env_file,
    _load_env_file,
    _save_env_file,
    _test_api_key,
    _test_censys,
    _test_securitytrails,
    _test_shodan,
    _test_virustotal,
    app,
)

runner = CliRunner()


# --- Helper functions tests ---


class TestHelperFunctions:
    """Tests for config helper functions."""

    def test_get_config_dir(self, tmp_path: Path) -> None:
        """Test _get_config_dir returns correct path."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = _get_config_dir()
            assert result == tmp_path / ".domainraptor"

    def test_get_env_file(self, tmp_path: Path) -> None:
        """Test _get_env_file returns correct path."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = _get_env_file()
            assert result == tmp_path / ".domainraptor" / ".env"

    def test_load_env_file_no_file(self, tmp_path: Path) -> None:
        """Test _load_env_file returns empty dict when file doesn't exist."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = _load_env_file()
            assert result == {}

    def test_load_env_file_with_content(self, tmp_path: Path) -> None:
        """Test _load_env_file parses env file correctly."""
        config_dir = tmp_path / ".domainraptor"
        config_dir.mkdir(parents=True)
        env_file = config_dir / ".env"
        env_file.write_text(
            "# Comment\n"
            'SHODAN_API_KEY="test_key_123"\n'  # pragma: allowlist secret
            "VIRUSTOTAL_API_KEY='another_key'\n"  # pragma: allowlist secret
            "PLAIN_KEY=no_quotes\n"
            "\n"
            "SPACED_KEY = spaced_value \n"
        )

        with patch.object(Path, "home", return_value=tmp_path):
            result = _load_env_file()

        assert result["SHODAN_API_KEY"] == "test_key_123"  # pragma: allowlist secret
        assert result["VIRUSTOTAL_API_KEY"] == "another_key"  # pragma: allowlist secret
        assert result["PLAIN_KEY"] == "no_quotes"
        assert result["SPACED_KEY"] == "spaced_value"

    def test_load_env_file_ignores_invalid_lines(self, tmp_path: Path) -> None:
        """Test _load_env_file skips lines without = sign."""
        config_dir = tmp_path / ".domainraptor"
        config_dir.mkdir(parents=True)
        env_file = config_dir / ".env"
        env_file.write_text("VALID_KEY=value\n" "invalid line without equals\n" "# comment line\n")

        with patch.object(Path, "home", return_value=tmp_path):
            result = _load_env_file()

        assert result == {"VALID_KEY": "value"}

    def test_save_env_file_creates_dir(self, tmp_path: Path) -> None:
        """Test _save_env_file creates config directory if needed."""
        with patch.object(Path, "home", return_value=tmp_path):
            _save_env_file({"TEST_KEY": "test_value"})

        env_file = tmp_path / ".domainraptor" / ".env"
        assert env_file.exists()
        content = env_file.read_text()
        assert "TEST_KEY" in content
        assert "test_value" in content

    def test_save_env_file_sets_permissions(self, tmp_path: Path) -> None:
        """Test _save_env_file sets restrictive permissions."""
        with patch.object(Path, "home", return_value=tmp_path):
            _save_env_file({"KEY": "value"})

        env_file = tmp_path / ".domainraptor" / ".env"
        # Check file is owner-readable only (0o600)
        assert (env_file.stat().st_mode & 0o777) == 0o600

    def test_save_env_file_sorts_keys(self, tmp_path: Path) -> None:
        """Test _save_env_file sorts keys alphabetically."""
        with patch.object(Path, "home", return_value=tmp_path):
            _save_env_file({"ZEBRA": "z", "APPLE": "a", "MANGO": "m"})

        env_file = tmp_path / ".domainraptor" / ".env"
        content = env_file.read_text()
        apple_pos = content.find("APPLE")
        mango_pos = content.find("MANGO")
        zebra_pos = content.find("ZEBRA")
        assert apple_pos < mango_pos < zebra_pos


# --- set command tests ---


class TestSetKeyCommand:
    """Tests for the set command."""

    def test_set_known_key(self, tmp_path: Path) -> None:
        """Test setting a known API key."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = runner.invoke(app, ["set", "SHODAN_API_KEY", "test123"])

        assert result.exit_code == 0
        assert "Shodan" in result.output or "saved" in result.output

    def test_set_unknown_key_confirm(self, tmp_path: Path) -> None:
        """Test setting an unknown key with confirmation."""
        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch("domainraptor.cli.commands.config.typer.confirm", return_value=True),
        ):
            result = runner.invoke(app, ["set", "CUSTOM_KEY", "custom_value"])

        assert result.exit_code == 0

    def test_set_unknown_key_abort(self, tmp_path: Path) -> None:
        """Test setting an unknown key with abort."""
        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch("domainraptor.cli.commands.config.typer.confirm", return_value=False),
        ):
            result = runner.invoke(app, ["set", "CUSTOM_KEY", "custom_value"])

        # Should abort with non-zero exit
        assert result.exit_code == 1 or "Aborted" in result.output

    def test_set_key_updates_environment(self, tmp_path: Path) -> None:
        """Test that set command updates current environment."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            with patch.object(Path, "home", return_value=tmp_path):
                result = runner.invoke(app, ["set", "SHODAN_API_KEY", "env_test_123"])

            assert result.exit_code == 0
            assert os.environ.get("SHODAN_API_KEY") == "env_test_123"
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)


# --- get command tests ---


class TestGetKeyCommand:
    """Tests for the get command."""

    def test_get_key_not_set(self, tmp_path: Path) -> None:
        """Test getting a key that is not set."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ.pop("SHODAN_API_KEY", None)
            with patch.object(Path, "home", return_value=tmp_path):
                result = runner.invoke(app, ["get", "SHODAN_API_KEY"])

            assert "not set" in result.output.lower()
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup

    def test_get_key_from_env(self, tmp_path: Path) -> None:
        """Test getting a key from environment."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ["SHODAN_API_KEY"] = "test_env_key_12345678"  # pragma: allowlist secret
            with patch.object(Path, "home", return_value=tmp_path):
                result = runner.invoke(app, ["get", "SHODAN_API_KEY"])

            # Should show masked version
            assert "Shodan" in result.output
            assert "test" in result.output  # First 4 chars
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)

    def test_get_key_with_show_flag(self, tmp_path: Path) -> None:
        """Test getting a key with --show flag."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ["SHODAN_API_KEY"] = "full_visible_key_12345678"  # pragma: allowlist secret
            with patch.object(Path, "home", return_value=tmp_path):
                result = runner.invoke(app, ["get", "SHODAN_API_KEY", "--show"])

            assert "full_visible_key_12345678" in result.output
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)

    def test_get_key_from_file(self, tmp_path: Path) -> None:
        """Test getting a key from .env file when not in environment."""
        config_dir = tmp_path / ".domainraptor"
        config_dir.mkdir(parents=True)
        env_file = config_dir / ".env"
        env_file.write_text('SHODAN_API_KEY="file_key_12345678"\n')  # pragma: allowlist secret

        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ.pop("SHODAN_API_KEY", None)
            with patch.object(Path, "home", return_value=tmp_path):
                result = runner.invoke(app, ["get", "SHODAN_API_KEY"])

            assert "Shodan" in result.output
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup

    def test_get_unknown_key_not_set(self, tmp_path: Path) -> None:
        """Test getting an unknown key that is not set."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = runner.invoke(app, ["get", "UNKNOWN_KEY"])

        assert "not set" in result.output.lower()

    def test_get_short_key_masked(self, tmp_path: Path) -> None:
        """Test that short keys are masked properly."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ["SHODAN_API_KEY"] = "short"  # < 12 chars  # pragma: allowlist secret
            with patch.object(Path, "home", return_value=tmp_path):
                result = runner.invoke(app, ["get", "SHODAN_API_KEY"])

            assert "***" in result.output
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)


# --- list command tests ---


class TestListKeysCommand:
    """Tests for the list command."""

    def test_list_keys_basic(self, tmp_path: Path) -> None:
        """Test listing all keys."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = runner.invoke(app, ["list"])

        assert result.exit_code == 0
        assert "Shodan" in result.output
        assert "VirusTotal" in result.output

    def test_list_keys_with_show(self, tmp_path: Path) -> None:
        """Test listing keys with --show flag."""
        config_dir = tmp_path / ".domainraptor"
        config_dir.mkdir(parents=True)
        env_file = config_dir / ".env"
        env_file.write_text('SHODAN_API_KEY="test_key_12345678"\n')  # pragma: allowlist secret

        with patch.object(Path, "home", return_value=tmp_path):
            result = runner.invoke(app, ["list", "--show"])

        assert result.exit_code == 0
        # Should show value column
        assert "test" in result.output  # First 4 chars of masked key

    def test_list_keys_shows_configured_status(self, tmp_path: Path) -> None:
        """Test that list shows configured status correctly."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ["SHODAN_API_KEY"] = "configured_key"  # pragma: allowlist secret
            with patch.object(Path, "home", return_value=tmp_path):
                result = runner.invoke(app, ["list"])

            assert "Configured" in result.output
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)


# --- test command tests ---


class TestTestKeysCommand:
    """Tests for the test command."""

    def test_test_all_keys(self, tmp_path: Path) -> None:
        """Test running tests for all keys."""
        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch(
                "domainraptor.cli.commands.config._test_api_key",
                return_value=(True, "OK"),
            ),
        ):
            result = runner.invoke(app, ["test"])

        assert result.exit_code == 0

    def test_test_specific_key(self, tmp_path: Path) -> None:
        """Test running test for specific key."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ["SHODAN_API_KEY"] = "test_key"  # pragma: allowlist secret
            with (
                patch.object(Path, "home", return_value=tmp_path),
                patch(
                    "domainraptor.cli.commands.config._test_api_key",
                    return_value=(True, "Connected"),
                ),
            ):
                result = runner.invoke(app, ["test", "SHODAN_API_KEY"])

            assert result.exit_code == 0
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)

    def test_test_unknown_key(self, tmp_path: Path) -> None:
        """Test testing an unknown key."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = runner.invoke(app, ["test", "UNKNOWN_KEY"])

        assert "Unknown" in result.output or result.exit_code == 0

    def test_test_not_configured_key(self, tmp_path: Path) -> None:
        """Test testing a key that is not configured."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ.pop("SHODAN_API_KEY", None)
            with patch.object(Path, "home", return_value=tmp_path):
                result = runner.invoke(app, ["test", "SHODAN_API_KEY"])

            # Should show "Not configured" in results
            assert "Not configured" in result.output or result.exit_code == 0
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup

    def test_test_key_exception(self, tmp_path: Path) -> None:
        """Test that exceptions during key test are caught."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ["SHODAN_API_KEY"] = "test_key"  # pragma: allowlist secret
            with (
                patch.object(Path, "home", return_value=tmp_path),
                patch(
                    "domainraptor.cli.commands.config._test_api_key",
                    side_effect=Exception("Test error"),
                ),
            ):
                result = runner.invoke(app, ["test", "SHODAN_API_KEY"])

            # Should handle exception gracefully
            assert result.exit_code == 0
            assert "Test error" in result.output
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)


# --- API test function tests ---


class TestApiTestFunctions:
    """Tests for individual API test functions."""

    def test_test_api_key_shodan(self) -> None:
        """Test _test_api_key dispatches to Shodan."""
        with patch(
            "domainraptor.cli.commands.config._test_shodan",
            return_value=(True, "OK"),
        ) as mock:
            result = _test_api_key("SHODAN_API_KEY", "test")
            mock.assert_called_once_with("test")
            assert result == (True, "OK")

    def test_test_api_key_virustotal(self) -> None:
        """Test _test_api_key dispatches to VirusTotal."""
        with patch(
            "domainraptor.cli.commands.config._test_virustotal",
            return_value=(True, "OK"),
        ) as mock:
            result = _test_api_key("VIRUSTOTAL_API_KEY", "test")
            mock.assert_called_once_with("test")
            assert result == (True, "OK")

    def test_test_api_key_securitytrails(self) -> None:
        """Test _test_api_key dispatches to SecurityTrails."""
        with patch(
            "domainraptor.cli.commands.config._test_securitytrails",
            return_value=(True, "OK"),
        ) as mock:
            result = _test_api_key("SECURITYTRAILS_API_KEY", "test")
            mock.assert_called_once_with("test")
            assert result == (True, "OK")

    def test_test_api_key_censys(self) -> None:
        """Test _test_api_key dispatches to Censys."""
        with patch(
            "domainraptor.cli.commands.config._test_censys",
            return_value=(False, "Not implemented"),
        ) as mock:
            _test_api_key("CENSYS_API_KEY", "test")
            mock.assert_called_once_with("test")

    def test_test_api_key_unknown(self) -> None:
        """Test _test_api_key returns no test for unknown key."""
        result = _test_api_key("UNKNOWN_KEY", "test")
        assert result == (False, "No test available")

    def test_test_shodan_success(self) -> None:
        """Test _test_shodan with successful connection."""
        mock_client = MagicMock()
        mock_client.dns_resolve.return_value = {"google.com": "1.2.3.4"}

        with patch(
            "domainraptor.discovery.shodan_client.ShodanClient",
            return_value=mock_client,
        ):
            result = _test_shodan("test_key")

        assert result[0] is True
        assert "success" in result[1].lower() or "Connected" in result[1]

    def test_test_shodan_empty_result(self) -> None:
        """Test _test_shodan with empty result."""
        mock_client = MagicMock()
        mock_client.dns_resolve.return_value = {}

        with patch(
            "domainraptor.discovery.shodan_client.ShodanClient",
            return_value=mock_client,
        ):
            result = _test_shodan("test_key")

        assert result[0] is True
        assert "accepted" in result[1].lower() or "Key" in result[1]

    def test_test_shodan_exception(self) -> None:
        """Test _test_shodan with exception."""
        with patch(
            "domainraptor.discovery.shodan_client.ShodanClient",
            side_effect=Exception("API error"),
        ):
            result = _test_shodan("test_key")

        assert result[0] is False
        assert "API error" in result[1]

    def test_test_virustotal_success(self) -> None:
        """Test _test_virustotal with successful connection."""
        mock_client = MagicMock()
        mock_report = MagicMock()
        mock_report.total_engines = 70
        mock_client.get_domain_report.return_value = mock_report

        with patch(
            "domainraptor.enrichment.virustotal.VirusTotalClient",
            return_value=mock_client,
        ):
            result = _test_virustotal("test_key")

        assert result[0] is True
        assert "70" in result[1] or "Connected" in result[1]

    def test_test_virustotal_exception(self) -> None:
        """Test _test_virustotal with exception."""
        with patch(
            "domainraptor.enrichment.virustotal.VirusTotalClient",
            side_effect=Exception("VT error"),
        ):
            result = _test_virustotal("test_key")

        assert result[0] is False
        assert "VT error" in result[1]

    def test_test_securitytrails_success(self) -> None:
        """Test _test_securitytrails with successful connection."""
        mock_client = MagicMock()
        mock_info = MagicMock()
        mock_info.subdomain_count = 100
        mock_client.get_domain.return_value = mock_info

        with patch(
            "domainraptor.enrichment.securitytrails.SecurityTrailsClient",
            return_value=mock_client,
        ):
            result = _test_securitytrails("test_key")

        assert result[0] is True
        assert "100" in result[1] or "Connected" in result[1]

    def test_test_securitytrails_exception(self) -> None:
        """Test _test_securitytrails with exception."""
        with patch(
            "domainraptor.enrichment.securitytrails.SecurityTrailsClient",
            side_effect=Exception("ST error"),
        ):
            result = _test_securitytrails("test_key")

        assert result[0] is False
        assert "ST error" in result[1]

    def test_test_censys_not_implemented(self) -> None:
        """Test _test_censys returns not implemented."""
        result = _test_censys("test_key")
        assert result[0] is False
        assert "not yet implemented" in result[1].lower()


# --- path command tests ---


class TestShowPathCommand:
    """Tests for the path command."""

    def test_show_path(self, tmp_path: Path) -> None:
        """Test showing configuration paths."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = runner.invoke(app, ["path"])

        assert result.exit_code == 0
        assert ".domainraptor" in result.output
        assert "Config" in result.output or "directory" in result.output

    def test_show_path_file_exists(self, tmp_path: Path) -> None:
        """Test path command when env file exists."""
        config_dir = tmp_path / ".domainraptor"
        config_dir.mkdir(parents=True)
        env_file = config_dir / ".env"
        env_file.write_text("KEY=value\n")

        with patch.object(Path, "home", return_value=tmp_path):
            result = runner.invoke(app, ["path"])

        assert result.exit_code == 0
        assert "exists" in result.output.lower()

    def test_show_path_file_not_exists(self, tmp_path: Path) -> None:
        """Test path command when env file doesn't exist."""
        with patch.object(Path, "home", return_value=tmp_path):
            result = runner.invoke(app, ["path"])

        assert result.exit_code == 0
        assert "not exist" in result.output.lower() or "does not exist" in result.output.lower()


# --- init command tests ---


class TestInitConfigCommand:
    """Tests for the init command."""

    @pytest.fixture(autouse=True)
    def clear_api_keys(self) -> None:
        """Clear all API keys before and after each test."""
        keys = ["SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "SECURITYTRAILS_API_KEY", "CENSYS_API_KEY"]
        backups = {k: os.environ.get(k) for k in keys}
        for k in keys:
            os.environ.pop(k, None)
        yield
        # Restore
        for k, v in backups.items():
            if v:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)

    def test_init_config_skip_all(self, tmp_path: Path) -> None:
        """Test init with all keys skipped."""
        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch("domainraptor.cli.commands.config.typer.prompt", return_value=""),
        ):
            result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert "complete" in result.output.lower() or "Configuration" in result.output

    def test_init_config_set_keys(self, tmp_path: Path) -> None:
        """Test init with keys being set."""
        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch("domainraptor.cli.commands.config.typer.prompt", return_value="test_key_value"),
        ):
            result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        # Keys should be saved
        env_file = tmp_path / ".domainraptor" / ".env"
        assert env_file.exists()

    def test_init_config_update_existing(self, tmp_path: Path) -> None:
        """Test init updates existing key when confirmed."""
        config_dir = tmp_path / ".domainraptor"
        config_dir.mkdir(parents=True)
        env_file = config_dir / ".env"
        env_file.write_text('SHODAN_API_KEY="old_key"\n')  # pragma: allowlist secret

        # Mark env var as set to trigger update prompt
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ["SHODAN_API_KEY"] = "existing_key"  # pragma: allowlist secret
            with (
                patch.object(Path, "home", return_value=tmp_path),
                patch("domainraptor.cli.commands.config.typer.confirm", return_value=True),
                patch("domainraptor.cli.commands.config.typer.prompt", return_value="new_key"),
            ):
                result = runner.invoke(app, ["init"])

            assert result.exit_code == 0
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)

    def test_init_config_skip_existing(self, tmp_path: Path) -> None:
        """Test init skips existing key when not confirmed."""
        env_backup = os.environ.get("SHODAN_API_KEY")
        try:
            os.environ["SHODAN_API_KEY"] = "existing_key"  # pragma: allowlist secret
            with (
                patch.object(Path, "home", return_value=tmp_path),
                patch("domainraptor.cli.commands.config.typer.confirm", return_value=False),
                patch("domainraptor.cli.commands.config.typer.prompt", return_value=""),
            ):
                result = runner.invoke(app, ["init"])

            assert result.exit_code == 0
        finally:
            if env_backup:
                os.environ["SHODAN_API_KEY"] = env_backup
            else:
                os.environ.pop("SHODAN_API_KEY", None)


# --- no_args_is_help behavior ---


class TestAppHelp:
    """Tests for app help behavior."""

    def test_no_args_shows_help(self) -> None:
        """Test that no arguments shows help."""
        result = runner.invoke(app, [])
        # no_args_is_help=True shows help with exit code 0
        assert result.exit_code == 0 or "Usage" in result.output


# --- API_KEYS constant tests ---


class TestApiKeysConstant:
    """Tests for API_KEYS constant structure."""

    def test_api_keys_has_required_fields(self) -> None:
        """Test that all API_KEYS entries have required fields."""
        required_fields = ["service", "description", "url", "free_tier"]
        for key_name, info in API_KEYS.items():
            for field in required_fields:
                assert field in info, f"{key_name} missing {field}"

    def test_api_keys_contains_major_services(self) -> None:
        """Test that API_KEYS contains expected services."""
        assert "SHODAN_API_KEY" in API_KEYS
        assert "VIRUSTOTAL_API_KEY" in API_KEYS
        assert "SECURITYTRAILS_API_KEY" in API_KEYS
        assert "CENSYS_API_KEY" in API_KEYS
