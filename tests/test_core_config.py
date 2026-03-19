"""Tests for core config module."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from domainraptor.core.config import (
    DEFAULT_SOURCES,
    AppConfig,
    OutputFormat,
    ScanMode,
    SourceConfig,
)


class TestScanMode:
    """Tests for ScanMode enum."""

    def test_scan_mode_values(self) -> None:
        """Test scan mode values."""
        assert ScanMode.QUICK.value == "quick"
        assert ScanMode.STANDARD.value == "standard"
        assert ScanMode.DEEP.value == "deep"
        assert ScanMode.STEALTH.value == "stealth"

    def test_scan_mode_from_string(self) -> None:
        """Test creating ScanMode from string."""
        assert ScanMode("quick") == ScanMode.QUICK
        assert ScanMode("deep") == ScanMode.DEEP


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_output_format_values(self) -> None:
        """Test output format values."""
        assert OutputFormat.TABLE.value == "table"
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.CSV.value == "csv"
        assert OutputFormat.YAML.value == "yaml"


class TestSourceConfig:
    """Tests for SourceConfig dataclass."""

    def test_source_config_creation(self) -> None:
        """Test source config creation."""
        source = SourceConfig(name="shodan", api_key="test_key", rate_limit=1.0)
        assert source.name == "shodan"
        assert source.api_key == "test_key"  # pragma: allowlist secret
        assert source.rate_limit == 1.0
        assert source.enabled is True

    def test_source_config_defaults(self) -> None:
        """Test source config defaults."""
        source = SourceConfig(name="test")
        assert source.enabled is True
        assert source.api_key is None
        assert source.rate_limit == 1.0
        assert source.timeout == 30
        assert source.priority == 1

    def test_source_config_disabled(self) -> None:
        """Test disabled source config."""
        source = SourceConfig(name="paid_source", enabled=False)
        assert source.enabled is False


class TestAppConfig:
    """Tests for AppConfig dataclass."""

    def test_default_config(self, default_config: AppConfig) -> None:
        """Test default config values."""
        assert default_config.verbose is False
        assert default_config.debug is False
        assert default_config.mode == ScanMode.STANDARD
        assert default_config.timeout == 30
        assert default_config.max_workers == 5
        assert default_config.output_format == OutputFormat.TABLE

    def test_verbose_config(self, verbose_config: AppConfig) -> None:
        """Test verbose config."""
        assert verbose_config.verbose is True
        assert verbose_config.debug is True

    def test_stealth_config(self, stealth_config: AppConfig) -> None:
        """Test stealth mode config."""
        assert stealth_config.mode == ScanMode.STEALTH
        assert stealth_config.timeout == 60

    def test_config_with_sources(self, config_with_sources: AppConfig) -> None:
        """Test config with API sources."""
        assert "shodan" in config_with_sources.sources
        api_key = config_with_sources.sources["shodan"].api_key
        assert api_key == "test_key"  # pragma: allowlist secret
        assert "virustotal" in config_with_sources.sources

    def test_config_load_from_file(self, temp_config_file: Path) -> None:
        """Test loading config from file."""
        config = AppConfig.load(temp_config_file)
        assert config.verbose is True
        assert config.debug is False
        assert config.mode == ScanMode.STANDARD
        assert "shodan" in config.sources

    def test_config_load_default_locations(self, tmp_path: Path) -> None:
        """Test loading config from default locations."""
        # Create a config in a temp directory
        config_path = tmp_path / "domainraptor.yaml"
        config_path.write_text("verbose: true\nmode: deep\n")

        with patch.object(Path, "cwd", return_value=tmp_path):
            config = AppConfig.load()
            assert config.verbose is True
            assert config.mode == ScanMode.DEEP

    def test_config_load_nonexistent(self) -> None:
        """Test loading config when file doesn't exist."""
        config = AppConfig.load(Path("/nonexistent/path/config.yaml"))
        # Should return default config
        assert config.mode == ScanMode.STANDARD
        assert config.verbose is False

    def test_config_env_overrides(self) -> None:
        """Test environment variable overrides."""
        with patch.dict(
            os.environ,
            {
                "DOMAINRAPTOR_VERBOSE": "true",
                "DOMAINRAPTOR_DEBUG": "true",
                "DOMAINRAPTOR_MODE": "deep",
                "SHODAN_API_KEY": "env_shodan_key",  # pragma: allowlist secret
            },
        ):
            config = AppConfig.load()
            assert config.verbose is True
            assert config.debug is True
            assert config.mode == ScanMode.DEEP
            shodan_api_key = config.sources.get("shodan", SourceConfig(name="x")).api_key
            assert shodan_api_key == "env_shodan_key"  # pragma: allowlist secret

    def test_config_save(self, tmp_path: Path) -> None:
        """Test saving config to file."""
        shodan_src = SourceConfig(name="shodan", api_key="test_key")  # pragma: allowlist secret
        config = AppConfig(
            verbose=True,
            mode=ScanMode.DEEP,
            sources={
                "shodan": shodan_src,
            },
        )

        config_path = tmp_path / "saved_config.yaml"
        config.save(config_path)

        assert config_path.exists()
        content = config_path.read_text()
        assert "verbose: true" in content
        assert "mode: deep" in content

    def test_config_save_creates_directory(self, tmp_path: Path) -> None:
        """Test that save creates parent directories."""
        config = AppConfig()
        config_path = tmp_path / "nested" / "dir" / "config.yaml"
        config.save(config_path)
        assert config_path.exists()

    def test_set_nested(self) -> None:
        """Test _set_nested helper method."""
        data: dict = {}
        AppConfig._set_nested(data, "a.b.c", "value")
        assert data == {"a": {"b": {"c": "value"}}}

        # Test overwriting
        AppConfig._set_nested(data, "a.b.d", "another")
        assert data["a"]["b"]["d"] == "another"

    def test_from_dict_with_sources(self) -> None:
        """Test _from_dict with source configurations."""
        data = {
            "verbose": True,
            "mode": "quick",
            "sources": {
                "shodan": {
                    "enabled": True,
                    "api_key": "key123",  # pragma: allowlist secret
                    "rate_limit": 0.5,
                },
                "virustotal": True,  # Simple boolean
            },
        }
        config = AppConfig._from_dict(data)
        assert config.verbose is True
        assert config.mode == ScanMode.QUICK
        assert config.sources["shodan"].api_key == "key123"  # pragma: allowlist secret
        assert config.sources["virustotal"].enabled is True


class TestDefaultSources:
    """Tests for DEFAULT_SOURCES configuration."""

    def test_default_sources_exist(self) -> None:
        """Test that default sources are defined."""
        assert "crt_sh" in DEFAULT_SOURCES
        assert "dnspython" in DEFAULT_SOURCES
        assert "hackertarget" in DEFAULT_SOURCES
        assert "whois" in DEFAULT_SOURCES

    def test_free_sources_enabled(self) -> None:
        """Test that free sources are enabled by default."""
        assert DEFAULT_SOURCES["crt_sh"].enabled is True
        assert DEFAULT_SOURCES["dnspython"].enabled is True

    def test_paid_sources_disabled(self) -> None:
        """Test that paid sources are disabled by default."""
        assert DEFAULT_SOURCES["shodan"].enabled is False
        assert DEFAULT_SOURCES["virustotal"].enabled is False

    def test_source_priorities(self) -> None:
        """Test that sources have correct priority tiers."""
        # Tier 1: Free
        assert DEFAULT_SOURCES["crt_sh"].priority == 1
        assert DEFAULT_SOURCES["dnspython"].priority == 1

        # Tier 2: Free utilities
        assert DEFAULT_SOURCES["sslyze"].priority == 2

        # Tier 3: Freemium
        assert DEFAULT_SOURCES["alienvault_otx"].priority == 3

        # Tier 4: Paid
        assert DEFAULT_SOURCES["shodan"].priority == 4
