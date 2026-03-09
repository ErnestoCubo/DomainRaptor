"""Core configuration management for DomainRaptor."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class ScanMode(str, Enum):
    """Scan intensity modes."""

    QUICK = "quick"  # Fast, minimal sources, no rate limiting
    STANDARD = "standard"  # Balanced, common sources
    DEEP = "deep"  # Thorough, all sources, slower
    STEALTH = "stealth"  # Slow, randomized delays, avoids detection


class OutputFormat(str, Enum):
    """Output format options."""

    TABLE = "table"
    JSON = "json"
    CSV = "csv"
    YAML = "yaml"


@dataclass
class SourceConfig:
    """Configuration for a data source."""

    name: str
    enabled: bool = True
    api_key: str | None = None
    rate_limit: float = 1.0  # requests per second
    timeout: int = 30
    priority: int = 1  # lower = higher priority


@dataclass
class AppConfig:
    """Main application configuration."""

    # General
    verbose: bool = False
    debug: bool = False
    no_color: bool = False

    # Scan settings
    mode: ScanMode = ScanMode.STANDARD
    timeout: int = 30
    max_workers: int = 5
    retry_count: int = 3

    # Data sources
    free_only: bool = False
    sources: dict[str, SourceConfig] = field(default_factory=dict)

    # Storage
    db_path: Path = field(default_factory=lambda: Path.home() / ".domainraptor" / "data.db")
    cache_ttl: int = 3600  # 1 hour

    # Output
    output_format: OutputFormat = OutputFormat.TABLE
    output_file: Path | None = None

    @classmethod
    def load(cls, config_path: Path | None = None) -> AppConfig:
        """Load configuration from file and environment."""
        config_data: dict[str, Any] = {}

        # Default config locations
        if config_path is None:
            config_locations = [
                Path.cwd() / "domainraptor.yaml",
                Path.cwd() / ".domainraptor.yaml",
                Path.home() / ".config" / "domainraptor" / "config.yaml",
                Path.home() / ".domainraptor" / "config.yaml",
            ]
            for loc in config_locations:
                if loc.exists():
                    config_path = loc
                    break

        # Load from file
        if config_path and config_path.exists():
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}

        # Override with environment variables
        config_data = cls._apply_env_overrides(config_data)

        return cls._from_dict(config_data)

    @classmethod
    def _apply_env_overrides(cls, config_data: dict[str, Any]) -> dict[str, Any]:
        """Apply environment variable overrides to config."""
        env_mappings = {
            "DOMAINRAPTOR_VERBOSE": ("verbose", lambda x: x.lower() == "true"),
            "DOMAINRAPTOR_DEBUG": ("debug", lambda x: x.lower() == "true"),
            "DOMAINRAPTOR_MODE": ("mode", str),
            "DOMAINRAPTOR_DB_PATH": ("db_path", Path),
            "SHODAN_API_KEY": ("sources.shodan.api_key", str),
            "VIRUSTOTAL_API_KEY": ("sources.virustotal.api_key", str),
            "SECURITYTRAILS_API_KEY": ("sources.securitytrails.api_key", str),
            "CENSYS_API_KEY": ("sources.censys.api_key", str),
        }

        for env_var, (key_path, converter) in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                cls._set_nested(config_data, key_path, converter(value))

        return config_data

    @staticmethod
    def _set_nested(data: dict, key_path: str, value: Any) -> None:
        """Set a nested dictionary value using dot notation."""
        keys = key_path.split(".")
        current = data
        for key in keys[:-1]:
            current = current.setdefault(key, {})
        current[keys[-1]] = value

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> AppConfig:
        """Create AppConfig from dictionary."""
        sources = {}
        for name, src_data in data.get("sources", {}).items():
            if isinstance(src_data, dict):
                sources[name] = SourceConfig(name=name, **src_data)
            else:
                sources[name] = SourceConfig(name=name, enabled=bool(src_data))

        mode_str = data.get("mode", "standard")
        mode = ScanMode(mode_str) if isinstance(mode_str, str) else mode_str

        output_fmt = data.get("output_format", "table")
        output_format = OutputFormat(output_fmt) if isinstance(output_fmt, str) else output_fmt

        return cls(
            verbose=data.get("verbose", False),
            debug=data.get("debug", False),
            no_color=data.get("no_color", False),
            mode=mode,
            timeout=data.get("timeout", 30),
            max_workers=data.get("max_workers", 5),
            retry_count=data.get("retry_count", 3),
            free_only=data.get("free_only", False),
            sources=sources,
            db_path=Path(data.get("db_path", Path.home() / ".domainraptor" / "data.db")),
            cache_ttl=data.get("cache_ttl", 3600),
            output_format=output_format,
            output_file=Path(data["output_file"]) if data.get("output_file") else None,
        )

    def save(self, config_path: Path) -> None:
        """Save configuration to file."""
        config_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "verbose": self.verbose,
            "debug": self.debug,
            "mode": self.mode.value,
            "timeout": self.timeout,
            "max_workers": self.max_workers,
            "free_only": self.free_only,
            "db_path": str(self.db_path),
            "cache_ttl": self.cache_ttl,
            "output_format": self.output_format.value,
            "sources": {
                name: {
                    "enabled": src.enabled,
                    "api_key": src.api_key,
                    "rate_limit": src.rate_limit,
                }
                for name, src in self.sources.items()
            },
        }

        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# Default source configurations (free-first)
DEFAULT_SOURCES = {
    # Tier 1: Always free
    "crt_sh": SourceConfig(name="crt_sh", priority=1),
    "dnspython": SourceConfig(name="dnspython", priority=1),
    "hackertarget": SourceConfig(name="hackertarget", priority=1),
    "whois": SourceConfig(name="whois", priority=1),
    "sslyze": SourceConfig(name="sslyze", priority=2),
    "nvd": SourceConfig(name="nvd", priority=2),
    # Tier 2: Freemium (limited free tier)
    "alienvault_otx": SourceConfig(name="alienvault_otx", priority=3),
    "urlscan": SourceConfig(name="urlscan", priority=3),
    # Tier 3: Paid (user must provide key)
    "shodan": SourceConfig(name="shodan", priority=4, enabled=False),
    "virustotal": SourceConfig(name="virustotal", priority=4, enabled=False),
    "censys": SourceConfig(name="censys", priority=4, enabled=False),
}
