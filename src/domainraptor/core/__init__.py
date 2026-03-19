"""Core module - shared utilities, config, and base classes."""

from domainraptor.core.config import AppConfig, OutputFormat, ScanMode, SourceConfig
from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    Change,
    ChangeType,
    ConfigIssue,
    DnsRecord,
    ScanResult,
    Service,
    SeverityLevel,
    Vulnerability,
    WatchTarget,
)

__all__ = [
    # Config
    "AppConfig",
    # Types
    "Asset",
    "AssetType",
    "Certificate",
    "Change",
    "ChangeType",
    "ConfigIssue",
    "DnsRecord",
    "OutputFormat",
    "ScanMode",
    "ScanResult",
    "Service",
    "SeverityLevel",
    "SourceConfig",
    "Vulnerability",
    "WatchTarget",
]
