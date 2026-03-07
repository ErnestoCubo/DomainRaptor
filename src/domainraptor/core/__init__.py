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
    "OutputFormat",
    "ScanMode",
    "SourceConfig",
    # Types
    "Asset",
    "AssetType",
    "Certificate",
    "Change",
    "ChangeType",
    "ConfigIssue",
    "DnsRecord",
    "ScanResult",
    "Service",
    "SeverityLevel",
    "Vulnerability",
    "WatchTarget",
]
