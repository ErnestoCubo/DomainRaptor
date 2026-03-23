"""Core module - shared utilities, config, and base classes."""

from domainraptor.core.config import AppConfig, OutputFormat, ScanMode, SourceConfig
from domainraptor.core.risk import (
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    calculate_risk_level,
    get_risk_level_description,
    get_risk_level_display,
)
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
    "AppConfig",
    "Asset",
    "AssetType",
    "Certificate",
    "Change",
    "ChangeType",
    "ConfigIssue",
    "DnsRecord",
    "OutputFormat",
    "RiskAssessment",
    "RiskFactor",
    "RiskLevel",
    "ScanMode",
    "ScanResult",
    "Service",
    "SeverityLevel",
    "SourceConfig",
    "Vulnerability",
    "WatchTarget",
    "calculate_risk_level",
    "get_risk_level_description",
    "get_risk_level_display",
]
