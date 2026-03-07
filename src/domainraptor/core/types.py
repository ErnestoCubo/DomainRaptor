"""Core type definitions for DomainRaptor."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class AssetType(str, Enum):
    """Type of discovered asset."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    EMAIL = "email"


class SeverityLevel(str, Enum):
    """Vulnerability/issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ChangeType(str, Enum):
    """Type of change detected between scans."""

    NEW = "new"
    REMOVED = "removed"
    MODIFIED = "modified"


@dataclass
class Asset:
    """Represents a discovered asset (domain, IP, service, etc.)."""

    type: AssetType
    value: str
    parent: str | None = None  # Parent domain/IP
    source: str = "unknown"
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.type, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Asset):
            return NotImplemented
        return self.type == other.type and self.value == other.value


@dataclass
class DnsRecord:
    """DNS record information."""

    record_type: str  # A, AAAA, MX, TXT, NS, CNAME, etc.
    value: str
    ttl: int | None = None
    priority: int | None = None  # For MX records


@dataclass
class Certificate:
    """SSL/TLS certificate information."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    san: list[str] = field(default_factory=list)  # Subject Alternative Names
    fingerprint_sha256: str = ""
    is_expired: bool = False
    days_until_expiry: int = 0


@dataclass
class Service:
    """Detected service on a port."""

    port: int
    protocol: str  # tcp, udp
    service_name: str = ""
    version: str = ""
    banner: str = ""
    cpe: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """Identified vulnerability."""

    id: str  # CVE-XXXX-XXXXX or internal ID
    title: str
    severity: SeverityLevel
    description: str = ""
    affected_asset: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    detected_at: datetime = field(default_factory=datetime.now)
    source: str = ""


@dataclass
class ConfigIssue:
    """Configuration issue or misconfiguration."""

    id: str
    title: str
    severity: SeverityLevel
    category: str  # ssl, dns, headers, etc.
    description: str = ""
    affected_asset: str = ""
    current_value: str = ""
    recommended_value: str = ""
    remediation: str = ""


@dataclass
class Change:
    """Detected change between scans."""

    change_type: ChangeType
    asset_type: AssetType
    asset_value: str
    old_value: Any = None
    new_value: Any = None
    detected_at: datetime = field(default_factory=datetime.now)
    description: str = ""


@dataclass
class ScanResult:
    """Complete result of a scan operation."""

    target: str
    scan_type: str  # discover, assess, etc.
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"  # running, completed, failed, cancelled
    assets: list[Asset] = field(default_factory=list)
    dns_records: list[DnsRecord] = field(default_factory=list)
    certificates: list[Certificate] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    config_issues: list[ConfigIssue] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        """Calculate scan duration in seconds."""
        if self.completed_at is None:
            return (datetime.now() - self.started_at).total_seconds()
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def is_complete(self) -> bool:
        return self.status in ("completed", "failed", "cancelled")


@dataclass
class WatchTarget:
    """Target being monitored by watch command."""

    target: str
    watch_type: str  # domain, ip, certificate
    interval_hours: int = 24
    last_check: datetime | None = None
    next_check: datetime | None = None
    enabled: bool = True
    notify_on: list[str] = field(default_factory=lambda: ["new", "removed", "modified"])
    metadata: dict[str, Any] = field(default_factory=dict)
