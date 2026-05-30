"""SQLAlchemy Core schema mirror for DomainRaptor.

This module provides cross-dialect ``Table`` definitions that mirror the
hand-written SQLite schema in :mod:`domainraptor.storage.database` (version 3).

It is the source of truth for Alembic migrations and for initializing
non-SQLite backends (PostgreSQL, MySQL) via ``metadata.create_all(engine)``.

The legacy SQLite code path in :class:`DatabaseManager` continues to use the
raw DDL strings for backwards compatibility; both paths must produce
equivalent schemas. Whenever the legacy DDL changes, update this metadata too.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)

SCHEMA_VERSION = 3

metadata = MetaData()


metadata_table = Table(
    "metadata",
    metadata,
    Column("key", String, primary_key=True),
    Column("value", String, nullable=False),
)

scans_table = Table(
    "scans",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("target", String, nullable=False),
    Column("scan_type", String, nullable=False),
    Column("status", String, nullable=False, server_default="running"),
    Column("started_at", String, nullable=False),
    Column("completed_at", String),
    Column("duration_seconds", Float),
    Column("error_count", Integer, server_default="0"),
    Column("metadata", Text, server_default="{}"),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Index("idx_scans_target", "target"),
    Index("idx_scans_type", "scan_type"),
    Index("idx_scans_status", "status"),
    Index("idx_scans_started_at", "started_at"),
)

assets_table = Table(
    "assets",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
    Column("type", String, nullable=False),
    Column("value", String, nullable=False),
    Column("parent", String),
    Column("source", String, server_default="unknown"),
    Column("first_seen", String, nullable=False),
    Column("last_seen", String, nullable=False),
    Column("metadata", Text, server_default="{}"),
    UniqueConstraint("scan_id", "type", "value", name="uq_assets_scan_type_value"),
    Index("idx_assets_scan_id", "scan_id"),
    Index("idx_assets_type", "type"),
    Index("idx_assets_value", "value"),
)

dns_records_table = Table(
    "dns_records",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
    Column("record_type", String, nullable=False),
    Column("value", String, nullable=False),
    Column("ttl", Integer),
    Column("priority", Integer),
    Index("idx_dns_scan_id", "scan_id"),
)

certificates_table = Table(
    "certificates",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
    Column("subject", String, nullable=False),
    Column("issuer", String, nullable=False),
    Column("serial_number", String, nullable=False),
    Column("not_before", String, nullable=False),
    Column("not_after", String, nullable=False),
    Column("san", Text, server_default="[]"),
    Column("fingerprint_sha256", String),
    Column("is_expired", Boolean, server_default="0"),
    Column("days_until_expiry", Integer),
    Index("idx_certs_scan_id", "scan_id"),
)

config_issues_table = Table(
    "config_issues",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
    Column("issue_id", String, nullable=False),
    Column("title", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("category", String, nullable=False),
    Column("description", Text),
    Column("affected_asset", String),
    Column("current_value", String),
    Column("recommended_value", String),
    Column("remediation", Text),
    Index("idx_issues_scan_id", "scan_id"),
    Index("idx_issues_severity", "severity"),
    Index("idx_issues_category", "category"),
)

vulnerabilities_table = Table(
    "vulnerabilities",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
    Column("vuln_id", String, nullable=False),
    Column("title", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("description", Text),
    Column("affected_asset", String),
    Column("cvss_score", Float),
    Column("cvss_vector", String),
    Column("vuln_references", Text, server_default="[]"),
    Column("remediation", Text),
    Column("detected_at", String, nullable=False),
    Column("source", String),
    Column("epss_score", Float),
    Column("in_cisa_kev", Boolean, server_default="0"),
    Column("exploit_refs", Text, server_default="[]"),
    Index("idx_vulns_scan_id", "scan_id"),
    Index("idx_vulns_severity", "severity"),
)

watch_targets_table = Table(
    "watch_targets",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("target", String, nullable=False, unique=True),
    Column("watch_type", String, nullable=False, server_default="domain"),
    Column("interval_hours", Integer, nullable=False, server_default="24"),
    Column("last_check", String),
    Column("next_check", String),
    Column("enabled", Boolean, nullable=False, server_default="1"),
    Column("notify_on", Text, server_default='["new", "removed", "modified"]'),
    Column("metadata", Text, server_default="{}"),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Index("idx_watch_target", "target"),
    Index("idx_watch_enabled", "enabled"),
    Index("idx_watch_next_check", "next_check"),
)

services_table = Table(
    "services",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
    Column("ip", String, nullable=False),
    Column("port", Integer, nullable=False),
    Column("protocol", String, server_default="tcp"),
    Column("service_name", String),
    Column("version", String),
    Column("banner", Text),
    Column("product", String),
    Column("os", String),
    Column("cpe", Text, server_default="[]"),
    Column("metadata", Text, server_default="{}"),
    Column("source", String, server_default="shodan"),
    Index("idx_services_scan_id", "scan_id"),
    Index("idx_services_ip", "ip"),
    Index("idx_services_port", "port"),
)


__all__ = [
    "SCHEMA_VERSION",
    "assets_table",
    "certificates_table",
    "config_issues_table",
    "dns_records_table",
    "metadata",
    "metadata_table",
    "scans_table",
    "services_table",
    "vulnerabilities_table",
    "watch_targets_table",
]
